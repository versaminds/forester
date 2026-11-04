#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
"""Generate an Active Directory-shaped LDIF for the local test slapd.

The data is deterministic (seeded), so screenshots and integration tests see
the same directory every run. Attributes AD computes (memberOf, directReports,
objectGUID, whenCreated) are written directly; slapadd accepts them offline.
"""
import base64
import os
import random
import struct
import sys
import uuid
import zlib
from datetime import datetime, timedelta, timezone

BASE = "DC=corp,DC=example"
DOMAIN_SID = (21, 1004336348, 1177238915, 682003330)
# Dates are relative to the day the server starts, so "expires soon", "not seen
# for 90 days" and the like stay true whenever it is run. The structure is seeded
# and identical every time.
NOW = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
rng = random.Random(4242)

entries = []          # list of (dn, [(attr, value)]) in insertion order
by_dn = {}
member_of = {}        # member dn -> [group dn]
direct_reports = {}   # manager dn -> [dn]


def sid_bytes(*sub, authority=5):
    out = struct.pack("BB", 1, len(sub)) + authority.to_bytes(6, "big")
    for s in sub:
        out += struct.pack("<I", s)
    return out


def domain_sid(rid):
    return sid_bytes(*DOMAIN_SID, rid)


def guid_bytes(name):
    return uuid.uuid5(uuid.NAMESPACE_DNS, name.lower()).bytes_le


def filetime(dt):
    return str(int((dt.timestamp() + 11644473600) * 10_000_000))


def gentime(dt):
    return dt.strftime("%Y%m%d%H%M%S.0Z")


def ntds(dc, site="Default-First-Site-Name"):
    return f"CN=NTDS Settings,CN={dc},CN=Servers,CN={site},CN=Sites,CN=Configuration,{BASE}"


CHANGE_PASSWORD = uuid.UUID("ab721a53-1e2f-11d0-9819-00aa0040529b").bytes_le


def security_descriptor(cannot_change_password=False):
    """A self-relative SD shaped like a new AD user's, owner and group Domain Admins.

    "User cannot change password" is two deny ACEs for the Change Password right,
    for Everyone and SELF, ahead of the allow ACEs: what ADUC writes.
    """
    def ace(kind, flags, mask, sid, object_type=None):
        body = struct.pack("<I", mask)
        if object_type is not None:
            body += struct.pack("<I", 1) + object_type
        body += sid
        return bytes([kind, flags]) + struct.pack("<H", 4 + len(body)) + body

    everyone, principal_self = sid_bytes(0, authority=1), sid_bytes(10)
    kind = 0x06 if cannot_change_password else 0x05
    change = [ace(kind, 0, 0x100, everyone, CHANGE_PASSWORD), ace(kind, 0, 0x100, principal_self, CHANGE_PASSWORD)]
    aces = change if cannot_change_password else []
    aces += [ace(0x00, 0, 0xF01FF, domain_sid(512)), ace(0x00, 0, 0xF01FF, sid_bytes(18)),
             ace(0x00, 0, 0x20094, sid_bytes(11))]
    if not cannot_change_password:
        aces += change
    aces += [ace(0x00, 0x12, 0x20094, sid_bytes(32, 554))]  # inherited, container-inherit
    body = b"".join(aces)
    dacl = bytes([4, 0]) + struct.pack("<HH", 8 + len(body), len(aces)) + b"\0\0" + body
    owner = group_sid = domain_sid(512)
    control = 0x8000 | 0x0400 | 0x0004  # self-relative, DACL auto-inherited, DACL present
    owner_at = 20 + len(dacl)
    header = bytes([1, 0]) + struct.pack("<HIIII", control, owner_at, owner_at + len(owner), 0, 20)
    return header + dacl + owner + group_sid


def invocation_id(dc):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, dc.lower()))


def repl_attr(attribute, version, when, dc, usn):
    return ("<DS_REPL_ATTR_META_DATA>\n"
            f"\t<pszAttributeName>{attribute}</pszAttributeName>\n"
            f"\t<dwVersion>{version}</dwVersion>\n"
            f"\t<ftimeLastOriginatingChange>{when.strftime('%Y-%m-%dT%H:%M:%SZ')}</ftimeLastOriginatingChange>\n"
            f"\t<uuidLastOriginatingDsaInvocationID>{invocation_id(dc)}</uuidLastOriginatingDsaInvocationID>\n"
            f"\t<usnOriginatingChange>{usn}</usnOriginatingChange>\n"
            f"\t<usnLocalChange>{usn + 17}</usnLocalChange>\n"
            f"\t<pszLastOriginatingDsaDN>{ntds(dc)}</pszLastOriginatingDsaDN>\n"
            "</DS_REPL_ATTR_META_DATA>\n")


def repl_value(attribute, value_dn, created, dc, usn):
    return ("<DS_REPL_VALUE_META_DATA>\n"
            f"\t<pszAttributeName>{attribute}</pszAttributeName>\n"
            f"\t<pszObjectDn>{value_dn}</pszObjectDn>\n"
            "\t<ftimeDeleted>1601-01-01T00:00:00Z</ftimeDeleted>\n"
            f"\t<ftimeCreated>{created.strftime('%Y-%m-%dT%H:%M:%SZ')}</ftimeCreated>\n"
            "\t<dwVersion>1</dwVersion>\n"
            f"\t<ftimeLastOriginatingChange>{created.strftime('%Y-%m-%dT%H:%M:%SZ')}</ftimeLastOriginatingChange>\n"
            f"\t<uuidLastOriginatingDsaInvocationID>{invocation_id(dc)}</uuidLastOriginatingDsaInvocationID>\n"
            f"\t<usnOriginatingChange>{usn}</usnOriginatingChange>\n"
            f"\t<usnLocalChange>{usn}</usnLocalChange>\n"
            f"\t<pszLastOriginatingDsaDN>{ntds(dc)}</pszLastOriginatingDsaDN>\n"
            "</DS_REPL_VALUE_META_DATA>\n")


def png_avatar(seed):
    """A 64x64 two-colour avatar, written as a raw PNG without any imaging library."""
    r = random.Random(seed)
    bg = (r.randint(40, 200), r.randint(40, 200), r.randint(40, 200))
    fg = (255, 255, 255)
    size = 64
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            dx, dy = x - 32, y - 26
            head = dx * dx + dy * dy < 13 * 13
            body = (x - 32) ** 2 + (y - 66) ** 2 < 28 * 28
            row += bytes(fg if head or body else bg)
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def add(dn, *pairs):
    attrs = []
    for k, v in pairs:
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            attrs.extend((k, x) for x in v)
        else:
            attrs.append((k, v))
    entries.append((dn, attrs))
    by_dn[dn] = attrs
    return dn


def stamps(created_days_ago):
    created = NOW - timedelta(days=created_days_ago, minutes=rng.randint(0, 600))
    changed = created + timedelta(days=rng.randint(0, max(1, created_days_ago - 1)))
    return [("whenCreated", gentime(created)), ("whenChanged", gentime(min(changed, NOW)))]


def container(dn, cn, description=None, cls="container"):
    return add(dn, ("objectClass", ["top", cls]), ("cn", cn), ("description", description),
               ("objectGUID", guid_bytes(dn)), *stamps(900))


def ou(dn, name, description=None, gplink=None):
    return add(dn, ("objectClass", ["top", "organizationalUnit"]), ("ou", name),
               ("description", description), ("gPLink", gplink),
               ("objectGUID", guid_bytes(dn)), *stamps(800))


rid_counter = [1103]


def next_rid():
    rid_counter[0] += 1
    return rid_counter[0]


UAC_NORMAL = 0x200
UAC_DISABLED = 0x2
UAC_DONT_EXPIRE = 0x10000
UAC_LOCKOUT = 0x10
UAC_SMARTCARD = 0x40000


def user(parent, given, sn, sam, title=None, dept=None, uac=UAC_NORMAL, rid=None, manager=None,
         photo=False, spn=None, admin=False, locked=False, last_logon_days=None, pwd_days=None,
         expires=None, description=None, created_days=None, mail=True, cannot_change_password=False):
    cn = f"{given} {sn}".strip()
    dn = f"CN={cn},{parent}"
    rid = rid or next_rid()
    created_days = created_days if created_days is not None else rng.randint(30, 1400)
    last_logon_days = last_logon_days if last_logon_days is not None else rng.randint(0, 20)
    pwd_days = pwd_days if pwd_days is not None else rng.randint(1, 170)
    pairs = [
        ("objectClass", ["top", "person", "organizationalPerson", "user"]),
        # This schema's person class requires sn (AD's does not), so accounts without one reuse their name.
        ("cn", cn), ("sn", sn or cn), ("givenName", given or None), ("displayName", cn),
        ("sAMAccountName", sam), ("userPrincipalName", f"{sam}@corp.example"),
        ("mail", f"{sam}@corp.example" if mail else None),
        ("title", title), ("department", dept), ("company", "Corp Example NV" if dept else None),
        ("telephoneNumber", f"+32 9 {rng.randint(100, 999)} {rng.randint(10, 99)} {rng.randint(10, 99)}" if dept else None),
        ("description", description),
        ("manager", manager),
        ("objectSid", domain_sid(rid)), ("objectGUID", guid_bytes(dn)),
        ("userAccountControl", str(uac | (UAC_LOCKOUT if locked else 0))),
        ("primaryGroupID", "513"), ("sAMAccountType", "805306368"),
        ("pwdLastSet", filetime(NOW - timedelta(days=pwd_days, hours=rng.randint(0, 23)))),
        ("lastLogonTimestamp", filetime(NOW - timedelta(days=last_logon_days, hours=rng.randint(0, 23))) if last_logon_days >= 0 else "0"),
        ("lastLogon", filetime(NOW - timedelta(days=max(last_logon_days - 1, 0), hours=rng.randint(0, 23))) if last_logon_days >= 0 else "0"),
        ("accountExpires", filetime(expires) if expires else "9223372036854775807"),
        ("badPwdCount", "5" if locked else "0"),
        ("logonCount", str(rng.randint(0, 900))),
        ("lockoutTime", filetime(NOW - timedelta(minutes=12)) if locked else None),
        ("adminCount", "1" if admin else None),
        ("servicePrincipalName", spn),
        ("thumbnailPhoto", png_avatar(sam) if photo else None),
        *stamps(created_days),
    ]
    pairs.append(("nTSecurityDescriptor", security_descriptor(cannot_change_password)))
    if dept != "Bulk":
        # Its own random source, so adding metadata leaves every name and date
        # drawn from rng (which the testing guide refers to) where it was.
        mrng = random.Random(sam)
        created = NOW - timedelta(days=created_days)
        usn = mrng.randint(12000, 90000)
        meta = [repl_attr("cn", 1, created, "DC01", usn), repl_attr("objectClass", 1, created, "DC01", usn),
                repl_attr("sAMAccountName", 1, created, "DC01", usn),
                repl_attr("pwdLastSet", mrng.randint(2, 30), NOW - timedelta(days=pwd_days), mrng.choice(["DC01", "DC02"]), usn + 900),
                repl_attr("userAccountControl", mrng.randint(1, 4), created + timedelta(days=1), "DC01", usn + 5)]
        if title:
            meta.append(repl_attr("title", mrng.randint(1, 3), created + timedelta(days=mrng.randint(1, max(2, created_days - 1))),
                                  mrng.choice(["DC01", "DC02"]), usn + 300))
        if locked:
            meta.append(repl_attr("lockoutTime", 6, NOW - timedelta(minutes=12), "DC02", usn + 2000))
        pairs.append(("msDS-ReplAttributeMetaData", meta))
    add(dn, *pairs)
    if manager:
        direct_reports.setdefault(manager, []).append(dn)
    return dn


GROUP_GLOBAL_SECURITY = -2147483646
GROUP_UNIVERSAL_SECURITY = -2147483640
GROUP_DOMAIN_LOCAL_SECURITY = -2147483644
GROUP_GLOBAL_DISTRIBUTION = 2
GROUP_BUILTIN_LOCAL = -2147483643


def group(parent, name, members=(), gtype=GROUP_GLOBAL_SECURITY, rid=None, description=None, sid=None,
          mail=None, managed_by=None, admin=False):
    dn = f"CN={name},{parent}"
    sid = sid or domain_sid(rid or next_rid())
    sam_type = "268435456" if gtype < 0 and gtype != GROUP_DOMAIN_LOCAL_SECURITY else "536870912"
    add(dn, ("objectClass", ["top", "group"]), ("cn", name), ("sAMAccountName", name),
        ("groupType", str(gtype)), ("sAMAccountType", sam_type), ("description", description),
        ("mail", mail), ("managedBy", managed_by), ("adminCount", "1" if admin else None),
        ("member", list(members)), ("objectSid", sid), ("objectGUID", guid_bytes(dn)), *stamps(1000))
    for m in members:
        member_of.setdefault(m, []).append(dn)
    return dn


def computer(parent, name, os_name, os_version, uac=0x1000, spn=None, last_logon_days=None, description=None):
    dn = f"CN={name},{parent}"
    host = f"{name.lower()}.corp.example"
    last_logon_days = last_logon_days if last_logon_days is not None else rng.randint(0, 10)
    add(dn, ("objectClass", ["top", "person", "organizationalPerson", "user", "computer"]),
        ("cn", name), ("sn", name), ("sAMAccountName", f"{name}$"), ("dNSHostName", host),
        # Apple's slapd reserves operatingSystemVersion for its root DSE, so the version is not stored.
        ("operatingSystem", os_name),
        ("userAccountControl", str(uac)), ("primaryGroupID", "516" if uac & 0x2000 else "515"),
        ("sAMAccountType", "805306369"), ("description", description),
        ("servicePrincipalName", spn or [f"HOST/{host}", f"HOST/{name}"]),
        ("lastLogonTimestamp", filetime(NOW - timedelta(days=last_logon_days))),
        ("pwdLastSet", filetime(NOW - timedelta(days=rng.randint(1, 29)))),
        ("objectSid", domain_sid(next_rid())), ("objectGUID", guid_bytes(dn)), *stamps(rng.randint(60, 1200)))
    return dn


# ── Domain root ──────────────────────────────────────────────────────────────
gpo_default = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
gpo_dc = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
gpo_wks = "{8F3C5A2E-4C1B-4E3A-9D6F-2B7C1E0A9F11}"
add(BASE, ("objectClass", ["top", "domain", "domainDNS"]), ("dc", "corp"),
    ("objectSid", sid_bytes(*DOMAIN_SID)), ("objectGUID", guid_bytes(BASE)),
    ("gPLink", f"[LDAP://cn={gpo_default},cn=policies,cn=system,{BASE};0]"),
    ("maxPwdAge", "-36288000000000"), ("minPwdLength", "12"), ("lockoutThreshold", "5"),
    ("lockoutDuration", "-18000000000"), ("msDS-Behavior-Version", "7"),
    ("minPwdAge", "-864000000000"), ("pwdHistoryLength", "24"), ("pwdProperties", "1"),
    ("lockoutObservationWindow", "-18000000000"), ("ms-DS-MachineAccountQuota", "10"),
    ("fSMORoleOwner", ntds("DC01")), *stamps(1500))

users_cn = container(f"CN=Users,{BASE}", "Users", "Default container for upgraded user accounts")
computers_cn = container(f"CN=Computers,{BASE}", "Computers", "Default container for upgraded computer accounts")
builtin = container(f"CN=Builtin,{BASE}", "Builtin")
system = container(f"CN=System,{BASE}", "System", "Builtin system settings")
policies = container(f"CN=Policies,{system}", "Policies")
for guid, name in [(gpo_default, "Default Domain Policy"), (gpo_dc, "Default Domain Controllers Policy"),
                   (gpo_wks, "Workstation Baseline")]:
    dn = f"CN={guid},{policies}"
    add(dn, ("objectClass", ["top", "container", "groupPolicyContainer"]), ("cn", guid),
        ("displayName", name), ("gPCFileSysPath", f"\\\\corp.example\\SysVol\\corp.example\\Policies\\{guid}"),
        ("versionNumber", str(rng.randint(1, 90))), ("flags", "0"), ("objectGUID", guid_bytes(dn)), *stamps(1500))
fsp = container(f"CN=ForeignSecurityPrincipals,{BASE}", "ForeignSecurityPrincipals",
                "Default container for security identifiers (SIDs) associated with objects from external, trusted domains")
add(f"CN=S-1-5-11,{fsp}", ("objectClass", ["top", "foreignSecurityPrincipal"]), ("cn", "S-1-5-11"),
    ("objectSid", sid_bytes(11)), ("objectGUID", guid_bytes("fsp-11")), *stamps(1500))

dcs = ou(f"OU=Domain Controllers,{BASE}", "Domain Controllers", "Default container for domain controllers",
         gplink=f"[LDAP://cn={gpo_dc},cn=policies,cn=system,{BASE};0]")
dc01 = computer(dcs, "DC01", "Windows Server 2025 Datacenter", "10.0 (26100)", uac=0x82000,
                spn=["ldap/dc01.corp.example", "HOST/dc01.corp.example", "GC/dc01.corp.example/corp.example"])
dc02 = computer(dcs, "DC02", "Windows Server 2025 Datacenter", "10.0 (26100)", uac=0x82000)

# ── Built-in accounts in CN=Users ────────────────────────────────────────────
administrator = user(users_cn, "Administrator", "", "Administrator", rid=500, uac=UAC_NORMAL | UAC_DONT_EXPIRE,
                     admin=True, description="Built-in account for administering the computer/domain",
                     pwd_days=412, mail=False, created_days=1500)
guest = user(users_cn, "Guest", "", "Guest", rid=501, uac=UAC_NORMAL | UAC_DISABLED | UAC_DONT_EXPIRE | 0x20,
             description="Built-in account for guest access to the computer/domain", last_logon_days=-1,
             mail=False, created_days=1500)
krbtgt = user(users_cn, "krbtgt", "", "krbtgt", rid=502, uac=UAC_NORMAL | UAC_DISABLED,
              description="Key Distribution Center Service Account", last_logon_days=-1, admin=True,
              mail=False, created_days=1500)

# ── Corp OU tree ─────────────────────────────────────────────────────────────
corp = ou(f"OU=Corp,{BASE}", "Corp", "Corp Example NV")
corp_users = ou(f"OU=Users,{corp}", "Users")
corp_groups = ou(f"OU=Groups,{corp}", "Groups", "Security and distribution groups")
wks = ou(f"OU=Workstations,{corp}", "Workstations", gplink=f"[LDAP://cn={gpo_wks},cn=policies,cn=system,{BASE};0]")
servers = ou(f"OU=Servers,{corp}", "Servers")
svc = ou(f"OU=Service Accounts,{corp}", "Service Accounts", "Managed by the platform team")
disabled_ou = ou(f"OU=Disabled Users,{corp}", "Disabled Users", "Leavers, kept 90 days before deletion")

FIRST = ["Lotte", "Wout", "Elise", "Jonas", "Marie", "Arne", "Sofie", "Pieter", "Hanne", "Bram", "Lien",
         "Thomas", "Fien", "Stijn", "Noor", "Robbe", "Ines", "Kobe", "Amber", "Jens", "Lore", "Senne",
         "Emma", "Lucas", "Julie", "Milan", "Laura", "Ruben", "Charlotte", "Matthias"]
LAST = ["Peeters", "Janssens", "Maes", "Jacobs", "Mertens", "Willems", "Claes", "Goossens", "Wouters",
        "De Smet", "Dubois", "Lambert", "Dupont", "Hermans", "Aerts", "Van Damme", "Pauwels", "Desmet"]

used = set()


def person_name():
    while True:
        g, s = rng.choice(FIRST), rng.choice(LAST)
        if (g, s) not in used:
            used.add((g, s))
            return g, s


sams = set()


def sam_for(g, s):
    """First initial and surname, as many AD sites do; a second person with the
    same one gets a number, because AD refuses a sAMAccountName twice."""
    base = (g[0] + s.replace(" ", "")).lower()
    sam, n = base, 1
    while sam in sams:
        n += 1
        sam = f"{base}{n}"
    sams.add(sam)
    return sam


departments = {
    "Engineering": ["Software Engineer", "Senior Software Engineer", "Site Reliability Engineer",
                    "Platform Engineer", "Engineering Manager"],
    "Finance": ["Accountant", "Financial Controller", "Payroll Specialist"],
    "Sales": ["Account Executive", "Sales Engineer", "Sales Manager"],
    "IT Operations": ["Systems Administrator", "Network Engineer", "Service Desk Analyst"],
}
dept_members = {}
dept_heads = {}
for dept, titles in departments.items():
    dept_ou = ou(f"OU={dept},{corp_users}", dept)
    g, s = person_name()
    head = user(dept_ou, g, s, sam_for(g, s), title=f"Head of {dept}", dept=dept, photo=True)
    dept_heads[dept] = head
    members = [head]
    count = {"Engineering": 16, "Finance": 7, "Sales": 9, "IT Operations": 8}[dept]
    for i in range(count):
        g, s = person_name()
        kwargs = {}
        if dept == "IT Operations" and i < 2:
            kwargs["admin"] = True
        if dept == "Sales" and i == 3:
            kwargs["locked"] = True
        if dept == "Engineering" and i == 5:
            kwargs["pwd_days"] = 400
            kwargs["uac"] = UAC_NORMAL | UAC_DONT_EXPIRE
        if dept == "Finance" and i == 1:
            kwargs["uac"] = UAC_NORMAL | UAC_SMARTCARD
        if dept == "Engineering" and i == 9:
            kwargs["expires"] = NOW + timedelta(days=21)
            kwargs["description"] = "Contractor, until end of month"
        members.append(user(dept_ou, g, s, sam_for(g, s), title=rng.choice(titles), dept=dept,
                             manager=head, photo=(i % 3 == 0), **kwargs))
    dept_members[dept] = members

leavers = []
for i in range(5):
    g, s = person_name()
    leavers.append(user(disabled_ou, g, s, sam_for(g, s), title="Former employee",
                        uac=UAC_NORMAL | UAC_DISABLED, last_logon_days=rng.randint(40, 300),
                        description=f"Disabled {(NOW - timedelta(days=rng.randint(5, 80))).date()} by service desk"))

svc_sql = user(svc, "svc_sql", "", "svc_sql", uac=UAC_NORMAL | UAC_DONT_EXPIRE, pwd_days=900,
               spn=["MSSQLSvc/sql01.corp.example:1433", "MSSQLSvc/sql01.corp.example"],
               description="SQL Server service account", mail=False)
svc_backup = user(svc, "svc_backup", "", "svc_backup", uac=UAC_NORMAL | UAC_DONT_EXPIRE, pwd_days=600, cannot_change_password=True,
                  description="Veeam backup service", mail=False)
svc_ldap = user(svc, "svc_ldapread", "", "svc_ldapread", uac=UAC_NORMAL | UAC_DONT_EXPIRE, pwd_days=200,
                description="Read-only bind account for applications", mail=False)

# Computers
wks_list = []
for i in range(1, 25):
    os_name, os_ver = rng.choice([("Windows 11 Enterprise", "10.0 (26100)"), ("Windows 11 Enterprise", "10.0 (22631)"),
                                   ("Windows 10 Enterprise", "10.0 (19045)"), ("Mac OS X", "15.6")])
    stale = i in (7, 19)
    wks_list.append(computer(wks, f"WKS-{i:04d}", os_name, os_ver, last_logon_days=rng.randint(120, 300) if stale else None,
                             description="Stale, not seen since migration" if stale else None))
bitlocker_parent = wks_list[0]
add(f"CN=2026-03-14T10:22:31-08:00{{5A1C0E2B-7F3D-4B9E-A1C2-3D4E5F6A7B8C}},{bitlocker_parent}",
    ("objectClass", ["top", "container"]), ("cn", "2026-03-14T10:22:31-08:00{5A1C0E2B-7F3D-4B9E-A1C2-3D4E5F6A7B8C}"),
    ("description", "BitLocker recovery information (test stand-in)"), *stamps(200))
srv = [computer(servers, n, "Windows Server 2022 Standard", "10.0 (20348)") for n in ("SQL01", "FS01", "APP01", "EXCH01")]
computer(servers, "LEGACY01", "Windows Server 2012 R2 Standard", "6.3 (9600)", last_logon_days=400,
         uac=0x1000 | 0x80000, description="Unconstrained delegation, scheduled for decommission")
computer(computers_cn, "TEMP-PC", "Windows 10 Pro", "10.0 (19045)", last_logon_days=90)

# Bulk OU, large enough to exercise paging (server page limit is 200).
# LDAP_TEST_BULK makes it larger, to measure the app against a big directory.
BULK = int(os.environ.get("LDAP_TEST_BULK", "1500"))
bulk = ou(f"OU=Bulk Import,{corp}", "Bulk Import", f"{BULK:,} synthetic accounts to test paging")
bulk_users = []
for i in range(1, BULK + 1):
    sam = f"bulk{i:04d}"
    bulk_users.append(user(bulk, f"Bulk", f"User {i:04d}", sam, title="Synthetic", dept="Bulk",
                           last_logon_days=rng.randint(0, 200), created_days=40))

# ── Groups ───────────────────────────────────────────────────────────────────
all_people = [m for ms in dept_members.values() for m in ms]
domain_users = group(users_cn, "Domain Users", rid=513, description="All domain users")
domain_admins = group(users_cn, "Domain Admins", [administrator] + dept_members["IT Operations"][1:3], rid=512,
                      description="Designated administrators of the domain", admin=True)
enterprise_admins = group(users_cn, "Enterprise Admins", [administrator], rid=519,
                          gtype=GROUP_UNIVERSAL_SECURITY, description="Designated administrators of the enterprise", admin=True)
domain_computers = group(users_cn, "Domain Computers", rid=515, description="All workstations and servers joined to the domain")
group(users_cn, "Domain Controllers", rid=516, description="All domain controllers in the domain")
group(builtin, "Administrators", [administrator, domain_admins, enterprise_admins], gtype=GROUP_BUILTIN_LOCAL,
      sid=sid_bytes(32, 544), description="Administrators have complete and unrestricted access", admin=True)
group(builtin, "Remote Desktop Users", gtype=GROUP_BUILTIN_LOCAL, sid=sid_bytes(32, 555),
      description="Members in this group are granted the right to logon remotely")

dept_groups = {}
for dept, members in dept_members.items():
    dept_groups[dept] = group(corp_groups, f"GG-{dept.replace(' ', '')}", members,
                              description=f"All members of {dept}", managed_by=dept_heads[dept])
sre = group(corp_groups, "GG-SRE", dept_members["Engineering"][2:6], description="On-call rotation")
vpn = group(corp_groups, "DL-VPN-Users", [dept_groups["Engineering"], dept_groups["IT Operations"], sre],
            gtype=GROUP_DOMAIN_LOCAL_SECURITY, description="Allowed to connect to the VPN (nested groups)")
group(corp_groups, "UG-All-Staff", all_people + bulk_users, gtype=GROUP_UNIVERSAL_SECURITY,
      description="Everyone, including synthetic accounts (1,500+ members)")
group(corp_groups, "Team Engineering (mail)", dept_members["Engineering"], gtype=GROUP_GLOBAL_DISTRIBUTION,
      mail="engineering@corp.example", description="Distribution list")
group(corp_groups, "GG-SQL-Admins", [svc_sql, dept_members["IT Operations"][3]], description="sysadmin on SQL01")
group(corp_groups, "GG-Empty-Legacy", [], description="No members, candidate for cleanup")
group(corp_groups, "GG-Workstation-Admins", [vpn, f"CN=S-1-5-11,{fsp}"],
      description="Local admin on workstations (nests DL-VPN-Users and Authenticated Users)")
add(f"CN=DYN-Engineering,{corp_groups}", ("objectClass", ["top", "groupOfURLs"]), ("cn", "DYN-Engineering"),
    ("description", "Dynamic group: every user in the Engineering OU"),
    ("memberURL", f"ldap:///OU=Engineering,{corp_users}??one?(objectClass=user)"))

# ── Configuration partition (in AD, its own naming context) ───────────────────
config = add(f"CN=Configuration,{BASE}", ("objectClass", ["top", "configuration"]), ("cn", "Configuration"), *stamps(1500))
partitions = add(f"CN=Partitions,{config}", ("objectClass", ["top", "crossRefContainer"]), ("cn", "Partitions"),
                 ("fSMORoleOwner", ntds("DC01")),
                 ("msDS-EnabledFeature", f"CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{config}"))
add(f"CN=CORP,{partitions}", ("objectClass", ["top", "crossRef"]), ("cn", "CORP"), ("nCName", BASE),
    ("nETBIOSName", "CORP"), ("dnsRoot", "corp.example"))
sites = add(f"CN=Sites,{config}", ("objectClass", ["top", "container"]), ("cn", "Sites"))
for site, site_dcs in [("Default-First-Site-Name", ["DC01"]), ("Brussels", ["DC02"])]:
    site_dn = add(f"CN={site},{sites}", ("objectClass", ["top", "site"]), ("cn", site))
    servers_dn = add(f"CN=Servers,{site_dn}", ("objectClass", ["top", "serversContainer"]), ("cn", "Servers"))
    for dc in site_dcs:
        server_dn = add(f"CN={dc},{servers_dn}", ("objectClass", ["top", "server"]), ("cn", dc))
        add(f"CN=NTDS Settings,{server_dn}", ("objectClass", ["top", "nTDSDSA"]), ("cn", "NTDS Settings"), ("options", "1"))
services = add(f"CN=Services,{config}", ("objectClass", ["top", "container"]), ("cn", "Services"))
windows_nt = add(f"CN=Windows NT,{services}", ("objectClass", ["top", "container"]), ("cn", "Windows NT"))
directory_service = add(f"CN=Directory Service,{windows_nt}", ("objectClass", ["top", "container"]),
                        ("cn", "Directory Service"), ("tombstoneLifetime", "180"))
optional = add(f"CN=Optional Features,{directory_service}", ("objectClass", ["top", "container"]), ("cn", "Optional Features"))
add(f"CN=Recycle Bin Feature,{optional}", ("objectClass", ["top", "msDS-OptionalFeature"]), ("cn", "Recycle Bin Feature"))
# In AD this is a dMD; Apple's slapd has its own dMD class, so a container stands in.
add(f"CN=Schema,{config}", ("objectClass", ["top", "container"]), ("cn", "Schema"), ("fSMORoleOwner", ntds("DC01")))
# DC02 sits in the Brussels site; its role holders say so.
add(f"CN=RID Manager$,{system}", ("objectClass", ["top", "rIDManager"]), ("cn", "RID Manager$"),
    ("fSMORoleOwner", ntds("DC02", "Brussels")))
add(f"CN=Infrastructure,{BASE}", ("objectClass", ["top", "infrastructureUpdate"]), ("cn", "Infrastructure"),
    ("fSMORoleOwner", ntds("DC02", "Brussels")))

# ── Fine-grained password policies ───────────────────────────────────────────
pso_container = add(f"CN=Password Settings Container,{system}", ("objectClass", ["top", "msDS-PasswordSettingsContainer"]),
                    ("cn", "Password Settings Container"))
pso_admins = add(f"CN=PSO-Admins,{pso_container}", ("objectClass", ["top", "msDS-PasswordSettings"]), ("cn", "PSO-Admins"),
                 ("description", "Long passwords and quick lockout for administrators"),
                 ("msDS-PasswordSettingsPrecedence", "10"), ("msDS-MinimumPasswordLength", "16"),
                 ("msDS-PasswordHistoryLength", "24"), ("msDS-PasswordComplexityEnabled", "TRUE"),
                 ("msDS-PasswordReversibleEncryptionEnabled", "FALSE"), ("msDS-MaximumPasswordAge", "-25920000000000"),
                 ("msDS-MinimumPasswordAge", "-864000000000"), ("msDS-LockoutThreshold", "3"),
                 ("msDS-LockoutDuration", "-36000000000"), ("msDS-LockoutObservationWindow", "-36000000000"),
                 ("msDS-PSOAppliesTo", domain_admins))
pso_services = add(f"CN=PSO-ServiceAccounts,{pso_container}", ("objectClass", ["top", "msDS-PasswordSettings"]),
                   ("cn", "PSO-ServiceAccounts"), ("description", "Service accounts: very long, never expiring"),
                   ("msDS-PasswordSettingsPrecedence", "20"), ("msDS-MinimumPasswordLength", "25"),
                   ("msDS-PasswordHistoryLength", "5"), ("msDS-PasswordComplexityEnabled", "TRUE"),
                   ("msDS-PasswordReversibleEncryptionEnabled", "FALSE"), ("msDS-MaximumPasswordAge", "-9223372036854775808"),
                   ("msDS-MinimumPasswordAge", "0"), ("msDS-LockoutThreshold", "0"),
                   ("msDS-LockoutDuration", "-18000000000"), ("msDS-LockoutObservationWindow", "-18000000000"),
                   ("msDS-PSOAppliesTo", [svc_sql, svc_backup]))
for admin_dn in [administrator] + dept_members["IT Operations"][1:3]:
    by_dn[admin_dn].append(("msDS-ResultantPSO", pso_admins))
for service_dn in (svc_sql, svc_backup):
    by_dn[service_dn].append(("msDS-ResultantPSO", pso_services))

# ── A forest trust ───────────────────────────────────────────────────────────
add(f"CN=partner.example,{system}", ("objectClass", ["top", "trustedDomain"]), ("cn", "partner.example"),
    ("trustPartner", "partner.example"), ("flatName", "PARTNER"), ("trustDirection", "3"), ("trustType", "2"),
    ("trustAttributes", "8"), ("securityIdentifier", sid_bytes(21, 3301245566, 1203376811, 2918007766)))

# When each member was added, as AD records it for linked values.
value_rng = random.Random(7)
for group_dn in [dept_groups["Engineering"], vpn]:
    entry_members = [v for k, v in by_dn[group_dn] if k == "member"]
    by_dn[group_dn].extend(
        ("msDS-ReplValueMetaData",
         repl_value("member", m, NOW - timedelta(days=value_rng.randint(5, 700)), value_rng.choice(["DC01", "DC02"]),
                    value_rng.randint(30000, 99000)))
        for m in entry_members)

# ── Back-links AD would compute ──────────────────────────────────────────────
for dn, groups in member_of.items():
    if dn in by_dn:
        by_dn[dn].extend(("memberOf", g) for g in groups)
for dn, reports in direct_reports.items():
    by_dn[dn].extend(("directReports", r) for r in reports)

# ── Generic (non-AD) suffix, to test a second naming context ─────────────────
ORG = "dc=example,dc=org"
add(ORG, ("objectClass", ["top", "dcObject", "organization"]), ("dc", "example"), ("o", "Example Org"))
add(f"ou=people,{ORG}", ("objectClass", ["top", "organizationalUnit"]), ("ou", "people"))
add(f"ou=groups,{ORG}", ("objectClass", ["top", "organizationalUnit"]), ("ou", "groups"))
people = []
for i, (g, s) in enumerate([("Ada", "Lovelace"), ("Alan", "Turing"), ("Grace", "Hopper"), ("Linus", "Torvalds")]):
    uid = (g[0] + s).lower()
    dn = add(f"uid={uid},ou=people,{ORG}", ("objectClass", ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "adtestAccountLock"]),
             ("uid", uid), ("cn", f"{g} {s}"), ("sn", s), ("givenName", g), ("mail", f"{uid}@example.org"),
             ("uidNumber", str(10000 + i)), ("gidNumber", "10000"), ("homeDirectory", f"/home/{uid}"),
             ("loginShell", "/bin/zsh"), ("jpegPhoto", png_avatar(uid) if i == 0 else None))
    people.append(dn)
add(f"cn=scientists,ou=groups,{ORG}", ("objectClass", ["top", "groupOfNames"]), ("cn", "scientists"),
    ("member", people[:3]))
add(f"cn=staff,ou=groups,{ORG}", ("objectClass", ["top", "posixGroup"]), ("cn", "staff"), ("gidNumber", "10000"),
    ("memberUid", ["alovelace", "aturing", "ghopper", "ltorvalds"]))
add(f"cn=everyone,ou=groups,{ORG}", ("objectClass", ["top", "groupOfURLs"]), ("cn", "everyone"),
    ("description", "Dynamic group of all people"), ("memberURL", f"ldap:///ou=people,{ORG}??one?(objectClass=inetOrgPerson)"))


# ── LDIF writer ──────────────────────────────────────────────────────────────
def ldif_value(attr, v):
    if isinstance(v, bytes):
        return f"{attr}:: {base64.b64encode(v).decode()}"
    safe = v and v[0] not in " :<" and v[-1] != " " and all(32 <= ord(c) < 127 for c in v)
    if safe or v == "":
        return f"{attr}: {v}"
    return f"{attr}:: {base64.b64encode(v.encode()).decode()}"


# Auxiliary classes the entries use; the structural class is the last of the others.
AUXILIARY = {"posixaccount", "adtestaccountlock", "dcobject", "adtestcommon", "extensibleobject"}
# Classes whose schema already allows AD's housekeeping attributes (GUID, timestamps…).
HOUSEKEEPING_CLASSES = {"user", "computer", "group", "domaindns", "foreignsecurityprincipal"}
HOUSEKEEPING = {"objectGUID", "objectSid", "whenCreated", "whenChanged", "gPLink", "managedBy", "adminCount", "description",
                "tombstoneLifetime", "fSMORoleOwner"}


def schema_ready(attrs):
    """Adds what slapd's schema check needs: structuralObjectClass, which an
    offline slapadd does not compute, and an auxiliary class for the AD
    housekeeping attributes on classes whose schema does not list them."""
    classes = [v for k, v in attrs if k == "objectClass"]
    structural = [c for c in classes if c.lower() not in AUXILIARY and c != "top"]
    out = list(attrs)
    if structural:
        out.append(("structuralObjectClass", structural[-1]))
    if not HOUSEKEEPING_CLASSES & {c.lower() for c in classes} and any(k in HOUSEKEEPING for k, _ in attrs):
        out.insert(len(classes), ("objectClass", "adtestCommon"))
    return out


def emit(out, suffix):
    for dn, attrs in entries:
        if not dn.lower().endswith(suffix.lower()):
            continue
        attrs = schema_ready(attrs)
        out.write(ldif_value("dn", dn) + "\n")
        for k, v in attrs:
            out.write(ldif_value(k, v) + "\n")
        out.write("\n")


# ── The same directory for a real AD domain controller (Samba, see samba/) ───
# A real AD manages much of what the slapd fixture writes directly (SIDs, GUIDs,
# timestamps, back-links, sign-in counters, replication metadata) and refuses
# it from a client. This keeps what an administrator could write, gives every
# account a password, and leaves out what the DC creates itself: its own
# accounts and groups in CN=Users and CN=Builtin, CN=System and Configuration,
# and the slapd-only dynamic group. Loaded with ldapadd over LDAPS, so it goes
# through the same checks a client's changes do.
SAMBA_PASSWORD = "Corp-Example-Test-Password-2026!"
SAMBA_KEEP = {
    "organizationalunit": {"objectclass", "ou", "description"},
    "user": {"objectclass", "cn", "sn", "givenname", "displayname", "samaccountname", "userprincipalname", "mail",
             "title", "department", "company", "telephonenumber", "description", "manager", "useraccountcontrol",
             "accountexpires", "serviceprincipalname", "thumbnailphoto", "admincount"},
    "computer": {"objectclass", "cn", "samaccountname", "dnshostname", "operatingsystem", "useraccountcontrol",
                 "description", "serviceprincipalname"},
    "group": {"objectclass", "cn", "samaccountname", "grouptype", "description", "mail", "managedby", "member",
              "admincount"},
}


def samba_kind(attrs):
    classes = {v.lower() for k, v in attrs if k == "objectClass"}
    for kind in ("computer", "user", "group", "organizationalunit"):
        if kind in classes:
            return kind
    return None


def unicode_pwd(password):
    return f'"{password}"'.encode("utf-16-le")


def emit_samba(out):
    builtin_groups = {f"CN={n},CN=Users,{BASE}" for n in ("Domain Admins",)}
    seeded = set()
    for dn, attrs in entries:
        lower = dn.lower()
        inside = lower.endswith(f"ou=corp,{BASE}".lower()) or lower == f"cn=temp-pc,cn=computers,{BASE}".lower()
        kind = samba_kind(attrs)
        if not inside or kind is None:
            continue
        keep = SAMBA_KEEP[kind]
        lines = [ldif_value("dn", dn)]
        for k, v in attrs:
            if k.lower() not in keep:
                continue
            if k == "userAccountControl":
                v = str(int(v) & ~UAC_LOCKOUT)  # locked out by failed sign-ins instead, after loading
            if k == "member" and v.lower() not in seeded and v not in builtin_groups:
                continue  # only members that exist by now (the DC's own built-ins are not referenced)
            lines.append(ldif_value(k, v))
        if kind in ("user", "computer"):
            lines.append(ldif_value("unicodePwd", unicode_pwd(SAMBA_PASSWORD)))
        out.write("\n".join(lines) + "\n\n")
        seeded.add(lower)
    # The DC's own groups: Domain Admins gains the two IT administrators.
    admins = [v for k, v in by_dn[domain_admins] if k == "member" and v.lower() in seeded]
    out.write(ldif_value("dn", f"CN=Domain Admins,CN=Users,{BASE}") + "\nchangetype: modify\nadd: member\n"
              + "".join(ldif_value("member", m) + "\n" for m in admins) + "-\n\n")
    # Fine-grained password policies, after the accounts they apply to.
    for pso in (pso_admins, pso_services):
        lines = [ldif_value("dn", pso)]
        for k, v in by_dn[pso]:
            if k == "msDS-PSOAppliesTo" and v.lower() not in seeded and v != domain_admins:
                continue
            lines.append(ldif_value(k, f"CN=Domain Admins,CN=Users,{BASE}" if v == domain_admins else v))
        out.write("\n".join(lines) + "\n\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "ad"
    if target == "samba":
        emit_samba(sys.stdout)
    else:
        emit(sys.stdout, BASE if target == "ad" else ORG)
