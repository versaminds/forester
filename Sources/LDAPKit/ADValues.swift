// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// Decoders for the Active Directory value formats that are unreadable raw:
/// binary SIDs and GUIDs, FILETIME integers, and flag bit fields.
public enum ADValues {

    // MARK: Security identifiers

    /// `S-1-5-21-…` from the binary form (MS-DTYP §2.4.2.2).
    public static func sidString(_ data: Data) -> String? {
        let b = [UInt8](data)
        guard b.count >= 8, b[0] == 1 else { return nil }
        let count = Int(b[1])
        guard b.count == 8 + count * 4 else { return nil }
        var authority: UInt64 = 0
        for i in 2..<8 { authority = authority << 8 | UInt64(b[i]) }
        var parts = ["S", "1", String(authority)]
        for i in 0..<count {
            let o = 8 + i * 4
            let value = UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
            parts.append(String(value))
        }
        return parts.joined(separator: "-")
    }

    /// The binary form of `S-1-5-21-…`, for searching by SID.
    public static func sidData(_ string: String) -> Data? {
        let parts = string.uppercased().split(separator: "-")
        guard parts.count >= 3, parts[0] == "S", parts[1] == "1",
              let authority = UInt64(parts[2]), authority < 1 << 48 else { return nil }
        let subs = parts.dropFirst(3).compactMap { UInt32($0) }
        guard subs.count == parts.count - 3, subs.count <= 15 else { return nil }
        var bytes: [UInt8] = [1, UInt8(subs.count)]
        for shift in stride(from: 40, through: 0, by: -8) { bytes.append(UInt8(truncatingIfNeeded: authority >> UInt64(shift))) }
        for sub in subs { bytes += [UInt8(sub & 0xFF), UInt8(sub >> 8 & 0xFF), UInt8(sub >> 16 & 0xFF), UInt8(sub >> 24)] }
        return Data(bytes)
    }

    /// The relative identifier: the last sub-authority of a domain SID.
    public static func rid(_ sid: String) -> Int? {
        sid.split(separator: "-").last.flatMap { Int($0) }
    }

    /// The domain part of an account SID (everything before the RID).
    public static func domainSID(of sid: String) -> String? {
        guard sid.hasPrefix("S-1-5-21-") else { return nil }
        return sid.split(separator: "-").dropLast().joined(separator: "-")
    }

    static let wellKnownSIDs: [String: String] = [
        "S-1-0-0": "Nobody", "S-1-1-0": "Everyone", "S-1-2-0": "Local", "S-1-3-0": "Creator Owner",
        "S-1-3-1": "Creator Group", "S-1-5-1": "Dialup", "S-1-5-2": "Network", "S-1-5-3": "Batch",
        "S-1-5-4": "Interactive", "S-1-5-6": "Service", "S-1-5-7": "Anonymous Logon",
        "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-10": "Self", "S-1-5-11": "Authenticated Users",
        "S-1-5-13": "Terminal Server Users", "S-1-5-14": "Remote Interactive Logon", "S-1-5-15": "This Organization",
        "S-1-5-18": "Local System", "S-1-5-19": "Local Service", "S-1-5-20": "Network Service",
        "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
        "S-1-5-32-547": "Power Users", "S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators",
        "S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators", "S-1-5-32-552": "Replicators",
        "S-1-5-32-554": "Pre-Windows 2000 Compatible Access", "S-1-5-32-555": "Remote Desktop Users",
        "S-1-5-32-556": "Network Configuration Operators", "S-1-5-32-558": "Performance Monitor Users",
        "S-1-5-32-559": "Performance Log Users", "S-1-5-32-560": "Windows Authorization Access Group",
        "S-1-5-32-562": "Distributed COM Users", "S-1-5-32-568": "IIS_IUSRS", "S-1-5-32-569": "Cryptographic Operators",
        "S-1-5-32-573": "Event Log Readers", "S-1-5-32-578": "Hyper-V Administrators",
        "S-1-5-32-580": "Remote Management Users",
    ]

    static let wellKnownRIDs: [Int: String] = [
        500: "Administrator", 501: "Guest", 502: "krbtgt", 512: "Domain Admins", 513: "Domain Users",
        514: "Domain Guests", 515: "Domain Computers", 516: "Domain Controllers", 517: "Cert Publishers",
        518: "Schema Admins", 519: "Enterprise Admins", 520: "Group Policy Creator Owners",
        521: "Read-only Domain Controllers", 522: "Cloneable Domain Controllers", 525: "Protected Users",
        526: "Key Admins", 527: "Enterprise Key Admins", 553: "RAS and IAS Servers",
        571: "Allowed RODC Password Replication Group", 572: "Denied RODC Password Replication Group",
    ]

    /// A name for a well-known SID, such as "Authenticated Users" or "Domain Admins".
    public static func wellKnownName(_ sid: String) -> String? {
        if let name = wellKnownSIDs[sid] { return name }
        if sid.hasPrefix("S-1-5-21-"), let rid = rid(sid), sid.split(separator: "-").count == 8 {
            return wellKnownRIDs[rid]
        }
        return nil
    }

    // MARK: GUIDs

    /// AD stores GUIDs with the first three fields little-endian (MS-DTYP §2.3.4.2).
    public static func guidString(_ data: Data) -> String? {
        let b = [UInt8](data)
        guard b.count == 16 else { return nil }
        let order = [3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15]
        return order.map { $0 < 0 ? "-" : String(format: "%02x", b[$0]) }.joined()
    }

    public static func guidData(_ string: String) -> Data? {
        let hex = string.filter(\.isHexDigit)
        guard hex.count == 32, let uuid = UUID(uuidString: [hex.prefix(8), hex.dropFirst(8).prefix(4), hex.dropFirst(12).prefix(4),
                                                            hex.dropFirst(16).prefix(4), hex.dropFirst(20)].joined(separator: "-"))
        else { return nil }
        let u = uuid.uuid
        let b = [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
        let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
        return Data(order.map { b[$0] })
    }

    // MARK: Time

    public enum FileTime: Equatable, Sendable {
        /// 0: the meaning depends on the attribute ("never logged on", "must change password").
        case zero
        /// 0x7FFFFFFFFFFFFFFF: "never", as accountExpires uses it.
        case never
        case date(Date)
    }

    static let fileTimeEpochOffset: Int64 = 11_644_473_600

    /// A FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
    public static func fileTime(_ value: Int64) -> FileTime {
        if value == 0 { return .zero }
        if value == Int64.max || value < 0 { return .never }
        let seconds = Double(value) / 10_000_000 - Double(fileTimeEpochOffset)
        return .date(Date(timeIntervalSince1970: seconds))
    }

    public static func fileTimeValue(_ date: Date) -> Int64 {
        Int64((date.timeIntervalSince1970 + Double(fileTimeEpochOffset)) * 10_000_000)
    }

    /// AD stores policy durations (maxPwdAge, lockoutDuration) as negative
    /// 100-nanosecond intervals.
    public static func interval(_ value: Int64) -> TimeInterval? {
        if value == Int64.min { return nil } // "never"
        return Double(abs(value)) / 10_000_000
    }

    /// RFC 4517 GeneralizedTime: `20240115093000.0Z`, `20240115093000Z`,
    /// `202401150930+0100`.
    public static func generalizedTime(_ text: String) -> Date? {
        let s = Array(text.trimmingCharacters(in: .whitespaces))
        guard s.count >= 10 else { return nil }
        func number(_ from: Int, _ length: Int) -> Int? {
            guard from + length <= s.count else { return nil }
            let digits = s[from..<(from + length)]
            // Only digits: Int("+0") would read a time zone's sign as seconds.
            guard digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
            return Int(String(digits))
        }
        guard let year = number(0, 4), let month = number(4, 2), let day = number(6, 2), let hour = number(8, 2) else { return nil }
        var index = 10
        var minute = 0, second = 0
        if let m = number(index, 2) { minute = m; index += 2
            if let sec = number(index, 2) { second = sec; index += 2 }
        }
        var fraction = 0.0
        if index < s.count, s[index] == "." || s[index] == "," {
            var digits = "0."
            index += 1
            while index < s.count, s[index].isNumber { digits.append(s[index]); index += 1 }
            fraction = Double(digits) ?? 0
        }
        var offset = 0
        if index < s.count {
            switch s[index] {
            case "Z": break
            case "+", "-":
                let sign = s[index] == "-" ? -1 : 1
                guard let h = number(index + 1, 2) else { return nil }
                let m = number(index + 3, 2) ?? 0
                offset = sign * (h * 3600 + m * 60)
            default: return nil
            }
        }
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(secondsFromGMT: offset)
        components.year = year; components.month = month; components.day = day
        components.hour = hour; components.minute = minute; components.second = second
        guard let date = components.date else { return nil }
        return date.addingTimeInterval(fraction)
    }

    // MARK: Flags

    public struct Flag: Sendable, Equatable {
        public var bit: Int64
        public var name: String
        public var label: String
        /// Worth a warning badge (disabled, locked out, unconstrained delegation…).
        public var notable: Bool
        /// What turning it on does besides setting the bit, when that is
        /// something to know before saving.
        public var whenTurnedOn: String? = nil
    }

    /// AD's answer to requiring a smart card: the password goes, for good.
    /// Turning the requirement off again does not bring the old one back.
    public static let smartCardRequiredNote = "Active Directory replaces the account's password with a random one, so the user can sign in only with a smart card. Turning this off again does not restore the old password; reset it then."

    public static let userAccountControlFlags: [Flag] = [
        Flag(bit: 0x1, name: "SCRIPT", label: "Logon script runs", notable: false),
        Flag(bit: 0x2, name: "ACCOUNTDISABLE", label: "Account disabled", notable: true),
        Flag(bit: 0x8, name: "HOMEDIR_REQUIRED", label: "Home directory required", notable: false),
        Flag(bit: 0x10, name: "LOCKOUT", label: "Locked out", notable: true),
        Flag(bit: 0x20, name: "PASSWD_NOTREQD", label: "Password not required", notable: true),
        Flag(bit: 0x40, name: "PASSWD_CANT_CHANGE", label: "User cannot change password", notable: false),
        Flag(bit: 0x80, name: "ENCRYPTED_TEXT_PWD_ALLOWED", label: "Reversible password encryption", notable: true),
        Flag(bit: 0x100, name: "TEMP_DUPLICATE_ACCOUNT", label: "Temporary duplicate account", notable: false),
        Flag(bit: 0x200, name: "NORMAL_ACCOUNT", label: "Normal account", notable: false),
        Flag(bit: 0x800, name: "INTERDOMAIN_TRUST_ACCOUNT", label: "Interdomain trust account", notable: false),
        Flag(bit: 0x1000, name: "WORKSTATION_TRUST_ACCOUNT", label: "Workstation or member server", notable: false),
        Flag(bit: 0x2000, name: "SERVER_TRUST_ACCOUNT", label: "Domain controller", notable: false),
        Flag(bit: 0x10000, name: "DONT_EXPIRE_PASSWORD", label: "Password never expires", notable: true),
        Flag(bit: 0x20000, name: "MNS_LOGON_ACCOUNT", label: "MNS logon account", notable: false),
        Flag(bit: 0x40000, name: "SMARTCARD_REQUIRED", label: "Smart card required", notable: false, whenTurnedOn: smartCardRequiredNote),
        Flag(bit: 0x80000, name: "TRUSTED_FOR_DELEGATION", label: "Trusted for unconstrained delegation", notable: true),
        Flag(bit: 0x100000, name: "NOT_DELEGATED", label: "Sensitive, cannot be delegated", notable: false),
        Flag(bit: 0x200000, name: "USE_DES_KEY_ONLY", label: "DES keys only", notable: true),
        Flag(bit: 0x400000, name: "DONT_REQ_PREAUTH", label: "Kerberos pre-authentication not required", notable: true),
        Flag(bit: 0x800000, name: "PASSWORD_EXPIRED", label: "Password expired", notable: true),
        Flag(bit: 0x1000000, name: "TRUSTED_TO_AUTH_FOR_DELEGATION", label: "Trusted to authenticate for delegation", notable: true),
        Flag(bit: 0x4000000, name: "PARTIAL_SECRETS_ACCOUNT", label: "Read-only domain controller", notable: false),
    ]

    public static let supportedEncryptionTypeFlags: [Flag] = [
        Flag(bit: 0x1, name: "DES_CBC_CRC", label: "DES-CBC-CRC", notable: true),
        Flag(bit: 0x2, name: "DES_CBC_MD5", label: "DES-CBC-MD5", notable: true),
        Flag(bit: 0x4, name: "RC4_HMAC", label: "RC4-HMAC", notable: false),
        Flag(bit: 0x8, name: "AES128_CTS_HMAC_SHA1_96", label: "AES128", notable: false),
        Flag(bit: 0x10, name: "AES256_CTS_HMAC_SHA1_96", label: "AES256", notable: false),
        Flag(bit: 0x20, name: "AES256_CTS_HMAC_SHA1_96_SK", label: "AES256 session keys", notable: false),
    ]

    public static func flags(_ value: Int64, in table: [Flag]) -> [Flag] {
        table.filter { value & $0.bit != 0 }
    }

    /// Bits set in `value` that the table does not name.
    public static func unknownBits(_ value: Int64, in table: [Flag]) -> Int64 {
        value & ~table.reduce(0) { $0 | $1.bit }
    }

    /// "Global security group", "Universal distribution group"…
    public static func groupTypeDescription(_ value: Int64) -> String {
        let bits = value & 0xFFFF_FFFF
        let security = bits & 0x8000_0000 != 0
        let scope: String
        if bits & 0x1 != 0 { scope = "Builtin local" }
        else if bits & 0x2 != 0 { scope = "Global" }
        else if bits & 0x4 != 0 { scope = "Domain local" }
        else if bits & 0x8 != 0 { scope = "Universal" }
        else if bits & 0x10 != 0 { scope = "Application basic" }
        else if bits & 0x20 != 0 { scope = "Application query" }
        else { scope = "Unknown scope" }
        return "\(scope) \(security ? "security" : "distribution") group"
    }

    public static func isSecurityGroup(_ groupType: Int64) -> Bool {
        groupType & 0x8000_0000 != 0
    }

    public static func samAccountTypeDescription(_ value: Int64) -> String? {
        [0x0: "Domain object", 0x1000_0000: "Security group", 0x1000_0001: "Distribution group",
         0x2000_0000: "Security alias (domain local)", 0x2000_0001: "Distribution alias",
         0x3000_0000: "User account", 0x3000_0001: "Computer account", 0x3000_0002: "Trust account",
         0x4000_0000: "Application basic group", 0x4000_0001: "Application query group"][value]
    }

    /// domainFunctionality, forestFunctionality, msDS-Behavior-Version.
    public static func functionalLevelName(_ value: Int) -> String {
        switch value {
        case 0: return "Windows 2000"
        case 1: return "Windows Server 2003 interim"
        case 2: return "Windows Server 2003"
        case 3: return "Windows Server 2008"
        case 4: return "Windows Server 2008 R2"
        case 5: return "Windows Server 2012"
        case 6: return "Windows Server 2012 R2"
        case 7: return "Windows Server 2016"
        case 10: return "Windows Server 2025"
        default: return "Level \(value)"
        }
    }
}
