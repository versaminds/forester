#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Removes the domain controller start-ad.sh started (and everything in it).
podman rm -f forester-ad >/dev/null 2>&1 && echo "Stopped." || echo "Not running."
