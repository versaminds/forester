#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Removes the server start-sasl.sh started, and its certificates.
podman rm -f forester-sasl >/dev/null 2>&1 && echo "Stopped." || echo "Not running."
rm -rf "${0:A:h}/.run/sasl"
