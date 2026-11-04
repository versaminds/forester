#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Stop the test slapd started by start.sh, and wait until it has exited:
# slapd writes its database log while shutting down, so a restart that
# deletes .run too early fails with "Directory not empty".
RUN=${0:A:h}/.run

stop() {
  local name=$1 file=$2
  [[ -f $file ]] || return 0
  local pid=$(cat "$file")
  if kill "$pid" 2>/dev/null; then
    for i in {1..100}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null
      sleep 0.2
    fi
    echo "$name stopped"
  fi
  rm -f "$file"
}

stop slapd "$RUN/slapd.pid"
stop "TLS proxy" "$RUN/proxy.pid"
