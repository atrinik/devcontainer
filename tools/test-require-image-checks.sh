#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
gate=${script_dir}/require-image-checks.sh

expect_success() {
  if ! "${gate}" "$@" >/dev/null 2>&1; then
    echo "Expected success: $*" >&2
    exit 1
  fi
}

expect_failure() {
  if "${gate}" "$@" >/dev/null 2>&1; then
    echo "Expected failure: $*" >&2
    exit 1
  fi
}

expect_success success true success true success true success success
expect_success success false skipped false skipped false skipped skipped

expect_failure failure true success true success true success success
expect_failure success true success true success true success
expect_failure success '' skipped false skipped false skipped skipped
expect_failure success malformed skipped false skipped false skipped skipped
expect_failure success true skipped false skipped false skipped skipped
expect_failure success false success false skipped false skipped skipped
expect_failure success false skipped false skipped true success skipped
expect_failure success false skipped false skipped false skipped success
