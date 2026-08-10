#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 8 ]]; then
  echo "Usage: $0 CHANGES CLASSIC_SELECTED CLASSIC_RESULT LINUX_SELECTED LINUX_RESULT WINDOWS_SELECTED WINDOWS_RESULT WINDOWS_NATIVE_RESULT" >&2
  exit 2
fi

changes_result=$1
classic_selected=$2
classic_result=$3
linux_selected=$4
linux_result=$5
windows_selected=$6
windows_result=$7
windows_native_result=$8

if [[ ${changes_result} != success ]]; then
  echo "Change selection concluded ${changes_result}." >&2
  exit 1
fi

require_result() {
  local name=$1
  local selected=$2
  local result=$3

  if [[ ${selected} != true && ${selected} != false ]]; then
    echo "${name} selection is invalid: '${selected}'." >&2
    exit 1
  fi
  if [[ ${selected} == true && ${result} != success ]]; then
    echo "${name} validation was selected but concluded ${result}." >&2
    exit 1
  fi
  if [[ ${selected} == false && ${result} != skipped ]]; then
    echo "${name} validation was not selected but concluded ${result}." >&2
    exit 1
  fi
}

require_result CLASSIC "${classic_selected}" "${classic_result}"
require_result LINUX "${linux_selected}" "${linux_result}"
require_result WINDOWS "${windows_selected}" "${windows_result}"
require_result "Native Windows" "${windows_selected}" \
  "${windows_native_result}"
