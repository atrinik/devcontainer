#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 OBJDUMP PE_FILE EXPECTED_DLL..." >&2
  exit 2
fi

objdump=$1
pe_file=$2
shift 2

if [[ ! -f ${pe_file} ]]; then
  echo "PE file does not exist: ${pe_file}" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT

"${objdump}" -p "${pe_file}" \
  | sed -n 's/^[[:space:]]*DLL Name: //p' \
  | tr '[:upper:]' '[:lower:]' \
  | LC_ALL=C sort -u > "${work}/actual"
printf '%s\n' "$@" \
  | tr '[:upper:]' '[:lower:]' \
  | LC_ALL=C sort -u > "${work}/expected"

if ! cmp --silent "${work}/expected" "${work}/actual"; then
  echo "unexpected DLL imports in ${pe_file}:" >&2
  diff -u "${work}/expected" "${work}/actual" >&2 || true
  exit 1
fi

printf 'verified DLL imports for %s:' "${pe_file}"
while IFS= read -r dependency; do
  printf ' %s' "${dependency}"
done < "${work}/actual"
printf '\n'
