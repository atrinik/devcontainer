#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: $0 CLASSIC_SOURCE REPORT_DIRECTORY" >&2
  exit 2
fi
root=/opt/atrinik-portable
source=$(realpath "$1")
reports=$(realpath "$2")
test "$(id -u)" != 0
expected=$(jq -er '.consumer.commit' "${root}/contract.json")
test "$(git -C "${source}" rev-parse HEAD)" = "${expected}"
test -z "$(git -C "${source}" status --porcelain --untracked-files=normal)"
while read -r expected_hash input; do
  relative=${input#/cohort/source/}
  [[ ${relative} == client/* && ${relative} != *..* ]]
  printf '%s  %s\n' "${expected_hash}" "${source}/${relative}" | sha256sum -c -
done < "${root}/shader-inputs.txt"
"${root}/smoke.sh"
work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT
cmake -S "${source}" -B "${work}/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DATRINIK_BUILD_CLIENT=ON -DATRINIK_BUILD_SERVER=OFF \
  -DBUILD_TESTING=ON -DPACKAGE_TYPE=none \
  -DATRINIK_GPU_SHADER_DIRECTORY="${root}/shaders" \
  '-DCMAKE_C_FLAGS=-march=x86-64 -mtune=generic'
cmake --build "${work}/build" --parallel 2
ctest --test-dir "${work}/build" --output-on-failure --timeout 120
python3 - "${work}/build/compile_commands.json" <<'CHECK'
import json, shlex, sys
for item in json.load(open(sys.argv[1])):
    flags = item.get('arguments') or shlex.split(item['command'])
    assert '-march=x86-64' in flags and '-mtune=generic' in flags, item['file']
    assert all(not flag.startswith('-march=') or flag == '-march=x86-64' for flag in flags), item['file']
CHECK
mapfile -t clients < <(find "${work}/build" -type f -name atrinik -executable)
test "${#clients[@]}" = 1
python3 "${root}/abi.py" --output "${reports}/consumer-abi.json" "${clients[0]}"
cp "${work}/build/compile_commands.json" "${reports}/compile_commands.json"
cp "${work}/build/Testing/Temporary/LastTest.log" "${reports}/consumer-tests.log"
printf '%s\n' "${expected}" > "${reports}/classic-commit.txt"
cp "${root}/installed.json" "${root}/contract.json" "${reports}/"
