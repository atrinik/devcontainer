#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi

work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT
repo="${work}/repo"
checkout="${work}/worktree"
payload='Atrinik Git LFS smoke payload'

git init --quiet "${repo}"
git -C "${repo}" config user.email 'image-smoke@example.invalid'
git -C "${repo}" config user.name 'Atrinik image smoke'
git -C "${repo}" lfs install --local >/dev/null
git -C "${repo}" lfs track '*.payload' >/dev/null
printf '%s\n' "${payload}" > "${repo}/sample.payload"
git -C "${repo}" add .gitattributes sample.payload
git -C "${repo}" commit --quiet -m 'smoke Git LFS payload'
git -C "${repo}" worktree add --quiet "${checkout}" HEAD

test "$(git -C "${checkout}" lfs ls-files --name-only)" = 'sample.payload'
test "$(cat "${checkout}/sample.payload")" = "${payload}"
test "$(git -C "${checkout}" check-attr filter -- sample.payload)" = \
  'sample.payload: filter: lfs'
test "$(git -C "${repo}" show HEAD:sample.payload | sed -n '1p')" = \
  'version https://git-lfs.github.com/spec/v1'

echo 'git-lfs smoke: passed'
