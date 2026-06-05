#!/usr/bin/env bash
# scripts/check-anchors.sh
#
# Anchor-stability guard for the protocol spec.
#
# Renders the spec from the current working tree and from `origin/main`,
# extracts every heading ID from each render, and fails if any anchor
# present on main is missing from the PR's render.
#
# Rationale: inbound links (provii-issuer README, ISMS pages, academic
# citations, blog posts) point at `#1-introduction` etc. Deleting an
# anchor silently is a breaking change for those consumers. Adding
# anchors is fine; removing them is not.
#
# Run locally:
#   ./scripts/check-anchors.sh
#
# CI calls this from the `anchor-stability` job in ci.yml.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

MAIN_HTML="${WORK}/main.html"
HEAD_HTML="${WORK}/head.html"
MAIN_IDS="${WORK}/main.ids"
HEAD_IDS="${WORK}/head.ids"

PANDOC_ARGS=(
  --from 'markdown+pipe_tables+raw_html+yaml_metadata_block+auto_identifiers'
  --to html5
  --standalone
  --toc
  --toc-depth=3
)

command -v pandoc >/dev/null 2>&1 || {
  echo "::error::pandoc is not installed. Install it before running this script."
  exit 2
}

# --- 1. render HEAD (current working tree) -----------------------------------
echo "Rendering working tree -> ${HEAD_HTML}"
pandoc "${PANDOC_ARGS[@]}" \
  --metadata title="Provii Protocol Specification (HEAD)" \
  -o "${HEAD_HTML}" \
  v0/protocol.md

# --- 2. render origin/main ---------------------------------------------------
# If origin/main is unavailable (fresh clone without fetch), we can't diff,
# so treat that as a soft pass rather than failing closed.
if ! git rev-parse --verify --quiet origin/main >/dev/null; then
  echo "::warning::origin/main not available; skipping anchor diff."
  exit 0
fi

# If the spec file does not yet exist on main (first-time addition), skip.
if ! git cat-file -e "origin/main:v0/protocol.md" 2>/dev/null; then
  echo "origin/main has no v0/protocol.md yet; nothing to diff. Skipping."
  exit 0
fi

echo "Rendering origin/main:v0/protocol.md -> ${MAIN_HTML}"
git show "origin/main:v0/protocol.md" > "${WORK}/main.md"
pandoc "${PANDOC_ARGS[@]}" \
  --metadata title="Provii Protocol Specification (main)" \
  -o "${MAIN_HTML}" \
  "${WORK}/main.md"

# --- 3. extract heading IDs --------------------------------------------------
# Grep for id="..." on heading tags (h1-h6). This is crude but deterministic
# and avoids a full HTML parser dependency.
extract_ids() {
  local html="$1"
  local out="$2"
  # Match id="..." inside h1..h6 opening tags. Pandoc emits these on its
  # own line for each heading when auto_identifiers is on.
  grep -oE '<h[1-6][^>]*id="[^"]+"' "${html}" \
    | sed -E 's/.*id="([^"]+)".*/\1/' \
    | LC_ALL=C sort -u \
    > "${out}"
}

extract_ids "${MAIN_HTML}" "${MAIN_IDS}"
extract_ids "${HEAD_HTML}" "${HEAD_IDS}"

main_count=$(wc -l < "${MAIN_IDS}" | tr -d ' ')
head_count=$(wc -l < "${HEAD_IDS}" | tr -d ' ')
echo "Anchors on main: ${main_count}"
echo "Anchors on HEAD: ${head_count}"

# --- 4. diff -----------------------------------------------------------------
# Anchors removed vs main = fatal. Anchors added on HEAD = fine.
MISSING="${WORK}/missing.ids"
LC_ALL=C comm -23 "${MAIN_IDS}" "${HEAD_IDS}" > "${MISSING}"

if [ -s "${MISSING}" ]; then
  echo
  echo "::error::Anchor-stability check FAILED. The following heading IDs exist on origin/main but are missing from this branch:"
  echo
  while IFS= read -r id; do
    echo "  - #${id}"
  done < "${MISSING}"
  echo
  echo "If you genuinely intended to rename a heading, update callers (README,"
  echo "provii-docs, ISMS pages, any blog posts) and call out the break in the"
  echo "PR description. Consider adding a redirect or an anchor alias instead."
  exit 1
fi

ADDED="${WORK}/added.ids"
LC_ALL=C comm -13 "${MAIN_IDS}" "${HEAD_IDS}" > "${ADDED}"
added_count=$(wc -l < "${ADDED}" | tr -d ' ')

echo "Anchor-stability OK. No removed anchors; ${added_count} added."
