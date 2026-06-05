#!/bin/sh
# Build static HTML render of the spec for spec.provii.app.
#
# Requires pandoc (brew install pandoc). Optional raster deps for the SEO
# OG image and PNG favicons: rsvg-convert OR ImageMagick.
#
# Guardrails:
#   - pandoc's auto-slug heading ids are preserved. The Lua filter
#     adds data-section="N.M" as an attribute only, never rewrites the id.
#   - the Lua filter asserts heading id uniqueness and fails
#     the build on any duplicate.
#   - --fail-if-warnings is set so pandoc warnings fail CI.

set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="${ROOT}/dist"
STATIC="${ROOT}/static"
BUILDDIR="${ROOT}/build"

# --- 1. Clean dist/ -------------------------------------------------------
rm -rf "${DIST}"
mkdir -p "${DIST}/v0" "${DIST}/styles" "${DIST}/assets"

# --- 2. Copy stylesheets --------------------------------------------------
cp "${BUILDDIR}/styles/"*.css "${DIST}/styles/"

# --- 3. Render the spec ---------------------------------------------------
pandoc "${ROOT}/v0/protocol.md" \
  --from markdown+pipe_tables+raw_html+yaml_metadata_block+auto_identifiers \
  --to html5 \
  --standalone \
  --template="${BUILDDIR}/template.html" \
  --lua-filter="${BUILDDIR}/lua/headings.lua" \
  --highlight-style=tango \
  --toc \
  --toc-depth=4 \
  --section-divs \
  --fail-if-warnings \
  --metadata title="Provii Protocol Specification" \
  --output "${DIST}/v0/protocol.html"

# --- 4. Copy static assets (landing page, sitemap, robots, favicons) -----
if [ -d "${STATIC}" ]; then
  cp -R "${STATIC}/." "${DIST}/"
fi

# --- 5. Rasterise SVG → PNG for favicons and OG image --------------------
ASSETS_DIR="${DIST}/assets"
RASTERISE=""
if command -v rsvg-convert >/dev/null 2>&1; then
  RASTERISE="rsvg-convert"
elif command -v magick >/dev/null 2>&1; then
  RASTERISE="magick"
elif command -v convert >/dev/null 2>&1; then
  RASTERISE="convert"
fi

if [ -n "${RASTERISE}" ] && [ -f "${ASSETS_DIR}/favicon.svg" ]; then
  case "${RASTERISE}" in
    rsvg-convert)
      rsvg-convert -w 32 -h 32 "${ASSETS_DIR}/favicon.svg" -o "${ASSETS_DIR}/favicon-32.png"
      rsvg-convert -w 180 -h 180 "${ASSETS_DIR}/favicon.svg" -o "${ASSETS_DIR}/apple-touch-icon.png"
      ;;
    magick|convert)
      "${RASTERISE}" -background none -resize 32x32 "${ASSETS_DIR}/favicon.svg" "${ASSETS_DIR}/favicon-32.png"
      "${RASTERISE}" -background none -resize 180x180 "${ASSETS_DIR}/favicon.svg" "${ASSETS_DIR}/apple-touch-icon.png"
      ;;
  esac
fi

if [ -n "${RASTERISE}" ] && [ -f "${ASSETS_DIR}/og-spec-v0.svg" ]; then
  case "${RASTERISE}" in
    rsvg-convert)
      rsvg-convert -w 1200 -h 630 "${ASSETS_DIR}/og-spec-v0.svg" -o "${ASSETS_DIR}/og-spec-v0.png"
      ;;
    magick|convert)
      "${RASTERISE}" -background "#0B1220" -resize 1200x630 "${ASSETS_DIR}/og-spec-v0.svg" "${ASSETS_DIR}/og-spec-v0.png"
      ;;
  esac
fi

if [ -z "${RASTERISE}" ]; then
  echo "warn: no SVG rasteriser found (install librsvg or imagemagick)." >&2
  echo "warn: favicon-32.png, apple-touch-icon.png, og-spec-v0.png not generated." >&2
fi

# --- 6. Splice head-seo.html into the protocol page ----------------------
# Sarah's template leaves a <!-- SEO_HEAD_INJECT --> marker at the end of
# <head>. Replace it with the real SEO tags, substituting {{GIT_COMMIT_DATE}}.
HEAD_SEO="${BUILDDIR}/head-seo.html"
PROTOCOL_HTML="${DIST}/v0/protocol.html"

if [ -f "${HEAD_SEO}" ] && [ -f "${PROTOCOL_HTML}" ]; then
  if GIT_DATE="$(git -C "${ROOT}" log -1 --format=%cI 2>/dev/null)" && [ -n "${GIT_DATE}" ]; then
    :
  else
    GIT_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi

  TMPHEAD="$(mktemp)"
  sed "s|{{GIT_COMMIT_DATE}}|${GIT_DATE}|g" "${HEAD_SEO}" > "${TMPHEAD}"

  TMPOUT="$(mktemp)"
  if grep -q "<!-- SEO_HEAD_INJECT -->" "${PROTOCOL_HTML}"; then
    awk -v inc="${TMPHEAD}" '
      /<!-- SEO_HEAD_INJECT -->/ {
        while ((getline line < inc) > 0) print line
        close(inc)
        next
      }
      { print }
    ' "${PROTOCOL_HTML}" > "${TMPOUT}"
    mv "${TMPOUT}" "${PROTOCOL_HTML}"
  else
    awk -v inc="${TMPHEAD}" '
      /<\/head>/ && !done {
        while ((getline line < inc) > 0) print line
        close(inc)
        done = 1
      }
      { print }
    ' "${PROTOCOL_HTML}" > "${TMPOUT}"
    mv "${TMPOUT}" "${PROTOCOL_HTML}"
  fi
  rm -f "${TMPHEAD}"
fi

echo "Built ${DIST}/v0/protocol.html"
[ -f "${DIST}/index.html" ] && echo "Copied ${DIST}/index.html (landing page)"
[ -f "${DIST}/sitemap.xml" ] && echo "Copied ${DIST}/sitemap.xml"
[ -f "${DIST}/robots.txt" ] && echo "Copied ${DIST}/robots.txt"
