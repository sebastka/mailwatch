#!/usr/bin/env bash
# Assembles the release bundle (used by CI, runnable locally):
#   scripts/bundle.sh [output dir, default build/mailwatch]
#
# Layout (same /app layout as the Docker image; run with `node /app/src/server/index.ts`):
#   dist/web/            built UI
#   src/server, shared/  TypeScript server, run directly by Node's type stripping
#   node_modules/        production dependencies (pure JS, architecture independent)
#   package.json, HEAD
set -euo pipefail
cd "$(dirname "$0")/.."

out="${1:-build/mailwatch}"
[[ -f dist/web/index.html ]] || { echo "dist/web missing, run npm run build first" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out/src"
cp -a dist "$out/dist"
cp -a src/server src/shared "$out/src/"
cp package.json package-lock.json "$out/"
(cd "$out" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund)
rm "$out/package-lock.json"
git rev-parse HEAD > "$out/HEAD" 2>/dev/null || echo unknown > "$out/HEAD"
chmod -R a+rX "$out"
echo "bundle ready in $out ($(du -sh "$out" | cut -f1))"
