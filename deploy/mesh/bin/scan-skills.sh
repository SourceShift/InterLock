#!/usr/bin/env bash
# Scan pinned skill corpora, build the review queue, and render the reviewed
# pack into commons/packs/skill-safety.json.
#
#   ROOT=/srv/interlock-mesh   deployment root
#   SCANNER=...                 SkillSpector executable (Python 3.12+)
#   CORPUS_ROOTS="a b c"        repository checkouts under $ROOT/corpus
#   REVIEW=$ROOT/scanner/review.json
set -euo pipefail
ROOT=${INTERLOCK_MESH_ROOT:-/srv/interlock-mesh}
SCANNER=${SCANNER:-$ROOT/scanner-venv/bin/skillspector}
REPORTS=${REPORTS:-$ROOT/scan-reports}
CORPUS_ROOTS=${CORPUS_ROOTS:-"anthropics-skills addyosmani-agent-skills vercel-labs-agent-skills obra-superpowers"}
REVIEW=${REVIEW:-$ROOT/scanner/review.json}
mkdir -p "$REPORTS"
report_args=()
for name in $CORPUS_ROOTS; do
  /usr/bin/env python3 "$ROOT/scanner/scan_corpus.py" \
    --root "$ROOT/corpus/$name" --out "$REPORTS/$name" \
    --scanner "$SCANNER" --workers "${WORKERS:-3}" --timeout "${TIMEOUT:-300}"
  report_args+=(--reports "$REPORTS/$name")
done
/usr/bin/env python3 "$ROOT/scanner/build_advisories.py" \
  "${report_args[@]}" --corpus-map "$ROOT/scanner/corpus-map.json" \
  --out "$ROOT/scan-reports/advisories.json"
if [[ -f "$REVIEW" ]]; then
  /usr/bin/env python3 "$ROOT/scanner/render_pack.py" \
    --advisories "$ROOT/scan-reports/advisories.json" \
    --review "$REVIEW" --out "$ROOT/commons/packs/skill-safety.json"
else
  echo "no review file at $REVIEW; advisories built, pack not rendered" >&2
fi
