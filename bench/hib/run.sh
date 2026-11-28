#!/usr/bin/env bash
# HIB end to end: generate both splits, check the ground truth in Chromium, score Ingress and the baselines, report.
# Run from the repository root after `npm ci && npm run build` and `pip install -r bench/hib/requirements.txt`.
# Every step is resumable; rerun to continue after an interruption.
set -euo pipefail
cd "$(dirname "$0")/../.."
export INGRESS_REPO="$PWD"
for split in public heldout; do
  python3 bench/hib/gen/generate.py --split "$split"
  node bench/hib/score/validate.mjs --split "$split"           # needs playwright's Chromium; skip if unavailable
  node bench/hib/score/ingress.mjs --split "$split"
  python3 bench/hib/score/flatten.py --split "$split"
  node bench/hib/score/text-baselines.mjs --split "$split"
  python3 bench/hib/score/report.py --split "$split" \
    --defense "Ingress 0.10.0 (real entry points)=results/ingress-0.10.0-$split.jsonl" \
    --defense "naive extraction + Ingress text scan=results/textscan-$split.jsonl" \
    --defense "naive extraction + Ingress classifier only=results/classifier-$split.jsonl" \
    --defense "naive extraction + 'ignore previous' regex=results/regex-$split.jsonl"
done
