"""
AcePaste Ingress evaluation function for the Lakera PINT Benchmark notebook
(github.com/lakeraai/pint-benchmark, benchmark/pint-benchmark.ipynb).

The notebook calls an eval function with one input string and expects True when the input is a prompt
injection. Ingress answers through its local HTTP service (packages/http, `POST /v1/scan`): a verdict of
`suspect` or `hostile` refuses the input, so both count as flagged; `clean` is not flagged.

    from ingress_pint import evaluate_ingress
    pint_benchmark(df=df, eval_function=evaluate_ingress, model_name="AcePaste Ingress 0.9.3")

Environment:
    INGRESS_URL      default http://127.0.0.1:8787
    INGRESS_API_KEY  the service key (for a local install: contents of ~/.acepaste-ingress/local-api-key)

Configuration evaluated: static passes only (no network fetch, no cloaking comparison, no sandbox),
plain-text scan, default thresholds (suspect 0.25, hostile 0.7). No PINT input was used to write or tune
Ingress's rules. Standard library only.
"""
import json
import os
import urllib.error
import urllib.request

_URL = os.environ.get("INGRESS_URL", "http://127.0.0.1:8787").rstrip("/") + "/v1/scan"
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def evaluate_ingress(prompt: str) -> bool:
    """True when Ingress refuses the input (suspect or hostile)."""
    headers = {"content-type": "application/json"}
    key = os.environ.get("INGRESS_API_KEY", "")
    if key:
        headers["authorization"] = f"Bearer {key}"
    body = json.dumps({"content": prompt, "isHtml": False, "source": "pint-benchmark"}).encode()
    req = urllib.request.Request(_URL, data=body, headers=headers, method="POST")
    try:
        with _OPENER.open(req, timeout=60) as r:
            verdict = json.load(r)
    except urllib.error.HTTPError as e:
        # 422 = suspect or hostile: a verdict, not an error
        if e.code != 422:
            raise
        verdict = json.load(e)
    return verdict["tier"] in ("suspect", "hostile")
