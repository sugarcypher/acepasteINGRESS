# @acepaste/gate-http

AcePaste Gate as a metered HTTP service with a public attack feed and a per-key audit plane.

```sh
PORT=8787 GATE_KEYS="key1:acme" GATE_SIGNING_KEY=… npx @acepaste/gate-http
```

`POST /v1/scan`, `POST /v1/fetch`, `POST /v1/verify` (Bearer key; refusals return 422). `GET /v1/feed` and `/` (public attack feed: attacking hosts and payload excerpts, never customer content). `GET /v1/receipts`, `/v1/receipts/export`, `/v1/receipts/stats`, `/console` (the caller's own signed receipts).

Full documentation and deploy notes: https://github.com/sugarcypher/acepasteGATE
