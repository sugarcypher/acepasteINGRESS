# Deploying the gate

A single small host runs the HTTP service. The public instance keeps the
browser sandbox off, so there is no Chromium to ship and the image is small.

## Run it (any container host)

`docker build -t acepaste-ingress . && docker run -p 8787:8787 -e INGRESS_SIGNING_KEY=… -e INGRESS_KEYS="k:name" -v $PWD/data:/data -e INGRESS_RECEIPTS_FILE=/data/receipts.jsonl acepaste-ingress`

## Turning the browser sandbox on

For a deployment that needs the sandbox (cloaking / post-load injection), set
`INGRESS_SANDBOX=escalate`, add a Chromium install layer to the Dockerfile, and
point `INGRESS_CHROMIUM` at the binary. Keep that off the public free instance —
it is slow and is what the paid tier runs.

## Scaling the audit store

The bundled receipt store is an append-only file behind the `ReceiptStore`
interface. For real volume, implement that interface against Postgres or
ClickHouse and construct it in `server.ts`; nothing else changes.
