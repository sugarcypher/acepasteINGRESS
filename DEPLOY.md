# Deploying the gate

A single small host runs the HTTP service. The public instance keeps the
browser sandbox off, so there is no Chromium to ship and the image is small.

## Fly (recommended; already in your stack)

```sh
fly launch --no-deploy          # creates the app; keep the generated name or set it in fly.toml
fly volumes create ingress_data --size 1 --region sjc
node packages/core/dist/src/cli.js --keygen > ingress-keys.txt   # keep the private key secret; publish the public key
fly secrets set INGRESS_SIGNING_PRIVATE_KEY="$(awk '/BEGIN PRIVATE/,/END PRIVATE/' ingress-keys.txt)"
fly secrets set INGRESS_KEYS="$(openssl rand -hex 16):design-partner-a"
fly deploy
```

Then:
- `https://<app>.fly.dev/` — the live attack feed (public)
- `https://<app>.fly.dev/console` — the audit console (needs an API key)
- `POST https://<app>.fly.dev/v1/scan` and `/v1/fetch` — the metered API (Bearer key)

## Any container host

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
