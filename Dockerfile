# AcePaste Gate — HTTP service. Public instance runs with the sandbox off, so
# no Chromium is shipped and the image stays small. Set GATE_SANDBOX=escalate
# and add a Chromium layer only for a deployment that needs the browser pass.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json ./
COPY packages/core/package.json packages/core/
COPY packages/http/package.json packages/http/
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN npm install --no-audit --no-fund --workspaces --include-workspace-root
COPY . .
RUN npm run build -w @acepaste/gate-core && npm run build -w @acepaste/gate-http

FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 PORT=8787 GATE_SANDBOX=off
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/core/package.json packages/core/
COPY --from=build /app/packages/core/dist packages/core/dist
COPY --from=build /app/packages/http/package.json packages/http/
COPY --from=build /app/packages/http/dist packages/http/dist
COPY --from=build /app/packages/http/public packages/http/public
EXPOSE 8787
# receipts persist on a mounted volume at /data when GATE_RECEIPTS_FILE is set
CMD ["node", "packages/http/dist/server.js"]
