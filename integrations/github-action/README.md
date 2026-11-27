# GitHub Action: AcePaste Ingress repo gate

Runs `ingress reposcan` on each pull request and shows what it finds as code scanning annotations.
See [docs/REPOSCAN.md](../../docs/REPOSCAN.md) for what it checks, a copy-paste workflow and a pre-commit hook.

**This works only once a release of `@acepaste/ingress` that includes `reposcan` is on npm.**
Until then, `npx @acepaste/ingress@latest reposcan` fails with a usage error and the job stops.
