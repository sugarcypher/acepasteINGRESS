# GitHub Action: AcePaste Ingress repo gate

Runs `ingress reposcan` on each pull request and shows what it finds as code scanning annotations.
See [docs/REPOSCAN.md](../../docs/REPOSCAN.md) for what it checks, a copy-paste workflow and a pre-commit hook.

It needs `@acepaste/ingress` 0.10.0 or later, the first release with `reposcan`. The action runs 0.10.0 by
default; set `version: latest` to follow new releases.
