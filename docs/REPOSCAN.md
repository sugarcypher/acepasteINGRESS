# Repo gate for coding agents: `ingress reposcan`

Coding agents (Claude Code, Cursor, Copilot, Codex, Windsurf, Cline and others) read a repository before they
act on it. They load `AGENTS.md` or `CLAUDE.md` as instructions, read the README and the docs, run
`npm install`, start the MCP servers listed in the repo, and read code comments as context. Anyone who can get
a change merged, or into a dependency, can write to all of those.

`ingress reposcan` reads a working tree the way an agent would and flags what a reviewer would not see, or
would not expect an agent to obey. It runs on your machine, reads files and runs `git`, and makes no network
connections.

```
ingress reposcan                      # the current directory
ingress reposcan path/to/repo --json
ingress reposcan --diff origin/main   # only files changed since a git ref (for pull requests)
ingress reposcan --sarif out.sarif    # also write SARIF 2.1.0 for GitHub code scanning
ingress reposcan --help
```

The exit code is 1 when anything is high, 0 otherwise, and 2 when the scan could not run.

## What it checks

| Check | Where | Severity |
|---|---|---|
| Bidirectional overrides and isolates (U+202A–202E, U+2066–2069): code that reads one way and runs another ("Trojan Source") | every text and code file | high. Embeddings and isolates inside right-to-left text are marked for review, since Arabic and Hebrew prose uses them |
| Unicode tag characters (U+E0000 block): text only a model reads. The report spells out what they say | every text and code file | high |
| Long runs of variation selectors, a known way to hide bytes inside one visible character | every text and code file | high |
| Zero-width characters (U+200B and friends, Hangul fillers) | every text and code file | high in agent instruction files and MCP configs, review elsewhere |
| Instructions hidden in markdown: HTML comments, collapsed `<details>`, inline styles that hide text (white, zero size, `display:none`), `hidden` attributes, link titles and image alt text. Each piece goes through the Ingress engine on its own | `AGENTS.md` and other agent files, `README*`, `docs/**/*.md` | high or review, from the engine's verdict |
| Agent instruction files that tell the agent to pipe a download into a shell, upload files, read or send secrets, dump the environment, turn off permission prompts or hooks, hide things from the user, or skip review | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/**`, `.github/copilot-instructions.md`, `.windsurfrules`, `.clinerules` and the rest of the list in `instructions.ts` | high; "do not ask before acting" and outside network commands are review |
| The Ingress engine's verdict on each agent instruction file as a whole | the same files | high (hostile) or review (suspect) |
| Install scripts (`preinstall`, `postinstall`, `prepare` and the rest) that download code and run it | every `package.json` | high; the same in an ordinary script is review |
| MCP server configs committed to the repo that pipe a download into a shell, run a package with no pinned version, use plain `http://`, or hold a literal credential (shown redacted) | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` | high or review |
| Code comments the engine rates hostile | source files (C-style `//` and `/* */`, and `#` languages) | high |

Emoji (including joined sequences, flags and skin tones), CJK, Korean, Greek, accented names, Persian and
Indic joiners, right-to-left marks in right-to-left text, ideographic variants and a leading byte-order mark
are not flagged.

What it skips: files ignored by `.gitignore` (through `git ls-files`; outside git, a simple reading of the
top-level `.gitignore`), `node_modules`, `dist`, binary files, files over 1 MB, and anything after 5,000 files
or 64 MB (`--max-files` raises the file cap). Symbolic links are never followed. Evidence is cut short,
credentials are redacted, and invisible characters are printed as `⟨U+202E⟩`, so the report cannot reorder
your terminal.

## Diff mode

`--diff <ref>` scans only files added, copied, modified, renamed or changed in type since `<ref>`, compared
with the working tree. That covers committed, staged and unstaged changes, so it works for pull requests and
for pre-commit hooks. Deleted files are not scanned. In GitHub Actions, check out with `fetch-depth: 0` so the
base commit is present.

## GitHub Action

> **This works only once a release of `@acepaste/ingress` that includes `reposcan` is on npm.** Until then,
> the action stops with a usage error.

Copy this into `.github/workflows/ingress-reposcan.yml`:

```yaml
name: Ingress repo gate
on:
  pull_request:

permissions:
  contents: read
  security-events: write   # to upload SARIF to code scanning

jobs:
  reposcan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # diff mode needs the base commit
      - uses: sugarcypher/acepasteINGRESS/integrations/github-action@main
        # with:
        #   version: latest        # pin a version of @acepaste/ingress
        #   fail-on-high: "true"
        #   base-ref: ""           # empty scans the whole tree
```

The action runs `npx @acepaste/ingress@latest reposcan --diff <base sha> --sarif ingress-reposcan.sarif`, then
uploads the SARIF with `github/codeql-action/upload-sarif`, so findings appear as annotations on the pull
request and under Security → Code scanning. The job fails when anything is high.

Without the action, the same thing in plain steps:

```yaml
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - run: npx --yes @acepaste/ingress@latest reposcan --diff "${{ github.event.pull_request.base.sha }}" --sarif out.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: out.sarif, category: ingress-reposcan }
```

Notes:

- Code scanning is free for public repositories. Private repositories need GitHub Advanced Security (Code
  Security) to show the annotations; the scan and the pass or fail still work without it (set `upload: "false"`).
- Pull requests from forks get a read-only token, so the SARIF upload is refused there. The scan still runs and
  still fails the job.
- To scan everything on a schedule, add `on: schedule` and set `base-ref: ""`.

## Pre-commit hook

A plain git hook, in `.git/hooks/pre-commit` (make it executable with `chmod +x`):

```sh
#!/bin/sh
# block a commit that adds hidden Unicode or instructions for coding agents
exec npx --yes @acepaste/ingress@latest reposcan --diff HEAD
```

With the [pre-commit](https://pre-commit.com) framework, in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: ingress-reposcan
        name: ingress reposcan
        entry: npx --yes @acepaste/ingress@latest reposcan --diff HEAD
        language: system
        pass_filenames: false
```

`--diff HEAD` compares your working tree with the last commit, so it sees what you are about to commit (and any
unstaged edits to tracked files). Brand-new files are seen once they are staged.

## Limits

- Pattern rules on instruction files are English. The engine's verdict covers more languages, but a carefully
  worded instruction can still pass.
- A security project that keeps attack samples as literal strings (like this one) will be flagged for them.
  Write invisible characters as escapes (`"\u202E"`) in code and tests; reposcan then has nothing to report.
- Comment extraction is a light scanner, not a parser. Template literals with nested expressions and
  languages outside the C and `#` families are only checked for hidden Unicode.
- Code comments are reported only when the engine rates them hostile, to keep noise down in security code.
- Dependencies (`node_modules`, vendored packages) are not scanned. `ingress instructions` lists instruction
  files inside dependencies.
- In library form: `reposcan(dir, options)`, `formatReposcan(report)` and `toSarif(report)` from
  `@acepaste/ingress`.
