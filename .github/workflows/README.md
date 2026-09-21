# `.github/workflows/` — CI + Release pipelines

## `ci.yml`

Fires on every push to `main` and every PR. Jobs:

| Job   | What it does                                              | Runs on             |
|-------|-----------------------------------------------------------|---------------------|
| rust  | `cargo check / clippy / fmt --check / test` on stable + MSRV (1.78). Treats warnings as errors. | matrix: stable, 1.78 |
| web   | `npm ci && npm run build` (tsc + Vite). Fails if the gzipped JS bundle exceeds the 300 KB budget. | ubuntu-latest |
| paper | Installs Pandoc + WeasyPrint, runs `docs/paper/build.sh`, verifies both PDFs exist + non-empty. Uploads PDFs as a 14-day artifact. | ubuntu-latest |

The Postgres testcontainers test on `ree0xq-server` auto-skips
when Docker isn't reachable, so we don't run a service
container. The `ree0xq-net-ebpf` crate needs a nightly
toolchain and isn't part of the workspace's default build —
it's built out-of-band per its own README.

## `release.yml`

Fires when a tag matching `v*` is pushed. Builds `.deb` + `.rpm`
for every shipping binary (see `docs/operator-packaging.md`)
plus the paper submission bundle (see
`scripts/paper-submission-package.sh`). Publishes everything as
a GitHub Release asset with a `SHA256SUMS` manifest, marking
the release as a pre-release when the tag contains `-`
(e.g. `v0.2.0-rc1`).

Trigger:

```bash
git tag v0.1.0
git push github v0.1.0
```

## Required gh token scope

Pushing files under `.github/workflows/` requires the
`workflow` scope. The repo's current PAT only has
`gist,read:org,repo`. Refresh with:

```bash
gh auth refresh --scopes workflow
```

…then re-push. Precedent: commit `69ac7e3` deferred CI for
exactly this reason.
