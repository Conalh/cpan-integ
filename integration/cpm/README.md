# cpm integration — native install-time verification

This directory holds a prototype that moves `cpan-integ` from a *preflight /
verified-mirror* model to **native enforcement inside the installer's own fetch
path**: a patched [`cpm`](https://github.com/skaji/cpm) verifies every
downloaded artifact against the SHA-256 pinned in `cpanfile.integrity` and
**aborts the distribution before it is unpacked, cached, or built** if the bytes
do not match.

## Why a patch is required

Reading cpm at `b9e75fb` (v1.1.1, the actively-maintained CPAN installer):

- cpm performs **no artifact-content verification of any kind** — no
  per-distribution digest check, and it does not read a mirror's `CHECKSUMS`
  file. Its only transport protection is TLS plus a trusted-mirror host
  allowlist.
- A resolver can be pointed at a custom class (`--resolver +Class`), and its
  result hashref flows through the cascade untouched, **but**
  `Master::_register_resolve_result` copies a fixed key set into the
  `Distribution` and drops everything else, and nothing downstream ever hashes
  the bytes. So a resolver-supplied checksum is inert against stock cpm.

The only place the raw artifact exists on disk under cpm's control, before any
build code runs, is `Worker::Installer::fetch`. That is the hook.

## The patch — `in-fetch-verify.patch`

Generated against cpm `BASE_COMMIT` (see that file). Apply with:

```sh
git clone https://github.com/skaji/cpm /tmp/cpmsrc
git -C /tmp/cpmsrc checkout "$(cat BASE_COMMIT)"
git -C /tmp/cpmsrc apply /path/to/in-fetch-verify.patch
```

It threads an optional `checksum` from the resolve result through to the fetch
task and verifies it (54 insertions, 7 deletions across 3 files):

- `Distribution.pm` — add a `checksum` accessor.
- `Master.pm` — carry `checksum` from the resolve result into the `Distribution`
  (`_register_resolve_result`) and forward it onto the fetch task
  (`_add_fetch_tasks`).
- `Worker/Installer.pm` — `verify_checksum()` (raw-bytes SHA-256), called before
  unpack in the real-download path (`fetch_distribution`), the cache-hit path (a
  poisoned cache entry is discarded and re-fetched), and the local-mirror
  `file://` path.

**Backward compatible:** when a resolver supplies no `checksum` (every existing
resolver), the code path is unchanged.

## The glue — `App::CpanInteg::CpmResolver`

Lives in this repo at [`lib/App/CpanInteg/CpmResolver.pm`](../../lib/App/CpanInteg/CpmResolver.pm).
A duck-typed cpm resolver that reads `cpanfile.snapshot` + `cpanfile.integrity`
(reusing `App::CpanInteg`'s own parsers — no Carton, no cpm internals) and
returns, per package, the pinned distribution plus `checksum => "sha256:<hex>"`.

```sh
cpm install \
  --mirror "file://$PWD/mirror" --mirror-only \
  --resolver "+App::CpanInteg::CpmResolver,snapshot=cpanfile.snapshot,integrity=cpanfile.integrity,mirror=file://$PWD/mirror" \
  Try::Tiny
```

Without `mirror=`, the resolver hands cpm the pinned `download_url` instead, so
real CPAN downloads are checked against the committed lock.

## Proof

The `cpm-integrity` job in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
runs the full chain on Linux:

1. **POSITIVE** — patched cpm installs `Try::Tiny` from the verified mirror and
   logs `Verified sha256:`; the module loads.
2. **TAMPER** — the mirrored tarball is overwritten with non-matching bytes
   while the lock is untouched; patched cpm aborts with `Checksum MISMATCH`,
   exits non-zero, and installs nothing.

A local `verify_checksum` primitive proof is in the cpm working branch; the
end-to-end wiring runs in CI because cpm's full dependency tree is needed.

## Relationship to the CPANSec proposal

This is the concrete answer to question 3 of
[CPAN-Security/security.metacpan.org#214](https://github.com/CPAN-Security/security.metacpan.org/issues/214)
("independent module vs. cpm/Carton integration"): the generic
"verify a resolver-supplied digest" capability is a small, upstreamable change
to cpm; `cpan-integ` supplies the pinned digests. Carton is a non-target for
native enforcement — it delegates fetch/build to Menlo in-process, has no hook
points, and its snapshot parser rejects any added field; the verified-mirror
path already covers Carton.
