# cpan-integ

Consumer-side, install-time **integrity verification** for CPAN distributions.

CPAN clients today pin *versions* but not *artifact hashes*. Carton's
`cpanfile.snapshot` records the resolved dependency tree and exact versions,
but no digests; `cpm` does not look at `CHECKSUMS` and has no option to;
`cpanm --verify` is off by default. And per the May 2026 work on signing CPAN
releases with Sigstore, *"no CPAN client checks them on install."*

`cpan-integ` fills the consumer side: it records an expected **SHA-256 per
resolved distribution** in a lockfile, and fails the build if a fetched
artifact does not match.

## Trust model

Trust-on-first-pin, cryptographically verified thereafter — the same model as
`pip`'s hash mode and `npm`'s lockfile `integrity` field. `pin` trusts
MetaCPAN's per-release `checksum_sha256` once; every `verify` after that is a
pure cryptographic check. No new trust infrastructure is introduced.

## Usage

```sh
# Record hashes for everything in a Carton snapshot:
cpan-integ pin --snapshot cpanfile.snapshot --out cpanfile.integrity

# Commit cpanfile.integrity to your repo, then in CI / before deploy:
cpan-integ verify --integrity cpanfile.integrity
```

`verify` exits non-zero on any mismatch, so it drops straight into a CI step.

The lockfile is line-based and diff-friendly; each distribution is identified
by its [Package URL](https://github.com/package-url/purl-spec) (ECMA-427):

```
pkg:cpan/ETHER/Try-Tiny@0.32 sha256:ef2d... https://cpan.metacpan.org/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz
```

## Design

- **Zero non-core dependencies** (`HTTP::Tiny`, `JSON::PP`, `Digest::SHA`,
  `IO::Socket::SSL`) — a supply-chain tool should not widen its own attack
  surface.
- **PURL identity** so the lockfile interoperates with CPANSec's SBOM /
  CycloneDX work rather than inventing a parallel identifier.
- **Sigstore-ready**: where an opt-in `.sigstore.json` bundle ships alongside a
  release, it can be cross-checked as a future trust source.

## Status

Early prototype. Built to validate the consumer-side install-time verification
gap and to accompany a proposal to the CPAN Security Group (CPANSec).
