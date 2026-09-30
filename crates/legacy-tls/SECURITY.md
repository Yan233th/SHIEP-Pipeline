# Security and validation

This is a client-only legacy TLS implementation, reviewed by its implementer.
It has not received an independent security audit. TLS 1.1, static RSA key
exchange and CBC remain legacy choices, regardless of implementation language.
The supported suites do not provide forward secrecy.

## Boundaries

- A certificate verifier is mandatory. It owns trust, validity, endpoint identity
  and certificate-usage checks. `NoCertificateVerification` deliberately removes
  peer authentication and permits active impersonation. Pipeline preserves that
  pre-existing gateway policy; changing crypto libraries does not repair it.
- TLS 1.2 and extended master secret are required by default. The application
  explicitly relaxes both requirements for its legacy gateway. There is no silent
  retry with weaker settings, resumption, client authentication or renegotiation.
- The client validates the server's Finished before releasing a stream. Record
  authentication precedes delivery of plaintext. Record sizes, handshake sizes,
  certificate-chain length and non-data record processing are bounded.
- CBC padding and MAC rejection share one error. HMAC work and input addresses
  depend on public record length; secret-dependent lengths are selected with
  `subtle`. Compression-count tests and timing samples are regression evidence,
  not proof about all compilers, CPUs or side channels.
- Partial read timeouts retain record/control-message state. Failed writes or
  flushes poison the stream. Raw EOF is not clean shutdown; authenticated
  close_notify receives a reply and prevents later application writes.
- The crate forbids unsafe code and creates no sockets, threads or timers. The
  caller must bound transport read/write time and overall connection lifetime.

## Reproducible checks

From the repository workspace:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --release -p legacy-tls cbc_rejection_timing -- --ignored --nocapture --test-threads=1
cargo package -p legacy-tls --locked
```

Tests include independent PRF vectors, every legal CBC padding length around
hash boundaries, tampering/replay checks, record fragmentation and read timeouts,
fragmented/coalesced control messages, and 24,400 truncated or mutated handshake
inputs. The bounded mutation corpus is not coverage-guided fuzzing.

The separate `experiments/legacy-tls-interop` package uses native OpenSSL or
AWS-LC solely as independent test servers. Its matrix covers TLS 1.1/1.2,
AES-128/256, ordinary/L3IP identifiers, SNI, multi-record traffic and bidirectional
shutdown. It also alters a native server Finished, recalculates its MAC with
the native keys, and checks that the wrong transcript is still rejected.
An opt-in release test checks 8 MiB in each direction over TLS 1.1/CBC.
See that package's README for commands.

The [native Actions run](https://github.com/Yan233th/SHIEP-Pipeline/actions/runs/36621555961)
at `bd233f6` passed workspace tests, debug/release application builds and
`--version` execution on Linux x64, Windows MSVC x64 and macOS ARM64. Live VPN
use has also been tested on Linux and reported working on Windows; macOS has
not yet had a live gateway test. These are functional checks, not an independent
security audit. The timing diagnostic reports samples and Welch's t statistic.
Host noise and the instrumented test build prevent treating it as certification.

## Dependency review

Pipeline's HTTPS path requires rustls 0.23.45 or later for
[GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc).
The application lockfile selects rustls-webpki 0.103.15 for its rustls path,
including the fix for
[RUSTSEC-2026-0049](https://rustsec.org/advisories/RUSTSEC-2026-0049.html).

RustCrypto's rustls provider still brings rustls-webpki 0.102.8 for algorithm
identifier constants. Inspection of that provider's source found no calls to
its certificate-chain or CRL verification paths. This explains the remaining
CRL advisory in the dependency graph; it is not a claim that the old package
is patched. No global advisory suppression is installed.

[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
affects RSA private-key operations. This client performs public-key encryption,
and Pipeline does not configure TLS client authentication or load RSA private
keys. That review must be revisited before adding signing or decryption.
The [RustCrypto rustls provider](https://github.com/RustCrypto/rustls-rustcrypto)
remains experimental; these checks do not replace upstream or independent review.
