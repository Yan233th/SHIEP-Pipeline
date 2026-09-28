# Independent TLS interoperability checks

This package is outside the production workspace. Native TLS is used only as an
independent reference server, never as a dependency of `legacy-tls` or Pipeline.

```sh
cargo test --manifest-path experiments/legacy-tls-interop/Cargo.toml --locked
cargo test --manifest-path experiments/legacy-tls-interop/Cargo.toml --locked --features aws-lc
```

The first command uses the installed OpenSSL, including encrypt-then-MAC. The
second builds AWS-LC, exercising traditional MAC-then-encrypt. Both check TLS
1.1/1.2, AES128/256, SNI, L3IP identifiers without session resumption, fragmented
I/O, multi-record bidirectional traffic, certificate rejection, tampered server
Finished records and truncated shutdown.
Tests bind ephemeral loopback TCP ports; they require local network access.

The legacy OpenSSL server deliberately uses security level 0 so its SHA-1 suites
can be tested. Test certificates are ephemeral and are not deployment credentials.
