# utls-chrome-dial

Small **Phase 1** tool: dial TLS with a Chrome-class ClientHello via
[`refraction-networking/utls`](https://github.com/refraction-networking/utls).

Used by:

- `scripts/tls-impersonate-measure.mjs` — capture tool-matched goldens against `tls-golden-probe wait`
- `scripts/tls-detector-validate.mjs --client tool` — hit public JA3/JA4 detector APIs

## Build

```bat
cd tools\utls-chrome-dial
go build -o utls-chrome-dial.exe .
```

The binary is gitignored; rebuild when missing.

## Examples

```bat
utls-chrome-dial.exe -addr 127.0.0.1:12345 -sni probe.local -hello chrome150
utls-chrome-dial.exe -url https://tls.browserleaks.com/json -hello chrome
```

HTTPS GET forces ALPN `http/1.1` so the response can be read without HTTP/2 framing.
That slightly changes the JA3 relative to a pure h2 Chrome parrot; JA4 still shows a
Chrome-class profile. Prefer probe capture (`-addr`) for goldens that keep full ALPN.

## Honesty

This is a **tool** stack (uTLS), not a real browser capture. Goldens must use
`source.kind=tool-capture` and `alignment=tool-matched` only.
