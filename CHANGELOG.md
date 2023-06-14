# Changelog

## 3.0.0 (2023-06-14)

Upgrade to tokio-rustls 0.24.1

## 2.0.0 (2023-03-29)

Comes with a bunch of breaking changes, necessary to address some issues.

Essentially, the rustls stream wasn't being drained properly in
`config_ktls_{client,server}`. Doing this properly required introducing
`CorkStream`, which is TLS-framing-aware.

As a result, `config_ktls_*` functions now take a `TlsStream<CorkStream<IO>>`
(where `IO` is typically `TcpStream`), and are async, since to properly drain we
might need to read till the end of the last TLS messages rustls has partially
buffered.

## 1.0.1 (2022-10-21)

Initial release.