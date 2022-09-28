# ktls

Configures kTLS (kernel TLS) for any type that implements `AsRawFd`, given a
rustls `ServerConnection`.

The `export` branch of this rustls fork must be used:
https://github.com/hapsoc/rustls to export all the relevant secrets.

