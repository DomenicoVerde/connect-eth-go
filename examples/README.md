# Examples

## How to run:

Building the sources and Docker images:
```sh
make build
```

Running a basic ping test from the client to the server:
```sh
make ping     # for IPv4
make pingv6   # for IPv6
```

Obtaining logs, keys and packet captures:
```sh
make copylogs target=../pcaps/
```
