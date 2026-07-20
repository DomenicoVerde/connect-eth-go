# Proxying Ethernet over HTTP 
[![codecov](https://codecov.io/github/DomenicoVerde/connect-eth-go/graph/badge.svg?token=GHO1XP3K14)](https://codecov.io/github/DomenicoVerde/connect-eth-go)

[*connect-eth-go*](https://github.com/DomenicoVerde/connect-eth-go) is an implementation of the [draft-ietf-masque-connect-ethernet](https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/), 
allowing the proxying of Ethernet packets via QUIC and HTTP/3. It is actually update to version 10 of the draft.

The project is entirely based on [quic-go](https://github.com/quic-go/quic-go), and provides both a client and 
a proxy implementation. Dockerized versions of client, proxy, and server are provided
under the [examples](examples) directory.

At this point, it supports the following use cases:
* Remote Access L2 VPN, see 
[Section 8.1](https://www.ietf.org/archive/id/draft-ietf-masque-connect-ethernet-10.html#section-8.1)
* Site-to-Site L2 VPN, see
[Section 8.2](https://www.ietf.org/archive/id/draft-ietf-masque-connect-ethernet-10.html#section-8.2)

It still does not support vlan-identifiers (VLANs are supported but unmanaged by the proxy).
Check captures under the [pcaps](pcaps) directory to
verify compliance with the draft.

## License

Distributed under the MIT License — see [LICENSE](LICENSE).

## Acknowledgements

This project is based in part on [connect-ip-go](https://github.com/quic-go/connect-ip-go) and [masque-go](https://github.com/quic-go/connect-ip-go), both licensed under the MIT License by [Marten Seeman](https://github.com/marten-seemann).
The original source code has been modified and adapted for this project.

## Contributing

Bug reports and pull requests are welcome.
