# zero-art-rs::core

Core library of `zero-art` asynchronous verifiable group management protocol. It encapsulates the following crates:
- [art](art) -- different ART trees routines
- [zk](zk) -- zero-knowledge proofs for ART trees based on [bulletproofs]
- [cortado](cortado) -- carefully crafted elliptic curve defined over [bulletproofs]' ristretto scalar field (e.g. 'native elliptic curve' for [bulletproofs])
- [crypto](crypto) -- various cryptographic primitives (X3DH etc.)

## Main idea

The main goal of the project is developing of distributed/federated messanger with features:

- support of p2p chats (with Signal protocol)
- support of large groups (> 1000 members) with custom [ART]-based protocol
- advanced identity management (with different identity modes)
- service provider intentionally does not know user identities (however, optional directory service does)
- mostly all user operations is provable so that service providers are mostly trustless entities that simply route users' messages
- e2e encryption by default in p2p and group modes


[Project M research paper by Illia and Serhii, 2024]: papers/Messenger.pdf
[proposed]: https://github.com/distributed-lab/papers/blob/main/in-da-club/In_Da_Club.pdf
[PM25]: https://www.overleaf.com/project/679b4c7dcc8fd2d1052f5849
[whitepaper]: https://www.overleaf.com/project/679b4c7dcc8fd2d1052f5849
[Signal]: https://signal.org/docs/
[ART]: https://eprint.iacr.org/2017/666.pdf
[Kafka]: https://kafka.apache.org/
[symmetric ratchet]: https://signal.org/docs/specifications/doubleratchet/#symmetric-key-ratchet
[argument system]: https://github.com/juja256/zkp/blob/main/sigma_cross.pdf
[bulletproofs]: https://crates.io/crates/bulletproofs
[DID]: https://www.w3.org/TR/did-1.0/
[credentials]: https://www.w3.org/TR/vc-data-model-2.0/
[BBS]: https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#BBS04
[hybrid]: https://datatracker.ietf.org/doc/rfc9180/
