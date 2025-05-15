# Project M

> Disclaimer: this README file is updated often so it might change according to research process

Project structure:
- `notes` - various notes about research process
- `misc` - various prototypes (IBBE with sage, gossipsub with go)
- `papers` - research papers, that the most actual version of messenger [whitepaper]
- `src` - rust implementation of messenger primitives:
  - `hibbe` - hybrid IBBE with ART implementation
  - `zk` - ART zk proofs implementation
  - `chat_node` - experimantal libp2p messenger node

## Main idea

The main goal of the project is developing of distributed/federated messanger with features:

- support of p2p chats (with Signal protocol)
- support of large groups (> 1000 members) with custom [ART]-based protocol
- advanced identity management (with different identity modes)
- service provider intentionally does not know user identities (however, optional directory service does)
- mostly all user operations is provable so that service providers are mostly trustless entities that simply route users' messages
- e2e encryption by default in p2p and group modes

## Encryption

For p2p chats we propose to use [Signal] protocol, for p2g(*peer-to-group*) we use custom [PM25] proto which is heavily based on [ART]. Key feature of our proto is provability of
each group operation so that every member can assure integrity and validity of a current group state.

### ART

> Here we briefly describe our protocol. Full description can be found at [PM25]

Let $`\langle P \rangle = \mathbb{G}`$ - cyclic (abstract) group written additively of order $q$. $`S`$ - a set of group members, $`\epsilon \in S`$ - blank group member.

A group is represented as an Asynchronous Ratcheting Tree (can be seen as a binary tree) where each node containts public key $`Q^e_{j} = [\lambda_{j}]P, j \in S^{*}`$, especially each leaf node is occupied by some group member $`i \in S`$ with public key $`Q^e_i`$.
Let $\iota: \mathbb{G} \to \mathbb{Z}_{q}$ - hash function. Secret key $\lambda_{ij}$ corresponding to public key $`Q_{ij}`$ of parent of nodes $i$ and $j$ is obtained as $`\lambda_{ij} = \iota([\lambda_{i}]Q_{j}) = \iota([\lambda_{j}]Q_{i})`$ and could be seen as a result of Diffie-Hellman secret sharing between $i$ and $j$.
A secret key in a root of the tree $`\lambda_{S}`$ is considered as shared group secret from which stage key $sk$ is derived. $sk$ is then used to derive message encryption and decryption symmetric keys. Symmetric keys is than rotated according to [symmetric ratchet] protocol.
An ART should be updated regularly to provide forward and post-compromise secrecy. Each ART update (obviously including all tree structure changing operations: `InitGroup, AddMember, RemoveMember` and regular key rotation) is supplemented with *update correctness proof*.

### Update correctness proof

![art](notes/schemes/art.png)

For $j$-th($j \neq 0$) level of ART a group member $i \in S$ shall prove the following relation:
```math
\mathcal{R}^{(j)}_{\mathcal{ART}}=\{ (Q'_{\mathcal{A}},Q_\mathcal{B},Q'_{\mathcal{AB}}; \lambda'_{\mathcal{AB}},\lambda'_{\mathcal{A}}) | Q'_{\mathcal{A}}=[\lambda'_{\mathcal{A}}]P, \lambda'_{\mathcal{AB}}=\iota([\lambda'_{\mathcal{A}}]Q_{\mathcal{B}}), Q'_{\mathcal{AB}}=[\lambda'_{\mathcal{AB}}]P\}
```
Where $`\lambda_{\mathcal{A}}`$ - current level secret, $`\lambda^\prime_{\mathcal{A}}`$ - new current level secret, $`Q_{\mathcal{B}}`$ - reciprocal node's public key, $`\lambda'_{\mathcal{AB}}`$ - new next level secret, $`Q'_{\mathcal{AB}}`$ - new next level public key.

Special case when $j=0$:
```math
\mathcal{R}^{(0)}_{\mathcal{ART}}=\{ (Q'_{\mathcal{A}},Q_\mathcal{B},Q'_{\mathcal{AB}}; \lambda'_{\mathcal{AB}},\lambda'_{\mathcal{A}}) | Q^{c}_i=[k_{c,i}]P, Q_{\mathcal{A}}=[\lambda_{\mathcal{A}}]P, Q'_{\mathcal{A}}=[\lambda'_{\mathcal{A}}]P, \lambda'_{\mathcal{AB}}=\iota([\lambda'_{\mathcal{A}}]Q_{\mathcal{B}}), Q'_{\mathcal{AB}}=[\lambda'_{\mathcal{AB}}]P\}
```

A proof of update correctness is composed by chaining $`\mathcal{R}^{(j)}_{\mathcal{ART}}`$ proofs with the same transcript for $`j=0..\ell`$ where $\ell$ is three depth.

We have presented a [argument system] for the relation using [bulletproofs], reference implementation for $`\mathcal{R}_{\iota}`$ part can be found in `src/zk`.

### Permission system

We propose the following roles for permission system:
- **member** - regular group member without auxiliary permissions
- **owner** - creator of the group that could endure any operation in group
- **admin** - group member with special credential issued by other admin or owner

We propose to use anonymous [credentials] for managing group permissions. One such scheme could be derived from [BBS] provable signatures. This credential could be issued by eligable entities(owner or admin) for new admins so that they could prove eligibility to the SP. Efficient credential management and revocation is a subject for further research.

### Group operations

#### InitGroup

The group **owner** initiates a group by generating an *ART* with authentically encrypted for other group members leaves containing initial key material $`\mathsf{AENC}(ikm_{i},d_{owner},Q^{inv}_i)`$. One known AENC scheme is [hybrid] encryption. For public key encryption the owner uses invitational keys $`Q^{inv}_i`$ published and signed by respective users and possibly stored by directory service.
 
#### AddMember
`TODO`

#### RemoveMember
`TODO`

## Network architecture

The project supports two major types of network architecture: *federated* and *full distributed*

### Federated

Federated architectures is supposed to be run in conventional *web2* setting. 

Main actors: 
- Service provider (SP):
  - Set of operational nodes
  - Message broker (for MVP [kafka] is proposed)
  - Optional directory service containing set of user and group identities
- User that connects to service provider via PC/mobile client

It's important to say that service provider barely delivers messages accross system and does not interfere with user identities nor any encrypted traffic.

#### Group management 

Each group has unique identifier `GID` known to SP. This GID identifies topic on messege broker containing all encrypted group events, messages and metadata. Authorized users are granted with read/write permissions to that topic.

#### Authorization

Each user connecting to SP shall authorize his access providing valid zk-proof of possesion to a list of groups, SP validates the proof and issues authorization token granting access to specific topics on message broker.

### Full decentralized

Fully decentralized architecture for future *web3* setting or modern IOT mesh networks(over some radio physical layer):

The system is consist of *operational nodes* connected with each other, each node handle shared state and DHT

## Identity

Let $\mathbb{G}_2$ - cryptographic pairing-friendly group. Each user of the system $`i \in S`$ is represented with his identity secret key $`d_{i}`$ along with a public key $`Q^{id}_i = [d_{i}]P \in \mathbb{G}_2`$ and auxiliary metadata $u_i$. Optinally $`Q^{id}_i`$ could be given to directory service that issues user's public key and metadata to X.509 certificate that could be obtained by the others. 

Each user maintains fresh list of signed invitational public keys $`(Q^{inv}_i,\mathsf{Sign}(d_{i},Q^{inv}_i))`$ used for invitation to groups.

For each group chat $c$ user $i \in S$ generates new chat secret key $`k_{c,i}`$ and public key $`Q^{c}_i=[k_{c,i}]P \in \mathbb{G}`$ acting as per-chat user identifier.

Several modes of preserving identity is [proposed] for every user:
- anonymous capybara - user only computes valid MAC tag to every group message so that other members can verify that he knows $sk$ but do not know any identity attributes.
- traceble elephant - user proves that he posseses only his leaf key $\lambda_i$ and chat key $`Q^{c}_i=[k_{c,i}]P`$ signing each message with this keys.
- public alligator - user proves he posseses his identity key $d_i$ signing each message with it

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