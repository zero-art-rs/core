# Project M

> Distributed web3 e2e messenger

## Main idea

The main goal of project is to develope decentralized web3 e2e messenger. 

First approach was to adopt [AgEncID]((https://arxiv.org/pdf/2309.16282)) scheme for e2e id broadcast encryption. **Setup** and **KeyGen** phases should be maintained by trusted **authorization party** but this scheme appears broken due to symmetric pairing on cyclic subgroups of Elliptic Curves which [degenerates](https://www.sagemath.org/files/thesis/hansen-thesis-2009.pdf#chapter.3).

The second approach is to adopt [Broadcast IBBE by Cecile Delerablee](https://www.iacr.org/archive/asiacrypt2007/48330198/48330198.pdf) (`Del7`) which security is based on GDDHE assumption. This approach will likely be included in the final proto as main broadcast encryption primitive. Reference sage implementation with BN381 curve could be found in `misc`.

The system contains of a set of distributed nodes. Each node represents specific user identity or several identities represented by IDs. Each user identity may be contained in several groups.

## Identity

Each user of a arbitrary group has an unique ID (some string identifying user, e.g. name, email, tel. number) and sk (secret key) corresponding to this ID.
Several modes of preserving identity is [proposed](https://github.com/distributed-lab/papers/blob/main/in-da-club/In_Da_Club.pdf) for every user:
- anonymous capybara - no trace, no id, just zk-proof that user is member of the group
- traceble elephant - tracing is possible, no id however, zk-proof that user is member of group and has some shadow id
- public alligator - user proves he posseses id and sk, e.g. just simple schnorr signature or simple zk-proof of knowledge of sk.
- variable chameleon - user proves he has some ID at the time of messege creation but after some time it remains unclear who sent messege.

## Encryption

The main algorithm for assymetric encryption is IBBE `PM25.Encrypt` function. A user generates header and symmetric encryption key with the mentioned function for group of receivers. A symmetric key is used after for `AES256-GCM` authenticated encryption of messege. After receiving messege user calls `PM25.Decrypt` function on messege header to decapsulate key and decrypt encrypted messege. The main construction is not [forward](https://yaogroup.cs.vt.edu/papers/fs-hibe-full.pdf) nor backword secure yet. Recently we managed to provide a *forward secure* construction which is described in our [paper](https://www.overleaf.com/project/679b4c7dcc8fd2d1052f5849) (`PM25`) currently under developement.

## Group management

In this section we briefly describe some desirable properties of `Project M` group system.

Every group is an abstract tuple $G = <S, M, attrs, mk, pp>$ where $S = {ID_1, ID_2, ..., ID_m}$ - set of user identifiers in group (possibly encrypted from unauthorized users), $M \subseteq S$ - subset of group managers who can endure the entrance ceremony, `attrs` - group attributes (name, creation date, etc., possibly encrypted), `mk` - group master key, `pp` - public parameters. Every member of a group gets a piece of group secret along with other public data during entrance ceremony.

### Creation of a group

1. The author of a group creates group `G` along with initialization of master key and public params with `PM25.Setup` procedure
2. The author invites other group members, gives them permissions and possibly shares master key pieces with them

### Entrance ceremony

When a new user with some $ID$ wants to join the group set of group managers could reach consensus and include new user into group performing additional `PM25.AddMember` procedure. After reaching consensus last group manager performs `PM25.Extract` obtaining $presk_{ID}$, creates ephemeral Diffie-Hellman keys with the new member, derives encryption key and send encrypted $presk_{ID}$ to the new member. After that user endures `PM25.KeyGen` procedure which produces a secret key $sk_{ID}$ and updates public aggregated value `pp.R`.

### Key Update ceremony

Every user could update his $sk_{ID}$ using `P25.KeyUpdate` procedure at the arbitrary moment of time deriving new key and updating group parameter `pp.R` using zk-proof of corectness, ideally after every messege sent achieving perfect forward secrecy.

### Revocation ceremony

When managers decide to revoke user they begin revocation ceremony, one approach is to rebuild `pp.R` using only valid at the time members of group excluding revoked member even though it's not perfectly efficient. Improvements are yet to be done.

## Infrastructure

Technically, each member of project M is represented by some node with messenger application which synchonizes state using other online nodes.

### Spam protection

Optionally some users could be equipped with an additonal role of rate-limiting penguin so that sending more than k messages during some period of time would disclose a user identity (ID or sk).

## Links

1. [AgEncID by indian guys, 2023](https://arxiv.org/pdf/2309.16282)
2. [IDBE concept by Dan Boneh, 2001](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf)
3. [Key-aggregate for data sharing by chinese guys, 2014](https://ink.library.smu.edu.sg/cgi/viewcontent.cgi?article=2937&context=sis_research)
4. [Collusion resistant IDBE with short ciphertext by Dan Boneh et al., 2005](https://eprint.iacr.org/2005/018.pdf)
5. [Project M research paper by Illia and Serhii, 2024](papers/Messenger.pdf)
6. [Broadcast IDBE with constant-size ciphertexts by Cecile Delerablee](https://www.iacr.org/archive/asiacrypt2007/48330198/48330198.pdf)
7. [Wonderful thesis describing Weil pairings and BLS](https://www.sagemath.org/files/thesis/hansen-thesis-2009.pdf)
8. [In Da Club](https://github.com/distributed-lab/papers/blob/main/in-da-club/In_Da_Club.pdf)
9. [Forward Secrecy on BE](https://yaogroup.cs.vt.edu/papers/fs-hibe-full.pdf)
10.[Current Project M Paper, referred as PM25](https://www.overleaf.com/project/679b4c7dcc8fd2d1052f5849)