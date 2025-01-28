# Project M

> Distributed web3 e2e messenger

## Main idea

The main goal of project is to develope web3 e2e messenger. First approach was to adopt [AgEncID]((https://arxiv.org/pdf/2309.16282)) scheme for e2e id broadcast encryption. **Setup** and **KeyGen** phases should be maintained by trusted **authorization party** but this scheme appears broken due to symmetric pairing on cyclic subgroups of Elliptic Curves which [degenerates](https://www.sagemath.org/files/thesis/hansen-thesis-2009.pdf#chapter.3).

The second approach is to adopt [Broadcast IDBE by Cecile Delerablee](https://www.iacr.org/archive/asiacrypt2007/48330198/48330198.pdf)

## Links

1. [AgEncID by indian guys, 2023](https://arxiv.org/pdf/2309.16282)
2. [IDBE concept by Dan Boneh, 2001](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf)
3. [Key-aggregate for data sharing by chinese guys, 2014](https://ink.library.smu.edu.sg/cgi/viewcontent.cgi?article=2937&context=sis_research)
4. [Collusion resistant IDBE with short ciphertext by Dan Boneh et al., 2005](https://eprint.iacr.org/2005/018.pdf)
5. [Project M research paper by Illia and Serhii, 2024](papers/Messenger.pdf)
6. [Broadcast IDBE with constant-size ciphertexts by Cecile Delerablee](https://www.iacr.org/archive/asiacrypt2007/48330198/48330198.pdf)
7. [Wonderful thesis describing Weil pairings and BLS](https://www.sagemath.org/files/thesis/hansen-thesis-2009.pdf)