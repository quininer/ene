# Ñ
[![travis-ci](https://api.travis-ci.org/quininer/ene.svg)](https://travis-ci.org/quininer/ene)
[![appveyor](https://ci.appveyor.com/api/projects/status/5nfd0i66ybt26qbu?svg=true)](https://ci.appveyor.com/project/quininer/ene)
[![license](https://img.shields.io/github/license/quininer/ene.svg)](https://github.com/quininer/ene/blob/master/LICENSE)
![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg)
![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

ENE is an end-to-end encryption tool designed for mail.

PGP has been used for message encryption for years,
but with the evolution of cryptography, part of PGP has become obsolete.
ENE wants to be a more modern alternative.

ENE will provide:

* Authenticated Key Exchange
* Deniable authentication
* Mail Integrity
* Nonce-misuse Resistant AEAD
* Post-quantum Key Exchange

## Build

ENE is written in nightly Rust,
install the Rust nightly toolchain in any way, then you just need

```
> env RUSTFLAGS="-C target-feature=+ssse3,+avx2,+aes" cargo build --release
```

You can add a feature flag to enable post-quantum support.

```
> env RUSTFLAGS="-C target-feature=+ssse3,+avx2,+aes" cargo build --features post-quantum --release
```

## Usage

```
# initialize your profile.
> ene profile <your id> --init

# Add contact
> ene contact --import ./<your friend's pubkey file>

# Encrypt message
> ene sendto <your firend's id> --input ./<your message file>

# Decrypt message
> ene recvfrom <your firend's id> --input ./<encrypted message file>
```

## License

ENE is open-source software, distributed under the MIT license.
