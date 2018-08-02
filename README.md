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

You can find an introduction in [here](https://dexhunter.github.io/cryptograph/toolkit/2018/08/02/ENE-Introduction.html)
([原文](https://quininer.github.io/?ene)).

ENE will provide:

* Authenticated Key Exchange
* Deniable authentication
* Mail Integrity
* Nonce-misuse Resistant AEAD
* Experimental Post-quantum Key Exchange

## Warnings

ENE is experimental!

## Build

ENE is written in nightly Rust.
Install the Rust nightly toolchain in any way, then you just need

```
> env RUSTFLAGS="-C target-feature=+ssse3,+avx2,+aes" cargo build --release
```

You can add a feature flag to enable experimental post-quantum support.

```
> env RUSTFLAGS="-C target-feature=+ssse3,+avx2,+aes" cargo build --features post-quantum --release
```

## Usage

```
# Initialize your profile.
> ene profile <your id> --init

# Export your pubkey
> ene profile --export-pubkey ./<path>

# Add contact
> ene contact --import ./<your friend's pubkey file>

# Encrypt message
> ene sendto <your firend's id> --input ./<your message file>

# Decrypt message
> ene recvfrom <your firend's id> --input ./<encrypted message file>
```

## License

ENE is open-source software, distributed under the MIT license.
