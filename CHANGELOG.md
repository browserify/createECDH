# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v4.0.5](https://github.com/browserify/createECDH/compare/v4.0.4...v4.0.5) - 2026-11-13

### Commits

- [eslint] remove autofixable overrides [`0d88756`](https://github.com/browserify/createECDH/commit/0d88756535ce694d513cf9f4586a66194c48db2e)
- [meta] modernize the package [`25eea4b`](https://github.com/browserify/createECDH/commit/25eea4bc4aec9a77e1d0e3c8da4ff06e31b614f5)
- [eslint] remove remaining overrides [`f733f24`](https://github.com/browserify/createECDH/commit/f733f2491f804ff4faa759c65cbfb75aa028466d)
- [Fix] `computeSecret`, `setPublicKey`: reject public keys that are invalid for the curve [`1cfaf33`](https://github.com/browserify/createECDH/commit/1cfaf332773237e5fea4b51a2ad3efab4c22bec1)
- [meta] switch to eslint [`cdd622f`](https://github.com/browserify/createECDH/commit/cdd622f17b1a5948eb823352515444fa46367009)
- [Fix] use the JS implementation when native `setPrivateKey` does not compute the public key [`13fadb6`](https://github.com/browserify/createECDH/commit/13fadb63b6be0e72fa1917b0396fdc9f28858684)
- [Deps] update `bn.js`, `elliptic` [`3adc987`](https://github.com/browserify/createECDH/commit/3adc987435d3849600267cd108bdaa83e1e52ab4)
- [Robustness] cache `Array.isArray` at module level [`4b33188`](https://github.com/browserify/createECDH/commit/4b33188665910b01c9e8472853bf8e4787204bf4)
- [meta] add missing auto-changelog settings [`bc21216`](https://github.com/browserify/createECDH/commit/bc212162ed25c069c9586f7a537afd60fde1f0fd)

## [v4.0.4](https://github.com/browserify/createECDH/compare/v4.0.3...v4.0.4) - 2020-08-04

### Merged

- Update elliptic version [`#16`](https://github.com/browserify/createECDH/pull/16)

### Fixed

- Update elliptic version (#16) [`#14`](https://github.com/crypto-browserify/createECDH/issues/14)

## [v4.0.3](https://github.com/browserify/createECDH/compare/v4.0.2...v4.0.3) - 2018-05-07

### Commits

- move standard to dev deps [`5b6ad7a`](https://github.com/browserify/createECDH/commit/5b6ad7a3697706b8c008135e4087c0e1a82f9efa)

## [v4.0.2](https://github.com/browserify/createECDH/compare/v4.0.1...v4.0.2) - 2018-05-07

### Merged

- Private key import [`#8`](https://github.com/browserify/createECDH/pull/8)

## [v4.0.1](https://github.com/browserify/createECDH/compare/v4.0.0...v4.0.1) - 2018-04-11

### Merged

- add license [`#10`](https://github.com/browserify/createECDH/pull/10)

## [v4.0.0](https://github.com/browserify/createECDH/compare/v3.0.0...v4.0.0) - 2015-10-29

### Merged

- update bn and elliptic [`#7`](https://github.com/browserify/createECDH/pull/7)

## [v3.0.0](https://github.com/browserify/createECDH/compare/v2.0.2...v3.0.0) - 2015-10-26

### Merged

- upgrade bn.js and elliptic, add 2 curves [`#6`](https://github.com/browserify/createECDH/pull/6)

### Commits

- upgrade bn.js and eleptic, add 2 curves [`84f7984`](https://github.com/browserify/createECDH/commit/84f798475470600dfbb2259ff03d702ccd91018d)

## [v2.0.2](https://github.com/browserify/createECDH/compare/v2.0.1...v2.0.2) - 2015-10-05

### Merged

- add browser field [`#5`](https://github.com/browserify/createECDH/pull/5)

## [v2.0.1](https://github.com/browserify/createECDH/compare/v2.0.0...v2.0.1) - 2015-05-21

### Merged

- update deps [`#4`](https://github.com/browserify/createECDH/pull/4)

### Commits

- adds npmignore [`3cbf265`](https://github.com/browserify/createECDH/commit/3cbf265600d93aef242c56e72c68ac812c844b92)

## [v2.0.0](https://github.com/browserify/createECDH/compare/v1.0.3...v2.0.0) - 2015-02-12

### Merged

- modularize, expand documentation, expand curve list [`#3`](https://github.com/browserify/createECDH/pull/3)

### Commits

- ecdh [`649d8ee`](https://github.com/browserify/createECDH/commit/649d8ee793c080c97f0dc9908075da51e5e66fd2)
- add prime generation [`feb843b`](https://github.com/browserify/createECDH/commit/feb843bb68872e2b2387839c10d0ecfa66476662)
- modularize [`96e6a1e`](https://github.com/browserify/createECDH/commit/96e6a1e18595b512ba600dd409640333d6fe30b5)
- gen primes [`32b0cd0`](https://github.com/browserify/createECDH/commit/32b0cd0b6c3bb8a52161a4776970d2950ac36008)
- clean up prime generation [`721d40b`](https://github.com/browserify/createECDH/commit/721d40b6418dfce6e356af62f297a1cced5679a7)
- rm fast primes [`08779de`](https://github.com/browserify/createECDH/commit/08779de3f58bf83ef7b135b867a503154cf9c472)
- add factory, return this on set functions [`9aa1df2`](https://github.com/browserify/createECDH/commit/9aa1df299026ea6c40a6dbd254f9d80b7cc075a3)
- generate primes [`f1d7cc3`](https://github.com/browserify/createECDH/commit/f1d7cc3257525be9e1a34338271dc4de27a0196d)
- update .travis.yml [`5576ed5`](https://github.com/browserify/createECDH/commit/5576ed5b70f622f6a70884ab963334d46e5a8afb)
- update eliptic [`6b3fbd0`](https://github.com/browserify/createECDH/commit/6b3fbd00c9930e23921b276acedcb1788d1d03d2)
- Update bn.js [`08a105a`](https://github.com/browserify/createECDH/commit/08a105a882f6db84abd81e9f9109146d20fe8562)
- Update bn.js [`fb6a7d9`](https://github.com/browserify/createECDH/commit/fb6a7d960c5c45469fa6abd3e67a7b1d9a976ddf)
- name [`99208c8`](https://github.com/browserify/createECDH/commit/99208c8728a9e671cc46d4afe97c7a3b71974f3d)
- travis [`810fac1`](https://github.com/browserify/createECDH/commit/810fac1b8ff14ace34ddd88c49b09bed1a45e25b)
- touch travis [`9039dea`](https://github.com/browserify/createECDH/commit/9039deaf14d2a1903aee048338cdf7fe5bb2e556)
- rm console log [`c40a075`](https://github.com/browserify/createECDH/commit/c40a075e7bf3b16e5eb6024eb472f3106b0f0f26)

## [v1.0.3](https://github.com/browserify/createECDH/compare/v1.0.2...v1.0.3) - 2014-11-04

### Commits

- Revert "bench" [`54dc2a2`](https://github.com/browserify/createECDH/commit/54dc2a28b5ff73a61c261b721b0665a349b2c67d)
- bench [`3a4f943`](https://github.com/browserify/createECDH/commit/3a4f943ef0070a8146c0aa8b75e20747acc24040)
- finish up [`de5c813`](https://github.com/browserify/createECDH/commit/de5c8132359dbf07182576e2dcdc771ae412e41f)

## [v1.0.2](https://github.com/browserify/createECDH/compare/v1.0.1...v1.0.2) - 2014-11-02

## v1.0.1 - 2015-01-03

### Commits

- ecdh [`649d8ee`](https://github.com/browserify/createECDH/commit/649d8ee793c080c97f0dc9908075da51e5e66fd2)
- first [`923fdc5`](https://github.com/browserify/createECDH/commit/923fdc540603443b7da981094c8906f722ce1ef8)
- add prime generation [`feb843b`](https://github.com/browserify/createECDH/commit/feb843bb68872e2b2387839c10d0ecfa66476662)
- gen primes [`32b0cd0`](https://github.com/browserify/createECDH/commit/32b0cd0b6c3bb8a52161a4776970d2950ac36008)
- works [`a4ec953`](https://github.com/browserify/createECDH/commit/a4ec953802fdc5944a0318331bfadea364942cde)
- clean up prime generation [`721d40b`](https://github.com/browserify/createECDH/commit/721d40b6418dfce6e356af62f297a1cced5679a7)
- Revert "bench" [`54dc2a2`](https://github.com/browserify/createECDH/commit/54dc2a28b5ff73a61c261b721b0665a349b2c67d)
- bench [`3a4f943`](https://github.com/browserify/createECDH/commit/3a4f943ef0070a8146c0aa8b75e20747acc24040)
- rm fast primes [`08779de`](https://github.com/browserify/createECDH/commit/08779de3f58bf83ef7b135b867a503154cf9c472)
- finish up [`de5c813`](https://github.com/browserify/createECDH/commit/de5c8132359dbf07182576e2dcdc771ae412e41f)
- deps [`911fcfb`](https://github.com/browserify/createECDH/commit/911fcfb2ffb579f2668a5e5dbd927bbaa36660fe)
- generate primes [`f1d7cc3`](https://github.com/browserify/createECDH/commit/f1d7cc3257525be9e1a34338271dc4de27a0196d)
- Update bn.js [`fb6a7d9`](https://github.com/browserify/createECDH/commit/fb6a7d960c5c45469fa6abd3e67a7b1d9a976ddf)
- name [`99208c8`](https://github.com/browserify/createECDH/commit/99208c8728a9e671cc46d4afe97c7a3b71974f3d)
- travis [`810fac1`](https://github.com/browserify/createECDH/commit/810fac1b8ff14ace34ddd88c49b09bed1a45e25b)
- rm console log [`c40a075`](https://github.com/browserify/createECDH/commit/c40a075e7bf3b16e5eb6024eb472f3106b0f0f26)
