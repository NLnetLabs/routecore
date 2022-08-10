# Changelog

## Unreleased future version

Breaking changes

New

* Parsing of BGP and BMP messages.

Bug fixes

Other changes

* Changed Rust edition from 2018 to 2021, bumping the minimal supported Rust
  version to 1.56.1 .


## 0.2.0

Released 2022-07-18.

Breaking Changes

* Adjust to new decode error handling in bcder. ([#11])

[#11]: https://github.com/NLnetLabs/routecore/pull/11


## 0.1.1

Released 2022-01-11.

Bug Fixes

* Fixed a panic in `addr::Prefix::new_v4_relaxed` and `new_v6_relaxed` for
  a prefix length of 0. ([#9])

[#9]: https://github.com/NLnetLabs/routecore/pull/9


## 0.1.0

Released 2021-12-13.

Initial (proper) release.

