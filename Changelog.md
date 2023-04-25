# Changelog

## 0.3.0

Released 2023-04-25

Breaking Changes

* The minimum required Rust version is now 1.63. ([#25])

New

* Added new `asn::SmallAsnSet` which, as, the name suggests, is supposed
  to hold a relatively small set of ASNs. ([#22] via [#25])

* Added implementations for the `arbitrary::Arbitrary` trait to ASN and IP
  resource types. ([#24] via [#25])

[#22]: https://github.com/NLnetLabs/routecore/pull/22
[#24]: https://github.com/NLnetLabs/routecore/pull/24
[#25]: https://github.com/NLnetLabs/routecore/pull/25


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

