# Changelog

## Unreleased future version

Breaking changes

New

* Parsing of BGP and BMP messages. ([#14])

  The newly added feature flags `bgp` and `bmp` enable parsing capabilities
  for these messages using the [OctSeq](https://github.com/NLnetLabs/octseq)
  crate. This allows parsing of raw wireformat representations in multiple
  data types, including
  [bytes::Bytes](https://docs.rs/bytes/latest/bytes/struct.Bytes.html). The
  parsing and the resulting types `bgp::Message` and `bmp::Message` are mostly
  non-allocating and provide (lazy) iterators to the actual data (e.g. Path
  Attributes or NLRI in a BGP UPDATE PDU), to enable use in high throughput
  scenarios.

* Added new `asn::SmallAsnSet` which, as, the name suggests, is supposed
  to hold a relatively small set of ASNs. ([#22])

* Added implementations for the `arbitrary::Arbitrary` trait to ASN and IP
  resource types. ([#24])

* Reworked AsPath

  Most of the code related to the BGP path attribute AS_PATH has been overhauled
  and moved away from `asn` into `bgp::aspath`. The main struct is now generic
  over `Octets` that represent the wireformat of the path attribute, moving away
  from the 'sentinel ASN'-approach.
  It also introduces `HopPath`, a representation that is more convenient to
  reason about than the wireformat. `HopPath` replaces `AsPathBuilder`.
  ([#23])

* Added `fn contains` to check whether an `std::net::IpAddr` lies within a
  `addr::Prefix`. ([#35])

* Better parsing and creation of BGP NOTIFICATION messages. ([#35])

Bug fixes

Other changes

* Changed Rust edition from 2018 to 2021.
* Changed the the minimal supported Rust version to 1.65, as the parsing of
  BGP and BMP messages relies on GATs.

[#14]: https://github.com/NLnetLabs/routecore/pull/14
[#22]: https://github.com/NLnetLabs/routecore/pull/22
[#23]: https://github.com/NLnetLabs/routecore/pull/23
[#24]: https://github.com/NLnetLabs/routecore/pull/24
[#35]: https://github.com/NLnetLabs/routecore/pull/35


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

