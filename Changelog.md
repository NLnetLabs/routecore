# Changelog

## 0.4.0-rc1

Unreleased


Breaking changes


New


Bug fixes


Other changes



## 0.4.0-rc0

Released 2024-01-10.

Breaking changes

* Extensive moving and refactoring of code,

  With the focus of _routecore_ heavily shifting towards BGP and BMP related
  functionality, we decided to copy over the few types used by dependants to
  those dependants and remove their depedency on _routecore_. This also means we
  could drop code from _routecore_, and get rid of certain dependencies and
  feature flags.

  In addition to that, there has been extensive renaming throughout the code
  base, though not all of the touched code was ever properly released before.
  All in all, the 0.4.0 release should be considered breaking and not backwards
  compatible.

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
 
* Composing of BGP messages.

  Creating BGP messages is supported to a certain extent, note that the API is
  still limited.

  For BGP OPENs, the Optional Parameters are limited to only the
  Capability type, and more specifically, only the Four Octet capability
  (RFC6793), MultiProtocol (RFC4760) and AddPath (RFC7911) can be set.
  
  For BGP UPDATEs, the builder (`bgp::message::update_builder`) includes methods
  to add announcements, withdrawals and next hop information for conventional
  IPv4 Unicast and MultiProtocol address families. Mandatory path attributes and
  standard communities have dedicated methods, but arbitrary PathAttributes can
  be added as well.  Depending on the resulting total  size, the builder results
  in multiple PDUs to adhere to the protocol.

  BGP NOTIFICATIONs and KEEPALIVEs can be created as well, so all message types
  needed for setting up a BGP session are supported. Note that actually setting
  up and maintaining a BGP session is (currently) not part of `routecore`.

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


Other changes

* Changed the minimal supported Rust version to 1.71.
* Changed Rust edition from 2018 to 2021.

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

