# Changelog

## 0.6.1

Released yyyy-mm-dd.


New

* Keep the 'NextHop' information from the `MP_REACH_NLRI` path attribute.


Other changes

* Rust Edition bumped to 2024, and with that, the MSRV to 1.85.



## 0.6.0

Released 2025-09-29.

Breaking changes

* MSRV bumped to 1.81.

* Serialisation of the different community types (BGP path attributes) now uses
  their `Display` implementations.

Bug fixes

* Fix TLV iterator on BMP PeerUpNotification messages.

Other changes

* Fine-tuned the warnings for unknown TLV types on BMP PeerUpNotifications.



## 0.5.2

Released 2025-04-23.

New

* `AsRef<u8>` impl for `OwnedPathAttributes`. This enables `rotonda-store` to
  store these values in a RIB.

Other changes

* Be more forgiving when parsing BGP Open Capabilities, specifically empty
  `AddPath` capabilities.


## 0.5.1

Released 2025-01-29.

Bug fixes

* The `communities()` method on a BGP `UpdateMessage` now returns an iterator
  yielding `StandardCommunity` instead of the enum `Community`. This way it is
  consistent with the other methods for the other flavours of communities.

New

* Introduce methods on `AsPath` to more ergonomically use paths comprised of a
  single _AS_SEQUENCE_.
* The MRT reader, still gated with the feature flag, now supports reading from
  `.bz2` directly (in addition to `.gz`). Support for the _ExtendedTime_ message
  types is added as well. This means we can process files from the RouteViews
  archives.


Other changes

* The hashing of, and comparison between, BMP _PerPeerHeaders_ now includes
  the _PeerFlags_. This way, the `RibType` is part of what defines a
  `PerPeerHeader` to be unique.



## 0.5.0

Released 2024-11-20.

This release features a lot of changes, big and small. The list below is not
exhaustive but tries to highlight and describe the bigger (and perhaps, more
important) ones.


Breaking changes

* Several common basic types (e.g. `Asn` and `Prefix`) are moved out of
  _routecore_ to the new _inetnum_ crate.
 
* Refactor of PathAttributes 

  The introduction of `PaMap` and `RouteWorkshop` (see below) required refactoring
  of the `PathAttributes` enum and related types. Most significantly, an entire
  layer in the enum was removed, changing how one matches on variants.
  Furthermore some of the types in those variants slightly changed.
 
* Overhaul of address family related code
  
  The types describing address families, and related traits to parse and compose
  NLRI of such families, have severely changed. This eliminates any possible
  ambiguity regarding the address family of announcements/withdrawals in UPDATE
  messages at compile time. 
 
    * Supported address families are now explicitly and exhaustively enumerated
      in the `AfiSafiType` enum.  As a SAFI by itself does not carry much meaning,
      the separate `SAFI` enum is removed. Almost all of the code now works
      based on the more descriptive `AfiSafiType`.
    * ADD-PATH is now supported on all supported address families, i.e. the
      `AfiSafiType` includes `~AddPath` variants for every single AFI+SAFI
      combination. 
    * This now allows for e.g. efficient iterators over NLRI that are generic
      over the `AfiSafiType`.
      But, as a possible downside, this moves the task of determining what
      address family a set of NLRI holds to the caller in order to then use the
      correctly typed iterator. The less efficient, 'easier to use' iterators
      returning an enum instead of a distinct NLRI type are therefore still
      available.

New

* RouteWorkshop / PaMap

  This release introduces the `RouteWorkshop` to create UPDATE messages based on
  an NLRI and a set of attributes. For creation, inspection and manipulation of
  those attributes, the `PaMap` is introduced. These new types work in
  conjunction with the existing `UpdateBuilder`.
  
  Another new, related type is the `OwnedPathAttributes`, which is sort of a mix
  between the `PathAttributes` and `PaMap`, keeping the actual wireformat
  attributes blob in tact (using a `Vec<u8>`). This makes it more memory
  efficient than the `PaMap`, at a small cost in forms of compute.
 
* BGP FSM (absorbed from _rotonda-fsm_)
  
  _routecore_ now contains the code to enable for actual BGP sessions, i.e. the
  BGP FSM and related machinery. By pulling this in into _routecore_ allows for
  less dependency juggling, easier development iterations and more sensible code
  in all parts. All of this has some rough edges and is prone to changes on the
  near future.

  The _rotonda-fsm_ crate for now is left as-is.


* Route Selection fundamentals

  This release introduces a first attempt at providing handles to perform the
  BGP Decision Process as described in RFC4271, colloquially known as 'route
  selection' or 'best path selection'.
  
  Most of the heavy-lifting for this comes from implementing `Ord` on a wrapper
  struct holding a 'route' (i.e., `PaMap`) and additional information to allow
  tie-breaking as described in the RFC.
  
  As the tie-breaking in RFC4271 is actually broken and not totally ordered, we
  aim to provide a certain degree of flexibility in the tie-breaking process by
  means of different `OrdStrat` ordering strategies.

 
* Limited MRT read support

  Support for reading and parsing MRT files, such as those published by RIPE
  RIS, is added behind the `mrt` feature flag. Both the 'dump' and the 'updates'
  files are supported, though not all exotic message types might be recognized,
  and the API will likely change.
  

Other changes

* Feature flags

  After splitting of parts of _routecore_ into the _inetnum_ crate, the default
  features set resulted in an almost empty library. Therefore the `bgp` flag is
  now on by default, and we introduced an `fsm` flag to enable the BGP FSM code
  absorbed from _rotonda-fsm_.


Known limitations

* Constructed UPDATE messages are MultiProtocol-only

  With regards to announcing and withdrawing NLRI, the `UpdateBuilder` is currently
  limited to putting everything in the MultiProtocol path attributes
  (MP_REACH_NLRI, MP_UNREACH_NLRI), so even for IPv4 Unicast.
 
  Note that this behaviour is considered preferable as it leads to somewhat more
  flexibility/resilience on the protocol level. But in case one of the peers
  does not signal the capability of doing IPv4 Unicast in MultiProtocol
  attributes, we should allow creation of PDUs in the traditional form anyway,
  so we plan to reintroduce this functionality.


## 0.4.0

Released 2024-01-18.

Breaking changes

* Extensive moving and refactoring of code

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

  The newly added feature flags `bgp` and `bmp` enable parsing capabilities for
  raw wireformat representations of these messages in multiple data types,
  including
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

