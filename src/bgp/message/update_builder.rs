use std::net::Ipv6Addr;

use octseq::OctetsBuilder;

use crate::bgp::communities::StandardCommunity;
use crate::bgp::message::nlri::Nlri;
use crate::bgp::message::update::{AFI, SAFI, NextHop};

use super::update::ComposeError;

// just drafting ideas, not used right now
#[allow(dead_code)]
pub mod new_pas {

    use std::net::Ipv4Addr;

    use octseq::{Octets, OctetsBuilder, Parser};

    use crate::asn::Asn;
    use crate::bgp::aspath::HopPath;
    use crate::bgp::message::update_builder::{
        MpReachNlriBuilder,
        MpUnreachNlriBuilder
    };
    use crate::bgp::message::SessionConfig;
    use crate::bgp::types::{AFI, SAFI};
    use crate::util::parser::{ParseError, parse_ipv4addr};

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct Flags(u8);

    impl Flags {
        // 0 1 2 3 4 5 6 7
        //
        // 0: optional (1 == optional)
        // 1: transitive (1 == transitive) (well-known attr are transitive)
        // 2: partial 
        // 3: extended length (0 -> 1 byte length, 1 -> 2 byte length)
        // 4-7: MUST be 0 when sent, ignored when received
        const OPT_NON_TRANS: u8 = 0b1000_0000;
        const OPT_TRANS: u8     = 0b1100_0000;
        const WELLKNOWN: u8     = 0b0100_0000;

        const EXTENDED_LEN: u8  = 0b0001_0000;
        const PARTIAL: u8       = 0b0010_0000;

        /// Returns true if the optional flag is set.
        pub fn is_optional(self) -> bool {
            self.0 & 0x80 == 0x80
        }

        /// Returns true if the transitive bit is set.
        pub fn is_transitive(self) -> bool {
            self.0 & 0x40 == 0x40
        }

        /// Returns true if the partial flag is set.
        pub fn is_partial(self) -> bool {
            self.0 & 0x20 == 0x20
        }

        /// Returns true if the extended length flag is set.
        pub fn is_extended_length(self) -> bool {
            self.0 & 0x10 == 0x10
        }

    }

    impl From<u8> for Flags {
        fn from(u: u8) -> Flags {
            Flags(u)
        }
    }

    impl From<Flags> for u8 {
        fn from(f: Flags) -> u8 {
            f.0
        }
    }


    pub trait AttributeHeader {
        const FLAGS: u8;
        const TYPECODE: u8;
    }

    macro_rules! attribute {
        ($name:ident($data:ty),
         $flags:expr,
         $typecode:expr
         ) => {

            #[derive(Debug, Eq, PartialEq)]
            pub struct $name($data);
            impl $name {
                pub fn new(data: $data) -> $name {
                    $name(data)
                }
            }

            impl AttributeHeader for $name {
                const FLAGS: u8 = $flags;
                const TYPECODE: u8 = $typecode;
            }
        }
    }

    macro_rules! path_attributes {
        (
            $(
                $typecode:expr => $name:ident($data:ty), $flags:expr
            ),+ $(,)*
        ) => {

            #[derive(Debug, Eq, PartialEq)]
            pub enum PathAttribute {
                $( $name($name) ),+,
                //Unimplemented(Flags, u8, Vec<u8>)
                Unimplemented(UnimplementedPathAttribute)
            }

            impl PathAttribute {
                pub fn compose<Target: OctetsBuilder>(
                    &self,
                    target: &mut Target
                ) -> Result<(), Target::AppendError> {

                    match self {
                    $(
                        PathAttribute::$name(i) => i.compose(target)
                    ),+,
                    //PathAttribute::Unimplemented(i) => TODO return Err(ComposeError) ?
                    PathAttribute::Unimplemented(u) => u.compose(target)
                    }
                }

                pub fn typecode(&self) -> PathAttributeType {
                    match self {
                        $(
                        PathAttribute::$name(_) =>
                            PathAttributeType::$name
                        ),+,
                        PathAttribute::Unimplemented(u) =>
                            PathAttributeType::Unimplemented(u.typecode())
                    }
                }
            }

            $(
            impl From<$name> for PathAttribute {
                fn from(pa: $name) -> PathAttribute {
                    PathAttribute::$name(pa)
                }
            }
            )+

            impl From<UnimplementedPathAttribute> for PathAttribute {
                fn from(u: UnimplementedPathAttribute) -> PathAttribute {
                    PathAttribute::Unimplemented(u)
                }
            }

            #[derive(Debug)]
            pub enum WireformatPathAttribute<'a, Octs> {
                $( $name(Parser<'a, Octs>, SessionConfig) ),+,
                Unimplemented(UnimplementedWireformat<'a, Octs>)
            }


            impl<'a, Octs: Octets> WireformatPathAttribute<'a, Octs> {
                fn parse(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
                    -> Result<WireformatPathAttribute<'a, Octs>, ParseError>
                {
                    let flags = parser.parse_u8()?;
                    let typecode = parser.parse_u8()?;
                    let mut _headerlen = 3;
                    let len = match flags & 0x10 == 0x10 {
                        true => {
                            _headerlen += 1;
                            parser.parse_u16_be()? as usize
                        },
                        false => parser.parse_u8()? as usize, 
                    };

                    let pp = parser.parse_parser(len)?;
                    let res = match typecode {
                        $(
                        $typecode => WireformatPathAttribute::$name(pp, sc)
                        ),+
                        ,
                        _ => WireformatPathAttribute::Unimplemented(
                            UnimplementedWireformat::new(
                                flags.into(), typecode, pp
                            ))
                    };

                    Ok(res)
                }

                // XXX this method is the reason we have fn parse as part of
                // the trait, forcing us the pass a SessionConfig to all of
                // the parse() implementations.
                fn to_owned(&self) -> PathAttribute {
                    match self {
                        $(
                        WireformatPathAttribute::$name(p, sc) => {
                            PathAttribute::$name(
                                $name::parse(&mut p.clone(), *sc).unwrap()
                            )
                        }
                        ),+,
                        WireformatPathAttribute::Unimplemented(u) => {
                            PathAttribute::Unimplemented(
                                UnimplementedPathAttribute::new(
                                    u.flags(),
                                    u.typecode(),
                                    u.value().to_vec()
                                )
                            )
                        }
                    }
                }

                pub fn typecode(&self) -> PathAttributeType {
                    match self {
                        $(
                            WireformatPathAttribute::$name(_,_) =>
                                PathAttributeType::$name
                        ),+,
                        WireformatPathAttribute::Unimplemented(u) =>
                            PathAttributeType::Unimplemented(u.typecode())
                    }
                }
            }

            #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            pub enum PathAttributeType {
                $( $name ),+,
                Unimplemented(u8)
            }
            impl From<u8> for PathAttributeType {
                fn from(code: u8) -> PathAttributeType {
                    match code {
                        $( $typecode => PathAttributeType::$name ),+,
                        u => PathAttributeType::Unimplemented(u)
                    }
                }
            }

            impl From<PathAttributeType> for u8 {
                fn from(pat: PathAttributeType) -> u8 {
                    match pat {
                        $( PathAttributeType::$name => $typecode ),+,
                        PathAttributeType::Unimplemented(i) => i
                    }
                }
            }

            $(
            attribute!($name($data), $flags, $typecode);
            )+
        }
    }

    path_attributes!(
        1   => Origin(OriginType), Flags::WELLKNOWN,
        2   => AsPath(HopPath), Flags::WELLKNOWN,
        3   => NextHop(Ipv4Addr), Flags::WELLKNOWN,
        4   => MultiExitDisc(u32), Flags::OPT_NON_TRANS,
        5   => LocalPref(u32), Flags::WELLKNOWN,
        6   => AtomicAggregate(()), Flags::WELLKNOWN,
        7   => Aggregator(AggregatorInfo), Flags::OPT_TRANS,
        8   => Communities(StandardCommunitiesList), Flags::OPT_TRANS,
        9   => OriginatorId(Ipv4Addr), Flags::OPT_NON_TRANS,
        10  => ClusterList(ClusterIds), Flags::OPT_NON_TRANS,
        14  => MpReachNlri(MpReachNlriBuilder), Flags::OPT_NON_TRANS,
        15  => MpUnreachNlri(MpUnreachNlriBuilder), Flags::OPT_NON_TRANS,
        16  => ExtendedCommunities(ExtendedCommunitiesList), Flags::OPT_TRANS,
        17  => As4Path(HopPath), Flags::OPT_TRANS,
        18  => As4Aggregator(Asn), Flags::OPT_TRANS,
        20  => Connector(Ipv4Addr), Flags::OPT_TRANS,
        21  => AsPathLimit(AsPathLimitInfo), Flags::OPT_TRANS,
        //22  => PmsiTunnel(todo), Flags::OPT_TRANS,
        // , 25 ExtIpv6Comm
        32  => LargeCommunities(LargeCommunitiesList), Flags::OPT_TRANS,
        // 33 => BgpsecAsPath,
        35 => Otc(Asn), Flags::OPT_TRANS,
        // 128 => AttrSet
        // 255 => RsrvdDevelopment

    );

    #[derive(Debug, Eq, PartialEq)]
    pub struct UnimplementedPathAttribute {
        flags: Flags,
        typecode: u8,
        value: Vec<u8>,
    }

    impl UnimplementedPathAttribute {
        pub fn new(flags: Flags, typecode: u8, value: Vec<u8>) -> Self {
            Self { flags, typecode, value }
        }

        pub fn typecode(&self) -> u8 {
            self.typecode
        }

        pub fn flags(&self) -> Flags {
            self.flags
        }

        pub fn value(&self) -> &Vec<u8> {
            &self.value
        }
    }

    #[derive(Debug)]
    pub struct UnimplementedWireformat<'a, Octs> {
        flags: Flags,
        typecode: u8,
        value: Parser<'a, Octs>,
    }

    impl<'a, Octs: Octets> UnimplementedWireformat<'a, Octs> {
        pub fn new(flags: Flags, typecode: u8, value: Parser<'a, Octs>) -> Self {
            Self { flags, typecode, value }
        }
        pub fn typecode(&self) -> u8 {
            self.typecode
        }

        pub fn flags(&self) -> Flags {
            self.flags
        }

        pub fn value(&self) -> &[u8] {
            self.value.peek_all()
        }

        /* TODO move these to all (wireformat)pathattributes
        /// Returns true if the optional flag is set.
        pub fn is_optional(self) -> bool {
            self.0 & 0x80 == 0x80
        }

        /// Returns true if the transitive bit is set.
        pub fn is_transitive(&self) -> bool {
            self.flags.is_transitive()
        }

        /// Returns true if the partial flag is set.
        pub fn is_partial(&self) -> bool {
            self.flags.is_partial()
        }

        /// Returns true if the extended length flag is set.
        pub fn is_extended_length(&self) -> bool {
            self.flags.is_extended_length()
        }
        */

    }


    pub trait Attribute: AttributeHeader {

        fn compose_len(&self) -> usize {
            self.header_len() + self.value_len()
        }

        fn is_extended(&self) -> bool {
            self.value_len() > 255
        }

        fn header_len(&self) -> usize {
            if self.is_extended() {
                4
            } else {
                3
            }
        }

        fn value_len(&self) -> usize;

        fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            self.compose_header(target)?;
            self.compose_value(target)
        }

        fn compose_header<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            if self.is_extended() {
                target.append_slice(&[
                    Self::FLAGS | Flags::EXTENDED_LEN,
                    Self::TYPECODE,
                ])?;
                target.append_slice(
                    &u16::try_from(self.value_len()).unwrap_or(u16::MAX)
                    .to_be_bytes()
                )
            } else {
                target.append_slice(&[
                    Self::FLAGS,
                    Self::TYPECODE,
                    u8::try_from(self.value_len()).unwrap_or(u8::MAX)
                ])
            }
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>;

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, sc: SessionConfig) 
            -> Result<Self, ParseError>
        where Self: Sized;
        
    }

    struct PathAttributes<'a, Octs> {
        parser: Parser<'a, Octs>,
        session_config: SessionConfig,
    }

    impl<'a, Octs> Clone for PathAttributes<'a, Octs> {
        fn clone(&self) -> Self {
            *self
        }
    }

    impl<'a, Octs> Copy for PathAttributes<'a, Octs> { }

    impl<'a, Octs: Octets> PathAttributes<'a, Octs> {
        fn new(parser: Parser<'a, Octs>, session_config: SessionConfig)
            -> PathAttributes<'_, Octs>
        {
            PathAttributes { parser, session_config }
        }
        
        fn get(&self, pat: PathAttributeType)
            -> Option<WireformatPathAttribute<'a, Octs>>
        {
            let mut iter = *self;
            iter.find(|pa|
                  //XXX We need Rust 1.70 for is_ok_and()
                  //pa.as_ref().is_ok_and(|pa| pa.typecode() == pat)
                  if let Ok(pa) = pa.as_ref() {
                      pa.typecode() == pat
                  } else {
                      false
                  }
            ).map(|res| res.unwrap()) // res is Ok(pa), so we can unwrap.
        }

    }

    impl<'a, Octs: Octets> Iterator for PathAttributes<'a, Octs> {
        type Item = Result<WireformatPathAttribute<'a, Octs>, ParseError>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            let res = WireformatPathAttribute::parse(
                &mut self.parser,
                self.session_config
            );
            Some(res)
        }
    }




    //--- Origin

    use crate::bgp::message::update::OriginType;

    impl Attribute for Origin {
        fn value_len(&self) -> usize { 1 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&[self.0.into()]) 
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<Origin, ParseError>
        {
            Ok(Origin(parser.parse_u8()?.into()))
        }
    }

    //--- AsPath (see bgp::aspath)

    impl Attribute for AsPath {
        fn value_len(&self) -> usize {
            self.0.to_as_path::<Vec<u8>>().unwrap().into_inner().len()
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, sc: SessionConfig) 
            -> Result<AsPath, ParseError>
        {
            // XXX reusing the old/existing AsPath here while PoC'ing, which
            // new() expects Octets (not a Parser<_,_>) starting at the actual
            // value, so without the first 3 or 4 bytes (flags/type/len).
            let asp = crate::bgp::aspath::AsPath::new(
                parser.octets_ref().as_ref()[3..].to_vec(),
                sc.has_four_octet_asn()
            ).unwrap();
            Ok(AsPath(asp.to_hop_path()))
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
           //HopPath::compose_as_path(self.0.hops(), target) 
           target.append_slice(
               self.0.to_as_path::<Vec<u8>>().unwrap().into_inner().as_ref()
            )
        }
    }

    //--- NextHop

    impl Attribute for NextHop {
        fn value_len(&self) -> usize { 4 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.octets())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<NextHop, ParseError>
        {
            Ok(NextHop(parse_ipv4addr(parser)?))
        }
    }

    //--- MultiExitDisc

    impl Attribute for MultiExitDisc {
        fn value_len(&self) -> usize { 4 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.to_be_bytes()) 
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<MultiExitDisc, ParseError>
        {
            Ok(MultiExitDisc(parser.parse_u32_be()?))
        }
    }

    //--- LocalPref

    impl Attribute for LocalPref {
        fn value_len(&self) -> usize { 4 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.to_be_bytes()) 
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<LocalPref, ParseError>
        {
            Ok(LocalPref(parser.parse_u32_be()?))
        }
    }

    //--- AtomicAggregate

    impl Attribute for AtomicAggregate {
        fn value_len(&self) -> usize { 0 }

        fn compose_value<Target: OctetsBuilder>(&self, _target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            Ok(())
        }

        fn parse<Octs: Octets>(_parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<AtomicAggregate, ParseError>
        {
            Ok(AtomicAggregate(()))
        }
    }

    //--- Aggregator

    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct AggregatorInfo {
        asn: Asn,
        address: Ipv4Addr,
    }

    impl AggregatorInfo {
        fn new(asn: Asn, address: Ipv4Addr) -> AggregatorInfo {
            AggregatorInfo { asn, address }
        }
        pub fn asn(&self) -> Asn {
            self.asn
        }
        pub fn address(&self) -> Ipv4Addr {
            self.address
        }
    }

    impl Attribute for Aggregator {
        // FIXME for legacy 2-byte ASNs, this should be 6.
        // Should we pass a (&)SessionConfig to this method as well?
        // Note that `fn compose_len` would then also need a SessionConfig,
        // which, sort of makes sense anyway.
        fn value_len(&self) -> usize { 
            8
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.asn().to_raw())?;
            target.append_slice(&self.0.address().octets())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, sc: SessionConfig) 
            -> Result<Aggregator, ParseError>
        {
            let asn = if sc.has_four_octet_asn() {
                Asn::from_u32(parser.parse_u32_be()?)
            } else {
                Asn::from_u32(parser.parse_u16_be()?.into())
            };

            let address = parse_ipv4addr(parser)?;
            Ok(Aggregator(AggregatorInfo::new(asn, address)))
        }
    }

    //--- Communities
    
    use crate::bgp::communities::StandardCommunity;
    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct StandardCommunitiesList {
        communities: Vec<StandardCommunity>
    }

    impl StandardCommunitiesList {
        fn new(communities: Vec<StandardCommunity>)
            -> StandardCommunitiesList
        {
            StandardCommunitiesList {communities }
        }

        pub fn communities(&self) -> &Vec<StandardCommunity> {
            &self.communities
        }
    }


    impl Attribute for Communities {
        fn value_len(&self) -> usize { 
            self.0.communities.len() * 4
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            for c in &self.0.communities {
                target.append_slice(&c.to_raw())?;
            }
            Ok(())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<Communities, ParseError>
        {
            let mut communities = Vec::with_capacity(parser.remaining() / 4);
            while parser.remaining() > 0 {
                communities.push(parser.parse_u32_be()?.into());
            }
            Ok(Communities(StandardCommunitiesList::new(communities)))
        }
    }

    //--- OriginatorId

    impl Attribute for OriginatorId {
        fn value_len(&self) -> usize { 4 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.octets())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<OriginatorId, ParseError>
        {
            Ok(OriginatorId(parse_ipv4addr(parser)?))
        }
    }

    //--- ClusterList
    
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct BgpIdentifier([u8; 4]);

    impl From<[u8; 4]> for BgpIdentifier {
        fn from(raw: [u8; 4]) -> BgpIdentifier {
            BgpIdentifier(raw)
        }
    }

    /*
    impl From<u32> for BgpIdentifier {
        fn from(raw: u32) -> BgpIdentifier {
            BgpIdentifier(raw.to_be_bytes())
        }
    }
    */

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct ClusterIds {
        cluster_ids: Vec<BgpIdentifier>
    }

    impl ClusterIds {
        fn new(cluster_ids: Vec<BgpIdentifier>) -> ClusterIds {
            ClusterIds {cluster_ids }
        }
        pub fn cluster_ids(&self) -> &Vec<BgpIdentifier> {
            &self.cluster_ids
        }
    }


    impl Attribute for ClusterList {
        fn value_len(&self) -> usize { 
            self.0.cluster_ids.len() * 4
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            for c in &self.0.cluster_ids {
                target.append_slice(&c.0)?;
            }
            Ok(())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<ClusterList, ParseError>
        {
            let mut cluster_ids = Vec::with_capacity(parser.remaining() / 4);
            while parser.remaining() > 0 {
                cluster_ids.push(parser.parse_u32_be()?.to_be_bytes().into());
            }
            Ok(ClusterList(ClusterIds::new(cluster_ids)))
        }
    }

    //--- MpReachNlri
    impl Attribute for MpReachNlri {
        fn value_len(&self) -> usize { 
            self.0.value_len()
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            self.0.compose_value(target)
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, sc: SessionConfig) 
            -> Result<MpReachNlri, ParseError>
        {
            let afi: AFI = parser.parse_u16_be()?.into();
            let safi: SAFI = parser.parse_u8()?.into();
            let nexthop = crate::bgp::types::NextHop::parse(parser, afi, safi)?;
            parser.advance(1)?; // reserved byte
            let mut builder = MpReachNlriBuilder::new(
                afi, safi, nexthop, sc.addpath_enabled()
            );
            let nlri_iter = crate::bgp::message::update::Nlris::new(
                *parser,
                sc,
                afi,
                safi
            ).iter();

            // FIXME
            // MpReachNlriBuilder works with Nlri<Vec<u8>>
            // but that is somewhat limiting. Here, we reuse the existing
            // Nlris iter from bgp::message::update, where the iterator
            // returns Item = Nlri<Octs::Range<'_>>.
            // Perhaps add_announcement should take Nlri<T> where T:
            // OctetsInto<Vec<u8>> or something like that?
            use crate::bgp::message::nlri::{Nlri, BasicNlri};
            for nlri in nlri_iter {
                match nlri {
                    Nlri::Unicast(b) => {
                        builder.add_announcement(
                            &Nlri::Unicast(BasicNlri {
                                prefix: b.prefix,
                                path_id: b.path_id
                            })
                        ).unwrap()
                    },
                    _ => unimplemented!()
                }
            }
            Ok(MpReachNlri(builder))
        }
    }

    //--- MpUnreachNlri
    impl Attribute for MpUnreachNlri {
        fn value_len(&self) -> usize { 
            self.0.value_len()
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            self.0.compose_value(target)
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, sc: SessionConfig) 
            -> Result<MpUnreachNlri, ParseError>
        {
            let afi: AFI = parser.parse_u16_be()?.into();
            let safi: SAFI = parser.parse_u8()?.into();

            let mut builder = MpUnreachNlriBuilder::new(
                afi, safi, sc.addpath_enabled()
            );
            let nlri_iter = crate::bgp::message::update::Nlris::new(
                *parser,
                sc,
                afi,
                safi
            ).iter();

            // FIXME
            // see note at MpReachNlri above
            use crate::bgp::message::nlri::{Nlri, BasicNlri};
            for nlri in nlri_iter {
                match nlri {
                    Nlri::Unicast(b) => {
                        builder.add_withdrawal(
                            &Nlri::Unicast(BasicNlri {
                                prefix: b.prefix,
                                path_id: b.path_id
                            })
                        ).unwrap()
                    },
                    _ => unimplemented!()
                }
            }

            Ok(MpUnreachNlri(builder))
        }
    }

    //--- ExtendedCommunities
    
    use crate::bgp::communities::ExtendedCommunity;
    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct ExtendedCommunitiesList {
        communities: Vec<ExtendedCommunity>
    }

    impl ExtendedCommunitiesList {
        fn new(communities: Vec<ExtendedCommunity>)
            -> ExtendedCommunitiesList
        {
            ExtendedCommunitiesList {communities }
        }

        pub fn communities(&self) -> &Vec<ExtendedCommunity> {
            &self.communities
        }
    }


    impl Attribute for ExtendedCommunities {
        fn value_len(&self) -> usize { 
            self.0.communities.len() * 8
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            for c in &self.0.communities {
                target.append_slice(&c.to_raw())?;
            }
            Ok(())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<ExtendedCommunities, ParseError>
        {
            let mut communities = Vec::with_capacity(parser.remaining() / 8);
            let mut buf = [0u8; 8];
            while parser.remaining() > 0 {
                parser.parse_buf(&mut buf)?;
                communities.push(buf.into());
            }
            Ok(ExtendedCommunities(ExtendedCommunitiesList::new(communities)))
        }
    }

    //--- As4Path (see bgp::aspath)

    impl Attribute for As4Path {
        fn value_len(&self) -> usize {
            self.0.to_as_path::<Vec<u8>>().unwrap().into_inner().len()
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(
                self.0.to_as_path::<Vec<u8>>().unwrap().into_inner().as_ref()
            )
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, sc: SessionConfig) 
            -> Result<As4Path, ParseError>
        {
            // XXX same as with AsPath, reusing the old/existing As4Path here
            // while PoC'ing, which new() expects Octets (not a Parser<_,_>)
            // starting at the actual value, so without the first 3 or 4 bytes
            // (flags/type/len).
            let asp = crate::bgp::aspath::AsPath::new(
                parser.octets_ref().as_ref()[3..].to_vec(),
                sc.has_four_octet_asn()
            ).unwrap();
            Ok(As4Path(asp.to_hop_path()))
        }

    }

    //--- As4Aggregator 
 
    impl Attribute for As4Aggregator {
        fn value_len(&self) -> usize { 4 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.to_raw())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<As4Aggregator, ParseError>
        {
            Ok(As4Aggregator(Asn::from_u32(parser.parse_u32_be()?)))
        }
    }


    //--- Connector (deprecated)

    impl Attribute for Connector {
        fn value_len(&self) -> usize { 4 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.octets())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<Connector, ParseError>
        {
            Ok(Connector(parse_ipv4addr(parser)?))
        }
    }

    //--- AsPathLimit (deprecated)

    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct AsPathLimitInfo {
        upper_bound: u8,
        attacher: Asn,
    }

    impl AsPathLimitInfo {
        pub fn new(upper_bound: u8, attacher: Asn) -> AsPathLimitInfo {
            AsPathLimitInfo { upper_bound, attacher }
        }
    }

    impl Attribute for AsPathLimit {
        fn value_len(&self) -> usize { 5 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&[self.0.upper_bound])?;
            target.append_slice(&self.0.attacher.to_raw())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<AsPathLimit, ParseError>
        {
            let info = AsPathLimitInfo {
                upper_bound: parser.parse_u8()?,
                attacher: Asn::from_u32(parser.parse_u32_be()?)
            };

            Ok(AsPathLimit(info))
        }
    }


    //--- LargeCommunities
    
    use crate::bgp::communities::LargeCommunity;
    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct LargeCommunitiesList {
        communities: Vec<LargeCommunity>
    }

    impl LargeCommunitiesList {
        fn new(communities: Vec<LargeCommunity>)
            -> LargeCommunitiesList
        {
            LargeCommunitiesList {communities }
        }

        pub fn communities(&self) -> &Vec<LargeCommunity> {
            &self.communities
        }
    }


    impl Attribute for LargeCommunities {
        fn value_len(&self) -> usize { 
            self.0.communities.len() * 12
        }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            for c in &self.0.communities {
                target.append_slice(&c.to_raw())?;
            }
            Ok(())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<LargeCommunities, ParseError>
        {
            let mut communities = Vec::with_capacity(parser.remaining() / 12);
            let mut buf = [0u8; 12];
            while parser.remaining() > 0 {
                parser.parse_buf(&mut buf)?;
                communities.push(buf.into());
            }
            Ok(LargeCommunities(LargeCommunitiesList::new(communities)))
        }
    }

    //--- Otc 
 
    impl Attribute for Otc {
        fn value_len(&self) -> usize { 4 }

        fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&self.0.to_raw())
        }

        fn parse<Octs: Octets>(parser: &mut Parser<Octs>, _sc: SessionConfig) 
            -> Result<Otc, ParseError>
        {
            Ok(Otc(Asn::from_u32(parser.parse_u32_be()?)))
        }
    }


    //--- Unimplemented
    // 
    // XXX implementing the Attribute trait requires to implement the
    // AttributeHeader trait to be implemented as well. But, we have no const
    // FLAGS and TYPECODE for an UnimplementedPathAttribute, so that does not
    // fly.
    //
    // Let's try to go without the trait.

    impl UnimplementedPathAttribute {
        fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            let len = self.value().len();
            target.append_slice(
                &[self.flags().into(), self.typecode()]
            )?;
            if self.flags().is_extended_length() {
                target.append_slice(
                    &u16::try_from(len).unwrap_or(u16::MAX)
                    .to_be_bytes()
                )?;
            } else {
                target.append_slice(&[
                    u8::try_from(len).unwrap_or(u8::MAX)
                ])?;
            }
            target.append_slice(self.value())
        }
    }


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
    mod tests {
        use super::*;
        use crate::asn::Asn;
        use crate::bgp::communities::Wellknown;
        use crate::bgp::message::nlri::Nlri;
        use crate::bgp::message::update::NextHop;

        // FIXME switch to use ::new() for all attributes instead of relying
        // on non public newtype constructor
        #[test]
        fn wireformat_to_owned_and_back() {
            use super::PathAttribute as PA;
            fn check(raw: Vec<u8>, owned: PathAttribute) {
                let mut parser = Parser::from_ref(&raw);
                let sc = SessionConfig::modern();
                let pa = WireformatPathAttribute::parse(&mut parser, sc)
                    .unwrap();
                assert_eq!(owned, pa.to_owned());
                let mut target = Vec::new();
                owned.compose(&mut target).unwrap();
                assert_eq!(target, raw);
            }

            check(vec![0x40, 0x01, 0x01, 0x00], PA::Origin(Origin(0.into())));

            check(
                vec![0x40, 0x02, 10,
                0x02, 0x02, // SEQUENCE of length 2
                0x00, 0x00, 0x00, 100,
                0x00, 0x00, 0x00, 200,
                ],
                PA::AsPath(AsPath(HopPath::from(vec![
                    Asn::from_u32(100),
                    Asn::from_u32(200)]
                )))
            );

            check(
                vec![0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04],
                PA::NextHop(NextHop("1.2.3.4".parse().unwrap()))
            );

            check(
                vec![0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff],
                PA::MultiExitDisc(MultiExitDisc::new(255))
            );

            check(
                vec![0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x0a],
                PA::LocalPref(LocalPref::new(10))
            );

            check(
                vec![0x40, 0x06, 0x00],
                PA::AtomicAggregate(AtomicAggregate(()))
            );
            
            check(
                vec![
                    0xc0, 0x07, 0x08, 0x00, 0x00, 0x00, 0x65, 0xc6,
                    0x33, 0x64, 0x01
                ],
                PA::Aggregator(Aggregator(AggregatorInfo::new(
                        Asn::from_u32(101),
                        "198.51.100.1".parse().unwrap()
                )))
            );

            check(
                vec![
                    0xc0, 0x08, 0x10, 0x00, 0x2a, 0x02, 0x06, 0xff,
                    0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x02, 0xff,
                    0xff, 0xff, 0x03
                ],
                PA::Communities(Communities(StandardCommunitiesList::new(
                    vec!["AS42:518".parse().unwrap(),
                        Wellknown::NoExport.into(),
                        Wellknown::NoAdvertise.into(),
                        Wellknown::NoExportSubconfed.into(),
                    ]
                )))
            );

            check(
                vec![0x80, 0x09, 0x04, 0x0a, 0x00, 0x00, 0x04],
                OriginatorId("10.0.0.4".parse().unwrap()).into()
            );

            check(
                vec![0x80, 0x0a, 0x04, 0x0a, 0x00, 0x00, 0x03],
                ClusterList(ClusterIds::new(
                        vec![[10, 0, 0, 3].into()]
                )).into()
            );
            
            check(
                vec![
                    0x80, 0x0e, 0x1c,
                    0x00, 0x02, 0x01,
                    0x10,
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
                    0x00,
                    0x30, 0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb
                ],
                {
                let mut builder = MpReachNlriBuilder::new(
                    AFI::Ipv6,
                    SAFI::Unicast,
                    NextHop::Ipv6("2001:db8::1234".parse().unwrap()),
                    false // no addpath
                );
                builder.add_announcement(
                    &Nlri::unicast_from_str("2001:db8:aabb::/48").unwrap()
                ).unwrap();

                MpReachNlri(builder).into()
                }
            );

            check(
                vec![
                    0x80, 0x0f, 0x27, 0x00, 0x02, 0x01, 0x40, 0x20,
                    0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x40,
                    0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01,
                    0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
                    0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff,
                    0x00, 0x03
                ],
                {
                let mut builder = MpUnreachNlriBuilder::new(
                    AFI::Ipv6,
                    SAFI::Unicast,
                    false // no addpath
                );
                [
                    "2001:db8:ffff::/64",
                    "2001:db8:ffff:1::/64",
                    "2001:db8:ffff:2::/64",
                    "2001:db8:ffff:3::/64",
                ].into_iter().for_each(|s|{
                    builder.add_withdrawal(
                        &Nlri::unicast_from_str(s).unwrap()
                    ).unwrap();
                });

                MpUnreachNlri(builder).into()
                }
            );

            check(
                vec![
                    0xc0, 0x10, 0x08, 0x00, 0x02, 0xfc, 0x85, 0x00,
                    0x00, 0xcf, 0x08
                ],
                ExtendedCommunities(ExtendedCommunitiesList::new(vec![
                    "rt:64645:53000".parse().unwrap()
                ])).into()
            );

            check(
                vec![0xc0, 0x11, 10,
                0x02, 0x02, // SEQUENCE of length 2
                0x00, 0x00, 0x00, 100,
                0x00, 0x00, 0x00, 200,
                ],
                PA::As4Path(As4Path(HopPath::from(vec![
                    Asn::from_u32(100),
                    Asn::from_u32(200)]
                )))
            );

            check(
                vec![0xc0, 0x12, 0x04, 0x00, 0x00, 0x04, 0xd2],
                As4Aggregator(Asn::from_u32(1234)).into()
            );

            check(
                vec![0xc0, 0x14, 0x04, 1, 2, 3, 4],
                Connector("1.2.3.4".parse().unwrap()).into()
            );

            check(
                vec![0xc0, 0x15, 0x05, 0x14, 0x00, 0x00, 0x04, 0xd2],
                AsPathLimit(
                    AsPathLimitInfo::new(20, Asn::from_u32(1234))
                ).into()
            );

            //TODO 22 PmsiTunnel

            check(
                vec![
                    0xc0, 0x20, 0x3c, 0x00, 0x00, 0x20, 0x5b, 0x00,
                    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x00,
                    0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x64, 0x00,
                    0x00, 0x0b, 0x62, 0x00, 0x00, 0xe2, 0x0a, 0x00,
                    0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x64, 0x00,
                    0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x67, 0x00,
                    0x00, 0x00, 0x01, 0x00, 0x00, 0xe2, 0x0a, 0x00,
                    0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x1f
                ],
                LargeCommunities(LargeCommunitiesList::new(
                    vec![
                        "AS8283:6:15".parse().unwrap(),
                        "AS57866:100:2914".parse().unwrap(),
                        "AS57866:101:100".parse().unwrap(),
                        "AS57866:103:1".parse().unwrap(),
                        "AS57866:104:31".parse().unwrap(),
                    ]
                )).into()
            );

            check(
                vec![0xc0, 0x23, 0x04, 0x00, 0x00, 0x04, 0xd2],
                Otc(Asn::from_u32(1234)).into()
            );


            // UnimplementedPathAttribute
            check(
                vec![0xc0, 254, 0x04, 0x01, 0x02, 0x03, 0x04],
                UnimplementedPathAttribute::new(
                    Flags::OPT_TRANS.into(),
                    254,
                    vec![0x01, 0x02, 0x03, 0x04]
                ).into()
            );



        }

        #[test]
        fn iter_and_find() {
            let raw = vec![
                0x40, 0x01, 0x01, 0x00, // ORIGIN
                0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, // NEXTHOP
                0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff // MED 
            ];
            let pas = PathAttributes::new(
                Parser::from_ref(&raw), SessionConfig::modern()
            );
            //for _ in 0..4 {
            //    let pa = pas.next();
            //    println!("{pa:?}");
            //}

            assert!(pas.get(PathAttributeType::Origin).is_some());
            assert!(pas.get(PathAttributeType::AsPath).is_none());
            assert!(pas.get(PathAttributeType::MultiExitDisc).is_some());
            assert!(pas.get(PathAttributeType::NextHop).is_some());
        }

        #[test]
        fn unimplemented_path_attributes() {
            let raw = vec![
                0xc0, 254, 0x04, 0x01, 0x02, 0x03, 0x04
            ];
            let mut parser = Parser::from_ref(&raw);
            let sc = SessionConfig::modern();
            let pa = WireformatPathAttribute::parse(&mut parser, sc);

            if let Ok(WireformatPathAttribute::Unimplemented(u)) = pa {
                assert_eq!(u.typecode(), 254);
                assert!(u.flags().is_optional());
                assert!(u.flags().is_transitive());
                assert_eq!(u.value(), &[0x01, 0x02, 0x03, 0x04]);
            } else {
                panic!("fail");
            }

        }
    }
}


//------------ MpReachNlriBuilder --------------------------------------------
// See notes at MpUnreachNlriBuilder, these also apply here.
//
// Additionally, the MpReachNlri attribute contains the nexthop information.
// The nexthop semantics can not always be derived from the AFI/SAFI tuple,
// i.e. for IPv6 unicast the nexthop might contain two addresses (one global
// and one link-local). The global address will always be there, the
// link-local is optional. 
//
// Now whether or not the additional link-local is necessary might not be
// known at the time we build the UPDATE PDU. Therefore we reserve 16 bytes
// for a LL address, to prevent ending up with a PDU larger than the max pdu
// size allowed on the BGP session.


#[derive(Debug, Eq, PartialEq)]
pub struct MpReachNlriBuilder {
    announcements: Vec<Nlri<Vec<u8>>>,
    len: usize, // size of value, excluding path attribute flags+typecode+len
    extended: bool,
    afi: AFI,
    safi: SAFI,
    nexthop: NextHop,
    addpath_enabled: bool,
}

impl MpReachNlriBuilder {


    // Minimal required size for a meaningful MP_REACH_NLRI. This comprises
    // the attribute flags/size/type (3 bytes), a IPv6 nexthop (17), reserved
    // byte (1) and then space for at least an IPv6 /48 announcement (7)
    //pub const MIN_SIZE: usize = 3 + 17 + 1 + 7;

    pub(crate) fn new(
        afi: AFI,
        safi: SAFI,
        nexthop: NextHop,
        addpath_enabled: bool,
    ) -> Self {
        // For now, we only do v4/v6 unicast and multicast.
        if !matches!(
            (afi, safi),
            (AFI::Ipv4 | AFI::Ipv6, SAFI::Unicast | SAFI::Multicast)
            )
        {
            unimplemented!()
        }

        MpReachNlriBuilder {
            announcements: vec![],
            // 3 bytes for AFI+SAFI, nexthop len, reserved byte
            len: 3 + nexthop.compose_len() + 1,
            extended: false,
            afi,
            safi,
            nexthop,
            addpath_enabled
        }
    }

    pub(crate) fn value_len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }

    pub(crate) fn get_nexthop(&self) -> &NextHop {
        &self.nexthop
    }

    pub(crate) fn set_nexthop(&mut self, addr: Ipv6Addr) {
        match self.nexthop {
            NextHop::Ipv6(_) => self.nexthop = NextHop::Ipv6(addr),
            NextHop::Ipv6LL(_, ll) => {
                self.nexthop = NextHop::Ipv6LL(addr, ll)
            }
            _ => unimplemented!()
        }
    }

    pub(crate) fn set_nexthop_ll(&mut self, addr: Ipv6Addr) {
        match self.nexthop {
            NextHop::Ipv6(a) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
                self.len += 16;
            }
            NextHop::Ipv6LL(a, _ll) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
            }
            _ => unreachable!()
        }
    }

    pub(crate) fn valid_combination(
        &self, afi: AFI, safi: SAFI, is_addpath: bool
    ) -> bool {
        self.afi == afi
        && self.safi == safi
        && (self.announcements.is_empty()
             || self.addpath_enabled == is_addpath)
    }

    pub(crate) fn add_announcement(&mut self, announcement: &Nlri<Vec<u8>>)
        -> Result<(), ComposeError>
    {
        let announcement_len = announcement.compose_len();
        if !self.extended && self.len + announcement_len > 255 {
            self.extended = true;
        }
        self.len += announcement_len;
        self.announcements.push(announcement.clone());
        Ok(())
    }

    pub(crate) fn compose_len_empty(&self) -> usize {
        3 + 3 + self.nexthop.compose_len() + 1
    }


    pub(crate) fn compose_len(&self, announcement: &Nlri<Vec<u8>>) -> usize {
        let announcement_len = announcement.compose_len();
        if !self.extended && self.len + announcement_len > 255 {
            // Adding this announcement would make the path attribute exceed
            // 255 and thus require the Extended Length bit to be set.
            // This adds a second byte to the path attribute length field,
            // so we need to account for that.
            return announcement_len + 1;
        }
        announcement_len
    }

    pub(crate) fn compose_value<Target: OctetsBuilder>(
        &self,
        target: &mut Target
    ) -> Result<(), Target::AppendError>
    {
        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;
        self.nexthop.compose(target)?;

        // Reserved byte:
        target.append_slice(&[0x00])?;

        for w in &self.announcements {
            match w {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!()
            }
        }
        Ok(())
    }

    // XXX can we get rid of this once MpReachNlri is supported in the new_pas
    // PathAttribute enum?
    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = self.len.to_be_bytes();

        if self.extended {
            // FIXME this assumes usize is 64bits
            target.append_slice(&[0b1001_0000, 14, len[6], len[7]])
        } else {
            target.append_slice(&[0b1000_0000, 14, len[7]])
        }?;

        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;
        self.nexthop.compose(target)?;

        // Reserved byte:
        target.append_slice(&[0x00])?;

        for w in &self.announcements {
            match w {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!()
            }
        }
        Ok(())
    }
}

// **NB:** This is bgp::message::update::NextHop, _not_ new_pas::NextHop
impl NextHop {
    fn compose_len(&self) -> usize {
        // 1 byte for the length, plus:
        1 + match *self {
            NextHop::Ipv4(_) => 4, 
            NextHop::Ipv6(_) => 16,
            NextHop::Ipv6LL(_, _) => 32,
            _ => unimplemented!()
            //NextHop::Ipv4MplsVpnUnicast(RouteDistinguisher, Ipv4Addr),
            //NextHop::Ipv6MplsVpnUnicast(RouteDistinguisher, Ipv6Addr),
            //NextHop::Empty, // FlowSpec
            //NextHop::Unimplemented(AFI, SAFI),
        }
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[u8::try_from(self.compose_len()).unwrap() - 1])?;
        match *self {
            NextHop::Ipv4(a) => target.append_slice(&a.octets())?,
            NextHop::Ipv6(a) => target.append_slice(&a.octets())?,
            NextHop::Ipv6LL(a, ll) => {
                target.append_slice(&a.octets())?;
                target.append_slice(&ll.octets())?;
            }
            _ => unimplemented!()
        }

        Ok(())
    }

}


//------------ MpUnreachNlriBuilder ------------------------------------------

// Note that all to-be-withdrawn NLRI should either have no PathID, or have a
// PathID. We can not mix non-addpath and addpath NLRI.
// Note that:
//  - add path works on a afi/safi level for a session, so a peer could do
//    addpath for v4 unicast but not for v6 unicast.
//  - in the Capability in the BGP OPEN, a peer can signal to be able to
//    receive, send, or receive+send add path NLRI. So, if we create methods
//    that take a NegotiatedConfig, the modification methods like
//    add_withdrawal should check whether the remote side is able to receive
//    path ids if the Nlri passed to add_withdrawal contains Some(PathId).
//
#[derive(Debug, Eq, PartialEq)]
pub struct MpUnreachNlriBuilder {
    withdrawals: Vec<Nlri<Vec<u8>>>,
    len: usize, // size of value, excluding path attribute flags+typecode+len
    extended: bool,
    afi: AFI,
    safi: SAFI,
    addpath_enabled: bool,
}

impl MpUnreachNlriBuilder {
    pub(crate) fn new(afi: AFI, safi: SAFI, addpath_enabled: bool) -> Self {
        MpUnreachNlriBuilder {
            withdrawals: vec![],
            len: 3, // 3 bytes for AFI+SAFI
            extended: false,
            afi,
            safi,
            addpath_enabled
        }
    }

    pub(crate) fn value_len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.withdrawals.is_empty()
    }

    pub(crate) fn valid_combination(
        &self, afi: AFI, safi: SAFI, is_addpath: bool
    ) -> bool {
        self.afi == afi
        && self.safi == safi
        && (self.withdrawals.is_empty()
             || self.addpath_enabled == is_addpath)
    }

    pub(crate) fn add_withdrawal(&mut self, withdrawal: &Nlri<Vec<u8>>)
        -> Result<(), ComposeError>
    {
        let withdrawal_len = withdrawal.compose_len();
        if !self.extended && self.len + withdrawal_len > 255 {
            self.extended = true;
        }
        self.len += withdrawal_len;
        self.withdrawals.push(withdrawal.clone());
        Ok(())
    }

    pub(crate) fn compose_len(&self, withdrawal: &Nlri<Vec<u8>>) -> usize {
        let withdrawal_len = withdrawal.compose_len();
        if self.withdrawals.is_empty() {
            // First withdrawal to be added, so the total number of
            // required octets includes the path attribute flags and
            // length, and the AFI/SAFI.
            return withdrawal_len + 3 + 3;
        }

        if !self.extended && self.len + withdrawal_len > 255 {
            // Adding this withdrawal would make the path attribute exceed
            // 255 and thus require the Extended Length bit to be set.
            // This adds a second byte to the path attribute length field,
            // so we need to account for that.
            return withdrawal_len + 1;
        }
        withdrawal_len
    }

    pub(crate) fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;

        for w in &self.withdrawals {
            match w {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!()
            }
        }
        Ok(())
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = self.len.to_be_bytes();

        if self.extended {
            // FIXME this assumes usize is 64bits
            target.append_slice(&[0b1001_0000, 15, len[6], len[7]])
        } else {
            target.append_slice(&[0b1000_0000, 15, len[7]])
        }?;

        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;

        for w in &self.withdrawals {
            match w {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!()
            }
        }
        Ok(())
    }
}


#[derive(Debug)]
pub(crate) struct StandardCommunitiesBuilder {
    communities: Vec<StandardCommunity>,
    len: usize, // size of value, excluding path attribute flags+typecode+len
    extended: bool,
}

impl StandardCommunitiesBuilder {
    pub(crate) fn new() -> StandardCommunitiesBuilder {
        StandardCommunitiesBuilder {
            communities: Vec::new(),
            len: 0,
            extended: false
        }
    }

    pub(crate) fn compose_len_empty(&self) -> usize {
        3
    }

    pub(crate) fn compose_len(&self, _community: StandardCommunity) -> usize {
        if !self.extended && self.len + 4 > 255 {
            4 +1
        } else {
            4
        }
    }

    pub(crate) fn add_community(&mut self, community: StandardCommunity) {
        if !self.extended && self.len + 4 > 255 {
            self.extended = true;
        }
        self.len += 4;
        self.communities.push(community);
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = self.len.to_be_bytes();
        if self.extended {
            // FIXME this assumes usize is 64bits
            target.append_slice(&[0b1001_0000, 8, len[6], len[7]])
        } else {
            target.append_slice(&[0b1000_0000, 8, len[7]])
        }?;

        for c in &self.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }
}
