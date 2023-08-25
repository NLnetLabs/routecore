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
    use crate::asn::Asn;
    use crate::bgp::aspath::HopPath;
    use crate::bgp::message::SessionConfig;

    // eventually we work towards
    // enum PathAttribute {
    //     ...
    //     ...
    //     MpUnreachNlri(MpUnreachNlri),
    //     ...
    // }
    // and we macro_rules! all the enum variants and boilerplate for the
    // struct they carry in their data field.
    // 
    // We can get rid off PathAttributeType, and have one or multiple impl
    // blocks for the specific types.

    use octseq::{Octets, OctetsBuilder, Parser};
    use crate::util::parser::{ParseError, parse_ipv4addr};

    struct Flags { }

    impl Flags {
        // 0 1 2 3 4 5 6 7
        //
        // 0: optional (1 == optional)
        // 1: transitive (1 == transitive) (well-known attr are transitive)
        // 2: partial 
        // 3: extended length (0 -> 1 byte length, 1 -> 2 byte length)
        // 4-7: MUST be 0 when sent, ignored when received
        const OPT_NON_TRANS: u8 = 0b1000_0000;
        const OPT_TRANS: u8 = 0b1100_0000;
        const WELLKNOWN: u8 = 0b0100_0000;

        const EXTENDED_LEN: u8 = 0b0001_0000;
        const PARTIAL: u8 = 0b0010_0000;
    }

    pub trait AttributeHeader {
        const FLAGS: u8;
        const TYPECODE: u8;
        //const VALUE_LEN: u8;
        //const COMPOSE_LEN: u8 = 3 + Self::VALUE_LEN;
    }

    macro_rules! attribute {
        ($name:ident($data:ty),
         $flags:expr,
         $typecode:expr
         //$value_len:expr
         ) => {

            #[derive(Debug, PartialEq)]
            pub struct $name($data);
            impl $name {
                pub fn new(data: $data) -> $name {
                    $name(data)
                }
            }

            impl AttributeHeader for $name {
                const FLAGS: u8 = $flags;
                const TYPECODE: u8 = $typecode;
                //const VALUE_LEN: u8 = $value_len;
            }
        }
    }

    macro_rules! path_attributes {
        (
            $(
                $typecode:expr =>   $name:ident($data:ty),
                                    $flags:expr
                                    //$value_len:expr
            ),+ $(,)*
        ) => {

            #[derive(Debug, PartialEq)]
            pub enum PathAttribute {
                $( $name($name) ),+
            }

            impl PathAttribute {
                pub fn compose<Target: OctetsBuilder>(
                    &self,
                    target: &mut Target
                ) -> Result<(), Target::AppendError> {

                    match self {
                    $(
                        PathAttribute::$name(i) => i.compose(target)
                    ),+
                    }
                }
            }

            /* FIXME
            impl From<$name> for PathAttribute {
                fn from(pa: $name) -> PathAttribute {
                    PathAttribute::$name($name)
                }
            }
            */

            pub enum WireformatPathAttribute<'a, Octs> {
                $( $name(Parser<'a, Octs>, SessionConfig) ),+
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
                        _ => unimplemented!() // FIXME return Err, or have an
                                              // Unknown/Unimplemented variant
                                              // again?
                    };

                    Ok(res)
                }

                fn to_owned(&self) -> PathAttribute {
                    match self {
                        $(
                        WireformatPathAttribute::$name(p, sc) => {
                            PathAttribute::$name(
                                $name::parse(&mut p.clone(), *sc).unwrap()
                            )
                        }
                        ),+
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
        32  => LargeCommunities(LargeCommunitiesList), Flags::OPT_TRANS,
    );

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

    #[derive(Debug, PartialEq)]
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
    #[derive(Debug, PartialEq)]
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
    
    #[derive(Debug, PartialEq)]
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

    #[derive(Debug, PartialEq)]
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

    //--- LargeCommunities
    
    use crate::bgp::communities::LargeCommunity;
    #[derive(Debug, PartialEq)]
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

        fn compose_value<Target: OctetsBuilder>(&self, _target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            todo!()
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

#[cfg(test)]
    mod tests {
        use super::*;
        use crate::asn::Asn;
        use crate::bgp::communities::Wellknown;

        #[test]
        fn wireformat_to_owned_and_back() {
            use super::PathAttribute as PA;
            fn check(raw: Vec<u8>, owned: PathAttribute) {
                let mut parser = Parser::from_ref(&raw);
                let sc = SessionConfig::modern();
                let pa = WireformatPathAttribute::parse(&mut parser, sc).unwrap();
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
                PA::OriginatorId(OriginatorId("10.0.0.4".parse().unwrap()))
            );
            check(
                vec![0x80, 0x0a, 0x04, 0x0a, 0x00, 0x00, 0x03],
                PA::ClusterList(ClusterList(ClusterIds::new(vec![[10, 0, 0, 3].into()])))
            );
            //TODO
            //check(
            //    vec![],
            //    PA::LargeCommunities(LargeCommunitiesList::new(
            //            vec![]
            //);


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


#[derive(Debug)]
pub(crate) struct MpReachNlriBuilder {
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
#[derive(Debug)]
pub(crate) struct MpUnreachNlriBuilder {
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
