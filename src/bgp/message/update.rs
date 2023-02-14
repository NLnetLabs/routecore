use crate::bgp::message::Header;
use octseq::{Octets, Parser};
use log::{debug, warn, error};

use crate::asn::{Asn, AsPath, AsPathBuilder, SegmentType};
pub use crate::bgp::types::{
    AFI, SAFI, LocalPref, MultiExitDisc, NextHop, OriginType, PathAttributeType
};

use crate::bgp::message::nlri::{
    Nlri, BasicNlri, MplsNlri, MplsVpnNlri, VplsNlri, FlowSpecNlri,
    RouteTargetNlri
};

use std::net::Ipv4Addr;
use crate::util::parser::{parse_ipv4addr, ParseError};


use crate::bgp::communities::{
    Community, StandardCommunity,
    ExtendedCommunity, Ipv6ExtendedCommunity, 
    LargeCommunity
};

const COFF: usize = 19; // XXX replace this with .skip()'s?

/// BGP UPDATE message, variant of the [`Message`] enum.
#[derive(Debug, Clone)]
pub struct UpdateMessage<Octs: Octets> {
    octets: Octs,
    session_config: SessionConfig,
}


impl<Octs: Octets> UpdateMessage<Octs> {

    pub fn octets(&self) -> &Octs {
        &self.octets
    }

    /// Returns the [`Header`] for this message.
    pub fn header(&self) -> Header<&Octs> {
        Header::for_slice(&self.octets)
    }

    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> u16 {
        self.header().length()
	}
}

impl<Octs: Octets> AsRef<[u8]> for UpdateMessage<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

/// BGP UPDATE message.
///
/// Offers methods to access and/or iterate over all the fields, and some
/// additional convenience methods.
///
/// ## Convenience methods
///
/// As the BGP standard has seen updates to support for example 32 bits ASNs
/// and other-than-IPv4 protocol information, some types of information can be
/// found in different places in the UPDATE message. The NLRIs for announced
/// prefixes can be at the end of the message, or in a `MP_REACH_NLRI` path
/// attribute. Similarly, the `NEXT_HOP` path attribute was once mandatory for
/// UPDATEs, but is now also part of the `MP_REACH_NLRI`, if present.
///
/// To accomodate for these hassles, the following methods are provided:
///
/// * [`nlris()`][`UpdateMessage::nlris`] and
/// [`withdrawals()`][`UpdateMessage::withdrawals`],
/// providing iterators over announced and withdrawn prefixes ;
/// * [`next_hop()`][`UpdateMessage::next_hop`], returning the [`NextHop`] ;
/// * [`all_communities()`][`UpdateMessage::all_communities`], returning an
/// optional `Vec` containing all conventional, Extended and Large
/// Communities, wrapped in the [`Community`] enum.
///
/// For the mandatory path attributes, we have:
///
/// * [`origin()`][`UpdateMessage::origin`]
/// * [`aspath()`][`UpdateMessage::aspath`]
///
/// Other path attributes ([`PathAttribute`] of a certain
/// [`PathAttributeType`]) can be access via the iterator provided via
/// [`path_attributes()`][`UpdateMessage::path_attributes`].
///
// ---BGP Update--------------------------------------------------------------
//
//  +-----------------------------------------------------+
//  |   Withdrawn Routes Length (2 octets)                |
//  +-----------------------------------------------------+
//  |   Withdrawn Routes (variable)                       |
//  +-----------------------------------------------------+
//  |   Total Path Attribute Length (2 octets)            |
//  +-----------------------------------------------------+
//  |   Path Attributes (variable)                        |
//  +-----------------------------------------------------+
//  |   Network Layer Reachability Information (variable) |
//  +-----------------------------------------------------+

impl<Octs: Octets> UpdateMessage<Octs> {
    pub fn for_slice(s: Octs, config: SessionConfig) -> Self {
        Self {
            octets: s,
            session_config: config
        }
    }
}

impl<Octs: Octets> UpdateMessage<Octs> {
    /// Print the Message in a `text2pcap` compatible way.
    pub fn print_pcap(&self) {
        print!("000000 ");
        for b in self.octets.as_ref() {
            print!("{:02x} ", b);
        }
        println!();
    }

	pub fn withdrawn_routes_len(&self) -> u16 {
        u16::from_be_bytes([
            self.octets.as_ref()[COFF],
            self.octets.as_ref()[COFF+1]
        ])
	}
}

impl<Octs: Octets> UpdateMessage<Octs> {
    pub fn withdrawals(&self) -> Withdrawals<'_, Octs> {
        if let Some(ref mut pa) = self.path_attributes().into_iter().find(|pa|
            pa.type_code() == PathAttributeType::MpUnreachNlri
        ) {
            Withdrawals::parse(
                &mut pa.value_into_parser(),
                self.session_config
            ).expect("parsed before")
        } else {
            let len = self.withdrawn_routes_len() as usize;
            let mut parser = Parser::from_ref(self.octets());
            parser.advance(COFF+2).expect("parsed before");
            let pp = Parser::parse_parser(&mut parser, len)
                .expect("parsed before");

            Withdrawals {
                parser: pp,
                session_config: self.session_config,
                afi: AFI::Ipv4,
                safi: SAFI::Unicast
            }
        }
    }

    // RFC4271: A value of 0 indicates that neither the Network Layer
    // Reachability Information field nor the Path Attribute field is present
    // in this UPDATE message.
	fn total_path_attribute_len(&self) -> u16 {
        let wrl = self.withdrawn_routes_len() as usize;
        u16::from_be_bytes([
            self.octets.as_ref()[COFF+2+wrl],
            self.octets.as_ref()[COFF+2+wrl+1]
        ])
	}

    pub fn path_attributes(&self) -> PathAttributes<'_, Octs> {
        let wrl = self.withdrawn_routes_len() as usize;
        let tpal = self.total_path_attribute_len() as usize;
        
        let mut parser = Parser::from_ref(&self.octets);
        parser.advance(COFF+2+wrl+2).unwrap();
        let pp = Parser::parse_parser(&mut parser, tpal).expect("parsed before");

        PathAttributes {
            parser: pp,
            session_config: self.session_config
        }
    }

    /// Iterator over the reachable NLRIs.
    ///
    /// If present, the NLRIs are taken from the MP_REACH_NLRI path attribute.
    /// Otherwise, they are taken from their conventional place at the end of
    /// the message.
    pub fn nlris(&self) -> Nlris<Octs> {
        if let Some(ref mut pa) = self.path_attributes().into_iter().find(|pa|
            pa.type_code() == PathAttributeType::MpReachNlri
        ) {
            let mut p = pa.value_into_parser();
            Nlris::parse(&mut p, self.session_config).expect("parsed before")
        } else {
            let wrl = self.withdrawn_routes_len() as usize;
            let tpal = self.total_path_attribute_len() as usize;
            let mut parser = Parser::from_ref(self.octets());
            parser.advance(COFF+2+wrl+2+tpal).expect("parsed before");
            Nlris::parse_conventional(&mut parser, self.session_config).expect("parsed before")
        }
    }

    /// Returns `Option<(AFI, SAFI)>` if this UPDATE represents the End-of-RIB
    /// marker for a AFI/SAFI combination.
    pub fn is_eor(&self) -> Option<(AFI, SAFI)> {
        // Conventional BGP
        if self.length() == 23 {
            // minimum length for a BGP UPDATE indicates EOR
            // (no annoucements, no withdrawals)
            return Some((AFI::Ipv4, SAFI::Unicast));
        }

        // Based on MP_UNREACH_NLRI
        if self.total_path_attribute_len() > 0
            && self.path_attributes().iter().all(|pa|
                pa.type_code() == PathAttributeType::MpUnreachNlri
                && pa.length() == 3 // only AFI/SAFI, no NLRI
            ) {
                let pa = self.path_attributes().into_iter().next().unwrap();
                return Some((
                    u16::from_be_bytes(
                            [pa.value().as_ref()[0], pa.value().as_ref()[1]]
                    ).into(),
                    pa.value().as_ref()[2].into()
                ));
        }

        None
    }

    //--- Methods to access mandatory path attributes ------------------------
    // Mandatory path attributes are ORIGIN, AS_PATH and NEXT_HOP
    // Though, in case of MP_REACH_NLRI, NEXT_HOP must be ignored if present.
    //
    // Also note that these are only present in announced routes. A BGP UPDATE
    // with only withdrawals will not have any of these mandatory path
    // attributes present.
    pub fn origin(&self) -> Option<OriginType> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::Origin
        ).map(|pa|
            match pa.value().as_ref()[0] {
                0 => OriginType::Igp,
                1 => OriginType::Egp,
                2 => OriginType::Incomplete,
                n => OriginType::Unknown(n),
            }
        )
    }

    pub fn as4path(&self) -> Option<AsPath<Vec<Asn>>> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::As4Path
        ).map(|pa| {
            let asn_size = 4;
            let octets = pa.value();
            let mut aspb = AsPathBuilder::new();

            let mut pos = 0;
            while pos < octets.as_ref().len() {
                let st = SegmentType::try_from(octets.as_ref()[pos])
                    .expect("parsed before");
                let num_asns = octets.as_ref()[pos+1] as usize;
                aspb.start(st);
                pos += 2;

                for _ in 0..num_asns {
                    let asn = Asn::from(
                        u32::from_be_bytes(
                            octets.as_ref()[pos..pos+asn_size]
                            .try_into().expect("parsed before")
                        )
                    );
                    aspb.push(asn).expect("parsed before");
                    pos += asn_size;
                }
            }
            aspb.finalize()
        })
    }

    /// Returns the AS_PATH path attribute.
    pub fn aspath(&self) -> Option<AsPath<Vec<Asn>>> {
        if let Some(as4path) = self.as4path() {
            // In all cases we know of, the AS4_PATH attribute contains
            // the entire AS_PATH with all the 4-octet ASNs. Instead of
            // replacing the AS_TRANS ASNs in AS_PATH, we can simply
            // return the AS4_PATH. 
            // This also saves us from perhaps misguessing the 2-vs-4
            // octet size of the AS_PATH, as the AS4_PATH is always 4-octet
            // anyway.
            return Some(as4path);
        }
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::AsPath
        ).map(|ref pa| {
            // Check for AS4_PATH
            // Note that all the as4path code in this part is useless because
            // of the early return above, but for now let's leave it here for
            // understanding/reasoning.
            let as4path = self.as4path();

            // Apparently, some BMP exporters do not set the legacy format
            // bit but do emit 2-byte ASNs. 
            let asn_size = match self.session_config.four_octet_asn { 
                FourOctetAsn::Enabled => 4,
                FourOctetAsn::Disabled => 2,
            };

            let octets = pa.value();
            let mut aspb = AsPathBuilder::new();

            let mut pos = 0;
            let mut segment_idx = 0;
            while pos < octets.as_ref().len() {
                let st = SegmentType::try_from(octets.as_ref()[pos]).expect("parsed
                    before");
                let num_asns = octets.as_ref()[pos+1] as usize;
                aspb.start(st);
                pos += 2;

                for _ in 0..num_asns {
                    let asn = if asn_size == 4 {
                    Asn::from(
                        u32::from_be_bytes(
                            octets.as_ref()[pos..pos+asn_size]
                            .try_into().expect("parsed before")
                            )
                        )
                    } else {
                    Asn::from(
                        u16::from_be_bytes(
                            octets.as_ref()[pos..pos+asn_size]
                            .try_into().expect("parsed before")
                            ) as u32
                        )
                    };
                    // In a very exotic (and incorrect?) case, we see AS_TRANS
                    // in the AS_PATH, but no AS4_PATH path attribute. For
                    // this reason, we check whether `as4path` actually holds
                    // a value.
                    if as4path.as_ref().is_some()
                        && asn == Asn::from_u32(23456) {
                        // This assert would trip the described exotic case.
                        //assert!(as4path.is_some());
                         
                        // replace this AS_TRANS with the 4-octet value from
                        // AS4_PATH:
                        let seg = as4path.as_ref().expect("parsed before")
                            .iter().nth(segment_idx).expect("parsed before");
                        let new_asn: Asn = seg.elements()[aspb.segment_len()];
                        aspb.push(new_asn).expect("parsed before");
                    } else {
                        aspb.push(asn).expect("parsed before");
                    }
                    pos += asn_size;
                }
                segment_idx += 1;
            }
            aspb.finalize()
        })
    }

    /// Returns the NEXT_HOP path attribute, or the equivalent from
    /// MP_REACH_NLRI.
    pub fn next_hop(&self) -> Option<NextHop> {
        if let Some(pa) = self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::MpReachNlri
        ) {
            // TODO value_into_parser ?
            let v = pa.value();
            let mut parser = Parser::from_ref(&v);
            let afi: AFI = parser.parse_u16().expect("parsed before").into();
            let safi: SAFI = parser.parse_u8().expect("parsed before").into();

            return Some(NextHop::parse(&mut parser, afi, safi).expect("parsed before"));
        } 

        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::NextHop
        ).map(|pa|
            NextHop::Ipv4(
                Ipv4Addr::new(
                    pa.value().as_ref()[0],
                    pa.value().as_ref()[1],
                    pa.value().as_ref()[2],
                    pa.value().as_ref()[3],
                )
            )
        )
    }

    //--- Non-mandatory path attribute helpers -------------------------------

    /// Returns the Multi-Exit Discriminator value, if any.
    pub fn multi_exit_desc(&self) -> Option<MultiExitDisc> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::MultiExitDisc
        ).map(|pa| {
            MultiExitDisc(u32::from_be_bytes(
                pa.value().as_ref()[0..4].try_into().expect("parsed before")
            ))
        })
    }

    /// Returns the Local Preference value, if any.
    pub fn local_pref(&self) -> Option<LocalPref> {
        self.path_attributes().iter().find(|pa|
            pa.type_code() == PathAttributeType::LocalPref
        ).map(|pa|
            LocalPref(u32::from_be_bytes(
                pa.value().as_ref()[0..4].try_into().expect("parsed before")
            ))
        )
    }

    /// Returns true if this UPDATE contains the ATOMIC_AGGREGATE path
    /// attribute.
    pub fn is_atomic_aggregate(&self) -> bool {
        self.path_attributes().iter().any(|pa|
            pa.type_code() == PathAttributeType::AtomicAggregate
        )
    }

    /// Returns the AGGREGATOR path attribute, if any.
    // this one originally carried a 2-octet ASN, but now also possibly a
    // 4-octet one (RFC 6793, Four Octet ASN support)
    // furthermore, it was designed to carry a IPv4 address, but that does not
    // seem to have changed with RFC4760 (multiprotocol)
    //
    // As such, we can determine whether there is a 2-octet or 4-octet ASN
    // based on the size of the attribute itself.
    // 
    pub fn aggregator(&self) -> Option<Aggregator> {
        self.path_attributes().iter().find(|pa| {
            pa.type_code() == PathAttributeType::Aggregator
        }).map(|mut pa| {
            Aggregator::parse(
                &mut pa.value_into_parser(),
                self.session_config
            ).expect("parsed before")
        })
    }


    //--- Communities --------------------------------------------------------

    /// Returns an iterator over Standard Communities (RFC1997), if any.
    pub fn communities(&self) -> Option<CommunityIter<Octs::Range<'_>>> {
        self.path_attributes().into_iter().find(|pa|
            pa.type_code() == PathAttributeType::Communities
        ).map(|pa| CommunityIter::new(pa.into_value()))
    }

    /// Returns an iterator over Extended Communities (RFC4360), if any.
    pub fn ext_communities(&self) -> Option<ExtCommunityIter<Octs::Range<'_>>>
    {
        self.path_attributes().into_iter().find(|pa|
            pa.type_code() == PathAttributeType::ExtendedCommunities
        ).map(|pa| ExtCommunityIter::new(pa.into_value()))
    }

    /// Returns an iterator over Large Communities (RFC8092), if any.
    pub fn large_communities(&self)
        -> Option<LargeCommunityIter<Octs::Range<'_>>>
    {
        self.path_attributes().into_iter().find(|pa|
            pa.type_code() == PathAttributeType::LargeCommunities
        ).map(|pa| LargeCommunityIter::new(pa.into_value()))
    }

    /// Returns an optional `Vec` containing all conventional, Extended and
    /// Large communities, if any, or None if none of the three appear in the
    /// path attributes of this message.
    pub fn all_communities(&self) -> Option<Vec<Community>> {
        let mut res = Vec::<Community>::new();

        // We can use unwrap safely because the is_some check.

        if self.communities().is_some() {
            res.append(&mut self.communities().unwrap().collect::<Vec<_>>());
        }
        if self.ext_communities().is_some() {
            res.append(&mut self.ext_communities().unwrap()
                .map(Community::Extended)
                .collect::<Vec<_>>());
        }
        if self.large_communities().is_some() {
            res.append(&mut self.large_communities().unwrap()
                .map(Community::Large)
                .collect::<Vec<_>>());
        }

        if res.is_empty() {
            None
        } else {
            Some(res)
        }
    }
    
}


impl<Octs: Octets> UpdateMessage<Octs> {
    /// Create an UpdateMessage from an octets sequence.
    ///
    /// As parsing of BGP UPDATE messages requires stateful information
    /// signalled by the BGP OPEN messages, this function requires a
    /// [`SessionConfig`].
    pub fn from_octets(octets: Octs, config: SessionConfig)
        -> Result<Self, ParseError>
   {
        Self::check(&octets, config)?;
        Ok(UpdateMessage {
            octets,
            session_config: config
        })
    }

    fn check(octets: &Octs, config: SessionConfig) -> Result<(), ParseError> {
        let mut parser = Parser::from_ref(octets);
        Header::<Octs>::check(&mut parser)?;

        let withdrawals_len = parser.parse_u16()?;
        if withdrawals_len > 0 {
            let mut wdraw_parser = parser.parse_parser(
                withdrawals_len.into()
            )?;
            while wdraw_parser.remaining() > 0 {
                // conventional withdrawals are always IPv4
                BasicNlri::check(&mut wdraw_parser, config, AFI::Ipv4)?;
            }
        }

        let path_attributes_len = parser.parse_u16()?;
        if path_attributes_len > 0 {
            let mut pas_parser = parser.parse_parser(
                path_attributes_len.into()
            )?;
            PathAttributes::<Octs>::check(&mut pas_parser, config)?;
        }

        while parser.remaining() > 0 {
            // conventional announcements are always IPv4
            BasicNlri::check(&mut parser, config, AFI::Ipv4)?;
        }

        Ok(())
    }

    // still used in bmp/message.rs
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>, config: SessionConfig)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>,
    {
        // parse header
        let pos = parser.pos();
        let hdr = Header::parse(parser)?;

        let withdrawn_len = parser.parse_u16()?;
        if withdrawn_len > 0 {
            let mut wdraw_parser = parser.parse_parser(withdrawn_len.into())?;
            while wdraw_parser.remaining() > 0 {
                // conventional withdrawals are always IPv4
                BasicNlri::parse(&mut wdraw_parser, config, AFI::Ipv4)?;
            }
        }
        let total_path_attributes_len = parser.parse_u16()?;
        if total_path_attributes_len > 0 {
            let mut pas_parser = parser.parse_parser(total_path_attributes_len.into())?;
            PathAttributes::parse(&mut pas_parser, config)?;
        }

        // conventional NLRI, if any
        while parser.remaining() > 0 {
            // conventional announcements are always IPv4
            BasicNlri::parse(parser, config, AFI::Ipv4)?;
        }

        let end = parser.pos();
        if end - pos != hdr.length() as usize {
            return Err(ParseError::form_error(
                "message length and parsed bytes do not match"
            ));
        }
        parser.seek(pos)?;

        Ok(Self::for_slice(
                parser.parse_octets(hdr.length().into())?,
                config
        ))
    }
}
//--- Enums for passing config / state ---------------------------------------

/// Configuration parameters for an established BGP session.
///
/// The `SessionConfig` is a structure holding parameters to parse messages
/// for the particular session. Storing these parameters is necessary because
/// some information crucial to correctly parsing BGP UPDATE messages is not
/// available in the UPDATE messages themselves, but are only exchanged in the
/// BGP OPEN messages when the session was established.
///
#[derive(Copy, Clone, Debug)]
pub struct SessionConfig {
    pub four_octet_asn: FourOctetAsn,
    pub add_path: AddPath,
}

impl SessionConfig {
    pub fn new(four_octet_asn: FourOctetAsn, add_path: AddPath) -> Self {
        Self { four_octet_asn, add_path }
    }

    pub fn modern() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Enabled,
            add_path: AddPath::Disabled,
        }
    }
    pub fn legacy() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Disabled,
            add_path: AddPath::Disabled,
        }
    }

    pub fn modern_addpath() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Enabled,
            add_path: AddPath::Enabled,
        }
    }

    pub fn legacy_addpath() -> Self {
        Self {
            four_octet_asn: FourOctetAsn::Disabled,
            add_path: AddPath::Enabled,
        }
    }

    pub fn enable_four_octet_asn(&mut self) {
        self.four_octet_asn = FourOctetAsn::Enabled
    }

    pub fn disable_four_octet_asn(&mut self) {
        self.four_octet_asn = FourOctetAsn::Disabled
    }

    pub fn set_four_octet_asn(&mut self, v: FourOctetAsn) {
        self.four_octet_asn = v;
    }

    pub fn enable_addpath(&mut self) {
        self.add_path = AddPath::Enabled
    }

    pub fn disable_addpath(&mut self) {
        self.add_path = AddPath::Disabled
    }

    pub fn set_addpath(&mut self, v: AddPath) {
        self.add_path = v;
    }
}

/// Indicates whether this session is Four Octet capable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FourOctetAsn {
    Enabled,
    Disabled,
}

/// Indicates whether AddPath is enabled for this session.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AddPath {
    Enabled,
    Disabled,
}

// XXX do we want an intermediary struct PathAttributes with an fn iter() to
// return a PathAttributesIter ?
pub struct PathAttributes<'a, Octs: Octets> {
    parser: Parser<'a, Octs>,
    session_config: SessionConfig,
}

impl<'a, Octs: Octets> PathAttributes<'a, Octs> {
    pub fn iter(&'a self) -> PathAttributesIter<'a, Octs> {
        PathAttributesIter {
            parser: self.parser,
            session_config: self.session_config
        }
    }
}

/// Iterator over all [`PathAttribute`]s in a BGP UPDATE message.
pub struct PathAttributesIter<'a, Ref> {
    parser: Parser<'a, Ref>,
    session_config: SessionConfig,
}

impl<'a, R: 'a + Octets> PathAttributesIter<'a, R>{
    // XXX remove?
    fn _new(path_attributes: &'a R, config: SessionConfig) -> Self {
        PathAttributesIter { 
            parser: Parser::from_ref(path_attributes),
            session_config: config,
        }
    }
}

impl<'a, Octs: Octets> PathAttributes<'a, Octs> {
    fn check(parser: &mut Parser<'a, Octs>, config: SessionConfig)
        -> Result<(), ParseError>
    {
        while parser.remaining() > 0 {
            PathAttribute::<Octs>::check(parser, config)?;
        }

        Ok(())
    }

    fn parse(parser: &mut Parser<'a, Octs>, config: SessionConfig)
        -> Result<Self, ParseError>
    {
        let pos = parser.pos();
        while parser.remaining() > 0 {
            let _pa = PathAttribute::parse(parser, config)?;
        }
        let end = parser.pos();
        parser.seek(pos)?;

        Ok(PathAttributes {
            parser: Parser::parse_parser(parser, end - pos).unwrap(),
            session_config: config
        })
    }
}

/// BGP Path Attribute, carried in BGP UPDATE messages.
#[derive(Debug)]
pub struct PathAttribute<'a, Octs: Octets> {
    parser: Parser<'a, Octs>
}

impl<'a, Octs: Octets> PathAttribute<'a, Octs> {
    /// Returns the flags as a raw byte.
    pub fn flags(&self) -> u8 {
        self.parser.peek(1).expect("parsed before")[0]
    }

    /// Returns true if the optional flag is set.
    pub fn is_optional(&self) -> bool {
        self.flags() & 0x80 == 0x80
    }

    /// Returns true if the transitive bit is set.
    pub fn is_transitive(&self) -> bool {
        self.flags() & 0x40 == 0x40
    }

    /// Returns true if the partial flag is set.
    pub fn is_partial(&self) -> bool {
        self.flags() & 0x20 == 0x20
    }

    /// Returns true if the extended length flag is set.
    pub fn is_extended_length(&self) -> bool {
        self.flags() & 0x10 == 0x10
    }

    /// Returns the type of this path attribute.
    pub fn type_code(&self) -> PathAttributeType {
        self.parser.peek(2).expect("parsed before")[1].into()
    }

    /// Returns the length of the value of this path attribute.
    pub fn length(&self) -> u16 {
        let lenbytes = self.parser.peek(4).expect("parsed before");
        match self.is_extended_length() {
            true => u16::from_be_bytes([lenbytes[2], lenbytes[3]]),
            false => lenbytes[2] as u16,
        }
    }

    fn hdr_len(&self) -> usize {
        match self.is_extended_length() {
            true => 2+2,  // 2 byte flags+codes, 2 byte value length
            false => 2+1, // 2 byte flags+codes, 1 byte value length
        }
    }
}

impl<'a, Octs: Octets> PathAttribute<'a, Octs> {
    /// Returns the raw value of this path attribute.
    pub fn value(&self) -> Octs::Range<'_> {
        let start = self.parser.pos() + self.hdr_len();
        let end = start + self.length() as usize;
        self.parser.octets_ref().range(start..end)
    }

    pub fn into_value(mut self) -> Octs::Range<'a> {
        self.parser.advance(self.hdr_len()).expect("parsed before");
        self.parser.parse_octets(self.parser.remaining()).expect("parsed before")
    }

    fn value_into_parser(&mut self) -> Parser<'a, Octs> {
        let start = self.hdr_len();
        //let mut p = Parser::from_ref(&self.octets);
        //p.advance(start).expect("parsed before");
        self.parser.advance(start).expect("parsed before");

        //Parser::parse_parser(&mut p, self.length() as usize).expect("parsed before")
        self.parser
    }

}

impl<'a, Octs: Octets> PathAttribute<'a, Octs> {
    fn check(parser: &mut Parser<'a, Octs>, config: SessionConfig)
        ->  Result<(), ParseError>
    {
        let flags = parser.parse_u8()?;
        let typecode = parser.parse_u8()?;
        let len = match flags & 0x10 == 0x10 {
            true => {
                parser.parse_u16()? as usize
            },
            false => parser.parse_u8()? as usize, 
        };

        // now, check the specific type of path attribute
        match typecode.into() {
            PathAttributeType::Origin => {
                if len != 1 {
                    return Err(
                        ParseError::form_error("expected len 1 for Origin pa")
                    );
                }
                parser.advance(1)?;
            },
            PathAttributeType::AsPath => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    // segment type
                    pp.advance(1)?;
                    // segment length describes the number of ASNs
                    let slen = pp.parse_u8()?;
                    for _ in 0..slen {
                        match config.four_octet_asn {
                            FourOctetAsn::Enabled => { pp.advance(4)?; }
                            FourOctetAsn::Disabled => { pp.advance(2)?; }
                        }
                    }
                }
            },
            PathAttributeType::NextHop => {
                // conventional NEXT_HOP, just an IPv4 address
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for NEXT_HOP pa")
                    );
                }
                parser.advance(4)?;
            }
            PathAttributeType::MultiExitDisc => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for MULTI_EXIT_DISC pa")
                    );
                }
                parser.advance(4)?;
            }
            PathAttributeType::LocalPref => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for LOCAL_PREF pa")
                    );
                }
                parser.advance(4)?;
            },
            PathAttributeType::AtomicAggregate => {
                if len != 0 {
                    return Err(
                        ParseError::form_error("expected len 0 for ATOMIC_AGGREGATE pa")
                    );
                }
            },
            PathAttributeType::Aggregator => {
                let mut pp = parser.parse_parser(len)?;
                Aggregator::check(&mut pp, config)?;
            },
            PathAttributeType::Communities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    StandardCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::OriginatorId => {
                parser.advance(4)?;
            },
            PathAttributeType::ClusterList => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    pp.advance(4)?;
                }
            },
            PathAttributeType::MpReachNlri => {
                let mut pp = parser.parse_parser(len)?;
                Nlris::<Octs>::check(&mut pp, config)?;
            },
            PathAttributeType::MpUnreachNlri => {
                let mut pp = parser.parse_parser(len)?;
                Withdrawals::<Octs>::check(&mut pp, config)?;
            },
            PathAttributeType::ExtendedCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    ExtendedCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::As4Path => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    let _stype = pp.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = pp.parse_u8()?;
                    for _ in 0..slen {
                         pp.advance(4)?;
                    }
                }
            }
            PathAttributeType::As4Aggregator => {
                // Asn + Ipv4Addr
                parser.advance(4 + 4)?;
            }
            PathAttributeType::Connector => {
                // Should be an Ipv4Addr according to
                // https://www.rfc-editor.org/rfc/rfc6037.html#section-5.2.1
                if len != 4 {
                    warn!(
                        "Connector PA, expected len == 4 but found {}",
                        len
                    );
                }
                parser.advance(len)?;
            },
            PathAttributeType::AsPathLimit => {
                // u8 limit + Ipv4Addr
                parser.advance(5)?;
            },
            PathAttributeType::PmsiTunnel => {
                let _flags = parser.parse_u8()?;
                let _tunnel_type = parser.parse_u8()?;
                let _mpls_label_1 = parser.parse_u8()?;
                let _mpls_label_2 = parser.parse_u16()?;
                let tunnel_id_len = len - 5;
                parser.advance(tunnel_id_len)?;
            },
            PathAttributeType::Ipv6ExtendedCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    Ipv6ExtendedCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::LargeCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    LargeCommunity::check(&mut pp)?;
                }
            },
            PathAttributeType::BgpsecAsPath => {
                let mut pp = parser.parse_parser(len)?;
                // SecurePath block
                //
                // Signature Block 1
                // Signature Block 2?
                //
                //Secure_Path
                //    [2 bytes length (octets of total Secure_Path) , 1..N Segments]
                //$(
                //Segment
                //    [1byte pCount (prependCount?), 1 byte flags, 4byte ASN]
                //)+

                let len_path = pp.parse_u16()?;
                if (len_path - 2) % 6 != 0 {
                    warn!("BGPsec_Path Path Segments not a multiple of 6 bytes")
                }
                pp.advance(len_path as usize - 2)?;

                //Signature_Block
                //    [2 bytes length , 1 byte algo suite, 1..N segments]
                //$(
                //Segment
                //    [20 bytes SKI, 2 bytes sig length, sig]
                //)+

                let len_sigs = pp.parse_u16()?;
                let algo_id = pp.parse_u8()?;
                if algo_id != 0x01 {
                    warn!("BGPsec_Path Signature Block containing unknown\
                            Algorithm Suite ID {algo_id}");
                }

                let mut sb1_parser = pp.parse_parser(len_sigs as usize - 3)?;
                while sb1_parser.remaining() > 0 {
                    // SKI
                    sb1_parser.advance(20)?;
                    let sig_len = sb1_parser.parse_u16()?;
                    sb1_parser.advance(sig_len as usize)?;
                }

                // check for another Signature Block:
                if pp.remaining() > 0 {
                    debug!("{} bytes in BgpsecAsPath,\
                           assuming a second Signature Block",
                           pp.remaining()
                    );

                    let mut sb2_parser = pp.parse_parser(len_sigs as usize - 3)?;
                    while sb2_parser.remaining() > 0 {
                        // SKI
                        sb2_parser.advance(20)?;
                        let sig_len = sb2_parser.parse_u16()?;
                        sb2_parser.advance(sig_len as usize)?;
                    }
                }
                if pp.remaining() > 0 {
                    warn!("{} bytes left in BgpsecAsPath\
                          after two Signature Blocks",
                           pp.remaining()
                    );
                }

            },
            PathAttributeType::AttrSet => {
                parser.advance(4)?;
                let mut pp = parser.parse_parser(len - 4)?;
                PathAttributes::<Octs>::check(&mut pp, config)?;
            },
            PathAttributeType::Reserved => {
                warn!("Path Attribute type 0 'Reserved' observed");
            },
            PathAttributeType::RsrvdDevelopment => {
                // This could be anything.
                // As long as we do the resetting seek() + parse_octets()
                // after the match, we do not need to do anything here.
                parser.advance(len)?;
            },
            PathAttributeType::Unimplemented(_) => {
                warn!("Unimplemented PA: {}", typecode);
                parser.advance(len)?;
            },
            //_ => {
            //    panic!("unimplemented: {}", <PathAttributeType as From::<u8>>::from(typecode));
            //},
        }
        
        Ok(())
    }

    fn parse(parser: &mut Parser<'a, Octs>, config: SessionConfig)
        ->  Result<PathAttribute<'a, Octs>, ParseError>
    {
        let pos = parser.pos();
        let flags = parser.parse_u8()?;
        let typecode = parser.parse_u8()?;
        let mut headerlen = 3;
        let len = match flags & 0x10 == 0x10 {
            true => {
                headerlen += 1;
                parser.parse_u16()? as usize
            },
            false => parser.parse_u8()? as usize, 
        };


        //parser.seek(pos)?;
        // now, parse the specific type of path attribute
        match typecode.into() {
            PathAttributeType::Origin => {
                if len != 1 {
                    return Err(
                        ParseError::form_error("expected len 1 for Origin pa")
                    );
                }
                let _origin = parser.parse_u8()?;
            },
            PathAttributeType::AsPath => {
                let pa = parser.parse_octets(len)?;
                let mut p = Parser::from_ref(&pa);
                while p.remaining() > 0 {
                    let _stype = p.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = p.parse_u8()?;
                    for _ in 0..slen {
                        match config.four_octet_asn {
                            FourOctetAsn::Enabled => { p.parse_u32()?; }
                            FourOctetAsn::Disabled => { p.parse_u16()?; }
                        }
                    }
                }
            },
            PathAttributeType::NextHop => {
                // conventional NEXT_HOP, just an IPv4 address
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for NEXT_HOP pa")
                    );
                }
                let _next_hop = parse_ipv4addr(parser)?;
            }
            PathAttributeType::MultiExitDisc => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for MULTI_EXIT_DISC pa")
                    );
                }
                let _med = parser.parse_u32()?;
            }
            PathAttributeType::LocalPref => {
                if len != 4 {
                    return Err(
                        ParseError::form_error("expected len 4 for LOCAL_PREF pa")
                    );
                }
                let _localpref = parser.parse_u32()?;
            },
            PathAttributeType::AtomicAggregate => {
                if len != 0 {
                    return Err(
                        ParseError::form_error("expected len 0 for ATOMIC_AGGREGATE pa")
                    );
                }
            },
            PathAttributeType::Aggregator => {
                let pa = parser.parse_octets(len)?;
                let mut p = Parser::from_ref(&pa);
                Aggregator::parse(&mut p, config)?;
            },
            PathAttributeType::Communities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    StandardCommunity::parse(parser)?;
                }
            },
            PathAttributeType::OriginatorId => {
                let _bgp_id = parser.parse_u32()?;
            },
            PathAttributeType::ClusterList => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    parser.parse_u32()?;
                }
            },
            PathAttributeType::MpReachNlri => {
                let mut pa_parser = parser.parse_parser(len)?;
                Nlris::parse(&mut pa_parser, config)?;
            },
            PathAttributeType::MpUnreachNlri => {
                let mut pa_parser = parser.parse_parser(len)?;
                Withdrawals::parse(&mut pa_parser, config)?;
            },
            PathAttributeType::ExtendedCommunities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    ExtendedCommunity::parse(parser)?;
                }
            },
            PathAttributeType::As4Path => {
                let mut pa_parser = parser.parse_parser(len)?;
                while pa_parser.remaining() > 0 {
                    let _stype = pa_parser.parse_u8()?;
                    // segment length describes the number of ASNs
                    let slen = pa_parser.parse_u8()?;
                    for _ in 0..slen {
                         pa_parser.parse_u32()?;
                    }
                }
            }
            PathAttributeType::As4Aggregator => {
                let _asn = parser.parse_u32()?;
                let _addr = parse_ipv4addr(parser)?;
            }
            PathAttributeType::Connector => {
                //let _addr = parse_ipv4addr(parser)?;
                // based on
                // https://www.rfc-editor.org/rfc/rfc6037.html#section-5.2.1
                // we expect an IPv4 address. We have seen contents of length
                // 14 instead of 4 though, so let's be lenient for now.
                parser.advance(len)?;
            },
            PathAttributeType::AsPathLimit => {
                let _limit = parser.parse_u8()?;
                let _asn = parser.parse_u32()?;
            },
            PathAttributeType::PmsiTunnel => {
                let _flags = parser.parse_u8()?;
                let _tunnel_type = parser.parse_u8()?;
                let _mpls_label_1 = parser.parse_u8()?;
                let _mpls_label_2 = parser.parse_u16()?;
                let tunnel_id_len = len - 5;
                parser.advance(tunnel_id_len)?;
            },
            PathAttributeType::Ipv6ExtendedCommunities => {
                let mut pp = parser.parse_parser(len)?;
                while pp.remaining() > 0 {
                    Ipv6ExtendedCommunity::parse(&mut pp)?;
                }
            },
            PathAttributeType::LargeCommunities => {
                let pos = parser.pos();
                while parser.pos() < pos + len {
                    LargeCommunity::parse(parser)?;
                }
            },
            PathAttributeType::BgpsecAsPath => {
                let mut pp = parser.parse_parser(len)?;
                // SecurePath block
                //
                // Signature Block 1
                // Signature Block 2?
                //
                //Secure_Path
                //    [2 bytes length (octets of total Secure_Path) , 1..N Segments]
                //$(
                //Segment
                //    [1byte pCount (prependCount?), 1 byte flags, 4byte ASN]
                //)+

                let len_path = pp.parse_u16()?;
                if (len_path - 2) % 6 != 0 {
                    warn!("BGPsec_Path Path Segments not a multiple of 6 bytes")
                }
                pp.advance(len_path as usize - 2)?;

                //Signature_Block
                //    [2 bytes length , 1 byte algo suite, 1..N segments]
                //$(
                //Segment
                //    [20 bytes SKI, 2 bytes sig length, sig]
                //)+

                let len_sigs = pp.parse_u16()?;
                let algo_id = pp.parse_u8()?;
                if algo_id != 0x01 {
                    warn!("BGPsec_Path Signature Block containing unknown\
                            Algorithm Suite ID {algo_id}");
                }

                let mut sb1_parser = pp.parse_parser(len_sigs as usize - 3)?;
                while sb1_parser.remaining() > 0 {
                    // SKI
                    sb1_parser.advance(20)?;
                    let sig_len = sb1_parser.parse_u16()?;
                    sb1_parser.advance(sig_len as usize)?;
                }

                // check for another Signature Block:
                if pp.remaining() > 0 {
                    debug!("{} bytes in BgpsecAsPath,\
                           assuming a second Signature Block",
                           pp.remaining()
                    );

                    let mut sb2_parser = pp.parse_parser(len_sigs as usize - 3)?;
                    while sb2_parser.remaining() > 0 {
                        // SKI
                        sb2_parser.advance(20)?;
                        let sig_len = sb2_parser.parse_u16()?;
                        sb2_parser.advance(sig_len as usize)?;
                    }
                }
                if pp.remaining() > 0 {
                    warn!("{} bytes left in BgpsecAsPath\
                          after two Signature Blocks",
                           pp.remaining()
                    );
                }
            },
            PathAttributeType::AttrSet => {
                let _origin_as = parser.parse_u32()?;
                let mut set_parser = parser.parse_parser(len - 4)?;
                //while set_parser.remaining() > 0 {
                //    PathAttribute::parse(&mut set_parser)?;
                //}
                PathAttributes::parse(&mut set_parser, config)?;
            },
            PathAttributeType::Reserved => {
                warn!("Path Attribute type 0 'Reserved' observed");
            },
            PathAttributeType::RsrvdDevelopment => {
                // This could be anything.
                // As long as we do the resetting seek() + parse_octets()
                // after the match, we do not need to do anything here.
            },
            PathAttributeType::Unimplemented(_) => {
                warn!("Unimplemented PA: {}", typecode);
                parser.advance(len)?;
            },
            //_ => {
            //    panic!("unimplemented: {}", <PathAttributeType as From::<u8>>::from(typecode));
            //},
        }
        
        parser.seek(pos)?;

        let pp = Parser::parse_parser(parser, headerlen+len)?;
        Ok(PathAttribute { parser: pp })
    }
}


impl<'a, Ref: Octets> Iterator for PathAttributesIter<'a, Ref> {
    type Item = PathAttribute<'a, Ref>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        Some(
            PathAttribute::parse(&mut self.parser, self.session_config)
            .expect("parsed before")
        )
    }
}

impl<'a, Ref: Octets> IntoIterator for PathAttributes<'a, Ref> {
    type Item = PathAttribute<'a, Ref>;
    type IntoIter = PathAttributesIter<'a, Ref>;
    fn into_iter(self) -> Self::IntoIter {
        PathAttributesIter {
            parser: self.parser,
            session_config: self.session_config
        }
    }
}

//--- Aggregator -------------------------------------------------------------
/// Path Attribute (7).
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Aggregator {
    asn: Asn,
    speaker: Ipv4Addr,
}

impl Aggregator {
    /// Creates a new Aggregator.
    pub fn new(asn: Asn, speaker: Ipv4Addr) -> Self {
        Aggregator{ asn, speaker }
    }

    /// Returns the `Asn`.
    pub fn asn(&self) -> Asn {
        self.asn
    }

    /// Returns the speaker IPv4 address.
    pub fn speaker(&self) -> Ipv4Addr {
        self.speaker
    }
}

/// Iterator for BGP UPDATE Communities.
///
/// Returns values of enum [`Community`], wrapping [`StandardCommunity`],
/// [`ExtendedCommunity`], [`LargeCommunity`] and well-known communities.
pub struct CommunityIter<Octs: Octets> {
    slice: Octs,
    pos: usize,
}

impl<Octs: Octets> CommunityIter<Octs> {
    fn new(slice: Octs) -> Self {
        CommunityIter { slice, pos: 0 }
    }

    fn get_community(&mut self) -> Community {
        let mut buf = [0u8; 4];
        buf[..].copy_from_slice(&self.slice.as_ref()[self.pos..self.pos+4]);
        self.pos += 4;
        buf.into()
    }
}

impl<Octs: Octets> Iterator for CommunityIter<Octs> {
    type Item = Community;
    
    fn next(&mut self) -> Option<Community> {
        if self.pos == self.slice.as_ref().len() {
            return None
        }
        Some(self.get_community())
    }
}

/// Iterator over [`ExtendedCommunity`]s.
pub struct ExtCommunityIter<Octs: Octets> {
    slice: Octs,
    pos: usize,
}

impl<Octs: Octets> ExtCommunityIter<Octs> {
    fn new(slice: Octs) -> Self {
        ExtCommunityIter { slice, pos: 0 }
    }

    fn get_community(&mut self) -> ExtendedCommunity {
        let res = ExtendedCommunity::from_raw(
            self.slice.as_ref()[self.pos..self.pos+8].try_into().expect("parsed before")
            );
        self.pos += 8;
        res
    }
}

impl<Octs: Octets> Iterator for ExtCommunityIter<Octs> {
    type Item = ExtendedCommunity;

    fn next(&mut self) -> Option<ExtendedCommunity> {
        if self.pos == self.slice.as_ref().len() {
            return None
        }
        Some(self.get_community())
    }
}

/// Iterator over [`LargeCommunity`]s.
pub struct LargeCommunityIter<Octs: Octets> {
    slice: Octs,
    pos: usize,
}

impl<Octs: Octets> LargeCommunityIter<Octs> {
    fn new(slice: Octs) -> Self {
        LargeCommunityIter { slice, pos: 0 }
    }

    fn get_community(&mut self) -> LargeCommunity {
        let res = LargeCommunity::from_raw(
            self.slice.as_ref()[self.pos..self.pos+12].try_into().expect("parsed before")
            );
        self.pos += 12;
        res
    }
}

impl<Octs: Octets> Iterator for LargeCommunityIter<Octs> {
    type Item = LargeCommunity;

    fn next(&mut self) -> Option<LargeCommunity> {
        if self.pos == self.slice.as_ref().len() {
            return None
        }
        Some(self.get_community())
    }
}

impl Aggregator {
    fn check<R: Octets>(parser: &mut Parser<'_, R>, config: SessionConfig)
        -> Result<(), ParseError>
    {
        let len = parser.remaining(); // XXX is this always correct?
        match (len, config.four_octet_asn) {
            (8, FourOctetAsn::Enabled) => {
                Ok(())
            },
            (6, FourOctetAsn::Disabled) => {
                Ok(())
            },
            (_, FourOctetAsn::Enabled) => {
                Err(
                    ParseError::form_error("expected len 8 for AGGREGATOR pa")
                )
            },
            (_, FourOctetAsn::Disabled) => {
                Err(
                    ParseError::form_error("expected len 6 for AGGREGATOR pa")
                )
            },
        }
    }

    fn parse<R: Octets>(parser: &mut Parser<'_, R>, config: SessionConfig)
        -> Result<Self, ParseError>
    {
        let len = parser.remaining(); // XXX is this always correct?
        match (len, config.four_octet_asn) {
            (8, FourOctetAsn::Enabled) => {
                let asn = Asn::from_u32(parser.parse_u32()?);
                let addr = parse_ipv4addr(parser)?;
                Ok(Self::new(asn, addr))
            },
            (6, FourOctetAsn::Disabled) => {
                let asn = Asn::from_u32(parser.parse_u16()?.into());
                let addr = parse_ipv4addr(parser)?;
                Ok(Self::new(asn, addr))
            },
            (_, FourOctetAsn::Enabled) => {
                Err(
                    ParseError::form_error("expected len 8 for AGGREGATOR pa")
                )
            },
            (_, FourOctetAsn::Disabled) => {
                Err(
                    ParseError::form_error("expected len 6 for AGGREGATOR pa")
                )
            },
        }

    }
}

pub struct Withdrawals<'a, Octs: Octets> {
    parser: Parser<'a, Octs>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<'a, Octs: Octets> Withdrawals<'a, Octs> {
    pub fn iter(&self) -> WithdrawalsIterMp<'a, Octs> {
        WithdrawalsIterMp {
            parser: self.parser,
            session_config: self.session_config,
            afi: self.afi,
            safi: self.safi
        }
    }

    /// Returns the AFI for these withdrawals.
    pub fn afi(&self) -> AFI {
        self.afi
    }

    /// Returns the SAFI for these withdrawals
    pub fn safi(&self) -> SAFI {
        self.safi
    }
}

/// Iterator over the withdrawn NLRIs.
///
/// Returns items of the enum [`Nlri`], thus both conventional and
/// BGP MultiProtocol (RFC4760) withdrawn NLRIs.
pub struct WithdrawalsIterMp<'a, Ref> {
    parser: Parser<'a, Ref>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<'a, Octs: 'a + Octets> WithdrawalsIterMp<'a, Octs> {
    fn get_nlri(&mut self) -> Nlri<Octs::Range<'a>> {
        match (self.afi, self.safi) {
            (_, SAFI::MplsVpnUnicast) => {
                Nlri::MplsVpn(MplsVpnNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::MplsUnicast) => {
                Nlri::Mpls(MplsNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::Unicast) => {
                Nlri::Basic(BasicNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            }
            (_, _) => panic!("should not come here")
        }
    }
}

impl<'a, Octs: Octets> Withdrawals<'a, Octs> {
    // XXX remove?
    fn _parse_conventional(parser: &mut Parser<'a, Octs>, config: SessionConfig)
        -> Result<Self, ParseError>
    {
        let pos = parser.pos();
        while parser.remaining() > 0 {
            BasicNlri::parse(parser, config, AFI::Ipv4)?;
        }
        let len = parser.pos() - pos;
        parser.seek(pos)?;

        let pp = Parser::parse_parser(parser, len).expect("parsed before");
        
        Ok(
            Withdrawals {
                parser: pp,
                session_config: config,
                afi: AFI::Ipv4,
                safi: SAFI::Unicast,
            }
        )
    }

    fn check<R: Octets>(parser: &mut Parser<'a, R>,  config: SessionConfig)
        -> Result<(), ParseError>
    {
        // NLRIs from MP_UNREACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, are also in this Path Attribute.

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::<Octs>::check(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::<Octs>::check(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::check(parser, config, afi)?; }
                (_, _) => { /* return Err(FormError("unimplemented")) */ }
            }
        }

        Ok(())
    }

    fn parse(parser: &mut Parser<'a, Octs>,  config: SessionConfig)
        -> Result<Self, ParseError>
    {
        // NLRIs from MP_UNREACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, are also in this Path Attribute.

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();
        let pos = parser.pos();

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::parse(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::parse(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::parse(parser, config, afi)?; }
                (_, _) => { /* return Err(FormError("unimplemented")) */ }
            }
        }

        let len = parser.pos() - pos;
        parser.seek(pos)?;
        let pp = Parser::parse_parser(parser, len).expect("parsed before");
        Ok(
            Withdrawals {
                parser: pp,
                session_config: config,
                afi,
                safi,
            }
        )
    }
}

impl<'a, Octs: Octets> Iterator for WithdrawalsIterMp<'a, Octs> {
    type Item = Nlri<Octs::Range<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(self.get_nlri())
    }
}

/// Represents the announced NLRI in a BGP UPDATE message.
pub struct Nlris<'a, Octs: Octets> {
    parser: Parser<'a, Octs>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<'a, Octs: Octets> Nlris<'a, Octs> {
    pub fn iter(&self) -> NlriIterMp<'a, Octs> {
        NlriIterMp {
            parser: self.parser,
            session_config: self.session_config,
            afi: self.afi,
            safi: self.safi,
        }
    }

    /// Returns the AFI for these NLRI.
    pub fn afi(&self) -> AFI {
        self.afi
    }

    /// Returns the SAFI for these NLRI.
    pub fn safi(&self) -> SAFI {
        self.safi
    }
}

/// Iterator over the reachable NLRIs.
///
/// Returns items of the enum [`Nlri`], thus both conventional and
/// BGP MultiProtocol (RFC4760) NLRIs.
pub struct NlriIterMp<'a, Ref> {
    parser: Parser<'a, Ref>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<'a, Octs: Octets> NlriIterMp<'a, Octs> {
    fn get_nlri(&mut self) -> Nlri<Octs::Range<'a>> {
        match (self.afi, self.safi) {
            (_, SAFI::MplsVpnUnicast) => {
                Nlri::MplsVpn(MplsVpnNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::MplsUnicast) => {
                Nlri::Mpls(MplsNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (_, SAFI::Unicast) => {
                Nlri::Basic(BasicNlri::parse(&mut self.parser, self.session_config, self.afi).expect("parsed before"))
            },
            (AFI::L2Vpn, SAFI::Vpls) => {
                Nlri::Vpls(VplsNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (AFI::Ipv4, SAFI::FlowSpec) => {
                Nlri::FlowSpec(FlowSpecNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (AFI::Ipv4, SAFI::RouteTarget) => {
                Nlri::RouteTarget(RouteTargetNlri::parse(&mut self.parser).expect("parsed before"))
            },
            (_, _) => panic!("unsupported AFI/SAFI in get_nlri(), should not come here")
        }
    }
}

impl<'a, Octs: Octets> Nlris<'a, Octs> {
    // XXX remove, make like Withdrawals
    fn parse_conventional(parser: &mut Parser<'a, Octs>, config: SessionConfig) -> Result<Self, ParseError>
    {
        let pos = parser.pos();
        while parser.remaining() > 0 {
            BasicNlri::parse(parser, config, AFI::Ipv4)?;
        }
        let len = parser.pos() - pos;
        parser.seek(pos)?;

        let pp = Parser::parse_parser(parser, len).expect("parsed before");

        Ok(
            Nlris {
                parser: pp,
                session_config: config,
                afi: AFI::Ipv4,
                safi: SAFI::Unicast,
            }
        )
    }

    fn check<R: Octets>(parser: &mut Parser<'a, R>, config: SessionConfig)
        -> Result<(), ParseError>
    {
        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();

        NextHop::check(parser, afi, safi)?;
        parser.advance(1)?; // 1 reserved byte

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::<Octs>::check(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::<Octs>::check(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::check(parser, config, afi)?; }
                (AFI::L2Vpn, SAFI::Vpls) => { VplsNlri::check(parser)?; }
                (AFI::Ipv4, SAFI::FlowSpec) => {
                    FlowSpecNlri::<Octs>::check(parser)?;
                },
                (AFI::Ipv4, SAFI::RouteTarget) => {
                    RouteTargetNlri::<Octs>::check(parser)?;
                },
                (_, _) => {
                    error!("unknown AFI/SAFI {}/{}", afi, safi);
                    return Err(
                        ParseError::form_error("unimplemented AFI/SAFI")
                    )
                }
            }
        }

        Ok(())
    }

    fn parse(parser: &mut Parser<'a, Octs>, config: SessionConfig)
        -> Result<Self, ParseError>
    {
        // NLRIs from MP_REACH_NLRI.
        // Length is given in the Path Attribute length field.
        // AFI, SAFI, Nexthop are also in this Path Attribute.

        let afi: AFI = parser.parse_u16()?.into();
        let safi: SAFI = parser.parse_u8()?.into();

        NextHop::skip(parser)?;
        parser.advance(1)?; // 1 reserved byte

        let pos = parser.pos();

        while parser.remaining() > 0 {
            match (afi, safi) {
                (_, SAFI::MplsVpnUnicast) => { MplsVpnNlri::parse(parser, config, afi)?;},
                (_, SAFI::MplsUnicast) => { MplsNlri::parse(parser, config, afi)?;},
                (_, SAFI::Unicast) => { BasicNlri::parse(parser, config, afi)?; }
                (AFI::L2Vpn, SAFI::Vpls) => { VplsNlri::parse(parser)?; }
                (AFI::Ipv4, SAFI::FlowSpec) => {
                    FlowSpecNlri::parse(parser)?;
                },
                (AFI::Ipv4, SAFI::RouteTarget) => {
                    RouteTargetNlri::parse(parser)?;
                },
                (_, _) => {
                    error!("unknown AFI/SAFI {}/{}", afi, safi);
                    return Err(
                        ParseError::form_error("unimplemented AFI/SAFI")
                    )
                }
            }
        }

        let len = parser.pos() - pos;
        parser.seek(pos)?;
        let pp = Parser::parse_parser(parser, len).expect("parsed before");

        Ok(Nlris {
            parser: pp,
            session_config: config,
            afi,
            safi,
        })
    }
}


impl<'a, Octs: Octets> Iterator for NlriIterMp<'a, Octs> {
    type Item = Nlri<Octs::Range<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(self.get_nlri())
    }
}

//--- Communities ------------------------------------------------------------
//

impl StandardCommunity {
    fn check<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        parser.advance(4)?;
        Ok(())
    }

    fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 4];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}

impl ExtendedCommunity {
    fn check<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        parser.advance(8)?;
        Ok(())
    }

    fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 8];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}

impl Ipv6ExtendedCommunity {
    fn check<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        parser.advance(20)?;
        Ok(())
    }

    fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 20];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}

impl LargeCommunity {
    fn check<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        parser.advance(12)?;
        Ok(())
    }

    fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let mut buf = [0u8; 12];
        parser.parse_buf(&mut buf)?;
        Ok( Self::from_raw(buf) )
    }
}

//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;
    use crate::bgp::communities::*;
    use crate::bgp::message::Message;
    use crate::addr::Prefix;

    use bytes::Bytes;

    //TODO:
    // X generic
    // - incomplete msg
    // - path attributes:
    //   - aspath
    //   - attributeset
    // - announcements:
    //   X single conventional
    //   X multiple conventional 
    //   x bgp-mp
    // - withdrawals
    //   - single conventional
    //   X multiple conventional
    //   x bgp-mp
    // - communities
    //   x normal
    //   x extended
    //   x large
    //   x chained iter
    // - MP NLRI types:
    //   announcements:
    //   - v4 mpls unicast
    //   - v4 mpls unicast unreach **missing**
    //   - v4 mpls vpn unicast
    //   - v6 mpls unicast addpath 
    //   - v6 mpls vpn unicast
    //   - multicast **missing
    //   - vpls
    //   - flowspec
    //   - routetarget
    //   withdrawals:
    //   - v4 mpls vpn unicast unreach
    //   - v6 mpls unicast addpath unreach
    //   - v6 mpls vpn unicast
    //
    //
    // x legacy stuff:
    //    as4path
    //


    #[test]
    fn incomplete_msg() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x88, 0x02, 
        ];
        assert!(Message::from_octets(&buf, None).is_err());
    }

    #[test]
    fn conventional() {
        let buf = vec![
            // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02,
            0x00, 0x00, 0x00, 0x1b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02,
            0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04,
            0x0a, 0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00,
            0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ];

        //let update: UpdateMessage<_> = parse_msg(&buf);
        let bytes = Bytes::from(buf);
        let update: UpdateMessage<_> = Message::from_octets(
            bytes,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

        assert_eq!(update.length(), 55);
        assert_eq!(update.total_path_attribute_len(), 27);

        //let mut pa_iter = update.path_attributes().iter();
        let pas = update.path_attributes();
        let mut pa_iter = pas.iter();

        let pa1 = pa_iter.next().unwrap();
        assert_eq!(pa1.type_code(), PathAttributeType::Origin);
        assert_eq!(pa1.flags(), 0x40);
        assert!(!pa1.is_optional());
        assert!(pa1.is_transitive());
        assert!(!pa1.is_partial());
        assert!(!pa1.is_extended_length());

        assert_eq!(pa1.length(), 1);
        assert_eq!(pa1.value().as_ref(), &[0x00]); // TODO enumify Origin types

        let pa2 = pa_iter.next().unwrap();
        assert_eq!(pa2.type_code(), PathAttributeType::AsPath);
        assert_eq!(pa2.flags(), 0x40);
        assert_eq!(pa2.length(), 6);

        let asp = pa2.value();
        assert_eq!(asp.as_ref(), [0x02, 0x01, 0x00, 0x01, 0x00, 0x00]);

        let mut pb = AsPathBuilder::new();
        pb.push(Asn::from_u32(65536)).unwrap();
        let asp: AsPath<Vec<Asn>> = pb.finalize();

        assert_eq!(update.aspath().unwrap(), asp);

        let pa3 = pa_iter.next().unwrap();
        assert_eq!(pa3.type_code(), PathAttributeType::NextHop);
        assert_eq!(pa3.flags(), 0x40);
        assert_eq!(pa3.length(), 4);
        assert_eq!(pa3.value().as_ref(), &[10, 255, 0, 101]);
        assert_eq!(
            update.next_hop(),
            Some(NextHop::Ipv4(Ipv4Addr::new(10, 255, 0, 101)))
            );

        let pa4 = pa_iter.next().unwrap();
        assert_eq!(pa4.type_code(), PathAttributeType::MultiExitDisc);
        assert_eq!(pa4.flags(), 0x80);
        assert!(pa4.is_optional());
        assert!(!pa4.is_transitive());
        assert!(!pa4.is_partial());
        assert!(!pa4.is_extended_length());
        assert_eq!(pa4.length(), 4);
        assert_eq!(pa4.value().as_ref(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(update.multi_exit_desc(), Some(MultiExitDisc(1)));

        assert!(pa_iter.next().is_none());

        //let mut nlri_iter = update.nlris().iter();
        let nlris = update.nlris();
        let mut nlri_iter = nlris.iter();
        let nlri1 = nlri_iter.next().unwrap();
        assert!(matches!(nlri1, Nlri::Basic(_)));
        assert_eq!(
            nlri1.prefix(),
            Some(Prefix::from_str("10.10.10.2/32").unwrap())
            );
        assert!(nlri_iter.next().is_none());
    }

    #[test]
    fn conventional_multiple_nlri() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x3c, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
            0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x07, 0x6c, 0x20, 0x0a, 0x0a, 0x0a, 0x09, 0x1e,
            0xc0, 0xa8, 0x61, 0x00
        ];

        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update: UpdateMessage<_> = Message::from_octets(
            &buf,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

        assert_eq!(update.total_path_attribute_len(), 27);
        assert_eq!(update.nlris().iter().count(), 2);

        let prefixes = ["10.10.10.9/32", "192.168.97.0/30"].map(|p|
                                                                Prefix::from_str(p).unwrap()
                                                               );

        for (nlri, prefix) in update.nlris().iter().zip(prefixes.iter()) {
            assert_eq!(nlri.prefix(), Some(*prefix))
        }
    }

    #[test]
    fn multiple_mp_reach() {
        // BGP UPDATE message containing MP_REACH_NLRI path attribute,
        // comprising 5 IPv6 NLRIs
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x88, 0x02, 0x00, 0x00, 0x00, 0x71, 0x80,
            0x0e, 0x5a, 0x00, 0x02, 0x01, 0x20, 0xfc, 0x00,
            0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xfe, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80,
            0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
            0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff,
            0x00, 0x01, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff,
            0xff, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8,
            0xff, 0xff, 0x00, 0x03, 0x40, 0x01, 0x01, 0x00,
            0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00,
            0xc8, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00
        ];
        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update: UpdateMessage<_> = Message::from_octets(
            &buf,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

        assert_eq!(update.withdrawn_routes_len(), 0);
        assert_eq!(update.total_path_attribute_len(), 113);

        let nlris = update.nlris();
        let nlri_iter = nlris.iter();
        assert_eq!(nlri_iter.count(), 5);
        //assert_eq!(update.nlris().iter().count(), 5);

        let prefixes = [
            "fc00::10/128",
            "2001:db8:ffff::/64",
            "2001:db8:ffff:1::/64",
            "2001:db8:ffff:2::/64",
            "2001:db8:ffff:3::/64",
        ].map(|p|
              Prefix::from_str(p).unwrap()
             );

        for (nlri, prefix) in update.nlris().iter().zip(prefixes.iter()) {
            assert_eq!(nlri.prefix(), Some(*prefix))
        }

    }

    #[test]
    fn conventional_withdrawals() {
        // BGP UPDATE with 12 conventional withdrawals
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x53, 0x02, 0x00, 0x3c, 0x20, 0x0a, 0x0a,
            0x0a, 0x0a, 0x1e, 0xc0, 0xa8, 0x00, 0x1c, 0x20,
            0x0a, 0x0a, 0x0a, 0x65, 0x1e, 0xc0, 0xa8, 0x00,
            0x18, 0x20, 0x0a, 0x0a, 0x0a, 0x09, 0x20, 0x0a,
            0x0a, 0x0a, 0x08, 0x1e, 0xc0, 0xa8, 0x61, 0x00,
            0x20, 0x0a, 0x0a, 0x0a, 0x66, 0x1e, 0xc0, 0xa8,
            0x00, 0x20, 0x1e, 0xc0, 0xa8, 0x62, 0x00, 0x1e,
            0xc0, 0xa8, 0x00, 0x10, 0x1e, 0xc0, 0xa8, 0x63,
            0x00, 0x00, 0x00
        ];
        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update: UpdateMessage<_> = Message::from_octets(
            &buf,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

        assert_eq!(update.withdrawals().iter().count(), 12);

        let ws = [
            "10.10.10.10/32",
            "192.168.0.28/30",
            "10.10.10.101/32",
            "192.168.0.24/30",
            "10.10.10.9/32",
            "10.10.10.8/32",
            "192.168.97.0/30",
            "10.10.10.102/32",
            "192.168.0.32/30",
            "192.168.98.0/30",
            "192.168.0.16/30",
            "192.168.99.0/30",
        ].map(|w|
              Prefix::from_str(w).unwrap()
             );

        for (nlri, w) in update.withdrawals().iter().zip(ws.iter()) {
            assert_eq!(nlri.prefix(), Some(*w))
        }

    }

    #[test]
    fn multiple_mp_unreach() {
        // BGP UPDATE with 4 MP_UNREACH_NLRI
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x41, 0x02, 0x00, 0x00, 0x00, 0x2a, 0x80,
            0x0f, 0x27, 0x00, 0x02, 0x01, 0x40, 0x20, 0x01,
            0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x40, 0x20,
            0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x02,
            0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
            0x03
        ];
        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update: UpdateMessage<_> = Message::from_octets(
            &buf,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

        assert_eq!(update.withdrawals().iter().count(), 4);

        let ws = [
            "2001:db8:ffff::/64",
            "2001:db8:ffff:1::/64",
            "2001:db8:ffff:2::/64",
            "2001:db8:ffff:3::/64",
        ].map(|w|
              Prefix::from_str(w).unwrap()
             );

        for (nlri, w) in update.withdrawals().iter().zip(ws.iter()) {
            assert_eq!(nlri.prefix(), Some(*w))
        }
    }

    //--- Path Attributes ------------------------------------------------

    #[test]
    fn local_pref_multi_exit_disc() {
        // BGP UPDATE with 5 conventional announcements, MULTI_EXIT_DISC
        // and LOCAL_PREF path attributes
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x60, 0x02, 0x00, 0x00, 0x00, 0x30, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x14, 0x03, 0x01,
            0x00, 0x00, 0xfd, 0xea, 0x02, 0x03, 0x00, 0x00,
            0x01, 0x90, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00,
            0x01, 0xf4, 0x40, 0x03, 0x04, 0x0a, 0x04, 0x05,
            0x05, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x20,
            0x0a, 0x00, 0x00, 0x09, 0x1a, 0xc6, 0x33, 0x64,
            0x00, 0x1a, 0xc6, 0x33, 0x64, 0x40, 0x1a, 0xc6,
            0x33, 0x64, 0x80, 0x1a, 0xc6, 0x33, 0x64, 0xc0
        ];
        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update: UpdateMessage<_> = Message::from_octets(
            &buf,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();
        assert_eq!(update.multi_exit_desc(), Some(MultiExitDisc(0)));
        assert_eq!(update.local_pref(), Some(LocalPref(100)));
    }

    #[test]
    fn atomic_aggregate() {
        // BGP UPDATE with AGGREGATOR and ATOMIC_AGGREGATE
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x44, 0x02, 0x00, 0x00, 0x00, 0x29, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x00, 0x00, 0x65, 0xc0, 0x07, 0x08, 0x00,
            0x00, 0x00, 0x65, 0xc6, 0x33, 0x64, 0x01, 0x40,
            0x06, 0x00, 0x40, 0x03, 0x04, 0x0a, 0x01, 0x02,
            0x01, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x18, 0xc6, 0x33, 0x64
        ];
        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update: UpdateMessage<_> = Message::from_octets(
            &buf,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();
        let aggr = update.aggregator().unwrap();

        assert!(update.is_atomic_aggregate());
        assert_eq!(aggr.asn(), Asn::from(101));
        assert_eq!(
            aggr.speaker(),
            Ipv4Addr::from_str("198.51.100.1").unwrap()
            );
    }

    #[test]
    fn as4path() {
        // BGP UPDATE with AS_PATH and AS4_PATH, both containing one
        // SEQUENCE of length 10. First four in AS_PATH are actual ASNs,
        // last six are AS_TRANS.
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x6e, 0x02, 0x00, 0x00, 0x00, 0x53, 0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x16, 0x02,
            0x0a, 0xfb, 0xf0, 0xfb, 0xf1, 0xfb, 0xf2, 0xfb,
            0xf3, 0x5b, 0xa0, 0x5b, 0xa0, 0x5b, 0xa0, 0x5b,
            0xa0, 0x5b, 0xa0, 0x5b, 0xa0, 0x40, 0x03, 0x04,
            0xc0, 0xa8, 0x01, 0x01, 0xd0, 0x11, 0x00, 0x2a,
            0x02, 0x0a, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00,
            0xfb, 0xf1, 0x00, 0x00, 0xfb, 0xf2, 0x00, 0x00,
            0xfb, 0xf3, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x0a, 0x16, 0x0a, 0x01, 0x04
        ];

        let sc = SessionConfig::legacy();
        let update: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
            .unwrap().try_into().unwrap();

        update.path_attributes().iter();//.count();
        if let Some(aspath) = update.path_attributes().iter().find(|pa|
                                                                   pa.type_code() == PathAttributeType::AsPath
                                                                  ){
            assert_eq!(aspath.flags(), 0x50);
            assert!(aspath.is_transitive());
            assert!(aspath.is_extended_length());
            assert_eq!(aspath.length(), 22);
            //TODO check actual aspath
        } else {
            panic!("ASPATH path attribute not found")
        }

        if let Some(as4path) = update.path_attributes().iter().find(|pa|
                                                                    pa.type_code() == PathAttributeType::As4Path
                                                                   ){
            assert_eq!(as4path.flags(), 0xd0);
            assert_eq!(as4path.length(), 42);
            //TODO check actual aspath
        } else {
            panic!("AS4PATH path attribute not found")
        }

    }

    //--- Communities ----------------------------------------------------

    #[test]
    fn pa_communities() {
        // BGP UPDATE with 9 path attributes for 1 NLRI with Path Id,
        // includes both normal communities and extended communities.
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x82, 0x02, 0x00, 0x00, 0x00, 0x62, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x16, 0x02, 0x05,
            0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x01, 0x2d,
            0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x02, 0x58,
            0x00, 0x00, 0x02, 0xbc, 0x40, 0x03, 0x04, 0x0a,
            0x01, 0x03, 0x01, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00,
            0x64, 0xc0, 0x08, 0x0c, 0x00, 0x2a, 0x02, 0x06,
            0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x03,
            0xc0, 0x10, 0x10, 0x00, 0x06, 0x00, 0x00, 0x44,
            0x9c, 0x40, 0x00, 0x40, 0x04, 0x00, 0x00, 0x44,
            0x9c, 0x40, 0x00, 0x80, 0x0a, 0x04, 0x0a, 0x00,
            0x00, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x01, 0x19, 0xc6, 0x33,
            0x64, 0x00
        ];
        let sc = SessionConfig::modern_addpath();
        let upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
            .unwrap().try_into().unwrap();

        assert_eq!(
            upd.nlris().iter().next().unwrap().prefix(),
            Some(Prefix::from_str("198.51.100.0/25").unwrap())
            );

        assert!(upd.communities().is_some());
        for c in upd.communities().unwrap() { 
            println!("{:?}", c);
        }
        assert!(upd.communities().unwrap().eq([
                                              Community::Standard(StandardCommunity::new(42.into(), Tag::new(518))),
                                              Wellknown::NoExport.into(),
                                              Wellknown::NoExportSubconfed.into()
        ]));

        assert!(upd.ext_communities().is_some());
        let mut ext_comms = upd.ext_communities().unwrap();
        let ext_comm1 = ext_comms.next().unwrap();
        assert!(ext_comm1.is_transitive());

        assert_eq!(
            ext_comm1.types(),
            (ExtendedCommunityType::TransitiveTwoOctetSpecific,
             ExtendedCommunitySubType::OtherSubType(0x06))
            );

        use crate::bgp::communities::Asn16;
        assert_eq!(ext_comm1.as2(), Some(Asn16::from_u16(0)));

        let ext_comm2 = ext_comms.next().unwrap();
        assert!(!ext_comm2.is_transitive());
        assert_eq!(
            ext_comm2.types(),
            (ExtendedCommunityType::NonTransitiveTwoOctetSpecific,
             ExtendedCommunitySubType::OtherSubType(0x04))
            );
        assert_eq!(ext_comm2.as2(), Some(Asn16::from_u16(0)));

        assert!(ext_comms.next().is_none());

    }

    #[test]
    fn large_communities() {
        // BGP UPDATE with several path attributes, including Large
        // Communities with three communities: 65536:1:1, 65536:1:2, 65536:1:3
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x57, 0x02, 0x00, 0x00, 0x00, 0x3b, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0xc0,
            0x00, 0x02, 0x02, 0xc0, 0x20, 0x24, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x03, 0x20, 0xcb, 0x00, 0x71, 0x0d
        ];
        let update: UpdateMessage<_> = Message::from_octets(
            &buf,
            Some(SessionConfig::modern())
            ).unwrap().try_into().unwrap();

        let mut lcs = update.large_communities().unwrap();
        let lc1 = lcs.next().unwrap();
        assert_eq!(lc1.global(), 65536);
        assert_eq!(lc1.local1(), 1);
        assert_eq!(lc1.local2(), 1);

        let lc2 = lcs.next().unwrap();
        assert_eq!(lc2.global(), 65536);
        assert_eq!(lc2.local1(), 1);
        assert_eq!(lc2.local2(), 2);

        let lc3 = lcs.next().unwrap();
        assert_eq!(lc3.global(), 65536);
        assert_eq!(lc3.local1(), 1);
        assert_eq!(lc3.local2(), 3);

        assert_eq!(format!("{}", lc3), "65536:1:3");

        assert!(lcs.next().is_none());

    }

    #[test]
    fn chained_community_iters() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x82, 0x02, 0x00, 0x00, 0x00, 0x62, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x16, 0x02, 0x05,
            0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x01, 0x2d,
            0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x02, 0x58,
            0x00, 0x00, 0x02, 0xbc, 0x40, 0x03, 0x04, 0x0a,
            0x01, 0x03, 0x01, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00,
            0x64, 0xc0, 0x08, 0x0c, 0x00, 0x2a, 0x02, 0x06,
            0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x03,
            0xc0, 0x10, 0x10, 0x00, 0x06, 0x00, 0x00, 0x44,
            0x9c, 0x40, 0x00, 0x40, 0x04, 0x00, 0x00, 0x44,
            0x9c, 0x40, 0x00, 0x80, 0x0a, 0x04, 0x0a, 0x00,
            0x00, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x01, 0x19, 0xc6, 0x33,
            0x64, 0x00
        ];
        let sc = SessionConfig::modern_addpath();
        let upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
            .unwrap().try_into().unwrap();

        for c in upd.all_communities().unwrap() {
            println!("{}", c);
        }
        assert!(upd.all_communities().unwrap().eq(&[
              Community::Standard(StandardCommunity::new(42.into(), Tag::new(518))),
              Wellknown::NoExport.into(),
              Wellknown::NoExportSubconfed.into(),
              [0x00, 0x06, 0x00, 0x00, 0x44, 0x9c, 0x40, 0x00].into(),
              [0x40, 0x04, 0x00, 0x00, 0x44, 0x9c, 0x40, 0x00].into(),
        ]))

    }

    #[test]
    fn bgpsec() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0xab, 0x02, 0x00, 0x00, 0x00, 0x94, 0x90,
            0x0e, 0x00, 0x11, 0x00, 0x01, 0x01, 0x04, 0xac,
            0x12, 0x00, 0x02, 0x00, 0x18, 0xc0, 0x00, 0x02,
            0x18, 0xc0, 0x00, 0x03, 0x40, 0x01, 0x01, 0x00,
            0x40, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x80,
            0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x90, 0x21,
            0x00, 0x69, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
            0xfb, 0xf0, 0x00, 0x61, 0x01, 0xab, 0x4d, 0x91,
            0x0f, 0x55, 0xca, 0xe7, 0x1a, 0x21, 0x5e, 0xf3,
            0xca, 0xfe, 0x3a, 0xcc, 0x45, 0xb5, 0xee, 0xc1,
            0x54, 0x00, 0x48, 0x30, 0x46, 0x02, 0x21, 0x00,
            0xe7, 0xb7, 0x0b, 0xaf, 0x00, 0x0d, 0xe1, 0xce,
            0x8b, 0xb2, 0x11, 0xaf, 0xd4, 0x8f, 0xc3, 0x76,
            0x59, 0x54, 0x3e, 0xa5, 0x80, 0x5c, 0xa2, 0xa2,
            0x06, 0x3a, 0xc9, 0x2e, 0x12, 0xfa, 0xc0, 0x67,
            0x02, 0x21, 0x00, 0xa5, 0x8c, 0x0f, 0x37, 0x0e,
            0xe9, 0x77, 0xae, 0xd4, 0x11, 0xbd, 0x3f, 0x0f,
            0x47, 0xbb, 0x1f, 0x38, 0xcf, 0xde, 0x09, 0x49,
            0xd5, 0x97, 0xcd, 0x2e, 0x41, 0xa4, 0x8a, 0x94,
            0x1b, 0x7e, 0xbf
            ];

        let sc = SessionConfig::modern_addpath();
        let upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
            .unwrap().try_into().unwrap();
        //for pa in upd.path_attributes() {
        //    println!("{}", pa.type_code());
        //    println!("{:#x?}", pa.value());
        //}
    }
}