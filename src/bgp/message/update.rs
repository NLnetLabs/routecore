use crate::bgp::message::Header;
use octseq::{Octets, Parser};
use log::debug;

use crate::asn::Asn;
use crate::bgp::aspath::AsPath;
use crate::bgp::path_attributes::{
    Aggregator, AggregatorInfo,
    PathAttributes, PathAttributeType, WireformatPathAttribute
};
pub use crate::bgp::types::{
    AFI, SAFI, LocalPref, MultiExitDisc, NextHop, OriginType,
};

use crate::bgp::message::nlri::{
    Nlri, BasicNlri, EvpnNlri, MplsNlri, MplsVpnNlri, VplsNlri, FlowSpecNlri,
    RouteTargetNlri
};

use core::ops::Range; 
use std::net::Ipv4Addr;
use crate::util::parser::ParseError;


use crate::bgp::communities::{
    Community, StandardCommunity,
    ExtendedCommunity, Ipv6ExtendedCommunity, 
    LargeCommunity
};

/// BGP UPDATE message, variant of the [`Message`] enum.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct UpdateMessage<Octs: Octets> {
    octets: Octs,
    withdrawals: Range<usize>,
    attributes: Range<usize>,
    announcements: Range<usize>,
    session_config: SessionConfig,
}


impl<Octs: Octets> UpdateMessage<Octs> {

    pub fn octets(&self) -> &Octs {
        &self.octets
    }

    ///// Returns the [`Header`] for this message.
    //pub fn header(&self) -> Header<&Octs> {
    //    Header::for_slice(&self.octets)
    //}

    /// Returns the length in bytes of the entire BGP message.
	pub fn length(&self) -> usize {
        //// marker, length, type
        16 + 2 + 1  
        // length of withdrawals
        + 2 + self.withdrawals.len()
        // length of path attributes
        + 2 + self.attributes.len()
        // remainder is announcements, no explicit length field
        + self.announcements.len()
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
    //pub fn for_slice_old(s: Octs, config: SessionConfig) -> Self {
    //    Self {
    //        octets: s,
    //        session_config: config
    //    }
    //}
}

impl<Octs: Octets> UpdateMessage<Octs> {
    /// Print the UpdateMessage in a `text2pcap` compatible way.
    pub fn print_pcap(&self) {
        println!("{}", self.fmt_pcap_string());
    }

    /// Format the UpdateMessage in a `text2pcap` compatible way.
    pub fn fmt_pcap_string(&self) -> String {
        let mut res = String::with_capacity(
            7 + ((19 + self.octets.as_ref().len()) * 3)
        );

        res.push_str(
            "000000 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff "
        );

        let len = u16::try_from(self.length())
            .unwrap_or(u16::MAX)
            .to_be_bytes();

        res.push_str(&format!("{:02x} {:02x} 02 ", len[0], len[1])); 

        for b in self.octets.as_ref() {
            res.push_str(&format!("{:02x} ", b));
        }

        res
    }

    pub fn withdrawn_routes_len(&self) -> usize {
        self.withdrawals.len()
    }
}

impl<Octs: Octets> UpdateMessage<Octs> {

    /// Returns the conventional withdrawals.
    pub fn conventional_withdrawals(&self) -> Result<Nlris<Octs>, ParseError>
    {
        let pp = Parser::with_range(self.octets(), self.withdrawals.clone());

        let iter = Nlris {
            parser: pp,
            session_config: self.session_config,
            afi: AFI::Ipv4,
            safi: SAFI::Unicast
        };

        Ok(iter)

    }

    /// Returns the withdrawals from the MP_UNREACH_NLRI attribute, if any.
    pub fn mp_withdrawals(&self) -> Result<Option< Nlris<Octs>>, ParseError>
    {
        if let Some(WireformatPathAttribute::MpUnreachNlri(epa)) = self.path_attributes()?.get(
            PathAttributeType::MpUnreachNlri
        ){
            let mut parser = epa.value_into_parser();
            let afi = parser.parse_u16_be()?.into();
            let safi = parser.parse_u8()?.into();
            return Ok(Some(Nlris{
                parser, 
                session_config: self.session_config,
                afi,
                safi
            }))
        }

       Ok(None)
    }

    /// Returns a combined iterator of conventional and MP_UNREACH_NLRI.
    ///
    /// Note that this iterator might contain NLRI of different AFI/SAFI
    /// types.
    pub fn withdrawals(&self)
        -> Result<
            impl Iterator<Item = Result<Nlri<Octs::Range<'_>>, ParseError>>,
            ParseError
            >
    {
        let mp_iter = self.mp_withdrawals()?.map(|i| i.iter());
        let conventional_iter = self.conventional_withdrawals()?.iter();

        Ok(mp_iter.into_iter().flatten().chain(conventional_iter))

    }

    /// Creates a vec of all withdrawals in this message.
    ///
    /// If any of the NLRI, in the conventional part or the MP_UNREACH_NLRI
    /// attribute, is invalid in any way, returns an Error.
    /// This means the result is either the complete (possibly empty)
    /// collection of all the announced NLRI, or none at all.
    ///
    /// For more fine-grained control, consider using the
    /// `unicast_withdrawals` method.
    pub fn withdrawals_vec(&self) 
        -> Result<Vec<Nlri<Octs::Range<'_>>>, ParseError>
    {
        let conv = self.conventional_withdrawals()?.iter();
        let mp = self.mp_withdrawals()?.map(|mp| mp.iter());

        conv.chain(mp.into_iter().flatten()).collect()
    }

    // RFC4271: A value of 0 indicates that neither the Network Layer
    // Reachability Information field nor the Path Attribute field is present
    // in this UPDATE message.
    pub fn total_path_attribute_len(&self) -> usize {
        self.attributes.len()
    }

    pub fn path_attributes(&self)
        -> Result<PathAttributes<Octs>, ParseError>
    {
        let pp = Parser::with_range(self.octets(), self.attributes.clone());

        Ok(PathAttributes::new(pp, self.session_config))
    }

    /// Returns the conventional announcements.
    pub fn conventional_announcements(&self)
        -> Result<Nlris<Octs>, ParseError>
    {
        let pp = Parser::with_range(self.octets(), self.announcements.clone());

        let iter = Nlris {
            parser: pp,
            session_config: self.session_config,
            afi: AFI::Ipv4,
            safi: SAFI::Unicast
        };

        Ok(iter)
    }

    /// Returns the announcements from the MP_UNREACH_NLRI attribute, if any.
    pub fn mp_announcements(&self) -> Result<Option<Nlris<Octs>>, ParseError>
    {
        if let Some(WireformatPathAttribute::MpReachNlri(epa)) = self.path_attributes()?.get(
            PathAttributeType::MpReachNlri
        ){
            let mut parser = epa.value_into_parser();
            let afi = parser.parse_u16_be()?.into();
            let safi = parser.parse_u8()?.into();
            NextHop::skip(&mut parser)?;
            parser.advance(1)?; // 1 reserved byte
            return Ok(Some(Nlris{
                parser, 
                session_config: self.session_config,
                afi,
                safi
            }))
        }

       Ok(None)
    }

    /// Returns a combined iterator of conventional and MP_REACH_NLRI.
    ///
    /// Consuming the returned iterator requires care. The `Item` is a
    /// Result, containing either a successfully parsed `Nlri`, or an Error
    /// describing why it failed to parse. After one such error, the iterator
    /// will return None on the next call to `next()`.
    ///
    /// This means that, if at any point an Error is returned from the
    /// iterator, there likely is unparsed data in the PDU in either the
    /// conventional part at the end of the PDU, or in the MP_REACH_NLRI
    /// attribute. So, at best, one has an incomplete view of the announced
    /// NLRI, but possibly even that incomplete view is not 100% correct
    /// depending on the exact reason the parsing failed.
    ///
    /// With the above in mind, using `.count()` on this iterator to get the
    /// number of announced prefixes might give the wrong impression, as it
    /// will count the Error case, after which the iterator fuses.
    ///
    /// To retrieve all announcements if and only if all are validly parsed,
    /// consder using `fn announcements_vec`.
    ///
    /// Note that this iterator might contain NLRI of different AFI/SAFI
    /// types.
    pub fn announcements(&self)
        -> Result<
            impl Iterator<Item = Result<Nlri<Octs::Range<'_>>, ParseError>>,
            ParseError
            >
    {
        let mp_iter = self.mp_announcements()?.map(|i| i.iter());
        let conventional_iter = self.conventional_announcements()?.iter();

        Ok(mp_iter.into_iter().flatten().chain(conventional_iter))
    }

    /// Creates a vec of all announcements in this message.
    ///
    /// If any of the NLRI, in the conventional part or the MP_REACH_NLRI
    /// attribute, is invalid in any way, returns an Error.
    /// This means the result is either the complete (possibly empty)
    /// collection of all the announced NLRI, or none at all.
    ///
    /// For more fine-grained control, consider using the
    /// `unicast_announcements` method.
    pub fn announcements_vec(&self) 
        -> Result<Vec<Nlri<Octs::Range<'_>>>, ParseError>
    {
        let conv = self.conventional_announcements()?.iter();
        let mp = self.mp_announcements()?.map(|mp| mp.iter());

        conv.chain(mp.into_iter().flatten()).collect()
    }

    /// Returns a combined iterator of conventional and unicast MP_REACH_NLRI.
    ///
    /// If at any point an error occurs, the iterator returns that error and
    /// fuses itself, i.e. any following call to `next()` will return None.
    pub fn unicast_announcements(&self)
        -> Result<
            impl Iterator<Item = Result<BasicNlri, ParseError>> + '_,
            ParseError
        >
    {
        let mp_iter = self.mp_announcements()?.filter(|nlris|
            matches!((nlris.afi(), nlris.safi()), 
                     (AFI::Ipv4 | AFI::Ipv6, SAFI::Unicast)
            )
        ).map(|nlris| nlris.iter());

        let conventional_iter = self.conventional_announcements()?.iter();

        Ok(mp_iter.into_iter().flatten().chain(conventional_iter)
           .map(|n|
                match n {
                Ok(Nlri::Unicast(b)) => Ok(b),
                Ok(_) => unreachable!(),
                Err(e) => Err(e),
                }
           )
        )
    }

    /// Creates a vec of all unicast announcements in this message.
    ///
    /// If any of the NLRI, in the conventional part or the MP_REACH_NLRI
    /// attribute, is invalid in any way, returns an Error.
    /// This means the result is either the complete (possibly empty)
    /// collection of all the announced NLRI, or none at all.
    ///
    /// For more fine-grained control, consider using the
    /// `unicast_announcements` method.
    pub fn unicast_announcements_vec(&self)
        -> Result<Vec<BasicNlri>, ParseError>
    {
        let conv = self.conventional_announcements()?
            .iter().map(|n|
                if let Ok(Nlri::Unicast(b)) = n {
                    Ok(b)
                } else {
                    Err(ParseError::form_error(
                        "invalid announced conventional unicast NLRI"
                    ))
                }
            )
        ;

        let mp = self.mp_announcements()?.map(|mp| mp.iter()
            .filter_map(|n|
                 match n {
                     Ok(Nlri::Unicast(b)) => Some(Ok(b)),
                     Ok(_) => None,
                     _ => {
                         Some(Err(ParseError::form_error(
                            "invalid announced MP unicast NLRI"
                         )))
                     }
                 }
            ))
        ;

        conv.chain(mp.into_iter().flatten()).collect()
    }


    /// Returns a combined iterator of conventional and unicast
    /// MP_UNREACH_NLRI.
    ///
    /// If at any point an error occurs, the iterator returns that error and
    /// fuses itself, i.e. any following call to `next()` will return None.
    pub fn unicast_withdrawals(&self)
        -> Result<
            impl Iterator<Item = Result<BasicNlri, ParseError>> + '_,
            ParseError
        >
    {
        let mp_iter = self.mp_withdrawals()?.filter(|nlris|
            matches!((nlris.afi(), nlris.safi()), 
                     (AFI::Ipv4 | AFI::Ipv6, SAFI::Unicast)
            )
        ).map(|nlris| nlris.iter());

        let conventional_iter = self.conventional_withdrawals()?.iter();

        Ok(mp_iter.into_iter().flatten().chain(conventional_iter)
           .map(|n|
                match n {
                    Ok(Nlri::Unicast(b)) => Ok(b),
                    Ok(_) => unreachable!(),
                    Err(e) => Err(e),
                }
           )
        )
    }

    /// Creates a vec of all unicast withdrawals in this message.
    ///
    /// If any of the NLRI, in the conventional part or the MP_UNREACH_NLRI
    /// attribute, is invalid in any way, returns an Error.
    /// This means the result is either the complete (possibly empty)
    /// collection of all the withdrawn NLRI, or none at all.
    ///
    /// For more fine-grained control, consider using the
    /// `unicast_withdrawals` method.
    pub fn unicast_withdrawals_vec(&self)
        -> Result<Vec<BasicNlri>, ParseError>
    {
        let conv = self.conventional_withdrawals()?
            .iter().map(|n|
                if let Ok(Nlri::Unicast(b)) = n {
                    Ok(b)
                } else {
                    Err(ParseError::form_error(
                        "invalid withdrawn conventional unicast NLRI"
                    ))
                }
            )
        ;

        let mp = self.mp_withdrawals()?.map(|mp| mp.iter()
            .filter_map(|n|
                 match n {
                     Ok(Nlri::Unicast(b)) => Some(Ok(b)),
                     Ok(_) => None,
                     _ => {
                         Some(Err(ParseError::form_error(
                            "invalid withdrawn MP unicast NLRI"
                         )))
                     }
                 }
            ))
        ;

        conv.chain(mp.into_iter().flatten()).collect()
    }

    pub fn has_conventional_nlri(&self) -> bool {
        self.announcements.len() > 0
    }

    pub fn has_mp_nlri(&self) -> Result<bool, ParseError> {
        Ok(
            self.path_attributes()?
                .get(PathAttributeType::MpReachNlri).is_some()
        )
    }

    /// Returns `Option<(AFI, SAFI)>` if this UPDATE represents the End-of-RIB
    /// marker for a AFI/SAFI combination.
    pub fn is_eor(&self) -> Result<Option<(AFI, SAFI)>, ParseError> {
        // Conventional BGP
        if self.length() == 23 {
            // minimum length for a BGP UPDATE indicates EOR
            // (no announcements, no withdrawals)
            return Ok(Some((AFI::Ipv4, SAFI::Unicast)));
        }

        // Based on MP_UNREACH_NLRI

        let mut pas = self.path_attributes()?;
        if let Some(Ok(WireformatPathAttribute::MpUnreachNlri(epa))) = pas.next() {
            let mut pa = epa.value_into_parser();
            if pa.remaining() == 3 && pas.next().is_none() {
                let afi = pa.parse_u16_be()?.into();
                let safi = pa.parse_u8()?.into();
                return Ok(Some((afi, safi)))
            }
        }

        Ok(None)
    }

    //--- Methods to access mandatory path attributes ------------------------
    // Mandatory path attributes are ORIGIN, AS_PATH and NEXT_HOP
    // Though, in case of MP_REACH_NLRI, NEXT_HOP must be ignored if present.
    //
    // Also note that these are only present in announced routes. A BGP UPDATE
    // with only withdrawals will not have any of these mandatory path
    // attributes present.
    pub fn origin(&self) -> Result<Option<OriginType>, ParseError> {
        if let Some(WireformatPathAttribute::Origin(epa)) = self.path_attributes()?.get(PathAttributeType::Origin) {
            Ok(Some(epa.value_into_parser().parse_u8()?.into()))
        } else {
            Ok(None)
        }
    }

    /// Returns the AS4_PATH attribute.
    pub fn as4path(&self) -> Result<
        Option<AsPath<Octs::Range<'_>>>,
        ParseError
    > {
        if let Some(WireformatPathAttribute::As4Path(epa)) = self.path_attributes()?.get(PathAttributeType::As4Path) {
            let mut p = epa.value_into_parser();
            Ok(Some(AsPath::new(p.parse_octets(p.remaining())?, true)?))
        } else {
            Ok(None)
        }
    }


    /// Returns the AS_PATH path attribute.
    //
    // NOTE: This is now the AS PATH and only the AS_PATH.
    pub fn aspath(&self)
        -> Result<Option<AsPath<Octs::Range<'_>>>, ParseError>
    {
        if let Some(WireformatPathAttribute::AsPath(epa)) = self.path_attributes()?.get(PathAttributeType::AsPath) {
            let mut p = epa.value_into_parser();
            Ok(Some(AsPath::new(p.parse_octets(p.remaining())?,
            epa.session_config().has_four_octet_asn())?))
        } else {
            Ok(None)
        }
    }

    /// Returns NextHop information from the NEXT_HOP path attribute, if any.
    pub fn conventional_next_hop(&self)
        -> Result<Option<NextHop>, ParseError>
    {
        if let Some(WireformatPathAttribute::NextHop(epa)) = self.path_attributes()?.get(PathAttributeType::NextHop) {
            Ok(Some(NextHop::Unicast(Ipv4Addr::from(epa.value_into_parser().parse_u32_be()?).into())))
        } else {
            Ok(None)
        }
    }

    /// Returns NextHop information from the MP_REACH_NLRI, if any.
    pub fn mp_next_hop(&self) -> Result<Option<NextHop>, ParseError> {
        if let Some(WireformatPathAttribute::MpReachNlri(epa)) = self.path_attributes()?.get(
            PathAttributeType::MpReachNlri
        ){
            let mut p = epa.value_into_parser();
            let afi = p.parse_u16_be()?.into();
            let safi = p.parse_u8()?.into();
            Ok(Some(NextHop::parse(&mut p, afi, safi)?))
        } else {
            Ok(None)
        }

    }

    pub fn find_next_hop(&self, afi: AFI, safi: SAFI) -> Result<NextHop, ParseError> {
        match (afi, safi) {
            (AFI::Ipv4, SAFI::Unicast) => {
                if let Ok(Some(mp)) = self.mp_next_hop() {
                    if mp.afi_safi() == (AFI::Ipv4, SAFI::Unicast) {
                        return Err(ParseError::form_error(
                            "ambiguous IPv4 Unincast nexthop"
                        ))
                    }
                }

                if let Ok(maybe_nh) = self.conventional_next_hop() {
                    if let Some(nh) = maybe_nh {
                        Ok(nh)
                    } else {
                        Err(ParseError::form_error(
                             "no conventional NEXT_HOP"
                        ))
                    }
                } else {
                    Err(ParseError::form_error(
                            "invalid conventional NEXT_HOP"
                    ))
                }
            }
            (..) => {
                if let Ok(maybe_mp) = self.mp_next_hop() {
                    if let Some(mp) = maybe_mp {
                        if mp.afi_safi() != (afi, safi) {
                            return Err(ParseError::form_error(
                                 "MP_REACH_NLRI for different AFI/SAFI"
                            ))
                        }
                        Ok(mp)
                    } else {
                        Err(ParseError::form_error(
                             "no MP_REACH_NLRI / nexthop"
                        ))
                    }
                } else {
                    Err(ParseError::form_error(
                            "invalid MP_REACH_NLRI / nexthop"
                    ))
                }
            }
        }
    }

    //--- Non-mandatory path attribute helpers -------------------------------

    /// Returns the Multi-Exit Discriminator value, if any.
    pub fn multi_exit_disc(&self)
        -> Result<Option<MultiExitDisc>, ParseError>
    {
        if let Some(WireformatPathAttribute::MultiExitDisc(epa)) = self.path_attributes()?.get(
            PathAttributeType::MultiExitDisc
        ){
            Ok(Some(MultiExitDisc(epa.value_into_parser().parse_u32_be()?)))
        } else {
            Ok(None)
        }

    }

    /// Returns the Local Preference value, if any.
    pub fn local_pref(&self) -> Result<Option<LocalPref>, ParseError> {
        if let Some(WireformatPathAttribute::LocalPref(epa)) = self.path_attributes()?.get(
            PathAttributeType::LocalPref
        ){
            Ok(Some(LocalPref(epa.value_into_parser().parse_u32_be()?)))
        } else {
            Ok(None)
        }
    }

    /// Returns true if this UPDATE contains the ATOMIC_AGGREGATE path
    /// attribute.
    pub fn is_atomic_aggregate(&self) -> Result<bool, ParseError> {
        Ok(
            self.path_attributes()?
                .get(PathAttributeType::AtomicAggregate).is_some()
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
    pub fn aggregator(&self) -> Result<Option<AggregatorInfo>, ParseError> {

        if let Some(WireformatPathAttribute::Aggregator(epa)) = self.path_attributes()?.get(
            PathAttributeType::Aggregator
        ){
            // XXX not nice that we have to do this here, also it is exactly
            // the same as in the fn parse in path_attributes.rs
            use crate::util::parser::parse_ipv4addr;
            let mut pa = epa.value_into_parser();
            let asn = if self.session_config.has_four_octet_asn() {
                Asn::from_u32(pa.parse_u32_be()?)
            } else {
                Asn::from_u32(pa.parse_u16_be()?.into())
            };

            let address = parse_ipv4addr(&mut pa)?;
            Ok(Some(AggregatorInfo::new(asn, address)))
            //Ok(Some(Aggregator::parse2(&mut epa.value_into_parser(), epa.session_config())?.inner()))
        } else {
            Ok(None)
        }
    }


    //--- Communities --------------------------------------------------------

    /// Returns an iterator over Standard Communities (RFC1997), if any.
    pub fn communities(&self)
        -> Result<Option<CommunityIter<Octs::Range<'_>>>, ParseError>
    {
        if let Some(WireformatPathAttribute::Communities(epa)) = self.path_attributes()?.get(PathAttributeType::Communities) {
            let mut p = epa.value_into_parser();
            Ok(Some(CommunityIter::new(p.parse_octets(p.remaining())?)))
        } else {
            Ok(None)
        }
    }

    /// Returns an iterator over Extended Communities (RFC4360), if any.
    pub fn ext_communities(&self)
        -> Result<Option<ExtCommunityIter<Octs::Range<'_>>>, ParseError>
    {
        if let Some(WireformatPathAttribute::ExtendedCommunities(epa)) = self.path_attributes()?.get(PathAttributeType::ExtendedCommunities) {
            let mut p = epa.value_into_parser();
            Ok(Some(ExtCommunityIter::new(p.parse_octets(p.remaining())?)))
        } else {
            Ok(None)
        }
    }

    /// Returns an iterator over Large Communities (RFC8092), if any.
    pub fn large_communities(&self)
        -> Result<Option<LargeCommunityIter<Octs::Range<'_>>>, ParseError>
    {
        if let Some(WireformatPathAttribute::LargeCommunities(epa)) = self.path_attributes()?.get(PathAttributeType::LargeCommunities) {
            let mut p = epa.value_into_parser();
            Ok(Some(LargeCommunityIter::new(p.parse_octets(p.remaining())?)))
        } else {
            Ok(None)
        }
    }

    /// Returns an optional `Vec` containing all conventional, Extended and
    /// Large communities, if any, or None if none of the three appear in the
    /// path attributes of this message.
    pub fn all_communities(&self) -> Result<Option<Vec<Community>>, ParseError> {
        let mut res = Vec::<Community>::new();

        if let Some(c) = self.communities()? {
            res.append(&mut c.collect::<Vec<_>>());
        }
        if let Some(c) = self.ext_communities()? {
            res.append(&mut c.map(Community::Extended).collect::<Vec<_>>());
        }
        if let Some(c) = self.large_communities()? {
            res.append(&mut c.map(Community::Large).collect::<Vec<_>>());
        }

        if res.is_empty() {
            Ok(None)
        } else {
            Ok(Some(res))
        }
    }
    
}


impl<Octs: Octets> UpdateMessage<Octs> {
    /// Create an UpdateMessage from an octets sequence.
    ///
    /// The 16 byte marker, length and type byte must be present when parsing,
    /// and will be included from `octets`.
    ///
    /// As parsing of BGP UPDATE messages requires stateful information
    /// signalled by the BGP OPEN messages, this function requires a
    /// [`SessionConfig`].
    pub fn from_octets(octets: Octs, config: SessionConfig)
        -> Result<Self, ParseError>
    {
        let mut parser = Parser::from_ref(&octets);
        let UpdateMessage{withdrawals, attributes, announcements, ..} = UpdateMessage::<_>::parse(&mut parser, config)?;
        let res  = 
            Self {
                octets,
                withdrawals: (withdrawals.start +19..withdrawals.end + 19),
                attributes: (attributes.start +19..attributes.end + 19),
                announcements: (announcements.start +19..announcements.end + 19),
                session_config: config
            }
        ;

        Ok(res)
    }

    /// Parses an UpdateMessage from `parser`.
    ///
    /// The 16 byte marker, length and type byte must be present when parsing,
    /// but will not be included in the resulting `Octs`.
    pub fn parse<'a, R: Octets>(
        mut parser: &mut Parser<'a, R>,
        config: SessionConfig
    ) -> Result<UpdateMessage<R::Range<'a>>, ParseError>
    where
        R: Octets<Range<'a> = Octs>,
    {

        let header = Header::parse(&mut parser)?;
        let start_pos = parser.pos();

        let withdrawals_len = parser.parse_u16_be()?;
        let withdrawals_start = parser.pos() - start_pos;
        if withdrawals_len > 0 {
            let mut wdraw_parser = parser.parse_parser(
                withdrawals_len.into()
            )?;
            while wdraw_parser.remaining() > 0 {
                // conventional withdrawals are always IPv4
                BasicNlri::check(&mut wdraw_parser, config, AFI::Ipv4)?;
            }
        }
        let withdrawals_end = parser.pos() - start_pos;
        let withdrawals = if withdrawals_start == withdrawals_end {
            (0..0)
        } else {
            (withdrawals_start..withdrawals_end)
        };


        let attributes_len = parser.parse_u16_be()?;
        let mut attributes_start = parser.pos() - start_pos;
        if attributes_len > 0 {
            let pas_parser = parser.parse_parser(
                attributes_len.into()
            )?;
            // XXX this calls `validate` on every attribute, do we want to
            // error on that level here?
            for pa in PathAttributes::new(pas_parser, config).into_iter() {
               pa?;
            }
        }
        let attributes_end = parser.pos() - start_pos;
        let attributes = if attributes_start == attributes_end {
            (0..0)
        } else {
            (attributes_start..attributes_end)
        };

        let announcements_start = parser.pos() - start_pos;
        while parser.pos() < start_pos + header.length() as usize - 19 {
            // conventional announcements are always IPv4
            BasicNlri::check(&mut parser, config, AFI::Ipv4)?;
        }

        let end_pos = parser.pos() - start_pos;

        let announcements = if announcements_start == end_pos {
            (0..0)
        } else {
            (announcements_start..end_pos)
        };


        if end_pos != (header.length() as usize) - 19 {
            return Err(ParseError::form_error(
                "message length and parsed bytes do not match"
            ));
        }

        parser.seek(start_pos)?;

        Ok(UpdateMessage {
            octets: parser.parse_octets((header.length() - 19).into())?,
            withdrawals,
            attributes,
            announcements,
            session_config: config
        })
    }

    pub fn into_octets(self) -> Octs {
        self.octets
    }


}
//--- Enums for passing config / state ---------------------------------------

//--------- SessionConfig ----------------------------------------------------

/// Configuration parameters for an established BGP session.
///
/// The `SessionConfig` is a structure holding parameters to parse messages
/// for the particular session. Storing these parameters is necessary because
/// some information crucial to correctly parsing BGP UPDATE messages is not
/// available in the UPDATE messages themselves, but are only exchanged in the
/// BGP OPEN messages when the session was established.
///
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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

    pub fn has_four_octet_asn(&self) -> bool {
        matches!(self.four_octet_asn, FourOctetAsn::Enabled)
    }

    pub fn addpath_enabled(&self) -> bool {
        matches!(self.add_path, AddPath::Enabled)
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
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum FourOctetAsn {
    Enabled,
    Disabled,
}

/// Indicates whether AddPath is enabled for this session.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AddPath {
    Enabled,
    Disabled,
}


//--- Aggregator -------------------------------------------------------------
///// Path Attribute (7).
//#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
//#[cfg_attr(feature = "serde", derive(serde::Serialize))]
//pub struct Aggregator {
//    asn: Asn,
//    speaker: Ipv4Addr,
//}
//
//impl Aggregator {
//    /// Creates a new Aggregator.
//    pub fn new(asn: Asn, speaker: Ipv4Addr) -> Self {
//        Aggregator{ asn, speaker }
//    }
//
//    /// Returns the `Asn`.
//    pub fn asn(&self) -> Asn {
//        self.asn
//    }
//
//    /// Returns the speaker IPv4 address.
//    pub fn speaker(&self) -> Ipv4Addr {
//        self.speaker
//    }
//}

//impl fmt::Display for Aggregator {
//    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//        write!(f, "AS{} Speaker {}", self.asn, self.speaker)        
//    }
//}


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

/// Represents the announced NLRI in a BGP UPDATE message.
pub struct Nlris<'a, Octs: Octets> {
    parser: Parser<'a, Octs>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<'a, Octs: Octets> Nlris<'a, Octs> {
    pub fn new(
        parser: Parser<'a, Octs>,
        session_config: SessionConfig,
        afi: AFI,
        safi: SAFI
    ) -> Nlris<'a, Octs> {
        Nlris { parser, session_config, afi, safi }
    }

    pub fn iter(&self) -> NlriIter<'a, Octs> {
        NlriIter {
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
///
/// If at any point an error occurs, the iterator returns that error and fuses
/// itself, i.e. any following call to `next()` will return None.
pub struct NlriIter<'a, Octs> {
    parser: Parser<'a, Octs>,
    session_config: SessionConfig,
    afi: AFI,
    safi: SAFI,
}

impl<'a, Octs: Octets> NlriIter<'a, Octs> {
    fn get_nlri(&mut self) -> Result<Nlri<Octs::Range<'a>>, ParseError> {
        let res = match (self.afi, self.safi) {
            (AFI::Ipv4 | AFI::Ipv6, SAFI::Unicast) => {
                Nlri::Unicast(BasicNlri::parse(
                        &mut self.parser,
                        self.session_config,
                        self.afi
                )?)
            }
            (AFI::Ipv4 | AFI::Ipv6, SAFI::Multicast) => {
                Nlri::Multicast(BasicNlri::parse(
                        &mut self.parser,
                        self.session_config,
                        self.afi
                )?)
            }
            (AFI::Ipv4 | AFI::Ipv6, SAFI::MplsVpnUnicast) => {
                Nlri::MplsVpn(MplsVpnNlri::parse(
                        &mut self.parser,
                        self.session_config,
                        self.afi
                )?)
            },
            (AFI::Ipv4 | AFI::Ipv6, SAFI::MplsUnicast) => {
                Nlri::Mpls(MplsNlri::parse(
                        &mut self.parser,
                        self.session_config,
                        self.afi
                )?)
            },
            (AFI::L2Vpn, SAFI::Vpls) => {
                Nlri::Vpls(VplsNlri::parse(
                        &mut self.parser
                )?)
            },
            (AFI::Ipv4 | AFI::Ipv6, SAFI::FlowSpec) => {
                Nlri::FlowSpec(FlowSpecNlri::parse(
                        &mut self.parser, self.afi
                )?)
            },
            (AFI::Ipv4, SAFI::RouteTarget) => {
                Nlri::RouteTarget(RouteTargetNlri::parse(
                        &mut self.parser
                )?)
            },
            (AFI::L2Vpn, SAFI::Evpn) => {
                Nlri::Evpn(EvpnNlri::parse(
                        &mut self.parser
                )?)
            },
            (_, _) => {
                debug!("trying to iterate over NLRI \
                       for unknown AFI/SAFI combination {}/{}",
                       self.afi, self.safi
                );

                // As all the NLRI in the iterator are of the same AFI/SAFI
                // type, we will not be able to make sense of anything in this
                // blob of NLRI. We advance the parser so the next call to
                // next() on this iterator will return None, and be done with
                // it.
                self.parser.advance(self.parser.remaining())?;
                return Err(ParseError::Unsupported)
            }
        };
        Ok(res)
    }
}

impl<'a, Octs: Octets> Iterator for NlriIter<'a, Octs> {
    type Item = Result<Nlri<Octs::Range<'a>>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        match self.get_nlri() {
            Ok(n) => Some(Ok(n)),
            Err(e) => {
                // Whenever an error occured, e.g. because the NLRI could not
                // be parsed, we return the error and 'fuse' the iterator by
                // advancing the parser, ensuring the next call to `next()`
                // returns a None.
                self.parser.advance(self.parser.remaining()).ok()?;
                Some(Err(e))
            }
        }
    }
}


//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;
    use crate::bgp::communities::{
        ExtendedCommunityType,
        ExtendedCommunitySubType,
        Tag, Wellknown,
    };
    use crate::bgp::message::{Message, nlri::PathId};
    use crate::addr::Prefix;

    use bytes::Bytes;

    #[allow(dead_code)]
    fn print_pcap<T: AsRef<[u8]>>(buf: T) {
        print!("000000 ");
        for b in buf.as_ref() {
            print!("{:02x} ", b);
        }
        println!();
    }


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
        let pas = update.path_attributes().unwrap();
        let mut pa_iter = pas.into_iter();

        let pa1 = pa_iter.next().unwrap().unwrap();
        assert_eq!(pa1.type_code(), PathAttributeType::Origin);
        assert_eq!(pa1.flags(), 0x40.into());
        assert!(!pa1.flags().is_optional());
        assert!(pa1.flags().is_transitive());
        assert!(!pa1.flags().is_partial());
        assert!(!pa1.flags().is_extended_length());

        assert_eq!(pa1.length(), 1);
        //assert_eq!(pa1.as_ref(), &[0x00]); // TODO get inner, into
        //                                           // OriginType

        let pa2 = pa_iter.next().unwrap().unwrap();
        assert_eq!(pa2.type_code(), PathAttributeType::AsPath);
        assert_eq!(pa2.flags(), 0x40.into());
        assert_eq!(pa2.length(), 6);

        //assert_eq!(pa2.as_ref(), [0x02, 0x01, 0x00, 0x01, 0x00, 0x00]);

        /*
        let mut pb = AsPathBuilder::new();
        pb.push(Asn::from_u32(65536)).unwrap();
        let asp: AsPath<Vec<Asn>> = pb.finalize();
        */

        //assert_eq!(update.aspath().unwrap(), asp);

        let pa3 = pa_iter.next().unwrap().unwrap();
        assert_eq!(pa3.type_code(), PathAttributeType::NextHop);
        assert_eq!(pa3.flags(), 0x40.into());
        assert_eq!(pa3.length(), 4);
        //assert_eq!(pa3.as_ref(), &[10, 255, 0, 101]);
        assert_eq!(
            update.conventional_next_hop().unwrap(),
            Some(NextHop::Unicast(Ipv4Addr::new(10, 255, 0, 101).into()))
            );

        let pa4 = pa_iter.next().unwrap().unwrap();
        assert_eq!(pa4.type_code(), PathAttributeType::MultiExitDisc);
        assert_eq!(pa4.flags(), 0x80.into());
        assert!( pa4.flags().is_optional());
        assert!(!pa4.flags().is_transitive());
        assert!(!pa4.flags().is_partial());
        assert!(!pa4.flags().is_extended_length());
        assert_eq!(pa4.length(), 4);
        //assert_eq!(pa4.as_ref(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(update.multi_exit_disc().unwrap(), Some(MultiExitDisc(1)));

        assert!(pa_iter.next().is_none());

        let mut nlri_iter = update.announcements().unwrap();
        let nlri1 = nlri_iter.next().unwrap();
        assert_eq!(nlri1.unwrap(), Nlri::unicast_from_str("10.10.10.2/32").unwrap());
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
        assert_eq!(update.announcements().unwrap().count(), 2);

        let prefixes = ["10.10.10.9/32", "192.168.97.0/30"]
            .map(|p| Nlri::unicast_from_str(p).unwrap());

        assert!(prefixes.into_iter().eq(update.announcements().unwrap().map(|n| n.unwrap())));

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
        let update = UpdateMessage::from_octets(
            &buf,
            SessionConfig::modern()
        ).unwrap();

        assert_eq!(update.withdrawn_routes_len(), 0);
        assert_eq!(update.total_path_attribute_len(), 113);

        assert!(!update.has_conventional_nlri());
        assert!(update.has_mp_nlri().unwrap());
        
        let nlri_iter = update.announcements().unwrap();
        assert_eq!(nlri_iter.count(), 5);

        let prefixes = [
            "fc00::10/128",
            "2001:db8:ffff::/64",
            "2001:db8:ffff:1::/64",
            "2001:db8:ffff:2::/64",
            "2001:db8:ffff:3::/64",
        ].map(|p| Nlri::unicast_from_str(p).unwrap());

        assert!(prefixes.into_iter().eq(
                update.announcements().unwrap().map(|n| n.unwrap())
        ));

        assert!(prefixes.into_iter().eq(
                update.announcements_vec().unwrap().into_iter()
        ));

        assert!(update.unicast_announcements().unwrap()
                .map(|b| Nlri::<&[u8]>::Unicast(b.unwrap()))
                .eq(prefixes)
        );

        assert!(
            update.unicast_announcements_vec().unwrap().into_iter()
                .map(|b| Nlri::<&[u8]>::Unicast(b))
                .eq(prefixes)
        );

        assert!(update.find_next_hop(AFI::Ipv6, SAFI::Multicast).is_err());

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

        assert_eq!(update.withdrawals().unwrap().count(), 12);

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
        ].map(|w| Ok(Nlri::unicast_from_str(w).unwrap()));

        assert!(ws.into_iter().eq(update.withdrawals().unwrap()));
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

        assert_eq!(update.withdrawals().unwrap().count(), 4);

        let ws = [
            "2001:db8:ffff::/64",
            "2001:db8:ffff:1::/64",
            "2001:db8:ffff:2::/64",
            "2001:db8:ffff:3::/64",
        ].map(|w| Ok(Nlri::unicast_from_str(w).unwrap()));
        assert!(ws.into_iter().eq(update.withdrawals().unwrap()));
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
        assert_eq!(update.multi_exit_disc().unwrap(), Some(MultiExitDisc(0)));
        assert_eq!(update.local_pref().unwrap(), Some(LocalPref(100)));
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

        assert!(update.is_atomic_aggregate().unwrap());
        assert_eq!(aggr.unwrap().asn(), Asn::from(101));
        assert_eq!(
            aggr.unwrap().address(),
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
        if let Some(Ok(aspath)) = update.path_attributes().unwrap()
            .find(|pa| pa.as_ref().unwrap().type_code() == PathAttributeType::AsPath)
        {
            assert_eq!(aspath.flags(), 0x50.into());
            assert!(aspath.flags().is_transitive());
            assert!(aspath.flags().is_extended_length());
            assert_eq!(aspath.length(), 22);
            //TODO check actual aspath
        } else {
            panic!("ASPATH path attribute not found")
        }

        if let Some(Ok(as4path)) = update.path_attributes().unwrap()
            .find(|pa| pa.as_ref().unwrap().type_code() == PathAttributeType::As4Path)
        {
            assert_eq!(as4path.flags(), 0xd0.into());
            assert_eq!(as4path.length(), 42);
            //TODO check actual aspath
        } else {
            panic!("AS4PATH path attribute not found")
        }

        assert_eq!(
            update.aspath().unwrap().unwrap().hops().collect::<Vec<_>>(),
            AsPath::vec_from_asns([
                0xfbf0, 0xfbf1, 0xfbf2, 0xfbf3, 0x5ba0, 0x5ba0,
                0x5ba0, 0x5ba0, 0x5ba0, 0x5ba0
            ]).hops().collect::<Vec<_>>(),
        );
        assert_eq!(
            update.as4path().unwrap().unwrap().hops().collect::<Vec<_>>(),
            AsPath::vec_from_asns([
                0xfbf0, 0xfbf1, 0xfbf2, 0xfbf3, 0x10000, 0x10000,
                0x10000, 0x10000, 0x10001, 0x1000a,
            ]).hops().collect::<Vec<_>>(),
        );
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

        let nlri1 = upd.announcements().unwrap().next().unwrap();
        assert_eq!(
            nlri1.unwrap(),
            Nlri::<&[u8]>::Unicast(BasicNlri::with_path_id(
                    Prefix::from_str("198.51.100.0/25").unwrap(),
                    PathId::from_u32(1)
                    ))
        );

        assert!(upd.communities().unwrap().is_some());
        for c in upd.communities().unwrap().unwrap() { 
            println!("{:?}", c);
        }
        assert!(upd.communities().unwrap().unwrap()
            .eq([
                StandardCommunity::new(42.into(), Tag::new(518)).into(),
                Wellknown::NoExport.into(),
                Wellknown::NoExportSubconfed.into()
            ])
        );

        assert!(upd.ext_communities().unwrap().is_some());
        let mut ext_comms = upd.ext_communities().unwrap().unwrap();
        let ext_comm1 = ext_comms.next().unwrap();
        assert!(ext_comm1.is_transitive());

        assert_eq!(
            ext_comm1.types(),
            (ExtendedCommunityType::TransitiveTwoOctetSpecific,
             ExtendedCommunitySubType::OtherSubType(0x06))
            );

        use crate::asn::Asn16;
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

        let mut lcs = update.large_communities().unwrap().unwrap();
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

        for c in upd.all_communities().unwrap().unwrap() {
            println!("{}", c);
        }
        assert!(upd.all_communities().unwrap().unwrap()
            .eq(&[
                StandardCommunity::new(42.into(), Tag::new(518)).into(),
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
        let _upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
            .unwrap().try_into().unwrap();
        //for pa in upd.path_attributes() {
        //    println!("{}", pa.type_code());
        //    println!("{:#x?}", pa.value());
        //}
    }

    #[test]
    fn mp_ipv4_multicast() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x52, 0x02, 0x00, 0x00, 0x00, 0x3b, 0x80,
            0x0e, 0x1d, 0x00, 0x01, 0x02, 0x04, 0x0a, 0x09,
            0x0a, 0x09, 0x00, 0x1a, 0xc6, 0x33, 0x64, 0x00,
            0x1a, 0xc6, 0x33, 0x64, 0x40, 0x1a, 0xc6, 0x33,
            0x64, 0x80, 0x1a, 0xc6, 0x33, 0x64, 0xc0, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x00, 0x01, 0xf4, 0x40, 0x03, 0x04, 0x0a,
            0x09, 0x0a, 0x09, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x00
        ];
        let sc = SessionConfig::modern();
        let upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
            .unwrap().try_into().unwrap();
        assert_eq!(upd.mp_announcements().unwrap().unwrap().afi(), AFI::Ipv4);
        assert_eq!(upd.mp_announcements().unwrap().unwrap().safi(), SAFI::Multicast);
        let prefixes = [
            "198.51.100.0/26",
            "198.51.100.64/26",
            "198.51.100.128/26",
            "198.51.100.192/26",
        ].map(|p| Nlri::<&[u8]>::Multicast(Prefix::from_str(p).unwrap().into()));

        assert!(prefixes.into_iter().eq(upd.announcements().unwrap().map(|n| n.unwrap())));
    }

    #[test]
    fn mp_unreach_ipv4_multicast() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x1d+5, 0x02, 0x00, 0x00, 0x00, 0x06+5, 0x80,
            0x0f, 0x03+5, 0x00, 0x01, 0x02,
            0x1a, 0xc6, 0x33, 0x64, 0x00
        ]; 
        let sc = SessionConfig::modern();
        let upd: UpdateMessage<_> = Message::from_octets(&buf, Some(sc))
            .unwrap().try_into().unwrap();
        assert_eq!(upd.mp_withdrawals().unwrap().unwrap().afi(), AFI::Ipv4);
        assert_eq!(upd.mp_withdrawals().unwrap().unwrap().safi(), SAFI::Multicast);
        assert_eq!(upd.mp_withdrawals().unwrap().iter().count(), 1);
    }

    #[test]
    fn evpn() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x89, 0x02, 0x00, 0x00, 0x00, 0x72, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x40, 0x05,
            0x04, 0x00, 0x00, 0x00, 0x64, 0xc0, 0x10, 0x08,
            0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
            0x80, 0x09, 0x04, 0x78, 0x00, 0x02, 0x05, 0x80,
            0x0a, 0x04, 0x78, 0x00, 0x01, 0x01, 0x90, 0x0e,
            0x00, 0x47, 0x00, 0x19, 0x46, 0x04, 0x78, 0x00,
            0x02, 0x05, 0x00, 0x01, 0x19, 0x00, 0x01, 0x78,
            0x00, 0x02, 0x05, 0x00, 0x64, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x35, 0x01, 0x02, 0x21,
            0x00, 0x01, 0x78, 0x00, 0x02, 0x05, 0x00, 0x64,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x30, 0x00,
            0x0c, 0x29, 0x82, 0xc2, 0xa9, 0x00, 0x49, 0x30,
            0x01
        ];

        use crate::bgp::message::nlri::EvpnRouteType;

        let upd = UpdateMessage::from_octets(&buf, SessionConfig::modern())
            .unwrap();

        for n in upd.announcements().unwrap() {
            println!("{:?}", n.unwrap());
        }
        let mut announcements = upd.announcements().unwrap();
        if let Some(Ok(Nlri::Evpn(e))) = announcements.next() {
                assert_eq!(
                    e.route_type(),
                    EvpnRouteType::EthernetAutoDiscovery
                )
        } else { panic!() }
        if let Some(Ok(Nlri::Evpn(e))) = announcements.next() {
                assert_eq!(
                    e.route_type(),
                    EvpnRouteType::MacIpAdvertisement)
        } else { panic!() }
        assert!(announcements.next().is_none());

        assert_eq!(
            upd.mp_next_hop().unwrap(),
            Some(NextHop::Evpn(Ipv4Addr::from_str("120.0.2.5").unwrap().into()))
        );
    }

    #[test]
    fn unknown_afi_safi_announcements() {
        // botched BGP UPDATE message containing MP_REACH_NLRI path attribute,
        // comprising 5 (originally) IPv6 unicast NLRIs, but with the AFI/SAFI
        // changed to 255/1
        // and
        // 2 conventional nlri
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x88 + 6, 0x02, 0x00, 0x00, 0x00, 0x71, 0x80,
            0x0e, 0x5a,
            //0x00, 0x02,
            0x00, 0xff,
            0x01,
            0x20, 0xfc, 0x00,
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
            0xc8, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
            // conventional NLRI
            16, 10, 10, // 10.10.0.0/16
            16, 10, 11, // 10.11.0.0/16
        ];
        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update = UpdateMessage::from_octets(
            &buf,
            SessionConfig::modern()
        ).unwrap();

        assert_eq!(update.mp_announcements().unwrap().unwrap().iter().count(), 1);
        assert!(update.mp_announcements().unwrap().unwrap().iter().next().unwrap().is_err());

        // We expect only the two conventional announcements here:
        assert_eq!(update.unicast_announcements().unwrap().count(), 2);

    }

    #[test]
    fn invalid_nlri_length_in_announcements() {
        // botched BGP UPDATE message containing MP_REACH_NLRI path attribute,
        // comprising 5 (originally) IPv6 unicast NLRIs, with the second one
        // having a prefix len of 129
        // and
        // 2 conventional nlri
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x88 + 6, 0x02, 0x00, 0x00, 0x00, 0x71, 0x80,
            0x0e, 0x5a,
            0x00, 0x02, // AFI
            0x01, // SAFI
            // NextHop:
            0x20,
            0xfc, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x00, // reserved byte
            0x80, 
            0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x81, // was 0x40, changed to 0x81 (/129)
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x02,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x03,
            0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00,
            0xc8, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
            // conventional NLRI
            16, 10, 10, // 10.10.0.0/16
            16, 10, 11, // 10.11.0.0/16
        ];

        let update = UpdateMessage::from_octets(
            &buf,
            SessionConfig::modern()
        ).unwrap();

        assert!(matches!(
            update.announcements_vec(),
            Err(ParseError::Form(..))
        ));

        assert!(matches!(
            update.unicast_announcements_vec(),
            Err(ParseError::Form(..))
        ));

        assert_eq!(update.announcements().unwrap().count(), 4);
        assert_eq!(update.unicast_announcements().unwrap().count(), 4);

        assert!(
            update.unicast_announcements().unwrap().eq(
            [
                Ok(BasicNlri::new(Prefix::from_str("fc00::10/128").unwrap())),
                Err(ParseError::form_error("illegal byte size for IPv6 NLRI")), 
                Ok(BasicNlri::new(Prefix::from_str("10.10.0.0/16").unwrap())),
                Ok(BasicNlri::new(Prefix::from_str("10.11.0.0/16").unwrap())),
            ]
            )
        );
    }

    #[test]
    fn unknown_afi_safi_withdrawals() {
        // botched BGP UPDATE with 4 MP_UNREACH_NLRI
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x41, 0x02, 0x00, 0x00, 0x00, 0x2a, 0x80,
            0x0f, 0x27,
            //0x00, 0x02, // AFI
            0x00, 0xff, // changed to unknown 255
            0x01,       // SAFI
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x02,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x03
        ];
        //let update: UpdateMessage<_> = parse_msg(&buf);
        let update = UpdateMessage::from_octets(
            &buf,
            SessionConfig::modern()
        ).unwrap();

        assert!(matches!(
            update.unicast_announcements_vec(),
            Ok(Vec { .. })
        ));

        assert!(matches!(
            update.unicast_withdrawals_vec(),
            Err(ParseError::Form(..))
        ));

    }

    #[test]
    fn invalid_withdrawals() {
        // botched BGP UPDATE with 4 MP_UNREACH_NLRI
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x41, 0x02, 0x00, 0x00, 0x00, 0x2a, 0x80,
            0x0f, 0x27,
            0x00, 0x02,
            0x01,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00,
            //0x40,
            0x41, // changed to 0x41, leading to a parse error somewhere in
                  // the remainder of the attribute.
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x02,
            0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x03
        ];

        let update = UpdateMessage::from_octets(
            &buf,
            SessionConfig::modern()
        ).unwrap();

        assert!(matches!(
            update.unicast_announcements_vec(),
            Ok(Vec { .. })
        ));

        assert!(matches!(
            update.unicast_withdrawals_vec(),
            Err(ParseError::Form(..))
        ));

        assert_eq!(update.withdrawals().unwrap().count(), 2);
        assert_eq!(update.unicast_withdrawals().unwrap().count(), 2);

        assert!(
            update.unicast_withdrawals().unwrap().eq(
            [
                Ok(BasicNlri::new(
                        Prefix::from_str("2001:db8:ffff::/64").unwrap())
                ),
                Err(ParseError::form_error("prefix parsing failed")), 
            ]
            )
        );

    }
}
