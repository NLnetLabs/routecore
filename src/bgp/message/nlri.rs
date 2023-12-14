use crate::bgp::types::{AFI, SAFI, AfiSafi, NextHop};

use crate::addr::Prefix;

use crate::util::parser::{parse_ipv4addr, parse_ipv6addr, ParseError};
use crate::bgp::message::update::{SessionConfig};
use crate::flowspec::Component;
use crate::typeenum;
use octseq::{Octets, OctetsBuilder, OctetsFrom, Parser};
use log::debug;

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};


//------------ FixedNlriIter -------------------------------------------------
//
// This is an alternative iterator for parsing wireformat encoded NLRI. Where
// the 'normal' iterator will match on afi/safi every time next() is called,
// the FixedNlriIter is generic over a type implementing AfiSafiParse. That
// trait has explicit implementations for every afi/safi pair, so the whole
// matching is lifted up one level.
// The normal iterator is nicer in terms of API, the fixed one might be a bit
// more performant in certain cases.

pub struct FixedNlriIter<'a, T, AS> {
    parser: Parser<'a, T>,
    afisafi: std::marker::PhantomData<AS>,
}

impl<'a, T: 'a + Octets, AS: AfiSafiParse > FixedNlriIter<'a, T, AS> {
    pub fn new(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter { parser: *parser, afisafi: std::marker::PhantomData}
    }

    pub fn validate(&mut self) -> Result<(), ParseError> {
        let pos = self.parser.pos();
        while self.parser.remaining() > 0 {
            self.skip_nlri()?
        }
        self.parser.seek(pos)?;
        Ok(())
    }

    fn get_nlri(&mut self) -> Result<AS::Item<T::Range<'a>>, ParseError> {
        AS::parse_nlri(&mut self.parser)
    }

    fn skip_nlri(&mut self) -> Result<(), ParseError> {
        AS::skip_nlri(&mut self.parser)
    }
}

//------------ Ipv4Unicast ---------------------------------------------------

pub(crate) struct Ipv4Unicast;
impl AfiSafiParse for Ipv4Unicast {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        Ok(
            BasicNlri::new(parse_prefix(parser, AFI::Ipv4)?)
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4Unicast> {
    pub(crate) fn ipv4unicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv4Unicast>::new(parser)
    }
}

//------------ Ipv4UnicastAddPath --------------------------------------------

pub(crate) struct Ipv4UnicastAddPath;
impl AfiSafiParse for Ipv4UnicastAddPath {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        let path_id = PathId::parse(parser)?;
        Ok(
            BasicNlri::with_path_id(
                parse_prefix(parser, AFI::Ipv4)?,
                path_id
            )
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix_addpath(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4UnicastAddPath> {
    pub(crate) fn ipv4unicast_addpath(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv4UnicastAddPath>::new(parser)
    }
}

//------------ Ipv6Unicast ---------------------------------------------------

pub(crate) struct Ipv6Unicast;
impl AfiSafiParse for Ipv6Unicast {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        Ok(
            BasicNlri::new(parse_prefix(parser, AFI::Ipv6)?)
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6Unicast> {
    pub(crate) fn ipv6unicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv6Unicast>::new(parser)
    }
}

//------------ Ipv6UnicastAddPath --------------------------------------------

pub(crate) struct Ipv6UnicastAddPath;
impl AfiSafiParse for Ipv6UnicastAddPath {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        let path_id = PathId::parse(parser)?;
        Ok(
            BasicNlri::with_path_id(
                parse_prefix(parser, AFI::Ipv6)?,
                path_id
            )
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix_addpath(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6UnicastAddPath> {
    pub(crate) fn ipv6unicast_addpath(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv6UnicastAddPath>::new(parser)
    }
}

//------------ Ipv4Multicast -------------------------------------------------

pub(crate) struct Ipv4Multicast;
impl AfiSafiParse for Ipv4Multicast {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        Ok(
            BasicNlri::new(parse_prefix(parser, AFI::Ipv4)?)
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4Multicast> {
    pub(crate) fn ipv4multicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv4Multicast>::new(parser)
    }
}

//------------ Ipv4MulticastAddPath ------------------------------------------

pub(crate) struct Ipv4MulticastAddPath;
impl AfiSafiParse for Ipv4MulticastAddPath {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        let path_id = PathId::parse(parser)?;
        Ok(
            BasicNlri::with_path_id(
                parse_prefix(parser, AFI::Ipv4)?,
                path_id
            )
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix_addpath(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4MulticastAddPath> {
    pub(crate) fn ipv4multicast_addpath(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv4MulticastAddPath>::new(parser)
    }
}

//------------ Ipv6Multicast -------------------------------------------------

pub(crate) struct Ipv6Multicast;
impl AfiSafiParse for Ipv6Multicast {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        Ok(
            BasicNlri::new(parse_prefix(parser, AFI::Ipv6)?)
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6Multicast> {
    pub(crate) fn ipv6multicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv6Multicast>::new(parser)
    }
}

//------------ Ipv6MulticastAddPath ------------------------------------------

pub(crate) struct Ipv6MulticastAddPath;
impl AfiSafiParse for Ipv6MulticastAddPath {
    type Item<O> = BasicNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        let path_id = PathId::parse(parser)?;
        Ok(
            BasicNlri::with_path_id(
                parse_prefix(parser, AFI::Ipv6)?,
                path_id
            )
        )
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        skip_prefix_addpath(parser)
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6MulticastAddPath> {
    pub(crate) fn ipv6multicast_addpath(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv6MulticastAddPath>::new(parser)
    }
}

//------------ Ipv4MplsUnicast -----------------------------------------------

pub(crate) struct Ipv4MplsUnicast;
impl AfiSafiParse for Ipv4MplsUnicast {
    type Item<O> = MplsNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsNlri::parse_no_addpath(parser, AfiSafi::Ipv4MplsUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        MplsNlri::skip_labels_and_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4MplsUnicast> {
    pub(crate) fn ipv4mpls_unicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv4MplsUnicast>::new(parser)
    }
}

//------------ Ipv4MplsUnicastAddPath ----------------------------------------

pub(crate) struct Ipv4MplsUnicastAddPath;
impl AfiSafiParse for Ipv4MplsUnicastAddPath {
    type Item<O> = MplsNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsNlri::parse_addpath(parser, AfiSafi::Ipv4MplsUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        parser.advance(4)?;
        MplsNlri::skip_labels_and_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4MplsUnicastAddPath> {
    pub(crate) fn ipv4mpls_unicast_addpath(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, Ipv4MplsUnicastAddPath>::new(parser)
    }
}

//------------ Ipv6MplsUnicast -----------------------------------------------

pub(crate) struct Ipv6MplsUnicast;
impl AfiSafiParse for Ipv6MplsUnicast {
    type Item<O> = MplsNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsNlri::parse_no_addpath(parser, AfiSafi::Ipv6MplsUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        MplsNlri::skip_labels_and_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6MplsUnicast> {
    pub(crate) fn ipv6mpls_unicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv6MplsUnicast>::new(parser)
    }
}

//------------ Ipv6MplsUnicastAddPath ----------------------------------------

pub(crate) struct Ipv6MplsUnicastAddPath;
impl AfiSafiParse for Ipv6MplsUnicastAddPath {
    type Item<O> = MplsNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsNlri::parse_addpath(parser, AfiSafi::Ipv6MplsUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        parser.advance(4)?;
        MplsNlri::skip_labels_and_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6MplsUnicastAddPath> {
    pub(crate) fn ipv6mpls_unicast_addpath(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, Ipv6MplsUnicastAddPath>::new(parser)
    }
}

//------------ Ipv4MplsVpnUnicast --------------------------------------------

pub(crate) struct Ipv4MplsVpnUnicast;
impl AfiSafiParse for Ipv4MplsVpnUnicast {
    type Item<O> = MplsVpnNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsVpnNlri::parse_no_addpath(parser, AfiSafi::Ipv4MplsVpnUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        MplsVpnNlri::skip_labels_rd_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4MplsVpnUnicast> {
    pub(crate) fn ipv4mpls_vpn_unicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv4MplsVpnUnicast>::new(parser)
    }
}

//------------ Ipv4MplsVpnUnicastAddPath -------------------------------------

pub(crate) struct Ipv4MplsVpnUnicastAddPath;
impl AfiSafiParse for Ipv4MplsVpnUnicastAddPath {
    type Item<O> = MplsVpnNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsVpnNlri::parse_addpath(parser, AfiSafi::Ipv4MplsVpnUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        parser.advance(4)?;
        MplsVpnNlri::skip_labels_rd_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4MplsVpnUnicastAddPath> {
    pub(crate) fn ipv4mpls_vpn_unicast_addpath(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, Ipv4MplsVpnUnicastAddPath>::new(parser)
    }
}

//------------ Ipv6MplsVpnUnicast --------------------------------------------

pub(crate) struct Ipv6MplsVpnUnicast;
impl AfiSafiParse for Ipv6MplsVpnUnicast {
    type Item<O> = MplsVpnNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsVpnNlri::parse_no_addpath(parser, AfiSafi::Ipv6MplsVpnUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        MplsVpnNlri::skip_labels_rd_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6MplsVpnUnicast> {
    pub(crate) fn ipv6mpls_vpn_unicast(parser: &mut Parser<'a, T>) -> Self {
        FixedNlriIter::<T, Ipv6MplsVpnUnicast>::new(parser)
    }
}

//------------ Ipv6MplsVpnUnicastAddPath -------------------------------------

pub(crate) struct Ipv6MplsVpnUnicastAddPath;
impl AfiSafiParse for Ipv6MplsVpnUnicastAddPath {
    type Item<O> = MplsVpnNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        MplsVpnNlri::parse_addpath(parser, AfiSafi::Ipv6MplsVpnUnicast)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        parser.advance(4)?;
        MplsVpnNlri::skip_labels_rd_prefix(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6MplsUnicastAddPath> {
    pub(crate) fn ipv6mpls_vpn_unicast_addpath(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, Ipv6MplsUnicastAddPath>::new(parser)
    }
}


//------------ Ipv4RouteTarget -------------------------------------

pub(crate) struct Ipv4RouteTarget;
impl AfiSafiParse for Ipv4RouteTarget {
    type Item<O> = RouteTargetNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        RouteTargetNlri::parse_no_addpath(parser)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        RouteTargetNlri::<Octs>::skip(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4RouteTarget> {
    pub(crate) fn ipv4route_target(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, Ipv4RouteTarget>::new(parser)
    }
}


//------------ Ipv4FlowSpec -------------------------------------

pub(crate) struct Ipv4FlowSpec;
impl AfiSafiParse for Ipv4FlowSpec {
    type Item<O> = FlowSpecNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        FlowSpecNlri::parse(parser, AFI::Ipv4)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        FlowSpecNlri::<Octs>::skip(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv4FlowSpec> {
    pub(crate) fn ipv4flowspec(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, Ipv4FlowSpec>::new(parser)
    }
}


//------------ Ipv6FlowSpec -------------------------------------

pub(crate) struct Ipv6FlowSpec;
impl AfiSafiParse for Ipv6FlowSpec {
    type Item<O> = FlowSpecNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        FlowSpecNlri::parse(parser, AFI::Ipv6)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        FlowSpecNlri::<Octs>::skip(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, Ipv6FlowSpec> {
    pub(crate) fn ipv6flowspec(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, Ipv6FlowSpec>::new(parser)
    }
}

//------------ L2VpnVpls -------------------------------------

pub(crate) struct L2VpnVpls;
impl AfiSafiParse for L2VpnVpls {
    type Item<O> = VplsNlri;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        VplsNlri::parse(parser)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        VplsNlri::skip(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, L2VpnVpls> {
    pub(crate) fn l2vpn_vpls(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, L2VpnVpls>::new(parser)
    }
}

//------------ L2VpnEvpn -------------------------------------

pub(crate) struct L2VpnEvpn;
impl AfiSafiParse for L2VpnEvpn {
    type Item<O> = EvpnNlri<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError> {
        EvpnNlri::parse(parser)
    }

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>
    {
        EvpnNlri::<Octs>::skip(parser)?;
        Ok(())
    }
}

impl<'a, T: 'a + Octets> FixedNlriIter<'a, T, L2VpnEvpn> {
    pub(crate) fn l2vpn_evpn(parser: &mut Parser<'a, T>)
        -> Self
    {
        FixedNlriIter::<T, L2VpnEvpn>::new(parser)
    }
}

//------------ AfiSafiParse --------------------------------------------------

pub trait AfiSafiParse {
    type Item<O>;
    fn parse_nlri<'a, Octs: Octets>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self::Item<Octs::Range<'a>>, ParseError>;

    fn skip_nlri<Octs: Octets>(parser: &mut Parser<'_, Octs>)
        -> Result<(), ParseError>;
}

//------------ Iterator ------------------------------------------------------

impl<'a, T: Octets, AS: AfiSafiParse> Iterator for FixedNlriIter<'a, T, AS> {
    type Item = Result<AS::Item<T::Range<'a>>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(self.get_nlri())
    }
}

//--- NextHop in MP_REACH_NLRI -----------------------------------------------
impl NextHop {
    // XXX remove? at least get rid of code repetition with fn parse below
    pub fn _check<Octs: Octets>(parser: &mut Parser<Octs>, afi: AFI, safi: SAFI)
        -> Result<(), ParseError>
    {
        let len = parser.parse_u8()?;
        match (len, afi, safi) {
            (16, AFI::Ipv6, SAFI::Unicast | SAFI::MplsUnicast) =>
                //NextHop::Ipv6
                parser.advance(16)?,
            (32, AFI::Ipv6, SAFI::Unicast | SAFI::Multicast) =>
                //NextHop::Ipv6LL
                parser.advance(16 + 16)?,
            (24, AFI::Ipv6, SAFI::MplsVpnUnicast) =>
                //NextHop::Ipv6MplsVpnUnicast
                parser.advance(8 + 16)?,
            (4, AFI::Ipv4, SAFI::Unicast | SAFI::Multicast | SAFI::MplsUnicast ) =>
                //NextHop::Ipv4
                parser.advance(4)?,
            (12, AFI::Ipv4, SAFI::MplsVpnUnicast) =>
                //NextHop::Ipv4MplsVpnUnicast
                parser.advance(8 + 4)?,
            // RouteTarget is always AFI/SAFI 1/132, so, IPv4,
            // but the Next Hop can be IPv6.
            (4, AFI::Ipv4, SAFI::RouteTarget) =>
                //NextHop::Ipv4
                parser.advance(4)?,
            (16, AFI::Ipv4, SAFI::RouteTarget) =>
                //NextHop::Ipv6
                parser.advance(16)?,
            (0, AFI::Ipv4, SAFI::FlowSpec) =>
                //NextHop::Empty
                { },
            _ => {
                parser.advance(len.into())?;
                debug!("Unimplemented NextHop AFI/SAFI {}/{} len {}",
                      afi, safi, len);
                return Err(ParseError::form_error(
                        "unimplemented AFI/SAFI in NextHop"
                ))
            }
        }

        Ok(())
    }

    pub fn parse<R: Octets>(parser: &mut Parser<'_, R>, afi: AFI, safi: SAFI)
        -> Result<Self, ParseError>
    {
        let len = parser.parse_u8()?;
        let res = match (len, afi, safi) {
            (16, AFI::Ipv6, SAFI::Unicast | SAFI::MplsUnicast) =>
                NextHop::Unicast(parse_ipv6addr(parser)?.into()),
            (16, AFI::Ipv6, SAFI::Multicast) =>
                NextHop::Multicast(parse_ipv6addr(parser)?.into()),
            (32, AFI::Ipv6, SAFI::Unicast | SAFI::Multicast) =>
                NextHop::Ipv6LL(
                    parse_ipv6addr(parser)?,
                    parse_ipv6addr(parser)?
                ),
            (24, AFI::Ipv6, SAFI::MplsVpnUnicast) =>
                NextHop::Ipv6MplsVpnUnicast(
                    RouteDistinguisher::parse(parser)?,
                    parse_ipv6addr(parser)?
                ),
            (4, AFI::Ipv4, SAFI::Unicast | SAFI::MplsUnicast ) =>
                NextHop::Unicast(parse_ipv4addr(parser)?.into()),
            (4, AFI::Ipv4, SAFI::Multicast) => 
                NextHop::Multicast(parse_ipv4addr(parser)?.into()),
            (12, AFI::Ipv4, SAFI::MplsVpnUnicast) =>
                NextHop::Ipv4MplsVpnUnicast(
                    RouteDistinguisher::parse(parser)?,
                    parse_ipv4addr(parser)?
                ),
            // RouteTarget is always AFI/SAFI 1/132, so, IPv4,
            // but the Next Hop can be IPv6.
            (4, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Unicast(parse_ipv4addr(parser)?.into()),
            (16, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Unicast(parse_ipv6addr(parser)?.into()),
            (0, AFI::Ipv4, SAFI::FlowSpec) =>
                NextHop::Empty,
            (4, AFI::L2Vpn, SAFI::Evpn) =>
                NextHop::Evpn(parse_ipv4addr(parser)?.into()),
            (16, AFI::L2Vpn, SAFI::Evpn) =>
                NextHop::Evpn(parse_ipv6addr(parser)?.into()),

            (4, AFI::Ipv6, SAFI::MplsUnicast) =>
                // IPv6 MPLS with IPv4 Nexthop (RFC4684)
                NextHop::Unicast(parse_ipv4addr(parser)?.into()),
            (16, AFI::Ipv4, SAFI::MplsUnicast) =>
                // IPv4 MPLS with IPv6 Nexthop (RFC4684)
                NextHop::Unicast(parse_ipv6addr(parser)?.into()),
            _ => {
                debug!("Unimplemented NextHop AFI/SAFI {}/{} len {}",
                      afi, safi, len);
                parser.advance(len.into())?;
                NextHop::Unimplemented(afi, safi)
            }
        };
        Ok(res)
    }

    pub fn skip<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        let len = parser.parse_u8()?;
        parser.advance(len.into())?;
        Ok(())
    }
}


//--- NLRI -------------------------------------------------------------------

/// Path Identifier for BGP Multiple Paths (RFC7911).
///
/// Optionally used in [`BasicNlri`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PathId(u32);

impl PathId {
    pub fn check<Octs: Octets>(parser: &mut Parser<Octs>)
        -> Result<(), ParseError> 
    {
        parser.advance(4)?;
        Ok(())
    }

    pub fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError> 
    {
        Ok(PathId(parser.parse_u32_be()?))
    }

    pub fn from_u32(id: u32) -> Self {
        PathId(id)
    }

    pub fn to_raw(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// MPLS labels, part of [`MplsNlri`] and [`MplsVpnNlri`].
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Labels<Octs> {
    octets: Octs
}

impl<Octs, Other> PartialEq<Labels<Other>> for Labels<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Labels<Other>) -> bool {
        self.octets.as_ref() == other.octets.as_ref()
    }
}

impl<Octs: AsRef<[u8]>> Eq for Labels<Octs> { }


impl<Octs: AsRef<[u8]>> Labels<Octs> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.octets.as_ref().len()
    }
}

impl<Octs: AsRef<[u8]>> AsRef<[u8]> for Labels<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octs: Octets> Labels<Octs> {
    // XXX check all this Label stuff again
    fn skip<'a, R>(parser: &mut Parser<'a, R>) -> Result<usize, ParseError>
        where
            R: Octets<Range<'a> = Octs>
    {
        let mut res = 0;
        let mut stop = false;
        let mut buf = [0u8; 3];

        while !stop {
            //20bits label + 3bits rsvd + S bit
            parser.parse_buf(&mut buf)?;
            res += 3;

            if buf[2] & 0x01 == 0x01  || // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00] // or RFC 8277 2.4
            {
                stop = true;
            }
        }

        Ok(res)
    }
    // There are two cases for Labels:
    // - in an announcement, it describes one or more MPLS labels
    // - in a withdrawal, it's a compatibility value without meaning
    // XXX consider splitting up the parsing for this for announcements vs
    // withdrawals? Perhaps via another fields in the (currently so-called)
    // SessionConfig...
    fn parse<'a, R>(parser: &mut Parser<'a, R>) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs> + ?Sized,
    {
        let pos = parser.pos();
        
        let mut stop = false;
        let mut buf = [0u8; 3];

        while !stop {
            //20bits label + 3bits rsvd + S bit
            parser.parse_buf(&mut buf)?;
            let _lbl =
                (buf[0] as u32) << 12 |
                (buf[1] as u32) << 4  |
                (buf[2] as u32) >> 4;

            if buf[2] & 0x01 == 0x01  || // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00] // or RFC 8277 2.4
            {
                stop = true;
            }
        }

        let len = parser.pos() - pos;
        parser.seek(pos)?;
        let res = parser.parse_octets(len)?;
        Ok(
            Labels { octets: res }
        )
    }
}

/// Route Distinguisher (RD) as defined in RFC4364.
///
/// Used in [`MplsVpnNlri`], [`VplsNlri`] and [`NextHop`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteDistinguisher {
    bytes: [u8; 8]
}

impl RouteDistinguisher {
    pub fn check<Octs: Octets>(parser: &mut Parser<Octs>)
        -> Result<(), ParseError>
    {
        parser.advance(8)?;
        Ok(())
    }

    pub fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let mut b = [0u8; 8];
        b[..8].copy_from_slice(parser.peek(8)?);
        parser.advance(8)?;
        Ok(
            RouteDistinguisher{ bytes: b }
        )
    }

    pub fn skip<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        Ok(parser.advance(8)?)
    }
}

impl RouteDistinguisher {
    /// Create a new RouteDistinguisher from a slice.
    pub fn new(bytes: &[u8]) -> Self {
        RouteDistinguisher { bytes: bytes.try_into().expect("parsed before") }
    }

    /// Returns the type this RouteDistinguisher.
    pub fn typ(&self) -> RouteDistinguisherType {
        match self.bytes[0..2] {
            [0x00, 0x00] => RouteDistinguisherType::Type0,
            [0x00, 0x01] => RouteDistinguisherType::Type1,
            [0x00, 0x02] => RouteDistinguisherType::Type2,
            _ => RouteDistinguisherType::UnknownType,
        }
    }

    /// Returns the raw value of this RouteDistinguisher.
    pub fn value(&self) -> [u8; 6] {
        self.bytes[2..8].try_into().expect("parsed before")
    }
}

impl fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self.bytes)
    }
}

/// Route Distinguisher types as defined in RFC4364.
#[derive(Eq, PartialEq, Debug)]
pub enum RouteDistinguisherType {
    Type0,
    Type1,
    Type2,
    UnknownType,
}

/// NLRI comprised of a [`Prefix`] and an optional [`PathId`].
///
/// The `BasicNlri` is extended in [`MplsNlri`] and [`MplsVpnNlri`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BasicNlri {
    pub prefix: Prefix,
    pub path_id: Option<PathId>,
}

/// NLRI comprised of a [`BasicNlri`] and MPLS `Labels`.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MplsNlri<Octs> {
    basic: BasicNlri,
    labels: Labels<Octs>,
}

impl<Octs, Other> PartialEq<MplsNlri<Other>> for MplsNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &MplsNlri<Other>) -> bool {
        self.basic == other.basic && self.labels == other.labels
    }
}

/// NLRI comprised of a [`BasicNlri`], MPLS `Labels` and a VPN
/// `RouteDistinguisher`.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MplsVpnNlri<Octs> {
    basic: BasicNlri,
    labels: Labels<Octs>,
    rd: RouteDistinguisher,
}

impl<T> MplsVpnNlri<T> {
    pub fn basic(&self) -> BasicNlri {
        self.basic
    }

    pub fn labels(&self) -> &Labels<T> {
        &self.labels
    }

    pub fn rd(&self) -> RouteDistinguisher {
        self.rd
    }
}

impl<Octs, Other> PartialEq<MplsVpnNlri<Other>> for MplsVpnNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &MplsVpnNlri<Other>) -> bool {
        self.basic == other.basic
            && self.labels == other.labels
            && self.rd == other.rd
    }
}

/// VPLS Information as defined in RFC4761.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VplsNlri {
    rd: RouteDistinguisher,
    ve_id: u16,
    ve_block_offset: u16,
    ve_block_size: u16,
    raw_label_base: u32,
}

/// NLRI containing a FlowSpec v1 specification.
///
/// Also see [`crate::flowspec`].
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlowSpecNlri<Octs> {
    #[allow(dead_code)]
    afi: AFI,
    raw: Octs,
}

impl<Octs, Other> PartialEq<FlowSpecNlri<Other>> for FlowSpecNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &FlowSpecNlri<Other>) -> bool {
        self.raw.as_ref() == other.raw.as_ref()
    }
}

/// NLRI containing a Route Target membership as defined in RFC4684.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RouteTargetNlri<Octs> {
    #[allow(dead_code)]
    raw: Octs,
}

impl<Octs, Other> PartialEq<RouteTargetNlri<Other>> for RouteTargetNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &RouteTargetNlri<Other>) -> bool {
        self.raw.as_ref() == other.raw.as_ref()
    }
}

/// NLRI containing a EVPN NLRI as defined in RFC7432.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EvpnNlri<Octs> {
    #[allow(dead_code)]
    route_type: EvpnRouteType,
    raw: Octs,
}

impl<Octs> EvpnNlri<Octs> {
    pub fn route_type(&self) -> EvpnRouteType {
        self.route_type
    }
}

impl<T: AsRef<[u8]>> EvpnNlri<T> {
    fn compose_len(&self) -> usize {
        1 + self.raw.as_ref().len()
    }
}

typeenum!(
    EvpnRouteType, u8,
    {
      1 => EthernetAutoDiscovery,
      2 => MacIpAdvertisement,
      3 => InclusiveMulticastEthernetTag,
      4 => EthernetSegment,
      5 => IpPrefix,
    }
);


impl<Octs, Other> PartialEq<EvpnNlri<Other>> for EvpnNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &EvpnNlri<Other>) -> bool {
        self.raw.as_ref() == other.raw.as_ref()
    }
}

/// Conventional and BGP-MP NLRI variants.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Nlri<Octets> {                     // (AFIs  , SAFIs):
    Unicast(BasicNlri),                     // (v4/v6, unicast)
    Multicast(BasicNlri),                   // (v4/v6, multicast)
    Mpls(MplsNlri<Octets>),                 // (v4/v6, mpls unicast) 
    MplsVpn(MplsVpnNlri<Octets>),           // (v4/v6, mpls vpn unicast)
    Vpls(VplsNlri),                         // (l2vpn, vpls)
    FlowSpec(FlowSpecNlri<Octets>),         // (v4/v6, flowspec)
    RouteTarget(RouteTargetNlri<Octets>),   // (v4, route target)
    Evpn(EvpnNlri<Octets>),
}
// XXX some thoughts on if and how we need to redesign Nlri:
//
// Looking at which enum variants represent which afis/safis, currently only
// the Basic variant represents more than one SAFI, i.e. unicast and
// multicast. The other variants represent a single SAFI, and many of them do
// that for both v4 and v6.
//
// This means that when an Iterator<Item = Nlri> is created, the user
// determines the SAFI by matching on the Nlri variant coming from next(), but
// for the BasicNlri it is uncertain whether we deal with unicast or
// multicast.
//
// It would be nice if the user could query the UpdateMessage to find out what
// AFI/SAFI is in the announcements/withdrawals. Currently, `fn nlris()` and
// `fn withdrawals()` return a struct with getters for both afi and safi, and
// a `fn iter()` to get an iterator over the actual NLRI. But because nlris()
// needs an overhaul to (correctly) return both conventional and MP_* NLRI, it
// might actually return an iterator over _two_ AFI/SAFI tuples: one
// conventional v4/unicast, and one MP tuple. 
//
// The AFI could be derived from the Prefix in all cases but FlowSpec. For
// the Vpls and RouteTarget variants, there can only be one (valid) AFI, i.e.
// l2vpn and v4, respectively.
//
// We also need to take into account the creation of messages, i.e. adding
// NLRI for announcement/withdrawal to an instance of UpdateBuilder. The
// UpdateBuilder needs to be able to determine from the NLRI which AFI/SAFI it
// is dealing with. Currently a BasicNlri could be both unicast and multicast,
// but there is no way to know which one. That must be fixed.
//
// Questions:
// - are we ok with deriving the AFI from the Prefix, or do we want to
// explicitly embed the AFI in the variant? (NB that would add 4 variants for
// now, possibly more later).
// - should we simply add a Multicast variant (and perhaps rename Basic to
// Unicast)?
// - should we remove methods from the enum level to force a user to pattern
// match on the exact variant? e.g. calling Nlri.prefix() hides the exact
// variant from the user, possibly causing confusion. They might unknowingly
// storing MplsVpn prefixes thinking it was a 'Basic unicast' thing.


impl<Octs: Octets> fmt::Display for Nlri<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Nlri::Unicast(b) => {
                write!(f, "{}", b.prefix())?;
                if let Some(path_id) = b.path_id() {
                    write!(f, " (path_id {})", path_id)?
                }
            }
            Nlri::Multicast(b) => {
                write!(f, "{} (mcast)", b.prefix())?;
                if let Some(path_id) = b.path_id() {
                    write!(f, " (path_id {})", path_id)?
                }
            }
            Nlri::Mpls(m) => {
                write!(f, "MPLS-{}-{:?}",
                    m.basic.prefix(), m.labels.as_ref()
                )?
            }
            Nlri::MplsVpn(m) => {
                write!(f, "MPLSVPN-{}-{:?}-{:?}",
                    m.basic.prefix(), m.labels.as_ref(), m.rd
                )?
            }
            Nlri::Vpls(n) => write!(f, "VPLS-{:?}", n.rd)?,
            Nlri::FlowSpec(_) => write!(f, "FlowSpec-NLRI")?,
            Nlri::RouteTarget(r) => {
                write!(f, "RouteTarget-NLRI-{:?}", r.raw.as_ref())?
            }
            Nlri::Evpn(r) => {
                write!(f, "Evpn-NLRI-{:?}", r.raw.as_ref())?
            }
        }
        Ok(())
    }
}

impl<Octs, SrcOcts> OctetsFrom<Nlri<SrcOcts>> for Nlri<Octs> 
    where Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Nlri<SrcOcts>) -> Result<Self, Self::Error> {
        match source {
            Nlri::Unicast(b) => Ok(Nlri::Unicast(b)),
            Nlri::Multicast(b) => Ok(Nlri::Multicast(b)),
            Nlri::FlowSpec(m) => Ok(Nlri::FlowSpec(FlowSpecNlri {
                    afi: m.afi,
                    raw: Octs::try_octets_from(m.raw)?
            })),
            _ => todo!()
        }
    }
}

/*
impl<'a, Octs, SrcOcts: 'a + Octets> OctetsFrom<&'a Nlri<SrcOcts>> for Nlri<Octs> 
where
    Octs: OctetsFrom<SrcOcts>,
    //SrcOcts: Clone,
    //Infallible: From<Octs::Error>
{
    type Error = Octs::Error;
    //type Error = std::convert::Infallible;

    fn try_octets_from(source: &'a Nlri<SrcOcts>) -> Result<Self, Self::Error> {
        match source {
            Nlri::Unicast(b) => Ok(Nlri::Unicast(*b)),
            Nlri::Multicast(b) => Ok(Nlri::Multicast(*b)),
            //Nlri::FlowSpec(m) => Ok(Nlri::FlowSpec(FlowSpecNlri::try_octets_from(m)?)),
            //Nlri::FlowSpec(_) => Ok(Nlri::try_octets_from(*source)?),
            Nlri::FlowSpec(m) => Ok(Nlri::FlowSpec(FlowSpecNlri {
                    afi: m.afi,
                    raw: Octs::try_octets_from(m.raw.as_ref())?
            })),
            _ => todo!()
        }
    }
}
*/

impl<'a, SrcOcts: 'a + Octets> OctetsFrom<&'a Nlri<SrcOcts>> for Nlri<Vec<u8>> 
    where Vec<u8>: OctetsFrom<SrcOcts>,
{
    type Error = <Vec<u8> as OctetsFrom<SrcOcts>>::Error;

    fn try_octets_from(source: &'a Nlri<SrcOcts>) -> Result<Self, Self::Error> {
        match source {
            Nlri::Unicast(b) => Ok(Nlri::Unicast(*b)),
            Nlri::Multicast(b) => Ok(Nlri::Multicast(*b)),
            Nlri::Mpls(m) => Ok(Nlri::Mpls(MplsNlri {
                basic: m.basic,
                labels: Labels{ octets: m.labels.as_ref().to_vec() },
            })),
            Nlri::MplsVpn(m) => Ok(Nlri::MplsVpn(MplsVpnNlri {
                basic: m.basic,
                labels: Labels{ octets: m.labels.as_ref().to_vec() },
                rd: m.rd
            })),
            Nlri::Vpls(v) => Ok(Nlri::Vpls(*v)),
            Nlri::FlowSpec(m) => Ok(Nlri::FlowSpec(FlowSpecNlri{
                    afi: m.afi,
                    raw: m.raw.as_ref().to_vec()
            })),
            Nlri::RouteTarget(r) => Ok(Nlri::RouteTarget(RouteTargetNlri{
                raw: r.raw.as_ref().to_vec(),
            })),
            Nlri::Evpn(e) => Ok(Nlri::Evpn( EvpnNlri{
                route_type: e.route_type,
                raw: e.raw.as_ref().to_vec(),
            })),
        }
    }
}

impl<Octs, SrcOcts: Octets> OctetsFrom<FlowSpecNlri<SrcOcts>> for FlowSpecNlri<Octs>
    where Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: FlowSpecNlri<SrcOcts>
    ) -> Result<Self, Self::Error> {
        Ok(FlowSpecNlri { afi: source.afi, raw: Octs::try_octets_from(source.raw)? } )
    }
}

/*
impl<'a, Octs, SrcOcts: 'a + Octets> OctetsFrom<&'a FlowSpecNlri<SrcOcts>> for FlowSpecNlri<Octs>
    where Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: &'a FlowSpecNlri<SrcOcts>
    ) -> Result<Self, Self::Error> {
        Ok(FlowSpecNlri { afi: source.afi, raw: Octs::try_octets_from(source.raw)? } )
    }
}
*/

impl<'a, SrcOcts: 'a + Octets> OctetsFrom<&'a FlowSpecNlri<SrcOcts>> for FlowSpecNlri<Vec<u8>>
    where Vec<u8>: OctetsFrom<SrcOcts>,
          Vec<u8>: From<SrcOcts>
{
    type Error = <Vec<u8> as OctetsFrom<SrcOcts>>::Error;

    fn try_octets_from(
        source: &'a FlowSpecNlri<SrcOcts>
    ) -> Result<Self, Self::Error> {
        Ok(FlowSpecNlri { afi: source.afi, raw: source.raw.as_ref().to_vec() } )
    }
}

impl<Octs, Other> PartialEq<Nlri<Other>> for Nlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Nlri<Other>) -> bool {
        match (self, other) {
            (Self::Unicast(s), Nlri::Unicast(o)) |
            (Self::Multicast(s), Nlri::Multicast(o)) => s == o,
            (Self::Mpls(s), Nlri::Mpls(o)) => s == o,
            (Self::MplsVpn(s), Nlri::MplsVpn(o)) => s == o,
            (Self::Vpls(s), Nlri::Vpls(o)) => s == o,
            (Self::FlowSpec(s), Nlri::FlowSpec(o)) => s == o,
            (Self::RouteTarget(s), Nlri::RouteTarget(o)) => s == o,
            _ => false
        }
    }
}

impl<Octs: AsRef<[u8]>> Eq for Nlri<Octs> { }

impl<T> Nlri<T> {
    /// Returns true if this NLRI contains a Path Id. 
    pub fn is_addpath(&self) -> bool {
        match self {
            Self::Unicast(b) | Self::Multicast(b) => b.is_addpath(),
            Self::Mpls(m) => m.basic.is_addpath(),
            Self::MplsVpn(m) => m.basic.is_addpath(),
            Self::Vpls(_) | Self::FlowSpec(_) | Self::RouteTarget(_) => false,
            Self::Evpn(_) => false,
        }
    }
}

impl<T> Nlri<T> {
    /// Returns the tuple of (AFI, SAFI) for this Nlri.
    pub fn afi_safi(&self) -> (AFI, SAFI) {
        match self {
            Self::Unicast(b) => {
                if b.is_v4() {
                    (AFI::Ipv4, SAFI::Unicast)
                } else {
                    (AFI::Ipv6, SAFI::Unicast)
                }
            }
            Self::Multicast(b) => {
                if b.is_v4() {
                    (AFI::Ipv4, SAFI::Multicast)
                } else {
                    (AFI::Ipv6, SAFI::Multicast)
                }
            }
            Self::Mpls(n) => {
                if n.basic.is_v4() {
                    (AFI::Ipv4, SAFI::MplsUnicast)
                } else {
                    (AFI::Ipv6, SAFI::MplsUnicast)
                }
            }
            Self::MplsVpn(n) => {
                if n.basic.is_v4() {
                    (AFI::Ipv4, SAFI::MplsVpnUnicast)
                } else {
                    (AFI::Ipv6, SAFI::MplsVpnUnicast)
                }
            }
            Self::Vpls(_) => (AFI::L2Vpn, SAFI::Vpls),
            Self::FlowSpec(n) => (n.afi, SAFI::FlowSpec) ,
            Self::RouteTarget(_) => (AFI::Ipv4, SAFI::RouteTarget),
            Self::Evpn(_) => (AFI::L2Vpn, SAFI::Evpn)
        }
    }

}

impl<Octs: AsRef<[u8]>> Nlri<Octs> {

    /// Returns the MPLS [`Labels`], if any.
    ///
    /// Applicable to MPLS and MPLS-VPN NLRI.
    pub fn labels(&self) -> Option<&Labels<Octs>> {
        match &self {
            Nlri::Mpls(n) => Some(&n.labels),
            Nlri::MplsVpn(n) => Some(&n.labels),
            _ => None
        }
    }

    /// Returns the RouteDistinguisher, if any.
    ///
    /// Applicable to MPLS VPN and VPLS NLRI.
    pub fn rd(&self) -> Option<RouteDistinguisher> {
        match self {
            Nlri::MplsVpn(n) => Some(n.rd),
            Nlri::Vpls(n) => Some(n.rd),
            _ => None
        }
    }

    // VPLS specific methods

    /// Returns the VPLS VE ID.
    pub fn ve_id(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_id),
            _ => None
        }

    }

    /// Returns the VPLS VE Block Offset.
    pub fn ve_block_offset(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_block_offset),
            _ => None
        }
    }

    /// Returns the VPLS VE Block Size.
    pub fn ve_block_size(&self) -> Option<u16> {
        match self {
            Nlri::Vpls(n) => Some(n.ve_block_size),
            _ => None
        }
    }

    /// Returns the VPLS Label Base.
    pub fn raw_label_base(&self) -> Option<u32> {
        match self {
            Nlri::Vpls(n) => Some(n.raw_label_base),
            _ => None
        }
    }

    //--- Compose methods

    pub fn compose_len(&self) -> usize {
        match self {
            Nlri::Unicast(b) | Nlri::Multicast(b) => b.compose_len(),
            Nlri::Mpls(m) => m.compose_len(),
            Nlri::MplsVpn(m) => m.compose_len(),
            Nlri::Vpls(v) => v.compose_len(),
            Nlri::FlowSpec(f) => f.compose_len(),
            Nlri::RouteTarget(r) => r.compose_len(),
            Nlri::Evpn(e) => e.compose_len(),
        }
    }
}


// XXX While Nlri<()> might make more sense, it clashes with trait bounds
// like Vec<u8>: OctetsFrom<T> elsewhere, as, From<()> is not implemented for
// Vec<u8>. Similarly, () is not AsRef<[u8]>.
impl Nlri<&[u8]> {
    /// Creates a `Nlri::Unicast` for `prefix`.
    ///
    /// This returns the error thrown by `Prefix::from_str` if `prefix` does
    /// not represent a valid IPv6 or IPv4 prefix.
    pub fn unicast_from_str(prefix: &str)
        -> Result<Nlri<&[u8]>, <Prefix as FromStr>::Err>
    {
        Ok(
            Nlri::Unicast(BasicNlri::new(
                    Prefix::from_str(prefix)?
            ))
        )
    }
}

// Calculate the number of bytes we need to parse for a certain prefix length
// given in bits.
fn prefix_bits_to_bytes(bits: u8) -> usize {
    if bits != 0 {
        (bits as usize - 1) / 8 + 1
    } else {
        0
    }
}

fn check_prefix<Octs: Octets>(
    parser: &mut Parser<Octs>,
    prefix_bits: u8,
    afi: AFI
) -> Result<(), ParseError> {
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    match (afi, prefix_bytes) {
        (AFI::Ipv4, 0) => { },
        (AFI::Ipv4, _b @ 5..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv4 NLRI")
            )
        },
        (AFI::Ipv4, _) => { parser.advance(prefix_bytes)?; }
        (AFI::Ipv6, 0) => { },
        (AFI::Ipv6, _b @ 17..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv6 NLRI")
            )
        },
        (AFI::Ipv6, _) => { parser.advance(prefix_bytes)?; },
        (_, _) => {
            return Err(
                ParseError::form_error("unknown prefix format")
            )
        }
    };

    Ok(())
}

fn parse_prefix_for_len<R: Octets>(
    parser: &mut Parser<'_, R>,
    prefix_bits: u8,
    afi: AFI
)
    -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let prefix = match (afi, prefix_bytes) {
        (AFI::Ipv4, 0) => {
            Prefix::new_v4(0.into(), 0)?
        },
        (AFI::Ipv4, _b @ 5..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv4 NLRI")
            )
        },
        (AFI::Ipv4, _) => {
            let mut b = [0u8; 4];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|e| 
                ParseError::form_error(e.static_description())
            )?
        }
        (AFI::Ipv6, 0) => {
            Prefix::new_v6(0.into(), 0)?
        },
        (AFI::Ipv6, _b @ 17..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv6 NLRI")
            )
        },
        (AFI::Ipv6, _) => {
            let mut b = [0u8; 16];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|e| 
                ParseError::form_error(e.static_description())
            )?
        },
        (_, _) => {
            return Err(
                ParseError::form_error("unknown prefix format")
            )
        }
    };
    Ok(prefix)
}

fn skip_prefix<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<(), ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    Ok(parser.advance(prefix_bytes)?)
}

fn skip_prefix_for_len<R: Octets>(parser: &mut Parser<'_, R>, prefix_bits: u8)
    -> Result<(), ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    Ok(parser.advance(prefix_bytes)?)
}

fn skip_prefix_addpath<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<(), ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    parser.advance(4)?;
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    Ok(parser.advance(prefix_bytes)?)
}

fn parse_prefix<R: Octets>(parser: &mut Parser<'_, R>, afi: AFI)
    -> Result<Prefix, ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    parse_prefix_for_len(parser, prefix_bits, afi)
}

impl BasicNlri {
    pub fn check<Octs: Octets>(
        parser: &mut Parser<Octs>,
        config: SessionConfig,
        afisafi: AfiSafi,
    ) -> Result<(), ParseError> {
        if config.rx_addpath(afisafi) {
            PathId::check(parser)?
        }

        let prefix_bits = parser.parse_u8()?;
        check_prefix(parser, prefix_bits, afisafi.afi())?;
        
        Ok(())
    }

    pub fn parse<R: Octets>(
        parser: &mut Parser<'_, R>,
        config: SessionConfig,
        afisafi: AfiSafi,
    ) -> Result<Self, ParseError> {
        let path_id = if config.rx_addpath(afisafi) {
            Some(PathId::parse(parser)?)
        } else {
            None
        };

        let prefix_bits = parser.parse_u8()?;
        let prefix = parse_prefix_for_len(
            parser,
            prefix_bits,
            afisafi.afi()
        )?;
        
        Ok(
            BasicNlri {
                prefix,
                path_id,
            }
        )
    }

    pub fn new(prefix: Prefix) -> BasicNlri {
        BasicNlri { prefix, path_id: None }
    }

    pub fn with_path_id(prefix: Prefix, path_id: PathId) -> BasicNlri {
        BasicNlri { prefix, path_id: Some(path_id) }
    }

    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// Returns the PathId for AddPath enabled prefixes, if some.
    pub fn path_id(&self) -> Option<PathId> {
        self.path_id
    }

    /// Returns true if this NLRI contains a Path Id. 
    pub fn is_addpath(&self) -> bool {
        self.path_id.is_some()
    }

    pub(crate) fn compose_len(&self) -> usize {
        let mut res = if self.path_id.is_some() {
            4
        } else {
            0
        };
        // 1 byte for the length itself
        res += 1 + prefix_bits_to_bytes(self.prefix.len());
        res
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = self.prefix.len();
        if let Some(path_id) = self.path_id {
            target.append_slice(&path_id.to_raw())?;
        }

        target.append_slice(&[len])?;
        let prefix_bytes = prefix_bits_to_bytes(len);

        match self.prefix.addr() {
            IpAddr::V4(a) => {
                target.append_slice(&a.octets()[..prefix_bytes])?;
            }
            IpAddr::V6(a) => {
                target.append_slice(&a.octets()[..prefix_bytes])?;
            }
        }
        Ok(())
    }

    pub fn is_v4(&self) -> bool {
        self.prefix.is_v4()
    }
}

impl From<Prefix> for BasicNlri {
    fn from(prefix: Prefix) -> BasicNlri {
        BasicNlri { prefix, path_id: None }
    }
}

impl From<(Prefix, PathId)> for BasicNlri {
    fn from(tuple: (Prefix, PathId)) -> BasicNlri {
        BasicNlri { prefix: tuple.0, path_id: Some(tuple.1) }
    }
}

impl From<(Prefix, Option<PathId>)> for BasicNlri {
    fn from(tuple: (Prefix, Option<PathId>)) -> BasicNlri {
        BasicNlri { prefix: tuple.0, path_id: tuple.1 }
    }
}


impl<Octs: Octets> MplsVpnNlri<Octs> {
    pub fn check(
        parser: &mut Parser<Octs>,
        config: SessionConfig,
        afisafi: AfiSafi,
        ) -> Result<(), ParseError>
    {
        if config.rx_addpath(afisafi) {
            parser.advance(4)?;
        }

        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::parse(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.
        if 8 * labels.len() as u8 > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;

        RouteDistinguisher::check(parser)?;
        prefix_bits -= 8 * 8_u8;

        check_prefix(parser, prefix_bits, afisafi.afi())?;

        Ok(())
    }
}

impl<Octs: Octets> MplsVpnNlri<Octs> {
    pub fn parse<'a, R>(
        parser: &mut Parser<'a, R>,
        config: SessionConfig,
        afisafi: AfiSafi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let path_id = if config.rx_addpath(afisafi) {
            Some(PathId::parse(parser)?)
        } else {
            None
        };

        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::parse(parser)?;

        // Check whether we can safely subtract both the labels length and the
        // route Distinguisher length from the prefix size. If there is an
        // unexpected path id, we might silently subtract too much, because
        // there is no 'subtract with overflow' warning when built in release
        // mode.

        if
            u8::try_from(8 * (8 + labels.len()))
                .map_err(|_| ParseError::form_error(
                        "MplsVpnNlri labels/rd too long"
                ))? > prefix_bits
        {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;

        let rd = RouteDistinguisher::parse(parser)?;

        prefix_bits -= 8*8;

        let prefix = parse_prefix_for_len(parser, prefix_bits, afisafi.afi())?;

        let basic = BasicNlri{ prefix, path_id };
        Ok(MplsVpnNlri{ basic, labels, rd })
    }

    pub fn parse_no_addpath<'a, R>(
        parser: &mut Parser<'a, R>,
        afisafi: AfiSafi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let (labels, rd, prefix) =
            Self::parse_labels_rd_prefix(parser, afisafi)?;

        let basic = BasicNlri::new(prefix);

        Ok(MplsVpnNlri{basic, labels, rd})
    }

    pub fn parse_addpath<'a, R>(
        parser: &mut Parser<'a, R>,
        afisafi: AfiSafi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let path_id = PathId::parse(parser)?;
        let (labels, rd, prefix) =
            Self::parse_labels_rd_prefix(parser, afisafi)?;

        let basic = BasicNlri::with_path_id(prefix, path_id);

        Ok(MplsVpnNlri{basic, labels, rd})
    }

    fn parse_labels_rd_prefix<'a, R>(
        parser: &mut Parser<'a, R>,
        afisafi: AfiSafi,
    ) -> Result<(Labels<Octs>, RouteDistinguisher, Prefix), ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::<Octs>::parse(parser)?;

        // 8 for the RouteDistinguisher, plus byte length of labels,
        // times 8 to go from bytes to bits
        let rd_label_len = u8::try_from(8 * (8 + labels.len()))
                .map_err(|_| ParseError::form_error(
                        "MplsVpnNlri labels/rd too long"
                ))?;

        if rd_label_len > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        let rd = RouteDistinguisher::parse(parser)?;
        prefix_bits -= rd_label_len;

        let prefix = parse_prefix_for_len(
            parser,
            prefix_bits,
            afisafi.afi()
        )?;

        Ok((labels, rd, prefix))
    }

    fn skip_labels_rd_prefix<'a, R>(
        parser: &mut Parser<'a, R>,
    ) -> Result<(), ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let mut prefix_bits = parser.parse_u8()?;
        let labels_len = Labels::<Octs>::skip(parser)?;

        let rd_label_len = u8::try_from(8 * (8 + labels_len))
                .map_err(|_| ParseError::form_error(
                        "MplsVpnNlri labels/rd too long"
                ))?;

        if rd_label_len > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        RouteDistinguisher::skip(parser)?;
        prefix_bits -= rd_label_len;

        skip_prefix_for_len(parser, prefix_bits)?;

        Ok(())
    }
}

impl<T: AsRef<[u8]>> MplsVpnNlri<T> {
    fn compose_len(&self) -> usize {
        self.basic.compose_len() + self.labels.len() + self.rd.bytes.len()
    }
}

impl<Octs: Octets> MplsNlri<Octs> {
    pub fn check(
        parser: &mut Parser<Octs>,
        config: SessionConfig,
        afisafi: AfiSafi,
    ) -> Result<(), ParseError> {
        if config.rx_addpath(afisafi) {
            PathId::check(parser)?
        }

        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::parse(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.
        if 8 * labels.len() as u8 > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;
        check_prefix(parser, prefix_bits, afisafi.afi())?;
        Ok(())
    }

    pub fn basic(&self) -> BasicNlri {
        self.basic
    }
}

impl<Octs: Octets> MplsNlri<Octs> {
    pub fn parse<'a, R>(
        parser: &mut Parser<'a, R>,
        config: SessionConfig,
        afisafi: AfiSafi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let path_id = if config.rx_addpath(afisafi) {
            Some(PathId::parse(parser)?)
        } else {
            None
        };

        let (prefix, labels) = Self::parse_labels_and_prefix(parser, afisafi)?;
        let basic = BasicNlri { prefix, path_id };

        Ok(
            MplsNlri {
                basic,
                labels, 
            }
        )
    }

    pub fn parse_no_addpath<'a, R>(
        parser: &mut Parser<'a, R>,
        afisafi: AfiSafi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let (prefix, labels) = Self::parse_labels_and_prefix(parser, afisafi)?;
        let basic = BasicNlri::new(prefix);

        Ok(
            MplsNlri {
                basic,
                labels, 
            }
        )
    }

    pub fn parse_addpath<'a, R>(
        parser: &mut Parser<'a, R>,
        afisafi: AfiSafi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let path_id = PathId::parse(parser)?;
        let (prefix, labels) = Self::parse_labels_and_prefix(parser, afisafi)?;
        let basic = BasicNlri::with_path_id(prefix, path_id);

        Ok(
            MplsNlri {
                basic,
                labels, 
            }
        )
    }

    fn parse_labels_and_prefix<'a, R>(
        parser: &mut Parser<'a, R>,
        afisafi: AfiSafi,
    ) -> Result<(Prefix, Labels<Octs>), ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::<Octs>::parse(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.

        if u8::try_from(8 * labels.len())
            .map_err(|_| ParseError::form_error("MplsNlri labels too long"))?
            > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;

        let prefix = parse_prefix_for_len(
            parser,
            prefix_bits,
            afisafi.afi()
        )?;

        Ok((prefix, labels))
    }

    fn skip_labels_and_prefix<'a, R>(
        parser: &mut Parser<'a, R>,
    ) -> Result<(), ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let mut prefix_bits = parser.parse_u8()?;
        let labels_len = Labels::<Octs>::skip(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.

        if u8::try_from(8 * labels_len)
            .map_err(|_| ParseError::form_error("MplsNlri labels too long"))?
            > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels_len as u8;

        skip_prefix_for_len(parser, prefix_bits)?;

        Ok(())
    }



}

impl<T: AsRef<[u8]>> MplsNlri<T> {
    fn compose_len(&self) -> usize {
        self.basic.compose_len() + self.labels.len()
    }
    pub fn labels(&self) -> &Labels<T> {
        &self.labels
    }
}

impl VplsNlri {
    pub fn skip<Octs: Octets>(parser: &mut Parser<Octs>)
        -> Result<(), ParseError>
    {
        parser.advance(2)?; // length, u16
        RouteDistinguisher::check(parser)?; 
        // ve id/block offset/block size, label base
        parser.advance(2 + 2 + 2 + 1 + 2)?;
        
        Ok(())
    }

    pub fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let _len = parser.parse_u16_be()?;
        let rd = RouteDistinguisher::parse(parser)?; 
        let ve_id = parser.parse_u16_be()?;
        let ve_block_offset = parser.parse_u16_be()?;
        let ve_block_size = parser.parse_u16_be()?;
        let label_base_1 = parser.parse_u8()? as u32;
        let label_base_2 = parser.parse_u16_be()? as u32;

        Ok(
            VplsNlri {
                rd,
                ve_id,
                ve_block_offset,
                ve_block_size,
                raw_label_base: label_base_1 << 16 | label_base_2,
            }
        )
    }

    fn compose_len(&self) -> usize {
        8 + 2 + 2 + 2 + 4
    }
}

impl<Octs: Octets> FlowSpecNlri<Octs> {
    pub fn check(parser: &mut Parser<Octs>, afi: AFI)
        -> Result<(), ParseError>
    {
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };
        let mut pp = parser.parse_parser(len.into())?;
        match afi {
            AFI::Ipv4 => {
                while pp.remaining() > 0 {
                    Component::parse(&mut pp)?;
                }
                Ok(())
            }
            AFI::Ipv6 => {
                debug!("FlowSpec v6 not implemented yet");
                Ok(())
            }
            _ => Err(ParseError::form_error("illegal AFI for FlowSpec"))

        }
    }

    fn skip(parser: &mut Parser<Octs>) -> Result<(), ParseError> {
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };

        Ok(parser.advance(len.into())?)
    }
}

impl<Octs: Octets> FlowSpecNlri<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>, afi: AFI)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };
        let pos = parser.pos();

        if usize::from(len) > parser.remaining() {
            return Err(ParseError::form_error(
                    "invalid length of FlowSpec NLRI"
            ));
        }

        match afi {
            AFI::Ipv4 => {
                while parser.pos() < pos + len as usize {
                    Component::parse(parser)?;
                }
            }
            AFI::Ipv6 => {
                debug!("FlowSpec v6 not implemented yet, \
                      returning unchecked NLRI"
                );
            }
            _ => {
                return Err(ParseError::form_error("illegal AFI for FlowSpec"))
            }
        }
                
        parser.seek(pos)?;
        let raw = parser.parse_octets(len as usize)?;

        Ok(
            FlowSpecNlri {
                afi,
                raw
            }
        )
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = self.raw.as_ref().len();
        if len >= 240 {
            todo!(); //FIXME properly encode into 0xfnnn for 239 < len < 4095
            /*
            target.append_slice(
                &u16::try_from(self.compose_len()).unwrap_or(u16::MAX)
                .to_be_bytes()
            )?;
            */
        } else {
            // We know len < 255 so we can safely unwrap.
            target.append_slice(&[u8::try_from(len).unwrap()])?;
        }
        target.append_slice(self.raw.as_ref())
    }
}


impl<Octs: AsRef<[u8]>> FlowSpecNlri<Octs> {
    pub(crate) fn compose_len(&self) -> usize {
        let value_len = self.raw.as_ref().len();
        let len_len = if value_len >= 240 { 2 } else { 1 } ;
        len_len + value_len
    }
}

impl<Octs: Octets> RouteTargetNlri<Octs> {
    pub fn _check(parser: &mut Parser<Octs>)
        -> Result<(), ParseError>
    {
        let prefix_bits = parser.parse_u8()?;
        let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
        parser.advance(prefix_bytes)?;

        Ok(())
    }
}

impl<Octs: Octets> RouteTargetNlri<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let prefix_bits = parser.parse_u8()?;
        let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
        let raw = parser.parse_octets(prefix_bytes)?;

        Ok(
            RouteTargetNlri {
                raw
            }
        )
    }

    pub fn parse_no_addpath<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        Self::parse(parser)
    }

    fn skip<R>(parser: &mut Parser<R>) -> Result<(), ParseError>
        where
            R: AsRef<[u8]>
    {
        let prefix_bits = parser.parse_u8()?;
        let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
        parser.advance(prefix_bytes)?;

        Ok(())
    }
}

impl<T: AsRef<[u8]>> RouteTargetNlri<T> {
    fn compose_len(&self) -> usize {
        self.raw.as_ref().len()
    }
}

impl<Octs: Octets> EvpnNlri<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let route_type = parser.parse_u8()?.into();
        let route_len = parser.parse_u8()?;
        let raw = parser.parse_octets(route_len.into())?;

        Ok(
            EvpnNlri {
                route_type,
                raw
            }
        )
    }

    fn skip<R>(parser: &mut Parser<R>) -> Result<(), ParseError>
        where
            R: AsRef<[u8]>
    {
        parser.advance(1)?; // Route Type
        let len = parser.parse_u8()?;
        parser.advance(len.into())?; // Length in bytes
        Ok(())
    }
}

//------------ Tests ----------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    #[test]
    fn compose_len() {
        fn test(p: (&str, Option<PathId>), expected_len: usize) {
            let prefix = Prefix::from_str(p.0).unwrap();
            let b: BasicNlri = (prefix, p.1).into();
            assert_eq!(b.compose_len(), expected_len);
        }

        [
            (("10.0.0.0/24",    None),  4 ),
            (("10.0.0.0/23",    None),  4 ),
            (("10.0.0.0/25",    None),  5 ),
            (("0.0.0.0/0",      None),  1 ),

            (("10.0.0.0/24",    Some(PathId(1))),  4 + 4 ),
            (("10.0.0.0/23",    Some(PathId(1))),  4 + 4 ),
            (("10.0.0.0/25",    Some(PathId(1))),  5 + 4 ),
            (("0.0.0.0/0",      Some(PathId(1))),  1 + 4 ),

            (("2001:db8::/32",  None),  5 ),
            (("::/0",           None),  1 ),

            (("2001:db8::/32",  Some(PathId(1))),  5 + 4 ),
            (("::/0",           Some(PathId(1))),  1 + 4 ),

        ].iter().for_each(|e| test(e.0, e.1));

    }
}

