use crate::bgp::types::{AFI, SAFI, NextHop};

use crate::addr::Prefix;

use crate::util::parser::{parse_ipv4addr, parse_ipv6addr, ParseError};
use crate::bgp::message::update::{AddPath, SessionConfig};
use crate::flowspec::Component;
use octseq::{Octets, OctetsBuilder, OctetsFrom, Parser};
use log::warn;

use std::fmt;
use std::net::IpAddr;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

//--- NextHop in MP_REACH_NLRI -----------------------------------------------
impl NextHop {
    pub fn check(parser: &mut Parser<[u8]>, afi: AFI, safi: SAFI)
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
                warn!("Unimplemented NextHop AFI/SAFI {}/{} len {}",
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
                NextHop::Ipv6(parse_ipv6addr(parser)?),
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
            (4, AFI::Ipv4, SAFI::Unicast | SAFI::Multicast | SAFI::MplsUnicast ) =>
                NextHop::Ipv4(parse_ipv4addr(parser)?),
            (12, AFI::Ipv4, SAFI::MplsVpnUnicast) =>
                NextHop::Ipv4MplsVpnUnicast(
                    RouteDistinguisher::parse(parser)?,
                    parse_ipv4addr(parser)?
                ),
            // RouteTarget is always AFI/SAFI 1/132, so, IPv4,
            // but the Next Hop can be IPv6.
            (4, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Ipv4(parse_ipv4addr(parser)?),
            (16, AFI::Ipv4, SAFI::RouteTarget) =>
                NextHop::Ipv6(parse_ipv6addr(parser)?),
            (0, AFI::Ipv4, SAFI::FlowSpec) =>
                NextHop::Empty,
            _ => {
                parser.advance(len.into())?;
                NextHop::Unimplemented( afi, safi)
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
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PathId(u32);

impl PathId {
    pub fn check(parser: &mut Parser<[u8]>)
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
#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub struct Labels<Octets: ?Sized> {
    octets: Octets
}

impl<Octs: Octets> Labels<Octs> {
    fn len(&self) -> usize {
        self.octets.as_ref().len()
    }

    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
    
}

impl<Octs: Octets> Labels<Octs> {
    // XXX check all this Label stuff again
    fn _check<'a, R>(parser: &mut Parser<'a, R>) -> Result<(), ParseError>
        where
            R: Octets<Range<'a> = Octs>
    {
        let mut stop = false;
        let mut buf = [0u8; 3];

        while !stop {
            //20bits label + 3bits rsvd + S bit
            parser.parse_buf(&mut buf)?;

            if buf[2] & 0x01 == 0x01  || // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00] // or RFC 8277 2.4
            {
                stop = true;
            }
        }

        Ok(())
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
    pub fn check(parser: &mut Parser<[u8]>)
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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BasicNlri {
    pub prefix: Prefix,
    pub path_id: Option<PathId>,
}

/// NLRI comprised of a [`BasicNlri`] and MPLS `Labels`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MplsNlri<Octets> {
    basic: BasicNlri,
    labels: Labels<Octets>,
}

/// NLRI comprised of a [`BasicNlri`], MPLS `Labels` and a VPN
/// `RouteDistinguisher`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MplsVpnNlri<Octets> {
    basic: BasicNlri,
    labels: Labels<Octets>,
    rd: RouteDistinguisher,
}

/// VPLS Information as defined in RFC4761.
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowSpecNlri<Octets> {
    #[allow(dead_code)]
    raw: Octets,
}

/// NLRI containing a Route Target membership as defined in RFC4684.
///
/// **TODO**: implement accessor methods for the contents of this NLRI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTargetNlri<Octets> {
    #[allow(dead_code)]
    raw: Octets,
}

/// Conventional and BGP-MP NLRI variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Nlri<Octets> {                     // (AFIs  , SAFIs):
    Unicast(BasicNlri),                     // (v4/v6, unicast)
    Multicast(BasicNlri),                   // (v4/v6, multicast)
    Mpls(MplsNlri<Octets>),                 // (v4/v6, mpls unicast) 
    MplsVpn(MplsVpnNlri<Octets>),           // (v4/v6, mpls vpn unicast)
    Vpls(VplsNlri),                         // (l2vpn, vpls)
    FlowSpec(FlowSpecNlri<Octets>),         // (v4/v6, flowspec)
    RouteTarget(RouteTargetNlri<Octets>),   // (v4, route target)
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
        }
        Ok(())
    }
}

impl<Octs, SrcOcts> OctetsFrom<Nlri<SrcOcts>> for Nlri<Octs> 
where
    Octs: OctetsFrom<SrcOcts>
{
    //type Error = Octs::Error;
    type Error = std::convert::Infallible;

    fn try_octets_from(source: Nlri<SrcOcts>) -> Result<Self, Self::Error> {
        match source {
            Nlri::Unicast(b) => Ok(Nlri::Unicast(b)),
            Nlri::Multicast(b) => Ok(Nlri::Multicast(b)),
            _ => todo!()
        }
    }
}

impl<'a, Octs, SrcOcts: 'a> OctetsFrom<&'a Nlri<SrcOcts>> for Nlri<Octs> 
where
    Octs: OctetsFrom<SrcOcts>
{
    type Error = std::convert::Infallible;

    fn try_octets_from(source: &'a Nlri<SrcOcts>) -> Result<Self, Self::Error> {
        match *source {
            Nlri::Unicast(b) => Ok(Nlri::Unicast(b)),
            Nlri::Multicast(b) => Ok(Nlri::Multicast(b)),
            _ => todo!()
        }
    }
}

impl<Octets> Nlri<Octets> {
    /// Returns the MPLS [`Labels`], if any.
    ///
    /// Applicable to MPLS and MPLS-VPN NLRI.
    pub fn labels(&self) -> Option<&Labels<Octets>> {
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
            Nlri::Unicast(b) => b.compose_len(),
            _ => unimplemented!()
        }
    }
}


use std::str::FromStr;
impl<Octs> Nlri<Octs> {
    /// Creates a `Nlri::Unicast` for `prefix`.
    ///
    /// This returns the error thrown by `Prefix::from_str` if `prefix` does
    /// not represent a valid IPv6 or IPv4 prefix.
    pub fn unicast_from_str(prefix: &str)
        -> Result<Nlri<Octs>, <Prefix as FromStr>::Err>
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

fn check_prefix(
    parser: &mut Parser<[u8]>,
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
            panic!("unimplemented")
        }
    };

    Ok(())
}

fn parse_prefix<R: Octets>(parser: &mut Parser<'_, R>, prefix_bits: u8, afi: AFI)
    -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let prefix = match (afi, prefix_bytes) {
        (AFI::Ipv4, 0) => {
            Prefix::new_v4(0.into(), 0)?
        },
        (AFI::Ipv4, _b @ 5..) => { 
            return Err(ParseError::form_error("illegal byte size for IPv4 NLRI"))
        },
        (AFI::Ipv4, _) => {
            let mut b = [0u8; 4];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|_e| 
                    ParseError::form_error("prefix parsing failed")
            )?
        }
        (AFI::Ipv6, 0) => {
            Prefix::new_v6(0.into(), 0)?
        },
        (AFI::Ipv6, _b @ 17..) => { 
            return Err(ParseError::form_error("illegal byte size for IPv6 NLRI"))
        },
        (AFI::Ipv6, _) => {
            let mut b = [0u8; 16];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|_e| 
                    ParseError::form_error("prefix parsing failed")
            )?
        },
        (_, _) => {
            panic!("unimplemented")
        }
    };
    Ok(prefix)
}

impl BasicNlri {
    pub fn check(
        parser: &mut Parser<[u8]>,
        config: SessionConfig,
        afi: AFI
    ) -> Result<(), ParseError> {
        if config.add_path == AddPath::Enabled {
            PathId::check(parser)?
        }

        let prefix_bits = parser.parse_u8()?;
        check_prefix(parser, prefix_bits, afi)?;
        
        Ok(())
    }

    pub fn parse<R: Octets>(
        parser: &mut Parser<'_, R>,
        config: SessionConfig,
        afi: AFI
    ) -> Result<Self, ParseError> {
        let path_id = match config.add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };
        let prefix_bits = parser.parse_u8()?;
        let prefix = parse_prefix(parser, prefix_bits, afi)?;
        
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


impl MplsVpnNlri<()> {
    pub fn check(
        parser: &mut Parser<[u8]>,
        config: SessionConfig,
        afi: AFI
        ) -> Result<(), ParseError>
    {
        if config.add_path == AddPath::Enabled {
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

        check_prefix(parser, prefix_bits, afi)?;

        Ok(())
    }
}

impl<Octs: Octets> MplsVpnNlri<Octs> {
    pub fn parse<'a, R>(
        parser: &mut Parser<'a, R>,
        config: SessionConfig,
        afi: AFI) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let path_id = match config.add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };

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

        let rd = RouteDistinguisher::parse(parser)?;
        prefix_bits -= 8*std::mem::size_of::<RouteDistinguisher>() as u8;

        let prefix = parse_prefix(parser, prefix_bits, afi)?;

        let basic = BasicNlri{ prefix, path_id };
        Ok(MplsVpnNlri{ basic, labels, rd })
    }
}

impl MplsNlri<()> {
    pub fn check(
        parser: &mut Parser<[u8]>,
        config: SessionConfig,
        afi: AFI) -> Result<(), ParseError>
    {
        if config.add_path == AddPath::Enabled {
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
        check_prefix(parser, prefix_bits, afi)?;
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
        afi: AFI) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let path_id = match config.add_path {
            AddPath::Enabled => Some(PathId::parse(parser)?),
            _ => None
        };

        let mut prefix_bits = parser.parse_u8()?;
        let labels = Labels::<Octs>::parse(parser)?;

        // Check whether we can safely subtract the labels length from the
        // prefix size. If there is an unexpected path id, we might silently
        // subtract too much, because there is no 'subtract with overflow'
        // warning when built in release mode.
        if 8 * labels.len() as u8 > prefix_bits {
            return Err(ParseError::ShortInput);
        }

        prefix_bits -= 8 * labels.len() as u8;

        let prefix = parse_prefix(parser, prefix_bits, afi)?;
        let basic = BasicNlri { prefix, path_id };
        Ok(
            MplsNlri {
                basic,
                labels, 
            }
        )
    }
}

impl VplsNlri {
    pub fn check(parser: &mut Parser<[u8]>)
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
}

impl FlowSpecNlri<()> {
    pub fn check(parser: &mut Parser<[u8]>)
        -> Result<(), ParseError>
    {
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };
        let pp = parser.parse_parser(len.into())?;
        while pp.remaining() > 0 {
            // TODO implement Component::check()
            Component::parse(parser)?;
        }

        Ok(())
    }
}

impl<Octs: Octets> FlowSpecNlri<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let pos = parser.pos();
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };
        while parser.pos() < pos + len as usize {
            Component::parse(parser)?;
        }

        
        let raw_len = parser.pos() - pos;
        parser.seek(pos)?;
        let raw = parser.parse_octets(raw_len)?;

        Ok(
            FlowSpecNlri {
                raw
            }
        )
    }
}

impl RouteTargetNlri<()> {
    pub fn check(parser: &mut Parser<[u8]>)
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

