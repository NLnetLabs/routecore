
use octseq::{Octets, OctetsBuilder, Parser};
use crate::util::parser::ParseError;
use inetnum::addr::Prefix;
use super::afisafi::Afi;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::fmt;

//------------ Types ---------------------------------------------------------
/// Path Identifier for BGP Multiple Paths (RFC7911).
///
/// Used in all AddpathNlri variants.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathId(pub u32);

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//------------ Helper functions ----------------------------------------------


#[deprecated = "use AFI specific methods"]
#[allow(dead_code)]
pub(super) fn parse_prefix<R: Octets>(parser: &mut Parser<'_, R>, afi: Afi)
    -> Result<Prefix, ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    parse_prefix_for_len(parser, prefix_bits, afi)
}

pub fn parse_prefix_for_len<R: Octets>(
    parser: &mut Parser<'_, R>,
    prefix_bits: u8,
    afi: Afi
)
    -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let res = match afi {
        Afi::Ipv4 => {
            let mut b = [0u8; 4];
            //b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.parse_buf(&mut b[..prefix_bytes])?;
            Prefix::new_v4(Ipv4Addr::from(b), prefix_bits).map_err(|e|
                ParseError::form_error(e.static_description())
            )?
        },
        Afi::Ipv6 => {
            let mut b = [0u8; 16];
            //b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.parse_buf(&mut b[..prefix_bytes])?;
            Prefix::new_v6(Ipv6Addr::from(b), prefix_bits).map_err(|e|
                ParseError::form_error(e.static_description())
            )?
        },
        _ => { return Err(ParseError::form_error("unknown prefix format")); }

    };
    Ok(res)
}

pub(crate) fn parse_v4_prefix<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<Prefix, ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    parse_v4_prefix_for_len(parser, prefix_bits)
}

pub(super) fn parse_v4_prefix_for_len<R: Octets>(
    parser: &mut Parser<'_, R>,
    prefix_bits: u8,
) -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    if prefix_bytes > 4 {
        return Err(ParseError::form_error("illegal prefix length"));
    }
    let mut b = [0u8; 4];
    parser.parse_buf(&mut b[..prefix_bytes])?;
    Prefix::new_v4(Ipv4Addr::from(b), prefix_bits).map_err(|e|
        ParseError::form_error(e.static_description())
    )
}

pub(crate) fn parse_v6_prefix<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<Prefix, ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    parse_v6_prefix_for_len(parser, prefix_bits)
}

pub(super) fn parse_v6_prefix_for_len<R: Octets>(
    parser: &mut Parser<'_, R>,
    prefix_bits: u8,
) -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    if prefix_bytes > 16 {
        return Err(ParseError::form_error("illegal prefix length"));
    }
    let mut b = [0u8; 16];
    parser.parse_buf(&mut b[..prefix_bytes])?;
    Prefix::new_v6(Ipv6Addr::from(b), prefix_bits).map_err(|e|
        ParseError::form_error(e.static_description())
    )
}

#[allow(clippy::manual_div_ceil)]
pub(crate) const fn prefix_bits_to_bytes(bits: u8) -> usize {
    // The div_ceil implemenation has an if statement and thus might introduce
    // branching. As this is super hot code, we do not like that.
    //(bits as usize).div_ceil(8)
    ((bits as usize) + 8 - 1) / 8

}

pub(super) fn compose_len_prefix(prefix: Prefix) -> usize {
    prefix_bits_to_bytes(prefix.len())
}

pub(super) fn compose_prefix<Target: OctetsBuilder>(
    prefix: Prefix,
    target: &mut Target
) -> Result<(), Target::AppendError> {
    let len = prefix.len();
    target.append_slice(&[len])?;
    let prefix_bytes = prefix_bits_to_bytes(len);
    match prefix.addr() {
        std::net::IpAddr::V4(a) => {
            target.append_slice(&a.octets()[..prefix_bytes])?
        }
        std::net::IpAddr::V6(a) => {
            target.append_slice(&a.octets()[..prefix_bytes])?
        }
    }
    Ok(())
}

pub(super) fn compose_prefix_without_len<Target: OctetsBuilder>(
    prefix: Prefix,
    target: &mut Target
) -> Result<(), Target::AppendError> {
    let prefix_bytes = prefix_bits_to_bytes(prefix.len());
    match prefix.addr() {
        std::net::IpAddr::V4(a) => {
            target.append_slice(&a.octets()[..prefix_bytes])?
        }
        std::net::IpAddr::V6(a) => {
            target.append_slice(&a.octets()[..prefix_bytes])?
        }
    }
    Ok(())
}


//--- Skip functions

#[allow(dead_code)]
fn skip_prefix<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<(), ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    Ok(parser.advance(prefix_bytes)?)
}

#[allow(dead_code)]
fn skip_prefix_for_len<R: Octets>(parser: &mut Parser<'_, R>, prefix_bits: u8)
    -> Result<(), ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    Ok(parser.advance(prefix_bytes)?)
}

#[allow(dead_code)]
fn skip_prefix_addpath<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<(), ParseError>
{
    parser.advance(4)?;
    let prefix_bits = parser.parse_u8()?;
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    Ok(parser.advance(prefix_bytes)?)
}
