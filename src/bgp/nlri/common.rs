
use octseq::{Octets, Parser};
use crate::util::parser::ParseError;
use crate::addr::Prefix;
use super::afisafi::Afi;

use std::net::IpAddr;
use std::fmt;

//------------ Types ---------------------------------------------------------
/// Path Identifier for BGP Multiple Paths (RFC7911).
///
/// Used in all AddpathNlri variants.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PathId(pub u32);

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//------------ Helper functions ----------------------------------------------

pub(super) fn parse_prefix<R: Octets>(parser: &mut Parser<'_, R>, afi: Afi)
    -> Result<Prefix, ParseError>
{
    let prefix_bits = parser.parse_u8()?;
    parse_prefix_for_len(parser, prefix_bits, afi)
}

pub(super) fn parse_prefix_for_len<R: Octets>(
    parser: &mut Parser<'_, R>,
    prefix_bits: u8,
    afi: Afi
)
    -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let prefix = match (afi, prefix_bytes) {
        (Afi::Ipv4, 0) => {
            Prefix::new_v4(0.into(), 0)?
        },
        (Afi::Ipv4, _b @ 5..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv4 NLRI")
            )
        },
        (Afi::Ipv4, _) => {
            let mut b = [0u8; 4];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|e| 
                ParseError::form_error(e.static_description())
            )?
        }
        (Afi::Ipv6, 0) => {
            Prefix::new_v6(0.into(), 0)?
        },
        (Afi::Ipv6, _b @ 17..) => { 
            return Err(
                ParseError::form_error("illegal byte size for IPv6 NLRI")
            )
        },
        (Afi::Ipv6, _) => {
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

pub(super) fn prefix_bits_to_bytes(bits: u8) -> usize {
    if bits != 0 {
        (bits as usize - 1) / 8 + 1
    } else {
        0
    }
}
