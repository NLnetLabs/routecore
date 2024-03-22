use std::fmt;

use log::debug;
use octseq::{Octets, Parser};

use crate::util::parser::ParseError;
use crate::flowspec::Component;
use super::afisafi::Afi;


/// NLRI containing a FlowSpec v1 specification.
///
/// Also see [`crate::flowspec`].
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlowSpecNlri<Octs> {
    #[allow(dead_code)]
    afi: Afi,
    raw: Octs,
}

impl<Octs> FlowSpecNlri<Octs> {
    pub(crate) fn raw(&self) -> &Octs {
        &self.raw
    }
}

impl<Octs: Octets> FlowSpecNlri<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>, afi: Afi)
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
            Afi::Ipv4 => {
                while parser.pos() < pos + len as usize {
                    Component::parse(parser)?;
                }
            }
            Afi::Ipv6 => {
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
}

impl<T> fmt::Display for FlowSpecNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FLOWSPEC-NLRI")
    }
}
