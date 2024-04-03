use std::fmt;

use log::debug;
use octseq::{Octets, OctetsBuilder, Parser};

use crate::util::parser::ParseError;
use crate::flowspec::Component;
use super::afisafi::Afi;


/// NLRI containing a FlowSpec v1 specification.
///
/// Also see [`crate::flowspec`].
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowSpecNlri<Octs> {
    #[allow(dead_code)]
    afi: Afi,
    raw: Octs,
}

impl<Octs> FlowSpecNlri<Octs> {
    pub fn raw(&self) -> &Octs {
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


impl<Octs: AsRef<[u8]>> FlowSpecNlri<Octs> {
    pub(super) fn compose_len(&self) -> usize {
        self.raw.as_ref().len()
    }

    pub(super) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        // length is represented as either a single byte for everything < 240,
        // or as 1.5 bytes with the first nibble set to 0xf, so 0xfnnn.
        // This results in a max length of 4095.
        let len = self.raw.as_ref().len();
        if len >= 240 {
            target.append_slice(&
                (0xf000 | u16::try_from(len).unwrap_or(4095)).to_be_bytes()
            )?;
        } else {
            // we know the length is between 0 and 239 so we can unwrap
            target.append_slice(&[u8::try_from(len).unwrap()])?;
        }
        target.append_slice(self.raw.as_ref())
    }
}

impl<Octs, Other> PartialEq<FlowSpecNlri<Other>> for FlowSpecNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &FlowSpecNlri<Other>) -> bool {
        self.afi == other.afi &&
            self.raw.as_ref() == other.raw.as_ref()
    }
}


impl<T> fmt::Display for FlowSpecNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FLOWSPEC-NLRI")
    }
}
