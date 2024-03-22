use std::fmt;

use octseq::{Octets, Parser};

use crate::util::parser::ParseError;
use super::mpls_vpn::RouteDistinguisher;

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

impl VplsNlri {
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


impl fmt::Display for VplsNlri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VPLS-{}", self.rd)
    }
}
