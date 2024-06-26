//! FlowSpec v1 parsing.

use inetnum::addr::Prefix;
use crate::bgp::{nlri::common::prefix_bits_to_bytes, types::Afi};
use crate::util::parser::ParseError;
use log::debug;
use octseq::{Octets, Parser};

use std::net::IpAddr;

fn op_to_len(op: u8) -> usize {
    match (op & 0b00110000) >> 4 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => panic!("impossible len bits in NumericOp")
    }
}

pub struct NumericOp(u8, u64);
impl NumericOp {
    pub fn end_of_list(&self) -> bool {
        self.0 & 0x80 == 0x80
    }

    pub fn and(&self) -> bool {
        self.0 & 0x40 == 0x40
    }

    pub fn length(&self) -> usize {
        op_to_len(self.0)
    }

    pub fn value(&self) -> u64 {
        self.1
    }
}

pub struct BitmaskOp(u8, u64);
impl BitmaskOp {
    pub fn end_of_list(&self) -> bool {
        self.0 & 0x80 == 0x80
    }

    pub fn value(&self) -> u64 {
        self.1
    }
}


#[derive(Copy, Clone, Debug)]
pub enum Component<Octets> {
    DestinationPrefix(Prefix),
    SourcePrefix(Prefix),
    IpProtocol(Octets),
    Port(Octets),
    DestinationPort(Octets),
    SourcePort(Octets),
    IcmpType(Octets),
    IcmpCode(Octets),
    TcpFlags(Octets), // list of (bitmask_op , value)
    PacketLength(Octets),
    DSCP(Octets),
    Fragment(Octets),
}

impl NumericOp {
    fn parse<R: Octets + ?Sized>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let op = parser.parse_u8()?;
        let value = match op_to_len(op) {
            1 => parser.parse_u8()? as u64,
            2 => parser.parse_u16_be()? as u64,
            4 => parser.parse_u32_be()? as u64,
            8 => parser.parse_u64_be()?,
            _ => panic!("illegal case"),
        };
        Ok(Self(op, value))
    }
}

impl BitmaskOp {
    fn parse<R: Octets + ?Sized>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let op = parser.parse_u8()?;
        let value = match op_to_len(op) {
            1 => parser.parse_u8()? as u64,
            2 => parser.parse_u16_be()? as u64,
            4 => parser.parse_u32_be()? as u64,
            8 => parser.parse_u64_be()?,
            _ => panic!("illegal case"),
        };
        Ok(Self(op, value))
    }
}

fn parse_prefix<R: Octets + ?Sized>(
    parser: &mut Parser<'_, R>,
    afi: Afi,
    prefix_bits: u8
) -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let prefix = match (afi, prefix_bytes) {
        (Afi::Ipv4, 0) => {
            Prefix::new_v4(0.into(), 0)?
        },
        (Afi::Ipv4, _b @ 5..) => { 
            return Err(ParseError::form_error("illegal byte size for IPv4 NLRI"))
        },
        (Afi::Ipv4, _) => {
            let mut b = [0u8; 4];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|_e| 
                    ParseError::form_error("prefix parsing failed")
            )?
        }
        (Afi::Ipv6, 0) => {
            Prefix::new_v6(0.into(), 0)?
        },
        (Afi::Ipv6, _b @ 17..) => { 
            return Err(ParseError::form_error("illegal byte size for IPv6 NLRI"))
        },
        (Afi::Ipv6, _) => {
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

impl<Octs: Octets> Component<Octs> {
    pub(crate) fn parse<'a, R>(parser: &mut Parser<'a, R>)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs> + ?Sized
    {
        let typ = parser.parse_u8()?;
        let res = match typ {
            1 => {
                let prefix_bits = parser.parse_u8()?;
                let pfx = parse_prefix(parser, Afi::Ipv4, prefix_bits)?;
                Component::DestinationPrefix(pfx)
            },
            2 => {
                let prefix_bits = parser.parse_u8()?;
                let pfx = parse_prefix(parser, Afi::Ipv4, prefix_bits)?;
                Component::SourcePrefix(pfx)
            },
            3 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::IpProtocol(
                    parser.parse_octets(octets_len)?
                )
            },
            4 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::Port(
                    parser.parse_octets(octets_len)?
                )
            },
            5 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::DestinationPort(
                    parser.parse_octets(octets_len)?
                )
            },
            6 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::SourcePort(
                    parser.parse_octets(octets_len)?
                )
            },
            7 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::IcmpType(
                    parser.parse_octets(octets_len)?
                )
            },
            8 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::IcmpCode(
                    parser.parse_octets(octets_len)?
                )
            },
            9 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = BitmaskOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::TcpFlags(
                    parser.parse_octets(octets_len)?
                )
            },
            10 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::PacketLength(
                    parser.parse_octets(octets_len)?
                )
            },
            11 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = NumericOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::DSCP(
                    parser.parse_octets(octets_len)?
                )
            },
            12 => {
                let pos = parser.pos();
                let mut done = false;
                while !done {
                    let op = BitmaskOp::parse(parser)?;
                    done = op.end_of_list();
                }
                let octets_len = parser.pos() - pos;
                parser.seek(pos)?;
                Component::Fragment(
                    parser.parse_octets(octets_len)?
                )
            },
            _ => { 
                debug!("unimplemented flowspec type {}", typ);
                return Err(ParseError::Unsupported)
            }
        };

        Ok(res)
    }
}



