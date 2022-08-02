use crate::addr::Prefix;
use crate::util::parser::{Parse, Parser, ParseError, OctetsRef};
use crate::bgp::message::AFI;
use std::net::IpAddr;
use log::warn;

fn op_to_len(op: u8) -> usize {
    match (op & 0b00110000) >> 4 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => panic!("impossible len bits in NumericOp")
    }
}

struct NumericOp(u8, u64);
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
}

struct BitmaskOp(u8, u64);
impl BitmaskOp {
    pub fn end_of_list(&self) -> bool {
        self.0 & 0x80 == 0x80
    }
}


#[derive(Debug)]
pub enum Component<'a> {
    DestinationPrefix(Prefix),
    SourcePrefix(Prefix),
    IpProtocol(&'a [u8]),
    Port(&'a [u8]),
    DestinationPort(&'a [u8]),
    SourcePort(&'a [u8]),
    IcmpType(&'a [u8]),
    IcmpCode(&'a [u8]),
    TcpFlags(&'a [u8]), // list of (bitmask_op , value)
    PacketLength(&'a [u8]),
    DSCP(&'a [u8]),
    Fragment(&'a [u8]),
}

impl<R: AsRef<[u8]>> Parse<R> for NumericOp {
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let op = parser.parse_u8()?;
        let value = match op_to_len(op) {
            1 => parser.parse_u8()? as u64,
            2 => parser.parse_u16()? as u64,
            4 => parser.parse_u32()? as u64,
            8 => parser.parse_u64()?,
            _ => panic!("illegal case"),
        };
        Ok(Self {
            0: op,
            1: value,
        })
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

impl<R: AsRef<[u8]>> Parse<R> for BitmaskOp {
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {
        let op = parser.parse_u8()?;
        let value = match op_to_len(op) {
            1 => parser.parse_u8()? as u64,
            2 => parser.parse_u16()? as u64,
            4 => parser.parse_u32()? as u64,
            8 => parser.parse_u64()?,
            _ => panic!("illegal case"),
        };
        Ok(Self {
            0: op,
            1: value,
        })
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}

fn prefix_bits_to_bytes(bits: u8) -> usize {
    if bits != 0 {
        (bits as usize - 1) / 8 + 1
    } else {
        0
    }
}

fn parse_prefix<R>(parser: &mut Parser<R>, afi: AFI, prefix_bits: u8)
    -> Result<Prefix, ParseError>
where
    R: AsRef<[u8]>
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

impl<'a, R> Parse<R> for Component<'a>
where 
    R: 'a + AsRef<[u8]> + OctetsRef<Range = &'a [u8]>
{
    fn parse(parser: &mut Parser<R>) -> Result<Self, ParseError> {

        let typ = parser.parse_u8()?;
        let res = match typ {
            1 => {
                let prefix_bits = parser.parse_u8()?;
                let pfx = parse_prefix(parser, AFI::Ipv4, prefix_bits)?;
                Component::DestinationPrefix(pfx)
            },
            2 => {
                let prefix_bits = parser.parse_u8()?;
                let pfx = parse_prefix(parser, AFI::Ipv4, prefix_bits)?;
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
            _ => { warn!("unimplemented typ {}", typ); unimplemented!() }
        };

        //debug!("flowspec component res: {:?}", res);
        Ok(res)
    }

    fn skip(parser: &mut Parser<R>) -> Result<(), ParseError> {
        Self::parse(parser).map(|_| ())
    }
}



