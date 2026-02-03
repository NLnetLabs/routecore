#![allow(dead_code)]
use octseq::{Octets, OctetsFrom, Parser};
use crate::bgp::fsm::state_machine::State;
use crate::bgp::message::SessionConfig;
use crate::bgp::nlri::common::{parse_v4_prefix, parse_v6_prefix};
use crate::bgp::types::AfiSafiType;
use crate::bgp::{message::Message as BgpMsg, ParseError};
use crate::util::parser::{parse_ipv4addr, parse_ipv6addr};
use crate::{bgp::types::Afi, typeenum};
use inetnum::{addr::Prefix, asn::Asn};

use std::fmt;
use std::net::IpAddr;
use std::ops::Index;
use std::slice::SliceIndex;

use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use serde::{Deserialize, Serialize};

//
//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                           Timestamp                           |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |             Type              |            Subtype            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                             Length                            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                      Message... (variable)
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Copy, Clone, Debug)]
pub struct CommonHeader<'a, Octs> {
    timestamp: u32,
    msg_type: MessageType,
    msg_subtype: MessageSubType,
    length: u32,
    timestamp_mus: u32, // only set in Extended Timestamp message types (_ET)
    message: Parser<'a, Octs>
}
impl<Octs: Octets> CommonHeader<'_, Octs> {
    pub fn length(&self) -> u32  {
        self.length
    }
    pub fn msgtype(&self) -> MessageType {
        self.msg_type
    }
    pub fn subtype(&self) -> MessageSubType {
        self.msg_subtype
    }
}

impl<'a, Octs: Octets> CommonHeader<'a, Octs> {
    pub fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let timestamp = parser.parse_u32_be()?;
        let msg_type = parser.parse_u16_be()?.into();
        let msg_subtype = match msg_type {
            MessageType::TableDumpv2 => {
                MessageSubType::TableDumpv2SubType(
                    parser.parse_u16_be()?.into()
                )
            }
            MessageType::Bgp4Mp | MessageType::Bgp4MpEt => {
                MessageSubType::Bgp4MpSubType(
                    parser.parse_u16_be()?.into()
                )
            }
            _ => {
                log::error!("no support for {msg_type}");
                return Err(ParseError::Unsupported);
            }
        };

        let length = parser.parse_u32_be()?;
        let (timestamp_mus, length) = match msg_type {
            MessageType::Bgp4MpEt
                | MessageType::IsisEt
                | MessageType::Ospfv3Et => {
                    (parser.parse_u32_be()?, length - 4 )
                }
                _ => (0, length)
        };

        let message = parser.parse_parser(length as usize)?;

        Ok( CommonHeader {
                timestamp,
                msg_type,
                msg_subtype,
                length,
                message,
                timestamp_mus,
        })
    }
}

//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                           Timestamp                           |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |             Type              |            Subtype            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                             Length                            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                      Microsecond Timestamp                    |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                      Message... (variable)
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
pub struct ExtendedHeader<'a, Octs> {
    timestamp: u32,
    msg_type: MessageType,
    msg_subtype: MessageSubType,
    length: u32,
    timestamp_ms: u32,
    message: Parser<'a, Octs>
}

typeenum!(MessageType, u16,
    {
    11 => Ospfv2,
    12 => TableDump,
    13 => TableDumpv2,
    16 => Bgp4Mp,
    17 => Bgp4MpEt,
    32 => Isis,
    33 => IsisEt,
    48 => Ospfv3,
    49 => Ospfv3Et,
    }
);

#[derive(Copy, Clone, Debug)]
pub enum MessageSubType {
    TableDumpv2SubType(TableDumpv2SubType),
    Bgp4MpSubType(Bgp4MpSubType),
}

typeenum!(TableDumpv2SubType, u16,
    {
    1 => PeerIndexTable,
    2 => RibIpv4Unicast,
    3 => RibIpv4Multicast,
    4 => RibIpv6Unicast,
    5 => RibIpv6Multicast,
    6 => RibGeneric,
    }
);

typeenum!(Bgp4MpSubType, u16,
    {
    0 => StateChange,
    1 => Message,
    4 => MessageAs4,
    5 => StateChangeAs4,
    6 => MessageLocal,
    7 => MessageAs4Local,
    }
);

//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                      Collector BGP ID                         |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |       View Name Length        |     View Name (variable)      |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |          Peer Count           |    Peer Entries (variable)
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

pub struct PeerIndexTable<'a, Octs> {
    collector_bgp_id: [u8; 4],
    view: Option<String>,
    peer_count: u16,
    peer_entries: Parser<'a, Octs>
}

impl<'a, Octs: Octets> PeerIndexTable<'a, Octs> {
    pub fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let collector_bgp_id = parser.parse_u32_be()?.to_be_bytes();
        let view_len = parser.parse_u16_be()?;
        let view = if view_len > 0 {
            let mut buf = vec![0u8; view_len.into()];
            parser.parse_buf(&mut buf[..])?;
            Some(String::from_utf8_lossy(&buf).into_owned())
        } else {
            None
        };


        let peer_count = parser.parse_u16_be()?;
        let peer_entries = parser.parse_parser(parser.remaining())?;

        Ok( PeerIndexTable {
            collector_bgp_id,
            view,
            peer_count,
            peer_entries
        })

    }

    pub fn view(&self) -> Option<&String> {
        self.view.as_ref()
    }

    pub fn peer_count(&self) -> u16 {
        self.peer_count
    }

    pub fn entries(&mut self) -> Parser<'_, Octs> {
        self.peer_entries
    }
}

//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |   Peer Type   |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                         Peer BGP ID                           |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                   Peer IP Address (variable)                  |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                        Peer AS (variable)                     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct PeerEntry {
    pub bgp_id: [u8; 4],
    pub addr: IpAddr,
    pub asn: Asn,
}

impl PeerEntry {
    pub fn parse<Octs: Octets>(
        parser: &mut Parser<'_, Octs>
    ) -> Result<Self, ParseError> {
        let peer_type = parser.parse_u8()?;
        let bgp_id = parser.parse_u32_be()?.to_be_bytes();
        let addr = if peer_type & 0x01 == 0x00 {
            // ipv4
            let mut buf = [0u8; 4];
            parser.parse_buf(&mut buf)?;
            buf.into()
        } else {
            // ipv6
            let mut buf = [0u8; 16];
            parser.parse_buf(&mut buf)?;
            buf.into()
        };
        let asn: Asn = if peer_type & 0x02 == 0x02  {
            // asn32
            parser.parse_u32_be()?.into()
        } else {
            // asn16
            u32::from(parser.parse_u16_be()?).into()
        };

        Ok( PeerEntry { bgp_id, addr, asn } )
    }
}


//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                         Sequence Number                       |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       | Prefix Length |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                        Prefix (variable)                      |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |         Entry Count           |  RIB Entries (variable)
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Copy, Clone, Debug)]
pub struct RibEntryHeader<'a, Octs> {
    seq_number: u32,
    prefix: Prefix,
    entry_count: u16,
    entries: Parser<'a, Octs>,
}

impl<'a, Octs: Octets> RibEntryHeader<'a, Octs> {
    pub fn parse(parser: &mut Parser<'a, Octs>, afi: Afi)
        -> Result<Self, ParseError>
    {
        let seq_number = parser.parse_u32_be()?;
        let prefix = parse_prefix(parser, afi)?;
        let entry_count = parser.parse_u16_be()?;
        let entries = parser.parse_parser(parser.remaining())?;
        Ok( RibEntryHeader {
            seq_number,
            prefix,
            entry_count,
            entries,
        })
    }

    pub fn seq_number(&self) -> u32 {
        self.seq_number
    }

    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    pub fn entries(&mut self) -> Parser<'_, Octs> {
        self.entries
    }
}

impl<Octs: Octets> fmt::Display for RibEntryHeader<'_, Octs> {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{:>10}] rib entry for {}",
               self.seq_number(),
               self.prefix()
        )
    }
}

//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |         Peer Index            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                         Originated Time                       |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |      Attribute Length         |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                    BGP Attributes... (variable)
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Copy, Clone, Debug)]
pub struct RibEntry<'a, Octs> {
    peer_idx: u16,
    orig_time: u32,
    pub attributes: Parser<'a, Octs>,
}

impl<'a, Octs: Octets> RibEntry<'a, Octs> {
    pub fn parse(parser: &mut Parser<'a, Octs>)
        -> Result<Self, ParseError>
    {
        let peer_idx = parser.parse_u16_be()?;
        let orig_time = parser.parse_u32_be()?;
        let attribute_len = parser.parse_u16_be()?;
        let attributes = parser.parse_parser(attribute_len as usize)?;

        Ok( RibEntry {
            peer_idx, orig_time, attributes
        })
    }
    pub fn peer_index(&self) -> u16 {
        self.peer_idx
    }

    pub fn orig_time(&self) -> u32 {
        self.orig_time
    }
}


impl<Octs: Octets> fmt::Display for RibEntry<'_, Octs> {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "peer idx {} orig_time {}",
               self.peer_index(),
               self.orig_time(),
        )
    }
}


fn parse_prefix<R: Octets>(parser: &mut Parser<'_, R>, afi: Afi)
    -> Result<Prefix, ParseError>
{
    match afi {
        Afi::Ipv4 => Ok(parse_v4_prefix(parser)?),
        Afi::Ipv6 => Ok(parse_v6_prefix(parser)?),
        _ => panic!("unimplemented"),
    }
}

//----------- Peer Index Table -----------------------------------------------

#[derive(Clone)]
pub struct PeerIndex {
    peers: Vec<PeerEntry>
}

impl PeerIndex {
    pub fn empty() -> Self {
        PeerIndex { peers: Vec::new() }
    }

    pub fn reserve(&mut self, n: usize) {
        self.peers.reserve(n);
    }

    pub fn with_capacity(n: usize) -> Self {
        PeerIndex { peers: Vec::with_capacity(n) }
    }

    pub fn push(&mut self, p: PeerEntry) {
        self.peers.push(p);
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.len() == 0
    }

    pub fn get<Octs: Octets>(&self, rib_entry: &RibEntry<Octs>)
        -> Option<&PeerEntry>
    {
        self.peers.get(usize::from(rib_entry.peer_index()))
    }
}

impl<I: SliceIndex<[PeerEntry]>> Index<I> for PeerIndex {
    type Output = I::Output;
    fn index(&self, i: I) -> &Self::Output {
        &self.peers[i]
    }
}

//------------ Convenience stuff / public API ---------------------------------

pub struct MrtFile<'a> {
    raw: &'a [u8],
}
impl<'a> MrtFile<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    pub fn rib_entries(
        &'a self
    ) -> Result<RibEntryIterator<'a, &'a [u8]>, ParseError> {
        let mut parser = Parser::from_ref(&self.raw);
        let peer_index = Self::extract_peer_index_table(&mut parser)?;
        Ok(
            RibEntryIterator::new(
                peer_index,
                parser
            )
        )
    }

    pub fn pi(&self) -> Result<PeerIndex, ParseError> {
        let mut parser = Parser::from_ref(&self.raw);
        Self::extract_peer_index_table(&mut parser)
    }

    pub fn rib_entries_mt<Octs: 'a + Octets>(&'a self)
        -> impl ParallelIterator<Item =
                    <SingleEntryIterator<'a, Octs> as Iterator>::Item
                > + 'a
    where
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        let mut parser = Parser::from_ref(&self.raw);
        let peer_index = Self::extract_peer_index_table(&mut parser).unwrap();

        let tables = TableDumpIterator::new(peer_index, parser);
        tables.par_bridge().map(|(_fam, reh)|{
            SingleEntryIterator::new(reh)
        }).flat_map_iter(|e| e.into_iter())
    }

    pub fn tables(
        &'a self
    ) -> Result<TableDumpIterator<'a, &'a [u8]>, ParseError> {
        let mut parser = Parser::from_ref(&self.raw);
        let peer_index = Self::extract_peer_index_table(&mut parser)?;
        Ok(TableDumpIterator::new(peer_index, parser))
    }

    fn extract_peer_index_table(
        parser: &mut Parser<'_, &[u8]>
    ) -> Result<PeerIndex, ParseError> {
        let mut m = CommonHeader::parse(parser)?;
        let mut peer_index = PeerIndex::empty();

        match m.subtype() {
            MessageSubType::TableDumpv2SubType(tdv2) => {
                match tdv2 {
                    TableDumpv2SubType::PeerIndexTable => {
                        assert!(peer_index.is_empty());
                        let mut pit = PeerIndexTable::parse(&mut m.message)?;
                        peer_index.reserve(pit.peer_count().into());
                        let mut pes = pit.entries();
                        while pes.remaining() > 0 {
                            let pe = PeerEntry::parse(&mut pes).unwrap();
                            //println!("peer entry {pe:?}");
                            peer_index.push(pe);
                        }
                        assert_eq!(peer_index.len(), usize::from(pit.peer_count()));
                        Ok(peer_index)
                    },
                    _ => {
                        Err(ParseError::form_error("expected PeerIndexTable"))
                    }
                }
            }
            _ => { Err(ParseError::form_error("no TableDumpv2SubType")) }
        }
    }

    pub fn messages(&self) -> UpdateIterator<'a, &[u8]> {
        let parser = Parser::from_ref(&self.raw);
        UpdateIterator { parser }
    }
}

//------------ UpdateIterator ------------------------------------------------

#[derive(Debug)]
pub enum Bgp4Mp<'a, Octs> {
    StateChange(StateChange),
    Message(Message<'a, Octs>),
    MessageAs4(MessageAs4<'a, Octs>),
    StateChangeAs4(StateChangeAs4),
    //MessageLocal(MessageLocal),
    //MessageAs4Local(MessageAs4Local),
}

impl<Octs> From<StateChange> for Bgp4Mp<'_, Octs> {
    fn from(msg: StateChange) -> Self {
        Self::StateChange(msg)
    }
}

impl<Octs> From<StateChangeAs4> for Bgp4Mp<'_, Octs> {
    fn from(msg: StateChangeAs4) -> Self {
        Self::StateChangeAs4(msg)
    }
}

impl<'a, Octs> From<Message<'a, Octs>> for Bgp4Mp<'a, Octs> {
    fn from(msg: Message<'a, Octs>) -> Self {
        Self::Message(msg)
    }
}
impl<'a, Octs> From<MessageAs4<'a, Octs>> for Bgp4Mp<'a, Octs> {
    fn from(msg: MessageAs4<'a, Octs>) -> Self {
        Self::MessageAs4(msg)
    }
}

#[derive(Debug)]
pub struct StateChange {
    peer_asn: Asn,
    local_asn: Asn,
    interface: u16,
    afi: Afi,
    peer_addr: IpAddr,
    local_addr: IpAddr,
    old_state: State,
    new_state: State,
}

impl StateChange {
    pub fn parse<Octs: Octets>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        let peer_asn = Asn::from_u32(parser.parse_u16_be()?.into());
        let local_asn = Asn::from_u32(parser.parse_u16_be()?.into());
        let interface = parser.parse_u16_be()?;
        let afi = parser.parse_u16_be()?.into();
        let (peer_addr, local_addr) = match afi {
            Afi::Ipv4 => {
                (parse_ipv4addr(parser)?.into(),
                parse_ipv4addr(parser)?.into())
            }
            Afi::Ipv6 => {
                (parse_ipv6addr(parser)?.into(),
                parse_ipv6addr(parser)?.into())
            }
            _ => {
                eprintln!("{:x?}", afi);
                return Err(
                    ParseError::form_error("unexpected AFI in StateChange")
                );
            }
        };
        let old_state = parser.parse_u16_be()?.into();
        let new_state = parser.parse_u16_be()?.into();

        Ok(
            StateChange {
                peer_asn,
                local_asn,
                interface,
                afi,
                peer_addr,
                local_addr,
                old_state,
                new_state,
            }
        )
    }

    pub fn peer_asn(&self) -> Asn { self.peer_asn }
    pub fn local_asn(&self) -> Asn { self.local_asn }
    pub fn interface(&self) -> u16 { self.interface }
    pub fn afi(&self) -> Afi { self.afi }
    pub fn peer_addr(&self) -> IpAddr { self.peer_addr }
    pub fn local_addr(&self) -> IpAddr { self.local_addr }
    pub fn old_state(&self) -> State { self.old_state }
    pub fn new_state(&self) -> State { self.new_state }
}

#[derive(Debug)]
pub struct StateChangeAs4 {
    peer_asn: Asn,
    local_asn: Asn,
    interface: u16,
    afi: Afi,
    peer_addr: IpAddr,
    local_addr: IpAddr,
    old_state: State,
    new_state: State,
}

impl StateChangeAs4 {
    pub fn parse<Octs: Octets>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        let peer_asn = parser.parse_u32_be()?.into();
        let local_asn = parser.parse_u32_be()?.into();
        let interface = parser.parse_u16_be()?;
        let afi = parser.parse_u16_be()?.into();
        let (peer_addr, local_addr) = match afi {
            Afi::Ipv4 => {
                (parse_ipv4addr(parser)?.into(),
                parse_ipv4addr(parser)?.into())
            }
            Afi::Ipv6 => {
                (parse_ipv6addr(parser)?.into(),
                parse_ipv6addr(parser)?.into())
            }
            _ => {
                eprintln!("{:x?}", afi);
                return Err(
                    ParseError::form_error("unexpected AFI in StateChangeAs4")
                );
            }
        };
        let old_state = parser.parse_u16_be()?.into();
        let new_state = parser.parse_u16_be()?.into();

        Ok(
            StateChangeAs4 {
                peer_asn,
                local_asn,
                interface,
                afi,
                peer_addr,
                local_addr,
                old_state,
                new_state
            }
        )
    }

    pub fn peer_asn(&self) -> Asn { self.peer_asn }
    pub fn local_asn(&self) -> Asn { self.local_asn }
    pub fn interface(&self) -> u16 { self.interface }
    pub fn afi(&self) -> Afi { self.afi }
    pub fn peer_addr(&self) -> IpAddr { self.peer_addr }
    pub fn local_addr(&self) -> IpAddr { self.local_addr }
    pub fn old_state(&self) -> State { self.old_state }
    pub fn new_state(&self) -> State { self.new_state }
}

impl From<StateChange> for StateChangeAs4 {
    fn from(value: StateChange) -> Self {
        Self {
            peer_asn: value.peer_asn,
            local_asn: value.local_asn,
            interface: value.interface,
            afi: value.afi,
            peer_addr: value.peer_addr,
            local_addr: value.local_addr,
            old_state: value.old_state,
            new_state: value.new_state
        }
    }
}

#[derive(Debug)]
pub struct Message<'a, Octs> {
    peer_asn: Asn,
    local_asn: Asn,
    interface: u16,
    afi: Afi,
    peer_addr: IpAddr,
    local_addr: IpAddr,
    bgp_msg: Parser<'a, Octs>
}

impl<'a, Octs: Octets> Message<'a, Octs> {
    pub fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let peer_asn = Asn::from_u32(parser.parse_u16_be()?.into());
        let local_asn = Asn::from_u32(parser.parse_u16_be()?.into());
        let interface = parser.parse_u16_be()?;
        let afi = parser.parse_u16_be()?.into();
        let (peer_addr, local_addr) = match afi {
            Afi::Ipv4 => {
                (parse_ipv4addr(parser)?.into(),
                parse_ipv4addr(parser)?.into())
            }
            Afi::Ipv6 => {
                (parse_ipv6addr(parser)?.into(),
                parse_ipv6addr(parser)?.into())
            }
            _ => {
                eprintln!("{:x?}", afi);
                return Err(
                    ParseError::form_error("unexpected AFI in Message")
                );
            }
        };
        let bgp_msg = parser.parse_parser(parser.remaining())?;

        Ok(
            Message {
                peer_asn,
                local_asn,
                interface,
                afi,
                peer_addr,
                local_addr,
                bgp_msg,
            }
        )

    }
}

#[derive(Debug)]
pub struct MessageAs4<'a, Octs> {
    peer_asn: Asn,
    local_asn: Asn,
    interface: u16,
    afi: Afi,
    peer_addr: IpAddr,
    local_addr: IpAddr,
    bgp_msg: Parser<'a, Octs>
}

impl<'a, Octs: Octets> MessageAs4<'a, Octs> {
    pub fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let peer_asn = parser.parse_u32_be()?.into();
        let local_asn = parser.parse_u32_be()?.into();
        let interface = parser.parse_u16_be()?;
        let afi = parser.parse_u16_be()?.into();
        let (peer_addr, local_addr) = match afi {
            Afi::Ipv4 => {
                (parse_ipv4addr(parser)?.into(),
                parse_ipv4addr(parser)?.into())
            }
            Afi::Ipv6 => {
                (parse_ipv6addr(parser)?.into(),
                parse_ipv6addr(parser)?.into())
            }
            _ => {
                eprintln!("{:x?}", afi);
                return Err(
                    ParseError::form_error("unexpected AFI in MessageAs4")
                );
            }
        };
        let bgp_msg = parser.parse_parser(parser.remaining())?;

        Ok(
            MessageAs4 {
                peer_asn,
                local_asn,
                interface,
                afi,
                peer_addr,
                local_addr,
                bgp_msg,
            }
        )

    }

    pub fn bgp_msg(&self) -> Result<BgpMsg<&[u8]>, ParseError> {
        BgpMsg::from_octets(
            self.bgp_msg.peek_all(),
            Some(&SessionConfig::modern())
        )
    }

    pub fn peer_asn(&self) -> Asn { self.peer_asn }
    pub fn local_asn(&self) -> Asn { self.local_asn }
    pub fn interface(&self) -> u16 { self.interface }
    pub fn afi(&self) -> Afi { self.afi }
    pub fn peer_addr(&self) -> IpAddr { self.peer_addr }
    pub fn local_addr(&self) -> IpAddr { self.local_addr }
}

impl<'a, Octs> From<Message<'a, Octs>> for MessageAs4<'a, Octs> {
    fn from(value: Message<'a, Octs>) -> Self {
        Self {
            peer_asn: value.peer_asn,
            local_asn: value.local_asn,
            interface: value.interface,
            afi: value.afi,
            peer_addr: value.peer_addr,
            local_addr: value.local_addr,
            bgp_msg: value.bgp_msg
        }
    }
}

/// Iterator over BGP4MP_MESSAGE_AS4 entries
pub struct UpdateIterator<'a, Octs> {
    parser: Parser<'a, Octs>,
}

impl<'a, Octs: Octets> Iterator for UpdateIterator<'a, Octs> {
    type Item = Bgp4Mp<'a, Octs>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.parser.remaining() == 0 {
                return None;
            }
            let mut m = CommonHeader::parse(&mut self.parser)
                .inspect_err(|e| eprintln!(
                    "failed to parse CommonHeader, fusing iterator: {e}"
                )).ok()?;

            match m.msg_type {
                MessageType::Bgp4Mp | MessageType::Bgp4MpEt => { }
                _ =>  {
                    continue;
                }
            }

            let subtype = if let MessageSubType::Bgp4MpSubType(subtype) = m.msg_subtype {
                subtype
            } else {
                continue;
            };
            let res = match subtype {
                Bgp4MpSubType::StateChange => {
                    StateChange::parse(&mut m.message).inspect_err(|e|
                        eprintln!("{e}")
                    ).ok().map(Into::into)
                }
                Bgp4MpSubType::Message => {
                   Message::parse(&mut m.message).inspect_err(|e|
                        eprintln!("{e}")
                    ).ok().map(Into::into)
                }
                Bgp4MpSubType::MessageAs4 => {
                   MessageAs4::parse(&mut m.message).inspect_err(|e|
                        eprintln!("{e}")
                   ).ok().map(Into::into)
                }
                Bgp4MpSubType::StateChangeAs4 => {
                    StateChangeAs4::parse(&mut m.message).inspect_err(|e|
                        eprintln!("{e}")
                    ).ok().map(Into::into)
                }
                Bgp4MpSubType::MessageLocal => todo!(),
                Bgp4MpSubType::MessageAs4Local => todo!(),
                Bgp4MpSubType::Unimplemented(_) => todo!(),
            };

            if res.is_none() {
                continue
            } else {
                return res
            }
        }

    }
}

//------------ TableDumpIterator ----------------------------------------------

pub struct TableDumpIterator<'a, Octs> {
    pub peer_index: PeerIndex,
    parser: Parser<'a, Octs>,
}

impl<'a, Octs> TableDumpIterator<'a, Octs> {
    pub fn new(peer_index: PeerIndex, parser: Parser<'a, Octs>) -> Self {
        Self { peer_index, parser }
    }
}

impl<'a, Octs: Octets> Iterator for TableDumpIterator<'a, Octs>
where
    Vec<u8>: OctetsFrom<Octs::Range<'a>>
{
    type Item = (AfiSafiType, RibEntryHeader<'a, Octs>);

    fn next(&mut self) -> Option<Self::Item> {
        
        if self.parser.remaining() == 0 {
            return None;
        }

        let mut m = CommonHeader::parse(&mut self.parser).unwrap();
        if let MessageSubType::TableDumpv2SubType(tdv2) = m.subtype() {
            match tdv2 {
                TableDumpv2SubType::RibIpv4Unicast => {
                    let reh = RibEntryHeader::parse(
                        &mut m.message, Afi::Ipv4
                    ).unwrap();
                    Some((AfiSafiType::Ipv4Unicast, reh))
                }
                TableDumpv2SubType::RibIpv6Unicast => {
                    let reh = RibEntryHeader::parse(
                        &mut m.message, Afi::Ipv6
                    ).unwrap();
                    Some((AfiSafiType::Ipv6Unicast, reh))
                }
                _ => todo!()
            }
        } else {
            None
        }
    }
}

pub struct SingleEntryIterator<'a, Octs> {
    prefix: Prefix,
    parser: Parser<'a, Octs>, // the RibEntryHeader.entries parser
}

impl<'a, Octs> SingleEntryIterator<'a, Octs> {
    pub fn new(reh: RibEntryHeader<'a, Octs>) -> Self {
        Self {
            prefix: reh.prefix,
            parser: reh.entries,
        }
    }
}

impl<'a, Octs: Octets> Iterator for SingleEntryIterator<'a, Octs>
where
    Vec<u8>: OctetsFrom<Octs::Range<'a>>
{
    type Item = (Prefix, u16, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let re = RibEntry::parse(&mut self.parser).unwrap();
        let mut v = re.attributes;
        let mut raw_attr = vec![0; v.remaining()];
        let _ = v.parse_buf(&mut raw_attr[..]);

        Some((self.prefix, re.peer_idx, raw_attr))
    }
}



//------------ RibEntryIterator -----------------------------------------------

pub struct RibEntryIterator<'a, Octs> {
    peer_index: PeerIndex,
    parser: Parser<'a, Octs>,
    current_table: Option<RibEntryHeader<'a, Octs>>,
    current_afisafi: Option<AfiSafiType>,
}
impl<'a, Octs> RibEntryIterator<'a, Octs> {
    fn new(peer_index: PeerIndex, parser: Parser<'a, Octs>) -> Self {
        Self {
            peer_index,
            parser, 
            current_table: None,
            current_afisafi: None,
        }
    }
}


impl<'a, Octs: Octets> Iterator for RibEntryIterator<'a, Octs>
where
    Vec<u8>: OctetsFrom<Octs::Range<'a>>
{
    type Item = (AfiSafiType, u16, PeerEntry, Prefix, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.current_table.is_none() {
            if self.parser.remaining() == 0 {
                return None;
            }

            let mut m = CommonHeader::parse(&mut self.parser).unwrap();

            if let MessageSubType::TableDumpv2SubType(tdv2) = m.subtype() {
                match tdv2 {
                    TableDumpv2SubType::RibIpv4Unicast => {
                        let reh = RibEntryHeader::parse(
                            &mut m.message, Afi::Ipv4
                        ).unwrap();
                        self.current_table = Some(reh);
                        self.current_afisafi = Some(AfiSafiType::Ipv4Unicast);
                    }
                    TableDumpv2SubType::RibIpv6Unicast => {
                        let reh = RibEntryHeader::parse(
                            &mut m.message, Afi::Ipv6
                        ).unwrap();
                        self.current_table = Some(reh);
                        self.current_afisafi = Some(AfiSafiType::Ipv6Unicast);
                    }
                    _ => todo!()
                }
            }
        }

        let mut table = self.current_table.take().unwrap();
        let re = RibEntry::parse(&mut table.entries).unwrap();
        let peer = self.peer_index.get(&re).unwrap();
        // XXX here we probably need a PduParseInfo::mrt()
        let prefix = table.prefix;

        let mut v = re.attributes;
        let mut raw_attr = vec![0; v.remaining()];
        let _ = v.parse_buf(&mut raw_attr[..]);


        if table.entries.remaining() != 0 {
            self.current_table = Some(table);
        } 

        Some((
            *self.current_afisafi.as_ref().unwrap(),
            re.peer_idx,
            *peer,
            prefix,
            raw_attr
        ))
    }
}

/*
//------------ Tests ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use memmap2::Mmap;
    use std::fs::File;
    use rayon::iter::ParallelBridge;
    use rayon::iter::ParallelIterator;

    use crate::bgp::message::PduParseInfo;
    use crate::bgp::{aspath::AsPath, path_attributes::{PathAttributeType, PathAttributes}};


    fn bviews_gh() -> Mmap {
        let filename = "test-data/bview.20241001.0000-rrc18.mrt";
        let file = File::open(filename).unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap()  };
        println!("{}: {}MiB", filename, mmap.len() >> 20);
        mmap
    }

    #[test]
    fn updates_file() {
        let filename = "test-data/updates.20241101.0000-rrc01.mrt";
        let file = File::open(filename).unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap()  };
        println!("{}: {}MiB", filename, mmap.len() >> 20);
        
        let fh = &mmap[..];
        let mrt_file = MrtFile::new(fh);
        eprintln!("{} messages in {filename}", mrt_file.messages().count());
    }

    // LH: so this is much slower than the original RibEntryIterator !
    #[test]
    fn par_bridge() {
        let fh = &bviews_gh()[..];
        let mrt_file = MrtFile::new(fh);
        let rib_entries = mrt_file.rib_entries().unwrap();
        
        println!();
        rib_entries.par_bridge().for_each(|e| {
            let (_, _, _, _, pa_map) = e;
            assert!(!pa_map.is_empty());
        });
    }

    #[test]
    fn tables_iterator() {
        let fh = &bviews_gh()[..];
        let mrt_file = MrtFile::new(fh);
        let tables = mrt_file.tables().unwrap();
        for (_fam, reh) in tables {
            let iter = SingleEntryIterator::new(reh);
            for (idx, (_prefix, _id, raw_attr)) in iter.enumerate() {
                assert!(!raw_attr.is_empty());
                print!("{idx}\r");
            }
        }
    }

    #[test]
    fn iter_mt() {
        let fh = &bviews_gh()[..];
        let mrt_file = MrtFile::new(fh);
        eprintln!("{}", mrt_file.rib_entries_mt::<&[u8]>().count());
    }
    
    #[test]
    fn par_bridge_tables_iterator() {
        let fh = &bviews_gh()[..];
        let mrt_file = MrtFile::new(fh);
        let tables = mrt_file.tables().unwrap();
        let count = tables.par_bridge().map(|(_fam, reh)| {
            SingleEntryIterator::new(reh)
        }).fold(|| 0_usize, |sum, iter| sum + iter.count()).sum::<usize>();
        eprintln!("count: {count}");
    }

    #[test]
    fn iterators_count() {
        let fh = &bviews_gh()[..];
        let mrt_file = MrtFile::new(fh);
        let rib_entries = mrt_file.rib_entries().unwrap();
        let tables = mrt_file.tables().unwrap();
        let single_entries_count = tables.map(|(_fam, reh)| {
            let iter = SingleEntryIterator::new(reh);
            iter
        }).fold(0, |acc, iter| acc + iter.count());

        eprintln!("{}", single_entries_count);
        assert_eq!(rib_entries.count(), single_entries_count);
    }

    #[ignore]
    #[test]
    fn it_works() {
        let fh = &bviews_gh()[..];

        let mut p = Parser::from_ref(&fh);
        let mut peer_index = PeerIndex::empty();

        // FIXME we need a special sessionconfig/pdu_parse_info because in MRT
        // the (I think) MP_REACH is slightly different than in actual BGP
        //let sc = SessionConfig::modern();

        while let Ok(ref mut m) = CommonHeader::parse(&mut p) {
            match m.subtype() {
                MessageSubType::TableDumpv2SubType(tdv2) => {
                    match tdv2 {
                        TableDumpv2SubType::PeerIndexTable => {
                            // XXX for now, we expect only a single
                            // PeerIndexTable per file
                            assert!(peer_index.is_empty());
                            let mut pit = PeerIndexTable::parse(&mut m.message).unwrap();
                            peer_index.reserve(pit.peer_count().into());
                            let mut pes = pit.entries();
                            while pes.remaining() > 0 {
                                let pe = PeerEntry::parse(&mut pes).unwrap();
                                //println!("peer entry {pe:?}");
                                peer_index.push(pe);
                            }
                            assert_eq!(peer_index.len(), pit.peer_count().into());
                            println!("peer table with {} entries", peer_index.len());
                        }
                        TableDumpv2SubType::RibIpv4Unicast => {
                            let mut reh = RibEntryHeader::parse(&mut m.message, Afi::Ipv4).unwrap();
                            //println!("{}", reh);
                            let mut entries = reh.entries();
                            while entries.remaining() > 0 {
                                let re = RibEntry::parse(&mut entries).unwrap();
                                let _peer = peer_index.get(&re);
                                //println!("\t{} {:?}", re, peer);

                                //println!("attr: {:?}", re.attributes);
                                //println!("attr: {:?}", re.attributes.parse_octets(re.attributes.remaining()).unwrap());
                                //let pas = match PathAttributes::parse(&mut re.attributes, sc) {
                                //let pas = match PathAttributes::new(re.attributes, sc) {
                                //    Ok(pas) => pas,
                                //    Err(e) => { eprintln!("error while parsing RibIpv4Unicast: {}", e); break; }
                                //};
                                let pas = PathAttributes::new(re.attributes, PduParseInfo::modern());
                                if let Some(aspath) = pas.get(PathAttributeType::AsPath) {
                                //if let Some(aspath) = pas.find(|pa| pa.type_code() == PathAttributeType::AsPath) {
                                    let _asp = unsafe {AsPath::new_unchecked(aspath.as_ref(), true) };
                                    //println!("\t{asp}");
                                }
                                //for pa in pas.iter() {
                                //    println!("{:?}", pa.type_code());
                                //}
                            }
                        }
                        TableDumpv2SubType::RibIpv6Unicast => {
                            let mut reh = RibEntryHeader::parse(&mut m.message, Afi::Ipv6).unwrap();
                            println!("{}", reh.prefix);
                            //println!("{}", reh);
                            let mut entries = reh.entries();
                            while entries.remaining() > 0 {
                                let re = RibEntry::parse(&mut entries).unwrap();
                                //println!("\t{}", re);
                                //let pas = match PathAttributes::parse(&mut re.attributes, sc) {
                                //    Ok(pas) => pas,
                                //    Err(e) => { eprintln!("error while parsing RibIpv6Unicast: {}", e); break; }
                                //};

                                let pas = PathAttributes::new(re.attributes, PduParseInfo::modern());
                                if let Some(aspath) = pas.get(PathAttributeType::AsPath) {
                                //if let Some(aspath) = pas.iter().find(|pa| pa.type_code() == PathAttributeType::AsPath) {
                                    let _asp = unsafe {AsPath::new_unchecked(aspath.as_ref(), true) };
                                    //println!("\t{asp}");
                                }
                                //for pa in pas.iter() {
                                //    println!("{:?}", pa.type_code());
                                //}
                            }
                        }
                        n => {
                            eprintln!("processed {}/{}", p.pos() >> 20, p.len() >> 20);
                            todo!("TODO: {n}")
                        }
                    }
                }
                MessageSubType::Bgp4MpSubType(_bgp4mp) => {
                    //match bgp4mp {
                    //    Bgp4MpSubType::Message | Bgp4MpSubType::MessageAs4 => { }
                    //    _ => { println!("got a {bgp4mp:?}"); }
                    //}
                }
            }
        }
        println!("done");
    }
}
*/
