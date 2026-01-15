use std::{borrow::Cow, fmt};

use log::warn;
use serde::ser::{SerializeSeq, SerializeStruct};

use crate::bgp::message_ng::{common::AfiSafiType, nlri::{common::{bits_to_bytes, Nlri}, CustomNlriIter, Ipv4UnicastNlri, NlriIterator}};



// In a BGP UPDATE PDU, there can be
// - one MP_REACH_NLRI, for the FlowSpec afisafi
//  - containing (possibly) multiple FlowSpecNlri,
//   - which each consist of one or more FlowSpec 'components'

// One NLRI, contains one or more components.
pub struct FlowSpecNlri<'a> {
    raw: &'a [u8],
}

impl<'a> FlowSpecNlri<'a> {
    pub fn components(&self) -> FlowSpecComponentIter<'a> {
        if self.raw.len() == 0 {
            FlowSpecComponentIter {
                raw: &[],
            }
        } else {
            FlowSpecComponentIter {
                raw: &self.raw[1..]
            }
        }
    }
}

impl<'a> Nlri<'a> for FlowSpecNlri<'a> {
    const AFI_SAFI_TYPE: AfiSafiType = AfiSafiType::FLOWSPEC;
    type Iterator = FlowSpecNlriIter<'a>;

}

impl fmt::Display for FlowSpecNlri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for component in self.components() {
            match component {
                Ok(component) => write!(f, "{}, ", component)?,
                Err(m) => write!(f, "flow spec error: {m}")?,
            }
        }
        Ok(())
    }
}

impl serde::Serialize for FlowSpecNlri<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        
            let mut seq = serializer.serialize_seq(None)?;
            for c in self.components() {
                let Ok(c) = c else {
                    warn!("failed to serialize flowspec component in {:?}", self.as_ref());
                    break;
                };
                seq.serialize_element(&c)?;
            }
            seq.end()
    }
}

impl AsRef<[u8]> for FlowSpecNlri<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl<'a> TryFrom<&'a [u8]> for FlowSpecNlri<'a> {
    type Error = Cow<'static, str>;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(FlowSpecNlri { raw: value} )
    }
}

pub struct FlowSpecNlriIter<'a> {
    custom_iter: CustomNlriIter<'a>,
}

impl<'a> NlriIterator<'a> for FlowSpecNlriIter<'a> {
    fn empty() -> Self {
        Self { 
            custom_iter: CustomNlriIter::empty_for_afisafi(AfiSafiType::FLOWSPEC),
        }
    }

    fn for_slice(raw: &'a [u8]) -> Self {
        Self {
            custom_iter: CustomNlriIter::unchecked(AfiSafiType::FLOWSPEC, raw)
        }
    }
}


impl<'a> Iterator for FlowSpecNlriIter<'a> {
    type Item = FlowSpecNlri<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.custom_iter.next().map(|raw_nlri|
           raw_nlri.try_into().unwrap() 
        )
    }
}


// A single filter rule, of which there can be multiple in a single FlowSpecNlri
pub struct FlowSpecComponent<'a> {
    raw: &'a [u8],
}

impl<'a> FlowSpecComponent<'a> {
    pub fn filter_type(&self) -> u8 {
        self.raw[0]
    }
}


// To iterate over N filter rules per single FlowSpecNlri
pub struct FlowSpecComponentIter<'a> {
    raw: &'a[u8],
}

impl<'a> TryFrom<&'a[u8]> for FlowSpecComponent<'a> {
    type Error = Cow<'static, str>;

    fn try_from(value: &'a[u8]) -> Result<Self, Self::Error> {
        Ok(Self { raw: value } )
    }
}



#[derive(Copy, Clone, Debug)]
pub enum Component<'a> {
    DestinationPrefix(Ipv4UnicastNlri<'a>),
    SourcePrefix(Ipv4UnicastNlri<'a>),
    IpProtocol(&'a [u8]),
    Port(&'a [u8]),
    DestinationPort(&'a [u8]),
    SourcePort(&'a [u8]),
    IcmpType(&'a [u8]),
    IcmpCode(&'a [u8]),
    TcpFlags(&'a [u8]), // list of (bitmask_op , value)
    PacketLength(&'a [u8]),
    Dscp(&'a [u8]),
    Fragment(&'a [u8]),
}

#[derive(Copy, Clone, Debug)]
pub struct NumericOp(pub u8);

impl NumericOp {
    pub fn end_of_list(&self) -> bool {
        self.0 & 0x80 == 0x80
    }

    pub fn and(&self) -> bool {
        self.0 & 0x40 == 0x40
    }

    pub fn length(&self) -> usize {
        1 << ((self.0 & 0b00110000) >> 4)
    }

    pub fn lt(&self) -> bool {
        self.0 & 0x04 == 0x04
    }

    pub fn gt(&self) -> bool {
        self.0 & 0x02 == 0x02
    }

    pub fn eq(&self) -> bool {
        self.0 & 0x01 == 0x01
    }
}

pub struct NumericOpAndValue<'a>(NumericOp, &'a [u8]);
impl<'a> NumericOpAndValue<'a> {
    pub fn op(&self) -> NumericOp {
        self.0
    }

    pub fn value(&self) -> &[u8] {
        self.1
    }
    pub fn value_as_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf[(8-self.1.len())..].copy_from_slice(&self.1);
        u64::from_be_bytes(buf)
    }
}

#[derive(Clone)]
pub struct NumericOpIterator<'a> {
    pub raw: &'a [u8],
}

impl<'a> Iterator for NumericOpIterator<'a> {
    type Item = NumericOpAndValue<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        let mut pos = 0;
        let op = NumericOp(self.raw[pos]);
        pos += 1 + op.length();

        let res = NumericOpAndValue(op, &self.raw[1..pos]);
        self.raw = &self.raw[pos..];
        Some(res)

    }
}

impl<'a> fmt::Display for NumericOpAndValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.op().lt() {
            write!(f, "<")?;
        }
        if self.op().gt() {
            write!(f, ">")?;
        }
        if self.op().eq() {
            write!(f, "=")?;
        }
        write!(f, "{}", self.value_as_u64())
    }
}

impl<'a> fmt::Display for NumericOpIterator<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.clone();
        if let Some(first) = iter.next() {
            write!(f, "{}", first)?;
        }
        while let Some(opval) = iter.next() {
            if opval.op().and() {
                write!(f, " && {}", opval)?;
            } else {
                write!(f, " || {}", opval)?;
            }
        }
        Ok(())
    }
}

impl serde::Serialize for NumericOpIterator<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
            let iter = self.clone();
            let mut seq = serializer.serialize_seq(None)?;
            for c in iter {
                seq.serialize_element(&c)?;
            }
            seq.end()
    }
}

impl serde::Serialize for NumericOpAndValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
            let mut state = serializer.serialize_struct("NumericOp", 5)?;
            if self.op().and() {
                state.serialize_field("logic", "and")?;
            } else {
                state.serialize_field("logic", "or")?;
            }
            state.serialize_field("lt", &self.op().lt())?;
            state.serialize_field("gt", &self.op().lt())?;
            state.serialize_field("eq", &self.op().eq())?;
            state.serialize_field("value", &self.value_as_u64())?;
            state.end() 
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BitmaskOp(u8);

impl BitmaskOp {
    pub fn end_of_list(&self) -> bool {
        self.0 & 0x80 == 0x80
    }

    pub fn and(&self) -> bool {
        self.0 & 0x40 == 0x40
    }

    pub fn length(&self) -> usize {
        1 << ((self.0 & 0b00110000) >> 4)
    }

    pub fn not(&self) -> bool {
        self.0 & 0x02 == 0x02
    }

    pub fn bitwise_match(&self) -> bool {
        self.0 & 0x01 == 0x01
    }
}


pub struct BitmaskOpAndValue<'a>(BitmaskOp, &'a [u8]);
impl<'a> BitmaskOpAndValue<'a> {
    pub fn op(&self) -> BitmaskOp {
        self.0
    }

    pub fn value(&self) -> &'a [u8] {
        self.1
    }

    pub fn value_as_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf[(8-self.1.len())..].copy_from_slice(&self.1);
        u64::from_be_bytes(buf)
    }
}


#[derive(Clone)]
pub struct BitmaskOpIterator<'a> {
    pub raw: &'a [u8],
}

impl<'a> Iterator for BitmaskOpIterator<'a> {
    type Item = BitmaskOpAndValue<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        let mut pos = 0;
        let op = BitmaskOp(self.raw[pos]);
        pos += 1 + op.length();

        let res = BitmaskOpAndValue(op, &self.raw[1..pos]);
        self.raw = &self.raw[pos..];
        Some(res)

    }
}

impl<'a> fmt::Display for BitmaskOpAndValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.op().not() {
            write!(f, "!")?;
        }
        if self.op().bitwise_match() {
            write!(f, "==")?;
        }
        write!(f, "{:0n$b}", self.value_as_u64(), n=self.op().length()*8)
    }
}

impl<'a> fmt::Display for BitmaskOpIterator<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.clone();
        if let Some(first) = iter.next() {
            write!(f, "{}", first)?;
        }
        while let Some(opval) = iter.next() {
            if opval.op().and() {
                write!(f, " && {}", opval)?;
            } else {
                write!(f, " || {}", opval)?;
            }
        }
        Ok(())
    }
}

impl serde::Serialize for BitmaskOpIterator<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
            let iter = self.clone();
            let mut seq = serializer.serialize_seq(None)?;
            for c in iter {
                seq.serialize_element(&c)?;
            }
            seq.end()
    }
}

impl serde::Serialize for BitmaskOpAndValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
            let mut state = serializer.serialize_struct("BitmaskOp", 5)?;
            if self.op().and() {
                state.serialize_field("logic", "and")?;
            } else {
                state.serialize_field("logic", "or")?;
            }
            state.serialize_field("negate", &self.op().not())?;
            state.serialize_field("bitwise_match", &self.op().bitwise_match())?;
            state.serialize_field("value", &self.value_as_u64())?;
            state.end() 
    }
}


// returns ops+tail
fn take_ops(raw: &[u8]) -> (&[u8], &[u8]) {

    let mut done = false;
    let mut pos = 0;
    while !done {
        let op = NumericOp(raw[pos]);
        pos += 1 + op.length();
        done = op.end_of_list();
    }

    raw.split_at(pos)
}

impl<'a> Iterator for FlowSpecComponentIter<'a> {
    type Item = Result<Component<'a>, Cow<'static, str>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        let typ = self.raw[0];

        // TODO check for enough bytes in all the match arms
        // this might be done best with a dedicated fn or macro
        // Also, fuzz this.

        let res = match typ {
            1 => {
                //dbg!(&self.raw);
                let prefix_bits = self.raw[1];
                let bytes = bits_to_bytes(prefix_bits);
                let res = Component::DestinationPrefix(Ipv4UnicastNlri::for_slice(&self.raw[1..2+bytes]));
                self.raw = &self.raw[2+bytes..];
                Ok(res)
            }
            2 => {
                let prefix_bits = self.raw[1];
                let bytes = bits_to_bytes(prefix_bits);
                let res = Component::SourcePrefix(Ipv4UnicastNlri::for_slice(&self.raw[1..2+bytes]));
                self.raw = &self.raw[2+bytes..];
                Ok(res)
            }
            3 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::IpProtocol(res))
            }
            4 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::Port(res))
            }
            5 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::DestinationPort(res))

            }
            6 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::SourcePort(res))
            }
            7 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::IcmpType(res))

            }
            8 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::IcmpCode(res))
            }
            9 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::TcpFlags(res))
            }
            10 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::PacketLength(res))
            }
            11 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::Dscp(res))
            }
            12 => {
                let (res, tail) = take_ops(&self.raw[1..]);
                self.raw = tail;
                Ok(Component::Fragment(res))

            }
            _ => { 
                warn!("unimplemented flowspec type {}", typ);
                self.raw = &[];
                return Some(Err(format!("unimplemented ({typ})").into()));
            }
        };

        Some(res)
    }
}


impl fmt::Display for Component<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Component::DestinationPrefix(pfx) => write!(f, "destination {pfx}"),
            Component::SourcePrefix(pfx) => write!(f, "source {pfx}"),
            Component::IpProtocol(raw) => {
                write!(f, "IP protos: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::Port(raw) => {
                write!(f, "ports: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::DestinationPort(raw) => {
                write!(f, "dst ports: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::SourcePort(raw) => {
                write!(f, "src ports: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::IcmpType(raw) => {
                write!(f, "ICMP types: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::IcmpCode(raw) => {
                write!(f, "ICMP codes: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::TcpFlags(raw) => {
                write!(f, "TCP flags: ")?;
                write!(f, "{}", BitmaskOpIterator{raw})
            }
            Component::PacketLength(raw) => {
                write!(f, "packet lengths: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::Dscp(raw) => {
                write!(f, "DSCP: ")?;
                write!(f, "{}", NumericOpIterator{raw})
            }
            Component::Fragment(raw) => {
                write!(f, "Fragments: ")?;
                write!(f, "{}", BitmaskOpIterator{raw})
            }
        }
    }
}

impl serde::Serialize for Component<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        match self {
            Component::DestinationPrefix(pfx) => {
                serializer.serialize_newtype_variant("Component", 0, "destinationPrefix", pfx)
            }
            Component::SourcePrefix(pfx) => {
                serializer.serialize_newtype_variant("Component", 1, "sourcePrefix", pfx)
            }
            Component::IpProtocol(raw) => {
                serializer.serialize_newtype_variant("Component", 2, "ipProtocol", &NumericOpIterator{raw})
            }
            Component::Port(raw) => {
                serializer.serialize_newtype_variant("Component", 3, "port", &NumericOpIterator{raw})
            }
            Component::DestinationPort(raw) => {
                serializer.serialize_newtype_variant("Component", 4, "destinationPort", &NumericOpIterator{raw})
            }
            Component::SourcePort(raw) => {
                serializer.serialize_newtype_variant("Component", 5, "sourcePort", &NumericOpIterator{raw})
            }
            Component::IcmpType(raw) => {
                serializer.serialize_newtype_variant("Component", 6, "icmpType", &NumericOpIterator{raw})
            }
            Component::IcmpCode(raw) => {
                serializer.serialize_newtype_variant("Component", 7, "icmpCode", &NumericOpIterator{raw})
            }
            Component::TcpFlags(raw) => {
                serializer.serialize_newtype_variant("Component", 8, "tcpFlags", &BitmaskOpIterator{raw})
            }
            Component::PacketLength(raw) => {
                serializer.serialize_newtype_variant("Component", 9, "packetLength", &NumericOpIterator{raw})
            }
            Component::Dscp(raw) => {
                serializer.serialize_newtype_variant("Component", 10, "dscp", &NumericOpIterator{raw})
            }
            Component::Fragment(raw) => {
                serializer.serialize_newtype_variant("Component", 11, "fragment", &BitmaskOpIterator{raw})
            }
        }
    }
}
