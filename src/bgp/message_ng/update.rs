use core::fmt;
use std::borrow::Cow;

use zerocopy::{byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes};

use crate::bgp::message_ng::common::{SessionConfig, SEGMENT_TYPE_SEQUENCE};

pub const HINT_4BYTE_ASNS: u8 = 0b0000_0001;
pub const HINT_SINGLE_SEQ: u8 = 0b0000_0010;
pub const HINT_ADDPATH: u8 = 0b0000_0100;
pub const HINT_MULTILABEL: u8 = 0b0000_1000;
pub const HINT_MALFORMED: u8 = 0b0001_0000;

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Eq, PartialEq)]
#[repr(C, packed)]
pub struct PathAttributeType(pub u8);
impl PathAttributeType {
    pub const AS_PATH: Self = Self(2);
    pub const NEXT_HOP: Self = Self(3);
    pub const MP_REACH_NLRI: Self = Self(14);
    pub const MP_UNREACH_NLRI: Self = Self(15);
}

impl fmt::Display for PathAttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        
        f.write_str(
            match *self {
                PathAttributeType::NEXT_HOP => "next_hop",
                PathAttributeType::MP_REACH_NLRI => "mp_reach_nlri",
                PathAttributeType::MP_UNREACH_NLRI => "mp_unreach_nlri",
                _ => "unrecognized path attribute"
            }
        )
    }
}

fn hexprint(buf: impl AsRef<[u8]>) {
    for c in buf.as_ref().chunks(16) {
        for b in c {
            print!("{:02X} ", b);
        }
        println!();
    }
}

/// Unchecked Update message without BGP header
///
/// There is no guarantee for this type other than that the length of the withdrawn routes and the
/// total path attributes length fit inside the PDU.
// TODO make generic over 2 vs 4 byte ASNs? and ADDPATH stuff?
// those characteristics should then end up in the byte with flags, to come out of
// fn into_checked_parts(...)
#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Update {
    contents: [u8],
}

impl Update {


    // `raw` should be the message content after the header
    // so, 19 bytes after the start of the full PDU
    // TODO pass in session config to properly set const usize A
    pub(crate) fn try_from_raw(raw: &[u8]) -> Result<&Update, Cow<'static, str>> {
        // The smallest UPDATE has
        // - two bytes withdraw len
        // - two bytes total path attributes len
        if raw.len() < 4 {
            return Err("minimal size of UPDATE is 19+4".into());
        }

        let withdrawn_routes_len: usize = u16::from_be_bytes([raw[0], raw[1]])
            .into();

        if 2 + withdrawn_routes_len > raw.len() {
            return Err("withdrawn routes length exceeds PDU length".into());
        }
        if 4 + withdrawn_routes_len + usize::from(u16::from_be_bytes([
                raw[2+withdrawn_routes_len],
                raw[3+withdrawn_routes_len]
            ])) > raw.len() {
                return Err("total path attributes length exceeds PDU length".into());
        }

        Update::try_ref_from_bytes(raw)
            .map_err(|e| e.to_string().into())
    }

    fn withdrawn_routes_len(&self) -> usize {
        // indexing is safe because of the checks in Self::try_from_raw(..)
        u16::from_be_bytes([
            self.contents[0], self.contents[1]
        ]).into()
    }

    fn withdrawn(&self) -> &Withdrawn {
        todo!()
    }


    fn total_path_attributes_len(&self) -> usize {
        let withdrawn_routes_len = self.withdrawn_routes_len();
        
        u16::from_be_bytes([
            self.contents[2+withdrawn_routes_len],
            self.contents[3+withdrawn_routes_len]
        ]).into()
    }

    fn path_attributes(&self) -> &UncheckedPathAttributes {
        let withdrawn_routes_len = self.withdrawn_routes_len();
        
        let total_path_attributes_len: usize = u16::from_be_bytes([
            self.contents[2+withdrawn_routes_len],
            self.contents[3+withdrawn_routes_len]
        ]).into();
        //dbg!(total_path_attributes_len);

        UncheckedPathAttributes::try_ref_from_bytes(
            &self.contents[4+withdrawn_routes_len..4+withdrawn_routes_len+total_path_attributes_len]
        ).unwrap()
    }

    fn conventional_nlri(&self) -> &[u8] {
        &self.contents[
            4 + self.withdrawn_routes_len() + self.total_path_attributes_len()..
        ]
    }

    pub(crate) fn into_checked_parts(&self, session_config: &SessionConfig) -> (u8, byteorder::U32<NetworkEndian>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {

        // first check whether there are conv nlri
        // chances of mixed mp+conv are low so only fill up one vec
        // based on tpal and conv nlri we can guess whether we are dealing with MP
        // we have to move this method up onto the Update msg itself though
        //
        //
        //TODO also extract and add info a la
        //- origin AS
        //- is AS_PATH a 32bit single_seq
        //- flag byte prepended to attributes:
        //  - 32bit ASNs
        //  - ADD_PATH
        //  - single_seq ASN yes/no
        //  - contains malformed blob yes/no
        //    - if so, use field for origin AS and put in index of where the malformed part starts?
        //
        //    flag byte: ( for now called pa_hints)
        //
        //    7 6 5 4 3 2 1 0
        //    _ _ _ _ _ _ _ A: ASNs, 1 => 32bits, 0 => 16 bits
        //    _ _ _ _ _ _ S -: single seq non_empty AS_PATH,1 => yes, 0 => no
        //    _ _ _ _ _ P - -: ADDPATH PathIds ,0 => no, 1 => yes
        //    _ _ _ _ L - - -: Multi label => TODO this needs a max value or something?
        //    _ _ _ M - - - -: Malformed blob: 0=> no, 1 => yes
        //
        //    NB A, P and L flags are session based info

        let mut pa_hints: u8 = 0b0000_0000; 
        if session_config.four_octet_asns(){
            pa_hints |= HINT_4BYTE_ASNS;
        }

        let conventional_nlri = !self.conventional_nlri().is_empty();
        
        let mut mp_attributes = vec![];
        let mut mp_reach = vec![];
        let mut mp_unreach = vec![];
        let mut conventional_attributes = vec![];
        let mut malformed_attributes = vec![];

        let mut iter = self.path_attributes().iter();

        let mut seen: u8 = 0;
        let mut origin_as: byteorder::U32<NetworkEndian> = 0.into();


        #[inline(always)]
        fn _attr_as_path(
            pa: &RawPathAttribute,
            session_config: &SessionConfig,
            pa_hints: &mut u8,
            origin_as: &mut byteorder::U32<NetworkEndian>,
        ) {
            let value_len = pa.value().len();

            // Check whether we have at least a segment with one 16 bit ASN,
            // which would be represented by 1 byte segment type, 1 byte number of ASNs, and two
            // bytes for the single ASN.
            // We leverage the check for 4 bytes while setting the origin as.
            // Also, check if this segment is of type AS_SEQUENCE.
            if value_len >= 4 && pa.value()[0] == SEGMENT_TYPE_SEQUENCE {
                let num_asns = pa.value()[1];
                let segment_size = if session_config.four_octet_asns() {
                    4
                } else {
                    2
                } * num_asns as usize;

                // if this segment is the entire value, this AS_PATH is just a single AS_SEQUENCE
                if 2 + segment_size == value_len {
                    *pa_hints |= HINT_SINGLE_SEQ;
                    // XXX can/should we make this faster? we know we have 4 bytes at least, and
                    // we're indexing already anyway.
                    if session_config.four_octet_asns() {
                        *origin_as = byteorder::U32::from_bytes([
                            pa.value()[value_len-4],
                            pa.value()[value_len-3],
                            pa.value()[value_len-2],
                            pa.value()[value_len-1],
                        ]);
                    } else {
                        *origin_as = byteorder::U32::from_bytes([
                            0,
                            0,
                            pa.value()[value_len-2],
                            pa.value()[value_len-1],
                        ]);
                    }
                }
            }
        }


        if conventional_nlri {
            // in this case, the PDU might still be mixed.
            // i.e. there can be MP_ attrs
            //
            // fill up checked_conventional
            // strip out MP_ attrs into mp_*
            // keep NEXT_HOP
            let mut also_mp = false;
            while let Some(r) = iter.next() {
                match r {
                    Ok(pa) => { 
                        //dbg!(pa);
                        match pa.pa_type {
                            PathAttributeType::MP_REACH_NLRI => {
                                // TODO add check whether MP_REACH_NLRI is the first path
                                // attribute, if not, mark in pa_hints
                                mp_reach.extend_from_slice(pa.as_bytes());
                                also_mp = true;
                                // clone whatever we already collected for conventional into mp
                                eprintln!("also_mp, extending from slice");
                                mp_attributes.extend_from_slice(&conventional_attributes[..]);
                                seen |= 0x1;
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                //checked_size -= pa.raw_len();
                                mp_unreach.extend_from_slice(pa.as_bytes());
                                seen |= 0x2;
                            }
                            PathAttributeType::NEXT_HOP => {
                                //checked_size -= pa.raw_len();
                                conventional_attributes.extend_from_slice(pa.as_bytes());
                                //dbg!("Unexpected NEXT_HOP in MP UPDATE");
                                seen |= 0x4;
                            }
                            PathAttributeType::AS_PATH => {
                                _attr_as_path(pa, session_config, &mut pa_hints, &mut origin_as);
                                //// check single seq? set flag accordingly
                                //// extract origin AS, set
                                //
                                //// check for sequence
                                //let value_len = pa.value().len();
                                //if value_len > 2 && pa.value()[0] == 2 {
                                //    let num_asns = pa.value()[1];
                                //    let asns_size = if session_config.four_octet_asns() {
                                //        4
                                //    } else {
                                //        2
                                //    } * num_asns as usize;

                                //    // check number of ASNs in sequence fills up entire PA
                                //    if 2 + asns_size != value_len {
                                //        pa_hints |= HINT_NOT_SINGLE_SEQ;
                                //    }
                                //} else {
                                //    pa_hints |= HINT_NOT_SINGLE_SEQ;
                                //}
                            }
                            _ => {
                                conventional_attributes.extend_from_slice(pa.as_bytes());
                                if also_mp {
                                    mp_attributes.extend_from_slice(pa.as_bytes());
                                }
                            }
                        }
                    }                   
                    Err(e) => {
                        dbg!("malformed");
                        malformed_attributes = e.as_bytes().into();
                        break;
                    }

                }
            }
        } else {
            // in this case, there are no attrs to go in checked_conventional
            // there still can be conventional withdrawals but those don't carry attrs
            //
            // so, we only fill up checked
            // strip out MP_ attrs into mp_*
            // strip NEXT_HOP
            while let Some(r) = iter.next() {
                match r {
                    Ok(pa) => { 
                        //dbg!(pa);
                        match pa.pa_type {
                            PathAttributeType::MP_REACH_NLRI => {
                                //checked_size -= pa.raw_len();
                                //pa.write_to(&mut mp_reach).unwrap();
                                mp_reach.extend_from_slice(pa.as_bytes());
                                seen |= 0x1;
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                //checked_size -= pa.raw_len();
                                mp_unreach.extend_from_slice(pa.as_bytes());
                                seen |= 0x2;
                            }
                            PathAttributeType::NEXT_HOP => {
                                //checked_size -= pa.raw_len();
                                //checked_conventional.extend_from_slice(pa.as_bytes());
                                dbg!("Unexpected NEXT_HOP in MP UPDATE");
                                //dbg!(self.conventional_nlri());
                                //hexprint(&self.contents);
                                //panic!();
                                seen |= 0x4;
                            }
                            PathAttributeType::AS_PATH => {
                                _attr_as_path(pa, session_config, &mut pa_hints, &mut origin_as);
                            }
                            _ => {
                                mp_attributes.extend_from_slice(pa.as_bytes());
                                //checked_conventional.extend_from_slice(pa.as_bytes());
                            }
                        }
                    }                   
                    Err(e) => {
                        dbg!("malformed");
                        malformed_attributes = e.as_bytes().into();
                        break;
                    }

                }
            }
        }
        (pa_hints, origin_as, mp_attributes, mp_reach, mp_unreach, conventional_attributes, malformed_attributes)
    }

}

#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Withdrawn {
    withdrawn_length: byteorder::U16<NetworkEndian>,
    withdrawn: [u8],
}
//
//
//#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
//#[repr(C, packed)]
//pub struct PathAttributes {
//    total_path_attributes_len: byteorder::U16<NetworkEndian>,
//    path_attributes: [u8],
//}

// Unchecked stuff
#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct UncheckedPathAttributes {
    path_attributes: [u8],
}

// Checked stuff
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct CheckedPathAttributes {
    path_attributes: [u8],
}

// Malformed stuff
#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct MalformedPathAttributes {
    path_attributes: [u8],
}





#[derive(TryFromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C, packed)]
pub struct RawPathAttribute {
    flags: u8,
    pa_type: PathAttributeType,
    length_and_value: [u8], // length can be 1 or 2 bytes
}

impl RawPathAttribute {
    fn raw_len(&self) -> usize {
        2 + self.length_and_value.len()
    }

    fn value(&self) -> &[u8] {
        if self.flags & EXTENDED_LEN == EXTENDED_LEN {
            &self.length_and_value[2..]
        } else {
            &self.length_and_value[1..]
        }
    }

}

impl UncheckedPathAttributes {
    fn iter(&self) -> UncheckedPathAttributesIter<'_> {
        UncheckedPathAttributesIter { raw: &self.path_attributes }
    }

    // return checked, mp_reach, mp_unreach, checked_conventional, malformed
    fn into_checked(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {

        let mut checked = vec![];
        let mut mp_reach = vec![];
        let mut mp_unreach = vec![];
        let mut checked_conventional = vec![];
        let mut malformed = vec![];


        let mut iter = self.iter();
        let mut seen: u8 = 0;
        
        //let mut checked_size = self.path_attributes.len();
        

        while let Some(r) = iter.next() {
            match r {
                Ok(pa) => { 
                    //dbg!(pa);
                    match pa.pa_type {
                        PathAttributeType::MP_REACH_NLRI => {
                            //checked_size -= pa.raw_len();
                            //pa.write_to(&mut mp_reach).unwrap();
                            mp_reach.extend_from_slice(pa.as_bytes());
                            seen |= 0x1;
                        }
                        PathAttributeType::MP_UNREACH_NLRI => {
                            //checked_size -= pa.raw_len();
                            mp_unreach.extend_from_slice(pa.as_bytes());
                            seen |= 0x2;
                        }
                        PathAttributeType::NEXT_HOP => {
                            //checked_size -= pa.raw_len();
                            checked_conventional.extend_from_slice(pa.as_bytes());
                            seen |= 0x4;
                        }
                        _ => {
                            checked.extend_from_slice(pa.as_bytes());
                            checked_conventional.extend_from_slice(pa.as_bytes());
                        }
                    }
                }                   
                Err(e) => {
                    dbg!("malformed");
                    malformed = e.as_bytes().into();
                    break;
                }

            }
        }
        //if seen.count_ones() > 1 {
        //    eprintln!("{seen:0X}");
        //}
        //if !mp_unreach.is_empty() {
        //    eprint!("U");
        //} else {
        //    eprint!(".");
        //}
        //if checked_conventional.is_empty() {
        //    eprint!("_");
        //} else {
        //    eprint!("X");
        //}

        (checked, mp_reach, mp_unreach, checked_conventional, malformed)
    }

    //fn check(&self) -> &CheckedPathAttributes {
    //    transmute_ref!(self)
    //}

    //fn check(&self) -> Result<CheckedPathAttributes, (CheckedPathAttributes, MalformedPathAttributes)>  {
    //    let mut iter = self.iter();
    //    while let Some(r) = iter.next() {
    //        match r {
    //            Ok(pa) => {  }
    //            Err(e) => { 
    //                //dbg!("error: {}", e); break
    //                let checked = CheckedPathAttributes { path_attributes: self.path_attributes[..self.path_attributes.len() - e.len()] };
    //                let malformed = MalformedPathAttributes { path_attributes: e };
    //                return Err((&checked, &malformed));
    //            }
    //        }
    //    }
    //    Ok(CheckedPathAttributes { path_attributes: self.path_attributes })
    //}
}

impl fmt::Debug for RawPathAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.pa_type)?;
        for b in &self.length_and_value {
            write!(f, "{:0x} ", b)?;
        }
        Ok(())
    }
}

#[repr(C, packed)]
struct UncheckedPathAttributesIter<'a> {
    raw: &'a [u8],
}

const EXTENDED_LEN: u8  = 0b0001_0000;

impl<'a> Iterator for UncheckedPathAttributesIter<'a> {
    type Item = Result<&'a RawPathAttribute, &'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        let flags = self.raw[0];
        // typecode = [1]
        

        let res;

        if flags & EXTENDED_LEN == EXTENDED_LEN {
            if self.raw.len() < 4 {
                return Some(Err(self.raw));
            }
            let len: usize = u16::from_be_bytes([self.raw[2], self.raw[3]]).into();
            if self.raw.len() < 4 + len {
                return Some(Err(self.raw));
            }
            
            res = RawPathAttribute::try_ref_from_bytes(&self.raw[..4+len])
                .map_err(|_| self.raw);
            self.raw = &self.raw[4+len..];

        } else {
            if self.raw.len() < 3 {
                return Some(Err(self.raw));
            }
            let len: usize = self.raw[2].into();
            if self.raw.len() < 3 + len {
                return Some(Err(self.raw));
            }

            res = RawPathAttribute::try_ref_from_bytes(&self.raw[..3+len])
                .map_err(|_| self.raw);
            self.raw = &self.raw[3+len..];
        }

        Some(res)
    }
}

#[cfg(test)]
mod tests{

    use std::{fs::File, io::{BufReader, Read}};

    use crate::bgp::message_ng::common::{Header, MessageType};

    use super::*;

    #[test]
    fn path_attributes_iter() {
        let raw = vec![
            0x40, 0x01, 0x01, 0x00, // ORIGIN
            0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, // NEXTHOP
            0x80 | EXTENDED_LEN, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff // MED 
        ];

        let mut iter = UncheckedPathAttributes::try_ref_from_bytes(&raw).unwrap().iter();
        while let Some(r) = iter.next() {
            match r {
                Ok(pa) => { dbg!(pa); }
                Err(e) => { dbg!("error: {}", e); break }
            }
        }
    }

    #[test]
    fn raw_into_checked() {
        let raw = vec![
            0x40, 0x01, 0x01, 0x00, // ORIGIN
            0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, // NEXTHOP
            0x80 | EXTENDED_LEN, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff // MED 
        ];

        let (c, m) : (&CheckedPathAttributes, Option<&MalformedPathAttributes>) = 'malformed : {
            let mut iter = UncheckedPathAttributes::try_ref_from_bytes(&raw).unwrap().iter();
            
            let checked; 
            let malformed;

            while let Some(r) = iter.next() {
                match r {
                    Ok(_pa) => { }
                    Err(e) => {
                        checked = CheckedPathAttributes::try_ref_from_bytes(&raw[..raw.len() - e.len()]).unwrap();
                        malformed = MalformedPathAttributes::try_ref_from_bytes(e).unwrap();
                        break 'malformed (checked, Some(malformed));
                    }
                }
            }
            (CheckedPathAttributes::try_ref_from_bytes(&raw).unwrap(), None)
        };
        dbg!(&(c.path_attributes));
        dbg!(&(m.unwrap().path_attributes));
    }

    //#[test]
    //fn transmute() {
    //    let raw = vec![
    //        0x40, 0x01, 0x01, 0x00, // ORIGIN
    //        0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, // NEXTHOP
    //        0x80 | EXTENDED_LEN, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff // MED 
    //    ];

    //    let unchecked = UncheckedPathAttributes::try_ref_from_bytes(&raw).unwrap();
    //    let checked = unchecked.check();

    //}
    #[test]
    fn raw_into_family_specific() {
        // BGP UPDATE message containing MP_REACH_NLRI path attribute,
        // comprising 5 IPv6 NLRIs
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x88, 0x02, 0x00, 0x00, 0x00, 0x71, 0x80,
            0x0e, 0x5a, 0x00, 0x02, 0x01, 0x20, 0xfc, 0x00,
            0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xfe, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80,
            0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
            0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff,
            0x00, 0x01, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff,
            0xff, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8,
            0xff, 0xff, 0x00, 0x03, 0x40, 0x01, 0x01, 0x00,
            0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00,
            0xc8, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00
        ];

        let (header, _) = Header::try_ref_from_prefix(&raw).unwrap();

        let update = if header.msg_type == MessageType::UPDATE {
            Update::try_ref_from_bytes(&raw[19..usize::from(header.length)]).unwrap()
        } else {
            panic!("not an update");
        };
        
        let unchecked = update.path_attributes();
        let (checked, mp_reach, mp_unreach, checked_conventional, malformed) = unchecked.into_checked();
        
        dbg!((checked, mp_reach, mp_unreach, checked_conventional, malformed));

    }

    #[test]
    fn read_from_file() {
        const FILENAME: &str = "/home/luuk/code/routecore.bak/examples/raw_bgp_updates";
        const MIN_MSG_SIZE: usize = 19;
        let f = File::open(FILENAME).unwrap();
        let mut reader = BufReader::new(f);
        let mut buf = [0u8; 2_usize.pow(20)];
        let mut buf_cursor = 0;
        let mut buf_end = 0;
        let mut cnt = 0;
        let sc = SessionConfig::default();
        'foo: loop {
            match reader.read(&mut buf[buf_end..]) {
                Ok(0) => {
                    eprintln!("EOF");
                    break 'foo;
                }
                Err(e) => panic!("{}", e.to_string()),
                Ok(n)  => {
                    //eprintln!("read {n} bytes into buf");
                    buf_end += n;

                    while buf_end-buf_cursor >= MIN_MSG_SIZE {
                        // parse header
                        //eprintln!("cur cursor: {buf_cursor}");
                        let (header, _) = Header::try_ref_from_prefix(&buf[buf_cursor..]).unwrap();
                        //hexprint(header.as_bytes());
                        if header.marker != [0xff; 16] {
                            panic!()
                        }

                        let len: usize = header.length.into();
                        if buf_end-buf_cursor-19 < len {
                            //eprintln!("breaking because len={len}");
                            break;
                        }
                        let msg = &buf[buf_cursor+19..buf_cursor+len];
                        //hexprint(msg);
                        buf_cursor += len;

                        match header.msg_type {
                            MessageType::UPDATE => {
                                let update = Update::try_from_raw(msg).unwrap();
                                let (..) = update.into_checked_parts(&sc);
                            },
                            MessageType::OPEN => { },
                            _ => { }
                        }
                        //eprintln!("19 + {len}");
                        //eprint!(".");
                        cnt += 1;
                        if cnt % 1000_000 == 0 {
                            eprint!("\r{cnt}");
                        }
                    }
                    //eprintln!("post while, buf_cursor/buf_end {buf_cursor}/{buf_end}");
                    //eprintln!("---- pre copy_within ----");
                    // move remainder to start of buf
                    //let (a,b) = buf.split_at_mut(buf_cursor);
                    //&a[0..buf_end-buf_cursor].copy_within(…)() &b[buf_cursor..buf_end];
                    //eprintln!("about to copy_within, buf.len {}", buf.len());
                    //hexprint(&buf[buf_cursor..buf_end]);
                    //eprintln!("current contents of buf on that range:");
                    //hexprint(&buf[0..buf_end - buf_cursor]);
                    buf.copy_within(buf_cursor..buf_end, 0);
                    buf_end = buf_end - buf_cursor;
                    buf_cursor = 0;
                    //eprintln!("cursor/end {buf_cursor}/{buf_end}");
                    //eprintln!("---- pre read ----");
                }
            }
        }

    }

}
