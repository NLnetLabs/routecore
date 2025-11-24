use std::fmt;
use std::borrow::Cow;

use zerocopy::{byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes};

use crate::bgp::message_ng::{common::{Header, MessageType, SessionConfig, SEGMENT_TYPE_SEQUENCE}, path_attributes::common::{PathAttributeHints, PathAttributeType, PreppedAttributesBuilder, RawPathAttribute, UncheckedPathAttributes, HINT_4BYTE_ASNS, HINT_SINGLE_SEQ}};

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

impl fmt::Debug for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f,
                "UPDATE ({}) withdrawn ({}) tpal ({}) attributes {:#?}",
                self.contents.len(),
                self.withdrawn_routes_len(),
                self.total_path_attributes_len(),
                self.path_attributes()
            )
        } else {
            write!(f,
                "UPDATE ({}) withdrawn ({}) tpal ({}) attributes {:?}",
                self.contents.len(),
                self.withdrawn_routes_len(),
                self.total_path_attributes_len(),
                self.path_attributes()
            )
        }
    }
}

impl Update {
    pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Update, Cow<'static, str>> {
        if raw.len() < 23 {
            return Err("minimal size of UPDATE PDU is 23 bytes".into());
        }
        let Ok((header, _)) = Header::try_ref_from_prefix(&raw.as_ref()) else {
            return Err("invalid header".into());
        };

        if header.marker != [0xff; 16] {
            return Err("invalid marker".into());
        }

        if usize::from(header.length) != raw.len() {
            return Err("length mismatches number of bytes in PDU".into());
        }

        if header.msg_type == MessageType::UPDATE {
            Update::try_from_raw(&raw[19..usize::from(header.length)])
        } else {
            Err("not an update".into())
        }
    }

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
        if 2 + withdrawn_routes_len + 2 > raw.len() {
            return Err("PDU too short, expected two bytes for total path attributes length".into());
        }
        if 4 + withdrawn_routes_len + usize::from(u16::from_be_bytes([
                raw[2+withdrawn_routes_len],
                raw[3+withdrawn_routes_len],
            ])) > raw.len() {
                return Err("total path attributes length exceeds PDU length".into());
        }

        Update::try_ref_from_bytes(raw)
            .map_err(|e| e.to_string().into())
    }

    pub fn withdrawn_routes_len(&self) -> usize {
        // indexing is safe because of the checks in Self::try_from_raw(..)
        u16::from_be_bytes([
            self.contents[0], self.contents[1]
        ]).into()
    }

    pub fn withdrawn(&self) -> &Withdrawn {
        todo!()
    }


    pub fn total_path_attributes_len(&self) -> usize {
        let withdrawn_routes_len = self.withdrawn_routes_len();
        
        u16::from_be_bytes([
            self.contents[2+withdrawn_routes_len],
            self.contents[3+withdrawn_routes_len]
        ]).into()
    }

    pub fn path_attributes(&self) -> &UncheckedPathAttributes {
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

    pub fn conventional_nlri(&self) -> &[u8] {
        &self.contents[
            4 + self.withdrawn_routes_len() + self.total_path_attributes_len()..
        ]
    }

    // used in the into_checked_parts methods below
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

    #[inline(always)]
    fn _attr_as_path2(
        pa: &RawPathAttribute,
        session_config: &SessionConfig,
        builder: &mut PreppedAttributesBuilder,
        //pa_hints: &mut u8,
        //origin_as: &mut byteorder::U32<NetworkEndian>,
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
                builder.mark_hint(HINT_SINGLE_SEQ);
                // XXX can/should we make this faster? we know we have 4 bytes at least, and
                // we're indexing already anyway.
                if session_config.four_octet_asns() {
                    builder.set_origin_as(byteorder::U32::from_bytes([
                        pa.value()[value_len-4],
                        pa.value()[value_len-3],
                        pa.value()[value_len-2],
                        pa.value()[value_len-1],
                    ]));
                } else {
                    builder.set_origin_as(byteorder::U32::from_bytes([
                        0,
                        0,
                        pa.value()[value_len-2],
                        pa.value()[value_len-1],
                    ]));
                }
            }
        }
    }




    pub fn into_checked_parts_2(&self, session_config: &SessionConfig) -> CheckedParts2 {

        let mut pab_mp: Option<PreppedAttributesBuilder> = None;
        let mut pab_conv: Option<PreppedAttributesBuilder> = None; 

        let mut mp_reach = Vec::new();
        let mut mp_unreach = Vec::new();
        // TODO also return withdrawn and conv nlri here?


        let conventional_nlri = !self.conventional_nlri().is_empty();
        let mut iter = self.path_attributes().iter();


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
                                pab_mp.get_or_insert_default().append(
                                    &pab_conv.get_or_insert_default().path_attributes()
                                );
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                mp_unreach.extend_from_slice(pa.as_bytes());
                            }
                            PathAttributeType::NEXT_HOP => {
                                pab_conv.get_or_insert_default().append(pa.as_bytes());
                            }
                            PathAttributeType::AS_PATH => {
                                Self::_attr_as_path2(pa, session_config, pab_conv.get_or_insert_default());
                                pab_conv.get_or_insert_default().append(pa.as_bytes());
                                if also_mp {
                                    Self::_attr_as_path2(pa, session_config, pab_mp.get_or_insert_default());
                                    pab_mp.get_or_insert_default().append(pa.as_bytes());
                                }
                            }
                            _ => {
                                pab_conv.get_or_insert_default().append(pa.as_bytes());
                                if also_mp {
                                    pab_mp.get_or_insert_default().append(pa.as_bytes());
                                }
                            }
                        }
                    }                   
                    Err(e) => {
                        //dbg!("malformed");
                        //malformed_attributes = e.as_bytes().into();

                        //dbg!("malformed");
                        pab_conv.get_or_insert_default().append(e.as_bytes());
                        pab_conv.as_mut().unwrap().mark_malformed();
                        if also_mp {
                            pab_mp.get_or_insert_default().append(e.as_bytes());
                            pab_mp.as_mut().unwrap().mark_malformed();
                        }

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
                                mp_reach.extend_from_slice(pa.as_bytes());
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                mp_unreach.extend_from_slice(pa.as_bytes());
                            }
                            PathAttributeType::NEXT_HOP => {
                                //dbg!("Unexpected NEXT_HOP in MP UPDATE");
                                //dbg!(self.conventional_nlri());
                                //hexprint(&self.contents);
                                //panic!();
                            }
                            PathAttributeType::AS_PATH => {
                                Self::_attr_as_path2(pa, session_config, pab_mp.get_or_insert_default());
                                pab_mp.get_or_insert_default().append(pa.as_bytes());
                            }
                            _ => {
                                pab_mp.get_or_insert_default().append(pa.as_bytes());
                            }
                        }
                    }                   
                    Err(e) => {
                        //dbg!("malformed");
                        pab_mp.get_or_insert_default().append(e.as_bytes());
                        pab_mp.as_mut().unwrap().mark_malformed();
                        break;
                    }

                }
            }
        }



        CheckedParts2 {
            checked_mp_attributes: pab_mp,
            checked_conv_attributes: pab_conv,
            mp_reach,
            mp_unreach,
        }
    }

    pub(crate) fn into_checked_parts(&self, session_config: &SessionConfig) -> CheckedParts {

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

        let mut origin_as: byteorder::U32<NetworkEndian> = 0.into();



        let mut iter = self.path_attributes().iter();


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
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                //checked_size -= pa.raw_len();
                                mp_unreach.extend_from_slice(pa.as_bytes());
                            }
                            PathAttributeType::NEXT_HOP => {
                                //checked_size -= pa.raw_len();
                                conventional_attributes.extend_from_slice(pa.as_bytes());
                                //dbg!("Unexpected NEXT_HOP in MP UPDATE");
                            }
                            PathAttributeType::AS_PATH => {
                                Self::_attr_as_path(pa, session_config, &mut pa_hints, &mut origin_as);
                                conventional_attributes.extend_from_slice(pa.as_bytes());
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
                        //dbg!("malformed");
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
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                //checked_size -= pa.raw_len();
                                mp_unreach.extend_from_slice(pa.as_bytes());
                            }
                            PathAttributeType::NEXT_HOP => {
                                //checked_size -= pa.raw_len();
                                //checked_conventional.extend_from_slice(pa.as_bytes());
                                //debug!("Unexpected NEXT_HOP in MP UPDATE");
                                //dbg!(self.conventional_nlri());
                                //hexprint(&self.contents);
                                //panic!();
                            }
                            PathAttributeType::AS_PATH => {
                                Self::_attr_as_path(pa, session_config, &mut pa_hints, &mut origin_as);
                                mp_attributes.extend_from_slice(pa.as_bytes());
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

        CheckedParts {
            pa_hints: pa_hints.into(),
            origin_as,
            mp_attributes,
            mp_reach,
            mp_unreach,
            conventional_attributes,
            malformed_attributes
        }

    }

}

pub(crate) struct CheckedParts {
    pub(crate) pa_hints: PathAttributeHints,
    pub(crate) origin_as: byteorder::U32<NetworkEndian>,
    pub(crate) mp_attributes: Vec<u8>,
    pub(crate) mp_reach: Vec<u8>,
    pub(crate) mp_unreach: Vec<u8>,
    pub(crate) conventional_attributes: Vec<u8>,
    pub(crate) malformed_attributes: Vec<u8>,
}

pub struct CheckedParts2 {
    pub checked_mp_attributes: Option<PreppedAttributesBuilder>,
    pub checked_conv_attributes: Option<PreppedAttributesBuilder>,
    pub mp_reach: Vec<u8>,
    pub mp_unreach: Vec<u8>,
}


// XXX TMP, to become the Rotonda 'Meta' type (i.e. the stored value)
#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct RouteDbValue {
    rpki_info: u8,
    path_attributes_hints: PathAttributeHints,
    path_attributes: UncheckedPathAttributes,
}

impl fmt::Debug for RouteDbValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteDbValue")
            .field("rpki_info", &self.rpki_info)
            .field("path_attributes_hints", &self.path_attributes_hints)
            .field("path_attributes", &&self.path_attributes)
            .finish()
    }
}

#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Withdrawn {
    withdrawn_length: byteorder::U16<NetworkEndian>,
    withdrawn: [u8],
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






#[cfg(test)]
mod tests{
    use crate::bgp::message_ng::{common::RpkiInfo, path_attributes::common::{PreppedAttributes, EXTENDED_LEN}};

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

    #[test]
    fn valid_conventional() {
        // BGP UPDATE with one conventional NLRI (1.0.0.0/24)
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x5a, 0x02, 0x00, 0x00, 0x00, 0x3f, 0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0e, 0x02,
            0x03, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x58,
            0x7c, 0x00, 0x00, 0x34, 0x17, 0x40, 0x03, 0x04,
            0x2d, 0x3d, 0x00, 0x55, 0xc0, 0x07, 0x08, 0x00,
            0x00, 0x34, 0x17, 0xa2, 0x9e, 0x7c, 0x01, 0xc0,
            0x08, 0x14, 0x34, 0x17, 0x27, 0x56, 0x34, 0x17,
            0x4a, 0x38, 0x34, 0x17, 0x4e, 0x52, 0x34, 0x17,
            0x50, 0x14, 0x34, 0x17, 0x50, 0x32, 0x18, 0x01,
            0x00, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let CheckedParts {
            mp_reach,
            mp_unreach,
            malformed_attributes,
            conventional_attributes,
            origin_as,
            ..
        } = update.into_checked_parts(&sc);
        assert!(malformed_attributes.is_empty());
        assert!(mp_reach.is_empty());
        assert!(mp_unreach.is_empty());
        assert!(!conventional_attributes.is_empty());
        assert_eq!(origin_as, byteorder::U32::<NetworkEndian>::new(13335));

    }

    #[test]
    fn valid_mp() {
        // BGP UPDATE with ORIGIN, AS_PATH, MP_REACH (with ::/0)
        // we toggle the Extended Len bit on the ORIGIN attribute
        // without actually making the path attribute length 2 bytes
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
            0x02, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x46,
            0xba, 0x90, 0x0e, 0x00, 0x16, 0x00, 0x02, 0x01,
            0x10, 0x20, 0x01, 0x0d, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x00, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let CheckedParts {
            mp_reach,
            mp_unreach,
            malformed_attributes,
            conventional_attributes,
            origin_as,
            ..
        } = update.into_checked_parts(&sc);
        assert!(malformed_attributes.is_empty());
        assert!(!mp_reach.is_empty());
        assert!(mp_unreach.is_empty());
        assert!(conventional_attributes.is_empty());
        assert_eq!(origin_as, byteorder::U32::<NetworkEndian>::new(18106));

    }

    #[test]
    fn malformed_attributes() {
        // BGP UPDATE with ORIGIN, AS_PATH, MP_REACH (with ::/0)
        // we toggle the Extended Len bit on the ORIGIN attribute
        // without actually making the path attribute length 2 bytes
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x40 | EXTENDED_LEN,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
            0x02, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x46,
            0xba, 0x90, 0x0e, 0x00, 0x16, 0x00, 0x02, 0x01,
            0x10, 0x20, 0x01, 0x0d, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x00, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        dbg!(&update);
        let sc = SessionConfig::default();
        let CheckedParts {
            mp_reach,
            malformed_attributes,
            origin_as,
            ..
        } = update.into_checked_parts(&sc);
        assert!(!malformed_attributes.is_empty());
        // Because MP_REACH came after the violating path attribute, it must be empty
        assert!(mp_reach.is_empty());
        assert_eq!(origin_as, byteorder::U32::<NetworkEndian>::new(0));

    }

    #[test]
    fn illegal_withdrawn_len_outside_pdu() {
        // BGP UPDATE with ORIGIN, AS_PATH, MP_REACH (with ::/0)
        // we toggle the Extended Len bit on the ORIGIN attribute
        // without actually making the path attribute length 2 bytes
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02,
            0x00 + 0xff, 0x00 + 0xff,
            0x00, 0x2c, 0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
            0x02, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x46,
            0xba, 0x90, 0x0e, 0x00, 0x16, 0x00, 0x02, 0x01,
            0x10, 0x20, 0x01, 0x0d, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x00, 0x00
        ];

        Update::try_from_full_pdu(&raw).unwrap_err();
    }

    #[test]
    fn illegal_withdrawn_len_inside_pdu() {
        // BGP UPDATE with ORIGIN, AS_PATH, MP_REACH (with ::/0)
        // we toggle the Extended Len bit on the ORIGIN attribute
        // without actually making the path attribute length 2 bytes
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02,
            0x00 + 0x00, 0x00 + 0x0a,
            0x00, 0x2c, 0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
            0x02, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x46,
            0xba, 0x90, 0x0e, 0x00, 0x16, 0x00, 0x02, 0x01,
            0x10, 0x20, 0x01, 0x0d, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x00, 0x00
        ];
        Update::try_from_full_pdu(&raw).unwrap_err();
    }

    #[test]
    fn illegal_total_path_attributes_len_outside_pdu() {
        // BGP UPDATE with ORIGIN, AS_PATH, MP_REACH (with ::/0)
        // we toggle the Extended Len bit on the ORIGIN attribute
        // without actually making the path attribute length 2 bytes
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02, 0x00, 0x00,
            0x00 + 0xff, 0x2c,
            0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
            0x02, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x46,
            0xba, 0x90, 0x0e, 0x00, 0x16, 0x00, 0x02, 0x01,
            0x10, 0x20, 0x01, 0x0d, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x00, 0x00
        ];
        Update::try_from_full_pdu(&raw).unwrap_err();
    }

    #[test]
    fn illegal_total_path_attributes_len_inside_pdu() {
        // BGP UPDATE with one conventional NLRI (1.0.0.0/24)
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x5a, 0x02, 0x00, 0x00,
            0x00, 0x3f + 0x0a,
            0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0e, 0x02,
            0x03, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x58,
            0x7c, 0x00, 0x00, 0x34, 0x17, 0x40, 0x03, 0x04,
            0x2d, 0x3d, 0x00, 0x55, 0xc0, 0x07, 0x08, 0x00,
            0x00, 0x34, 0x17, 0xa2, 0x9e, 0x7c, 0x01, 0xc0,
            0x08, 0x14, 0x34, 0x17, 0x27, 0x56, 0x34, 0x17,
            0x4a, 0x38, 0x34, 0x17, 0x4e, 0x52, 0x34, 0x17,
            0x50, 0x14, 0x34, 0x17, 0x50, 0x32, 0x18, 0x01,
            0x00, 0x00
        ];

        Update::try_from_full_pdu(&raw).unwrap_err();
    }


    // TODO add tests for
    // - illegal tpal
    // - malformed attributes
    // - mixed MP+conventional
    // - only MP
    // - only conventional
    // - 
    //
    //




    #[test]
    fn into_routedb_values() {
        // BGP UPDATE with ORIGIN, AS_PATH, MP_REACH (with ::/0)
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
            0x02, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x46,
            0xba, 0x90, 0x0e, 0x00, 0x16, 0x00, 0x02, 0x01,
            0x10, 0x20, 0x01, 0x0d, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x00, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let CheckedParts {
            mut mp_attributes,
            ..
        } = update.into_checked_parts(&sc);

        let pas = UncheckedPathAttributes::try_ref_from_bytes(&mp_attributes).unwrap();
        assert_eq!(
            pas.iter().map(|pa| pa.unwrap().pa_type.clone()).collect::<Vec<_>>(),
            vec![PathAttributeType::ORIGIN, PathAttributeType::AS_PATH]
        );

        let mut rpki_and_hints = vec![1,2];

        rpki_and_hints.append(&mut mp_attributes);
        let routedb_val = RouteDbValue::try_ref_from_bytes(&rpki_and_hints);

        //eprintln!("{}", &routedb_val);
        eprintln!("{:?}", &routedb_val);
        eprintln!("{:#?}", &routedb_val);
    }


    #[test]
    fn prepped_attributes_builder() {
        let mut b = PreppedAttributesBuilder::new();
        b.set_rpki_info(RpkiInfo(3));
        b.set_origin_as(6447.into());
        b.append(&[0x40,1,1,0]);

        let p = b.into_vec();
        assert_eq!(p, [3,0,0,0,0x19,0x2f,0x40,1,1,0]);

        let prepped = PreppedAttributes::try_ref_from_bytes(&p).unwrap();

        assert_eq!(prepped.header.rpki_info, RpkiInfo(3));
        assert_eq!(prepped.header.origin_as, byteorder::U32::<NetworkEndian>::from(6447));
        assert!(prepped.iter().next().unwrap().unwrap().pa_type == PathAttributeType::ORIGIN);
    }

    #[test]
    fn into_prepped_attributes() {
        // BGP UPDATE with ORIGIN, AS_PATH, MP_REACH (with ::/0)
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x40,
            0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
            0x02, 0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x46,
            0xba, 0x90, 0x0e, 0x00, 0x16, 0x00, 0x02, 0x01,
            0x10, 0x20, 0x01, 0x0d, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x00, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let CheckedParts2 {
            checked_mp_attributes,
            ..
        } = update.into_checked_parts_2(&sc);

        let owned = checked_mp_attributes.unwrap().into_vec();
        let zc = PreppedAttributes::try_ref_from_bytes(&owned[..]).unwrap();

        assert_eq!(
            zc.iter().map(|pa| pa.unwrap().pa_type).collect::<Vec<_>>(),
            vec![PathAttributeType::ORIGIN, PathAttributeType::AS_PATH]
        );

        //eprintln!("{:?}", &routedb_val);
        //eprintln!("{:#?}", &routedb_val);
    }
}

