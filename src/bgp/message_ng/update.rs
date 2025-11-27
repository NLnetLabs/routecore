use std::fmt;
use std::borrow::Cow;

use zerocopy::{byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes};

use crate::bgp::message_ng::{common::{AfiSafiType, Header, MessageType, SessionConfig, SEGMENT_TYPE_SEQUENCE}, nlri::{NlriAddPathIter, NlriHints, NlriIter, PathId}, path_attributes::common::{PathAttributeType, PreppedAttributesBuilder, RawPathAttribute, UncheckedPathAttributes}};

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
            Err("not an UPDATE".into())
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

    pub fn withdrawn(&self) -> &[u8] {
        &self.contents[2..2+self.withdrawn_routes_len()]
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

    //#[inline(always)] // should we hint at inlining?
    fn _attr_as_path(
        pa: &RawPathAttribute,
        session_config: &SessionConfig,
        builder: &mut PreppedAttributesBuilder,
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
                builder.mark_single_seq();
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


    fn _attr_mp_reach<'a>(
        pa: &'a RawPathAttribute,
        session_config: &SessionConfig,
        mp_reach_hints: &mut NlriHints,
        mp_reach_afisafi: &mut AfiSafiType,
        mp_nexthop: &mut &'a [u8],
        mp_reach: &mut &'a [u8],
    ) -> Result<(), Cow<'static, str>> {
        let value = pa.value();
        //let _afi = full[0,1];
        //let _safi = full[2];
        //let _nhlen = full[3];
        //let nh = full[4..4+nhlen]
        //let _ = full[4+nhlen+1
        //let nlri = full[4+nhlen+1..]
        

        //why do we split out the NH again? why not keep it in an otherwise empty MP_REACH_NLRI (or
        //in the NEXT_HOP attribute for conventional stuff)
        
        let nhlen = usize::from(value[3]);
        if !mp_nexthop.is_empty() {
            return Err("multiple MP_REACH_NLRI in single PDU".into());
        }
        if 4+nhlen == value.len() {
            //eprintln!("{:?}", HexFormatted(full_pa));
            return Err("no NLRI in MP_REACH_NLRI".into());
        }
        // TODO what do when we do not recognize the afisafi?
        *mp_reach_afisafi = value[0..3].try_into().unwrap();
        *mp_nexthop = &value[4..4+nhlen+1];
        *mp_reach = &value[4+nhlen+1..];

        if session_config.addpath_rx(AfiSafiType::from(*mp_reach_afisafi)) {
            mp_reach_hints.set(NlriHints::ADDPATH);
            if let Err(_e) = NlriAddPathIter::new_checked(*mp_reach_afisafi, mp_reach) {
                return Err(
                    format!("Invalid MP_REACH_NLRI (+ADDPATH) for afisafi {}",
                    mp_reach_afisafi
                ).into())
            }
        } else {
            if let Err(_e) = NlriIter::new_checked(*mp_reach_afisafi, mp_reach) {
                return Err(
                    format!("Invalid MP_REACH_NLRI for afisafi {}",
                    mp_reach_afisafi
                ).into())
            }

        }

        Ok(())
    }

    fn _attr_mp_unreach<'a>(
        pa: &'a RawPathAttribute,
        session_config: &SessionConfig,
        mp_unreach_hints: &mut NlriHints,
        mp_unreach_afisafi: &mut AfiSafiType,
        mp_unreach: &mut &'a [u8],
    ) -> Result<(), Cow<'static, str>> {
        let value = pa.value();
        //let _afi = full[0,1];
        //let _safi = full[2];
        //let nlri = full[4+nhlen+1..]

        if !mp_unreach.is_empty() {
            return Err("multiple MP_UNREACH_NLRI in single PDU".into());
        }

        *mp_unreach_afisafi = value[0..3].try_into().unwrap();
        *mp_unreach = &value[3..];
        if session_config.addpath_rx(AfiSafiType::from(*mp_unreach_afisafi)) {
            mp_unreach_hints.set(NlriHints::ADDPATH);
            if let Err(_e) = NlriAddPathIter::new_checked(*mp_unreach_afisafi, mp_unreach) {
                return Err(
                    format!("Invalid MP_UNREACH_NLRI (+ADDPATH) for afisafi {}",
                    mp_unreach_afisafi
                ).into())
            }
        } else {
            if let Err(_e) = NlriIter::new_checked(*mp_unreach_afisafi, mp_unreach) {
                return Err(
                    format!("Invalid MP_UNREACH_NLRI for afisafi {}",
                    mp_unreach_afisafi
                ).into())
            }
        }
        Ok(())
    }



    pub fn into_checked_parts(&self, session_config: &SessionConfig) -> Result<CheckedParts<'_>, Cow<'static, str>> {

        let mut pab_mp: Option<PreppedAttributesBuilder> = None;
        let mut pab_conv: Option<PreppedAttributesBuilder> = None; 

        let mut conv_nexthop: Option<[u8; 4]> = None;

        let mut mp_reach_afisafi = AfiSafiType::RESERVED;
        let mut mp_nexthop = &self.contents[0..0];
        let mut mp_reach = &self.contents[0..0];

        let mut mp_unreach_afisafi = AfiSafiType::RESERVED;
        let mut mp_unreach = &self.contents[0..0];

        let mut mp_reach_hints = NlriHints::empty();
        let mut mp_unreach_hints = NlriHints::empty();
        let mut conv_nlri_hints = NlriHints::empty();

        let conv_reach = self.conventional_nlri();
        let conv_unreach = self.withdrawn();

        let conventional_nlri_present = !conv_reach.is_empty();
        let mut pa_iter = self.path_attributes().iter();


        if conventional_nlri_present {
            // in this case, the PDU might still be mixed.
            // i.e. there can be MP_ attrs
            //
            // fill up checked_conventional
            // strip out MP_ attrs into mp_*
            // keep NEXT_HOP

            if session_config.addpath_rx(AfiSafiType::IPV4UNICAST) {
                conv_nlri_hints.set(NlriHints::ADDPATH);
                if let Err(_e) = NlriAddPathIter::new_checked(AfiSafiType::IPV4UNICAST, conv_reach) {
                    return Err(
                        "invalid conventional NLRI (+ADDPATH) announcements"
                        .into()
                    )
                }
            } else {
                if let Err(_e) = NlriIter::new_checked(AfiSafiType::IPV4UNICAST, conv_reach) {
                    return Err(
                        "invalid conventional NLRI announcements"
                        .into()
                    )
                }
            }
            let mut also_mp = false;
            while let Some(r) = pa_iter.next() {
                match r {
                    Ok(pa) => { 
                        //dbg!(pa);
                        match pa.pa_type {
                            PathAttributeType::MP_REACH_NLRI => {
                                // TODO add check whether MP_REACH_NLRI is the first path
                                // attribute, if not, mark in pa_hints
                                
                                if let Err(e) = Self::_attr_mp_reach(
                                    pa,
                                    session_config,
                                    &mut mp_reach_hints,
                                    &mut mp_reach_afisafi,
                                    &mut mp_nexthop,
                                    &mut mp_reach
                                ) {
                                    return Err(e);
                                }

                                also_mp = true;

                                // clone whatever we already collected for conventional into mp
                                eprintln!("also_mp, extending from slice");
                                pab_mp.get_or_insert_default().append(
                                    &pab_conv.get_or_insert_default().path_attributes()
                                );
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                if let Err(e) = Self::_attr_mp_unreach(
                                    pa,
                                    session_config,
                                    &mut mp_unreach_hints,
                                    &mut mp_unreach_afisafi,
                                    &mut mp_unreach
                                ) {
                                    return Err(e);
                                }
                            }
                            PathAttributeType::NEXT_HOP => {
                                //pab_conv.get_or_insert_default().append(pa.as_bytes());
                                if pa.as_bytes().len() != 4 {
                                    // TODO error on wrongly formatted NEXT_HOP
                                } else {
                                    conv_nexthop = Some(pa.as_bytes()[0..4].try_into().unwrap())
                                }

                            }
                            PathAttributeType::AS_PATH => {
                                Self::_attr_as_path(pa, session_config, pab_conv.get_or_insert_default());
                                pab_conv.get_or_insert_default().append(pa.as_bytes());
                                if also_mp {
                                    Self::_attr_as_path(pa, session_config, pab_mp.get_or_insert_default());
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
            while let Some(r) = pa_iter.next() {
                match r {
                    Ok(pa) => { 
                        //dbg!(pa);
                        match pa.pa_type {
                            PathAttributeType::MP_REACH_NLRI => {
                                if let Err(e) = Self::_attr_mp_reach(
                                    pa,
                                    session_config,
                                    &mut mp_reach_hints,
                                    &mut mp_reach_afisafi,
                                    &mut mp_nexthop,
                                    &mut mp_reach
                                ) {
                                    return Err(e);
                                }
                            }
                            PathAttributeType::MP_UNREACH_NLRI => {
                                if let Err(e) = Self::_attr_mp_unreach(
                                    pa,
                                    session_config,
                                    &mut mp_unreach_hints,
                                    &mut mp_unreach_afisafi,
                                    &mut mp_unreach
                                ) {
                                    return Err(e);
                                }
                            }
                            PathAttributeType::NEXT_HOP => {
                                // TODO add proper warning of unexpected NEXT_HOP in MP UPDATE
                                //hexprint(&self.contents);
                            }
                            PathAttributeType::AS_PATH => {
                                Self::_attr_as_path(pa, session_config, pab_mp.get_or_insert_default());
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

        Ok(CheckedParts {
            mp_reach_afisafi,
            mp_unreach_afisafi,
            checked_mp_attributes: pab_mp,
            checked_conv_attributes: pab_conv,
            mp_reach,
            mp_unreach,
            mp_nexthop,
            conv_nexthop,
            mp_nlri_hints,
            conv_nlri_hints,
            conv_reach,
            conv_unreach,
        }
    }
}

pub struct CheckedParts<'a> {
    pub checked_mp_attributes: Option<PreppedAttributesBuilder>,
    pub checked_conv_attributes: Option<PreppedAttributesBuilder>,
    pub mp_reach: &'a [u8],
    pub mp_unreach: &'a [u8],
    pub mp_nexthop: &'a [u8],
    pub mp_reach_afisafi: AfiSafiType,
    pub mp_unreach_afisafi: AfiSafiType,
    pub mp_reach_hints: NlriHints,
    pub mp_unreach_hints: NlriHints,


    pub conv_reach: &'a [u8],
    pub conv_unreach: &'a [u8],
    pub conv_nexthop: Option<[u8; 4]>,
    pub conv_nlri_hints: NlriHints,
}

impl CheckedParts<'_> {
    pub fn mp_reach_afisafi(&self) -> Option<AfiSafiType> {
        if self.mp_reach_afisafi != AfiSafiType::RESERVED {
            Some(self.mp_reach_afisafi)
        } else {
            None
        }
    }

    // TODO somewhere (here or in NlriIter) we also need to have a path to get an iterator for
    // afisafis where the nlri length is in bytes as opposed to bits (e.g. flowspec)
    pub fn mp_reach_iter_raw(&self) -> impl Iterator<Item = (Option<PathId>, &[u8])> {
        let ap_iter = if self.mp_reach_hints.get(NlriHints::ADDPATH) {
            NlriAddPathIter::unchecked(self.mp_reach_afisafi, self.mp_reach)
        } else {
            NlriAddPathIter::empty()
        }.map(|(path_id, nlri)| (Some(path_id), nlri));

        let normal_iter = if !self.mp_reach_hints.get(NlriHints::ADDPATH) {
            NlriIter::unchecked(self.mp_reach_afisafi, self.mp_reach)
        } else {
            NlriIter::empty()

        }.map(|nlri| (None, nlri));

        ap_iter.chain(normal_iter)


    }
    // TODO do we also want special raw iters for nlri with RDs?
   
    pub fn conv_reach_iter_raw(&self) -> impl Iterator<Item = (Option<PathId>, &[u8])> {
        // this won't compile: 'expected closure, found a different closure'
        //if self.conv_nlri_hints.get(NlriHints::ADDPATH) {
        //    NlriAddPathIter::new(AfiSafiType::IPV4UNICAST, self.conv_reach)
        //        .map(|(path_id, nlri)| (Some(path_id), nlri))
        //        .chain(NlriIter::empty().map(|nlri| (None, nlri)))
        //} else {
        //    NlriAddPathIter::empty()
        //    .map(|(path_id, nlri)| (Some(path_id), nlri))
        //    .chain(NlriIter::new(AfiSafiType::IPV4UNICAST, self.conv_reach)
        //        .map(|nlri| (None, nlri))
        //    )
        //}

        let ap_iter = if self.conv_nlri_hints.get(NlriHints::ADDPATH) {
            NlriAddPathIter::unchecked(AfiSafiType::IPV4UNICAST, self.conv_reach)
        } else {
            NlriAddPathIter::empty()
        }.map(|(path_id, nlri)| (Some(path_id), nlri));

        let normal_iter = if !self.conv_nlri_hints.get(NlriHints::ADDPATH) {
            NlriIter::unchecked(AfiSafiType::IPV4UNICAST, self.conv_reach)
        } else {
            NlriIter::empty()

        }.map(|nlri| (None, nlri));

        ap_iter.chain(normal_iter)
    }

    pub fn mp_unreach_iter_raw(&self) -> impl Iterator<Item = (Option<PathId>, &[u8])> {
        let ap_iter = if self.mp_reach_hints.get(NlriHints::ADDPATH) {
            NlriAddPathIter::unchecked(self.mp_unreach_afisafi, self.mp_unreach)
        } else {
            NlriAddPathIter::empty()
        }.map(|(path_id, nlri)| (Some(path_id), nlri));

        let normal_iter = if !self.mp_reach_hints.get(NlriHints::ADDPATH) {
            NlriIter::unchecked(self.mp_unreach_afisafi, self.mp_unreach)
        } else {
            NlriIter::empty()

        }.map(|nlri| (None, nlri));

        ap_iter.chain(normal_iter)
    }

    pub fn conv_unreach_iter_raw(&self) -> impl Iterator<Item = (Option<PathId>, &[u8])> {
        let ap_iter = if self.conv_nlri_hints.get(NlriHints::ADDPATH) {
            NlriAddPathIter::unchecked(AfiSafiType::IPV4UNICAST, self.conv_unreach)
        } else {
            NlriAddPathIter::empty()
        }.map(|(path_id, nlri)| (Some(path_id), nlri));

        let normal_iter = if !self.conv_nlri_hints.get(NlriHints::ADDPATH) {
            NlriIter::unchecked(AfiSafiType::IPV4UNICAST, self.conv_unreach)
        } else {
            NlriIter::empty()

        }.map(|nlri| (None, nlri));

        ap_iter.chain(normal_iter)
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
    use crate::bgp::message_ng::{common::{HexFormatted, RpkiInfo}, path_attributes::common::{PreppedAttributes, EXTENDED_LEN}};

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
            checked_conv_attributes,
            mp_reach,
            mp_unreach,
            ..
        } = update.into_checked_parts(&sc).unwrap();


        //assert!(malformed_attributes.is_empty());
        assert!(!checked_conv_attributes.as_ref().unwrap().as_ref().is_malformed());
        assert!(mp_reach.is_empty());
        assert!(mp_unreach.is_empty());
        assert!(checked_conv_attributes.is_some());
        assert_eq!(checked_conv_attributes.unwrap().as_ref().origin_as(), byteorder::U32::<NetworkEndian>::new(13335));

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
            checked_mp_attributes,
            checked_conv_attributes,
            mp_reach,
            mp_unreach,
            ..
        } = update.into_checked_parts(&sc).unwrap();
        assert!(!checked_mp_attributes.as_ref().unwrap().as_ref().is_malformed());
        assert!(!mp_reach.is_empty());
        assert!(mp_unreach.is_empty());
        assert!(checked_conv_attributes.is_none());
        assert_eq!(checked_mp_attributes.unwrap().as_ref().origin_as(), byteorder::U32::<NetworkEndian>::new(18106));

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
            checked_mp_attributes,
            mp_reach,
            ..
        } = update.into_checked_parts(&sc).unwrap();
        assert!(checked_mp_attributes.as_ref().unwrap().as_ref().is_malformed());
        assert!(mp_reach.is_empty());
        assert_eq!(checked_mp_attributes.unwrap().as_ref().origin_as(), byteorder::U32::<NetworkEndian>::new(0));



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
        let CheckedParts {
            checked_mp_attributes,
            ..
        } = update.into_checked_parts(&sc).unwrap();

        let owned = checked_mp_attributes.unwrap().into_vec();
        let zc = PreppedAttributes::try_ref_from_bytes(&owned[..]).unwrap();

        assert_eq!(
            zc.iter().map(|pa| pa.unwrap().pa_type).collect::<Vec<_>>(),
            vec![PathAttributeType::ORIGIN, PathAttributeType::AS_PATH]
        );

        //eprintln!("{:?}", &routedb_val);
        //eprintln!("{:#?}", &routedb_val);
    }


    #[test]
    fn mp_reach_iter() {
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

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let update = update.into_checked_parts(&sc).unwrap();

        assert_eq!(update.mp_reach_iter_raw().count(), 5);
        for (path_id, nlri) in update.mp_reach_iter_raw() {
            assert!(path_id.is_none());
            eprintln!("{:?}", HexFormatted(nlri));
        }
    }

    #[test]
    fn conv_reach_iter() {
        // BGP UPDATE with 2 conventional announcements:
        // 10.10.10.9/32 and 192.168.97.0/30
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x3c, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
            0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x07, 0x6c, 0x20, 0x0a, 0x0a, 0x0a, 0x09, 0x1e,
            0xc0, 0xa8, 0x61, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let update = update.into_checked_parts(&sc).unwrap();

        
        assert_eq!(update.conv_reach_iter_raw().count(), 2);
        for (path_id, nlri) in update.conv_reach_iter_raw() {
            assert!(path_id.is_none());
            eprintln!("{:?}", HexFormatted(nlri));
        }

    }


    #[test]
    fn mp_unreach_iter() {
        // BGP UPDATE with 4 MP_UNREACH_NLRI
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x41, 0x02, 0x00, 0x00, 0x00, 0x2a, 0x80,
            0x0f, 0x27, 0x00, 0x02, 0x01, 0x40, 0x20, 0x01,
            0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x40, 0x20,
            0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x02,
            0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
            0x03
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let update = update.into_checked_parts(&sc).unwrap();

        
        assert_eq!(update.mp_unreach_iter_raw().count(), 4);
        for (path_id, nlri) in update.mp_unreach_iter_raw() {
            assert!(path_id.is_none());
            eprintln!("{:?}", HexFormatted(nlri));
        }

    }


    #[test]
    fn conv_unreach_iter() {
        // BGP UPDATE with 12 conventional withdrawals
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x53, 0x02, 0x00, 0x3c, 0x20, 0x0a, 0x0a,
            0x0a, 0x0a, 0x1e, 0xc0, 0xa8, 0x00, 0x1c, 0x20,
            0x0a, 0x0a, 0x0a, 0x65, 0x1e, 0xc0, 0xa8, 0x00,
            0x18, 0x20, 0x0a, 0x0a, 0x0a, 0x09, 0x20, 0x0a,
            0x0a, 0x0a, 0x08, 0x1e, 0xc0, 0xa8, 0x61, 0x00,
            0x20, 0x0a, 0x0a, 0x0a, 0x66, 0x1e, 0xc0, 0xa8,
            0x00, 0x20, 0x1e, 0xc0, 0xa8, 0x62, 0x00, 0x1e,
            0xc0, 0xa8, 0x00, 0x10, 0x1e, 0xc0, 0xa8, 0x63,
            0x00, 0x00, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let sc = SessionConfig::default();
        let update = update.into_checked_parts(&sc).unwrap();

        
        assert_eq!(update.conv_unreach_iter_raw().count(), 12);
        for (path_id, nlri) in update.conv_unreach_iter_raw() {
            assert!(path_id.is_none());
            eprintln!("{:?}", HexFormatted(nlri));
        }
    }


    #[test]
    fn addpath() {
        // BGP UPDATE with 9 path attributes for 1 conv v4 NLRI with Path Id,
        // includes both normal communities and extended communities.
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x82, 0x02, 0x00, 0x00, 0x00, 0x62, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x16, 0x02, 0x05,
            0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x01, 0x2d,
            0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x02, 0x58,
            0x00, 0x00, 0x02, 0xbc, 0x40, 0x03, 0x04, 0x0a,
            0x01, 0x03, 0x01, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00,
            0x64, 0xc0, 0x08, 0x0c, 0x00, 0x2a, 0x02, 0x06,
            0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x03,
            0xc0, 0x10, 0x10, 0x00, 0x06, 0x00, 0x00, 0x44,
            0x9c, 0x40, 0x00, 0x40, 0x04, 0x00, 0x00, 0x44,
            0x9c, 0x40, 0x00, 0x80, 0x0a, 0x04, 0x0a, 0x00,
            0x00, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x01, 0x19, 0xc6, 0x33,
            0x64, 0x00
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let mut sc = SessionConfig::default();
        sc.set_addpath_rx(AfiSafiType::IPV4UNICAST);

        let update = update.into_checked_parts(&sc).unwrap();
        
        for (path_id, nlri) in update.conv_reach_iter_raw() {
            eprintln!("[{:?}] {:?}", path_id, HexFormatted(nlri));
        }
    }

    #[test]
    fn mp_reach_addpath() {
        let raw: [u8; _] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x57, 0x02, 0x00, 0x00, 0x00, 0x40, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x00, 0xff, 0x34, 0x40, 0x05, 0x04, 0x00,
            0x00, 0x03, 0xe7, 0xc0, 0x08, 0x08, 0xff, 0x34,
            0x03, 0x78, 0xff, 0xff, 0xff, 0x01, 0x90, 0x0e,
            0x00, 0x1d, 0x00, 0x02, 0x01, 0x10, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x14, 0x00, 0x64, 0xe0
        ];

        let update = Update::try_from_full_pdu(&raw).unwrap();
        let mut sc = SessionConfig::default();
        sc.set_addpath_rx(AfiSafiType::IPV6UNICAST);

        let update = update.into_checked_parts(&sc).unwrap();
        assert_eq!(update.mp_reach_afisafi, AfiSafiType::IPV6UNICAST);
        
        for (path_id, nlri) in update.mp_reach_iter_raw() {
            eprintln!("[{:?}] {:?}", path_id, HexFormatted(nlri));
        }

        assert_eq!(update.mp_reach_iter_raw().count(), 1);

    }




}

