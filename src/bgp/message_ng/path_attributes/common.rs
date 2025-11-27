use std::fmt;

use zerocopy::{byteorder, FromBytes, Immutable, IntoBytes, KnownLayout, NetworkEndian, TryFromBytes};

use crate::bgp::message_ng::common::{HexFormatted, RpkiInfo};

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C, packed)]
pub struct PathAttributeType(u8);

impl PathAttributeType {
    pub const ORIGIN: Self = Self(1);
    pub const AS_PATH: Self = Self(2);
    pub const NEXT_HOP: Self = Self(3);
    pub const MP_REACH_NLRI: Self = Self(14);
    pub const MP_UNREACH_NLRI: Self = Self(15);
}

pub(crate) const EXTENDED_LEN: u8  = 0b0001_0000;

impl fmt::Display for PathAttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            match *self {
                PathAttributeType::ORIGIN => "origin",
                PathAttributeType::AS_PATH => "as_path",
                PathAttributeType::NEXT_HOP => "next_hop",
                PathAttributeType::MP_REACH_NLRI => "mp_reach_nlri",
                PathAttributeType::MP_UNREACH_NLRI => "mp_unreach_nlri",
                _ => "unrecognized path attribute"
            }
        )
    }
}

impl fmt::Debug for PathAttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            fmt::Display::fmt(&self, f)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PathAttributeHints(u8);

impl PathAttributeHints {
    const HINT_4BYTE_ASNS:  u8 = 0b0000_0001;
    const HINT_SINGLE_SEQ:  u8 = 0b0000_0010;
    const HINT_ADDPATH:     u8 = 0b0000_0100;
    const HINT_MULTILABEL:  u8 = 0b0000_1000;
    const HINT_MALFORMED:   u8 = 0b0001_0000;
    const HINT_UNRECOGNIZED:u8 = 0b0010_0000; // TODO for unknown/unimplemented path attribute
                                              // types

    pub fn is_4byte_asns(&self) -> bool {
        self.0 & Self::HINT_4BYTE_ASNS == Self::HINT_4BYTE_ASNS
    }

    pub fn is_single_seq(&self) -> bool {
        self.0 & Self::HINT_SINGLE_SEQ == Self::HINT_SINGLE_SEQ
    }

    pub fn is_addpath(&self) -> bool {
        self.0 & Self::HINT_ADDPATH == Self::HINT_ADDPATH
    }

    pub fn is_multilabel(&self) -> bool {
        self.0 & Self::HINT_MULTILABEL == Self::HINT_MULTILABEL
    }

    pub fn is_malformed(&self) -> bool {
        self.0 & Self::HINT_MALFORMED == Self::HINT_MALFORMED
    }
}


impl From<u8> for PathAttributeHints {
    fn from(value: u8) -> Self {
        Self(value)
    }
}
impl PartialEq<u8> for PathAttributeHints {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}
impl std::ops::BitOr<u8> for PathAttributeHints {
    type Output = Self;

    fn bitor(self, rhs: u8) -> Self::Output {
        Self(self.0 | rhs)
    }
}
impl std::ops::BitOrAssign<u8> for PathAttributeHints {
    fn bitor_assign(&mut self, rhs: u8) {
        self.0 |= rhs
    }
}
impl std::ops::BitAnd<u8> for PathAttributeHints {
    type Output = Self;

    fn bitand(self, rhs: u8) -> Self::Output {
        Self(self.0 & rhs)
    }
}

#[allow(unused)]
impl PreppedAttributesBuilder {
    pub(crate) fn new() -> Self {
        let buf = Vec::from(PreppedAttributesHeader::default().as_bytes());
        assert_eq!(buf.len(), std::mem::size_of::<PreppedAttributesHeader>());
        Self {
            buf,
        }
    }
    pub(crate) fn append(&mut self, bytes: &[u8]) {
        // XXX at some point, measure how often buf needs to grow (thus causing allocations)
        // and figure out whether there is a sane, safe with_capacity we could use in new() to
        // prevent those allocations
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn set_rpki_info(&mut self, rpki_info: RpkiInfo) {
        let (h, _) = PreppedAttributesHeader::mut_from_prefix(self.buf.as_mut()).unwrap();
        h.rpki_info = rpki_info;
    }

    fn mark_hint(&mut self, hint: u8) {
        let (h, _) = PreppedAttributesHeader::mut_from_prefix(self.buf.as_mut()).unwrap();
        h.pa_hints |= hint;
    }

    pub(crate) fn mark_malformed(&mut self) {
        self.mark_hint(PathAttributeHints::HINT_MALFORMED);
    }

    pub(crate) fn mark_single_seq(&mut self) {
        self.mark_hint(PathAttributeHints::HINT_SINGLE_SEQ);
    }

    pub(crate) fn set_origin_as(&mut self, origin_as: byteorder::U32<NetworkEndian>) {
        let (h, _) = PreppedAttributesHeader::mut_from_prefix(self.buf.as_mut()).unwrap();
        h.origin_as = origin_as;
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf
    }
    pub(crate) fn path_attributes(&self) -> &[u8] {
        &self.buf[std::mem::size_of::<PreppedAttributesHeader>()..]
    }
}

impl AsRef<PreppedAttributes> for PreppedAttributesBuilder {
    fn as_ref(&self) -> &PreppedAttributes {
        PreppedAttributes::try_ref_from_bytes(&self.buf[..]).unwrap()
    }
}


#[derive(TryFromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C, packed)]
pub struct RawPathAttribute {
    flags: u8,
    pub pa_type: PathAttributeType,
    length_and_value: [u8], // length can be 1 or 2 bytes
}

impl RawPathAttribute {
    // Do we need such a thing?
    //fn raw_len(&self) -> usize {
    //    2 + self.length_and_value.len()
    //}

    //fn pa_type(&self) -> PathAttributeType {
    //    self.pa_type
    //}

    pub fn value(&self) -> &[u8] {
        if self.flags & EXTENDED_LEN == EXTENDED_LEN {
            &self.length_and_value[2..]
        } else {
            &self.length_and_value[1..]
        }
    }

}

impl UncheckedPathAttributes {
    pub fn iter(&self) -> UncheckedPathAttributesIter<'_> {
        UncheckedPathAttributesIter { raw: &self.path_attributes }
    }
}

impl fmt::Debug for RawPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.pa_type)?;
        for b in &self.length_and_value {
            write!(f, "{:0x} ", b)?;
        }
        Ok(())
    }
}

#[repr(C, packed)]
pub struct UncheckedPathAttributesIter<'a> {
    raw: &'a [u8],
}


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


#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct PreppedAttributes {
    pub header: PreppedAttributesHeader,
    path_attributes: UncheckedPathAttributes,
}

impl PreppedAttributes {
    pub fn iter(&self) -> UncheckedPathAttributesIter<'_> {
        self.path_attributes.iter()
    }

    pub fn is_malformed(&self) -> bool {
        self.header.pa_hints.is_malformed()
    }

    pub fn is_single_seq(&self) -> bool {
        self.header.pa_hints.is_single_seq()
    }

    pub fn origin_as(&self) -> byteorder::U32<NetworkEndian> {
        self.header.origin_as
    }
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Default)]
#[repr(C, packed)]
pub struct PreppedAttributesHeader {
    pub(crate) rpki_info: RpkiInfo,
    pub(crate) pa_hints: PathAttributeHints,
    pub(crate) origin_as: byteorder::U32<NetworkEndian>,
}

pub struct PreppedAttributesBuilder {
    buf: Vec<u8>,
}

impl Default for PreppedAttributesBuilder {
    fn default() -> Self {
        Self::new()
    }
}


#[derive(IntoBytes, TryFromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct UncheckedPathAttributes {
    path_attributes: [u8],
}


impl fmt::Debug for UncheckedPathAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alternate = f.alternate();
        let mut l = f.debug_list();
        for pa in self.iter() {
            match pa {
                Ok(pa) => {
                    if alternate {
                        l.entry(&format!("{:#?}: {:?}", &pa.pa_type, HexFormatted(&pa.value())));
                    } else {
                        l.entry(&pa.pa_type);
                    }
                }
                Err(_) => {
                    l.entry(&"MALFORMED");
                    return l.finish_non_exhaustive()
                }
            }
        }
        l.finish()
    }
}

