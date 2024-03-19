use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::net::Ipv4Addr;

use log::{debug, warn};
use octseq::{Octets, OctetsBuilder, OctetsFrom, Parser};

use crate::asn::Asn;
use crate::bgp::message::{
    PduParseInfo,
    UpdateMessage,
    update_builder::ComposeError,
};
use crate::bgp::message::update_builder::{
    MpReachNlriBuilder,
    MpUnreachNlriBuilder,
    StandardCommunitiesList
};
use crate::bgp::communities::StandardCommunity;
use crate::bgp::nlri::afisafi::NlriCompose;
use crate::util::parser::{ParseError, parse_ipv4addr};


#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Flags(u8);

impl core::ops::BitOr<u8> for Flags {
    type Output = Self;

    fn bitor(self, rhs: u8) -> Self::Output {
        Self(self.0 | rhs)
    }
}

impl core::ops::BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl Flags {
    // 0 1 2 3 4 5 6 7
    //
    // 0: optional (1 == optional)
    // 1: transitive (1 == transitive) (well-known attr are transitive)
    // 2: partial 
    // 3: extended length (0 -> 1 byte length, 1 -> 2 byte length)
    // 4-7: MUST be 0 when sent, ignored when received
    const OPT_NON_TRANS: u8 = 0b1000_0000;
    const OPT_TRANS: u8     = 0b1100_0000;
    const WELLKNOWN: u8     = 0b0100_0000;

    const EXTENDED_LEN: u8  = 0b0001_0000;
    #[allow(dead_code)]
    const PARTIAL: u8       = 0b0010_0000;

    /// Returns true if the optional flag is set.
    pub fn is_optional(self) -> bool {
        self.0 & 0x80 == 0x80
    }

    /// Returns true if the transitive bit is set.
    pub fn is_transitive(self) -> bool {
        self.0 & 0x40 == 0x40
    }

    /// Returns true if the partial flag is set.
    pub fn is_partial(self) -> bool {
        self.0 & 0x20 == 0x20
    }

    /// Returns true if the extended length flag is set.
    pub fn is_extended_length(self) -> bool {
        self.0 & 0x10 == 0x10
    }

}

impl From<u8> for Flags {
    fn from(u: u8) -> Flags {
        Flags(u)
    }
}

impl From<Flags> for u8 {
    fn from(f: Flags) -> u8 {
        f.0
    }
}


pub trait AttributeHeader {
    const FLAGS: u8;
    const TYPE_CODE: u8;
}


//------------ PathAttributesBuilder -----------------------------------------

pub type AttributesMap = BTreeMap<u8, PathAttribute>;

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PaMap {
    attributes: AttributesMap,
}

impl PaMap {
    pub fn empty() -> Self {
        Self {
            attributes: BTreeMap::new()
        }
    }

    // Assemble a AttributesMap, but skipping MP_*REACH_NLRI, so that the
    // returned result is valid for all NLRI in this message.
    pub fn from_update_pdu<'a, Octs: Octets>(pdu: &'a UpdateMessage<Octs>)
    -> Result<Self, ComposeError>
    where
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        let mut pa_map = Self::empty();
        for pa in pdu.path_attributes()? {
            if let Ok(pa) = pa {
                if pa.type_code() != MpReachNlriBuilder::<()>::TYPE_CODE
                    && pa.type_code() != MpUnreachNlriBuilder::<()>::TYPE_CODE
                {
                    if let PathAttributeType::Invalid(n) = pa.type_code().into() {
                        warn!("invalid PA {}:\n{}", n, pdu.fmt_pcap_string());
                    }
                    pa_map.attributes_mut().insert(pa.type_code(), pa.to_owned()?);
                }
            } else {
                return Err(ComposeError::InvalidAttribute);
            }
        }
        Ok(pa_map)
    }

    pub fn set<A: FromAttribute + Into<PathAttribute>>(
        &mut self, attr: A
    ) -> Option<A> {
        let attr = attr.into();
        self.attributes.insert(attr.type_code(), attr).map(A::from_attribute)?
    }

    pub fn get<A: FromAttribute>(
        &self,
    ) -> Option<A> {
        if let Some(attr_type) = A::attribute_type() {
            self.attributes
                .get(&attr_type.into()).and_then(|a| A::from_attribute(a.clone()))
        } else {
            None
        }
    }

    pub fn get_by_type_code(&self, type_code: u8) -> Option<&PathAttribute> {
        self.attributes.get(&type_code)
    }

    pub fn get_mut_by_type_code(&mut self, type_code: u8) -> Option<&mut PathAttribute> {
        self.attributes.get_mut(&type_code)
    }

    pub fn add_attribute(
        &mut self,
        attr: PathAttribute,
    ) -> Result<Option<PathAttribute>, ComposeError> {
        if let PathAttribute::Invalid(..) = attr {
            warn!(
                "adding Invalid attribute to UpdateBuilder: {}",
                &attr.type_code()
            );
        }

        let replaced = self.attributes_mut().insert(attr.type_code(),attr);
        Ok(replaced)
    }

    pub fn attributes(&self) -> &AttributesMap {
        &self.attributes
    }

    pub fn attributes_mut(&mut self) -> &mut AttributesMap {
        &mut self.attributes
    }

    pub fn into_attributes(self) -> AttributesMap {
        self.attributes
    }

    pub fn remove<A: FromAttribute>(&mut self) -> Option<A>
    {
        if let Some(attr_type) = A::attribute_type() {
            self.attributes.remove(&attr_type.into()).and_then(|a| A::from_attribute(a))
        } else {
            None
        }
    }

    pub fn merge_upsert(&mut self, other: &mut Self) {
        self.attributes_mut().append(other.attributes_mut())
    }

    pub(in crate::bgp) fn take<A: FromAttribute>(&mut self) -> Option<A> {
        /*
        if let Some(attr_type) = A::attribute_type() {
            self.attributes_mut()
                .get_mut(&attr_type.into()).and_then(|a| A::from_attribute(std::mem::take(a)))
        } else {
            None
        }
        */
        self.remove::<A>()
    }

    pub(in crate::bgp) fn contains<A: FromAttribute>(&self) -> bool {
        if let Some(attr_type) = A::attribute_type() {
            self.attributes().contains_key(&attr_type.into())
        } else {
            false
        }
    }

    pub fn len(&self) -> usize { self.attributes().len() }

    pub fn is_empty(&self) -> bool { self.attributes().is_empty() }

    // Length of the Path attributes in bytes
    pub fn bytes_len(&self) -> usize {
        self.attributes.values()
            .fold(0, |sum, a| sum + a.compose_len())
    }

    
    // pub fn append(&mut self, other: &mut AttributesMap) {
    //     self.attributes.append(other)
    // }

    // pub fn merge(&mut self, other: &Self) -> Result<(), ComposeError> {
    //     for val in other.attributes.values().cloned() {
    //         self.add_attribute(val)?;
    //     }
    //     Ok(())
    // }

    // pub fn into_inner(self) -> AttributesMap {
    //     self.attributes
    // }

    // pub fn into_update_builder(self) -> UpdateBuilder<Vec<u8>>  {
    //     UpdateBuilder::<Vec<u8>>::from_attributes_builder(self)
    // }

    // pub fn from_update_builder<T>(builder: UpdateBuilder<T>) -> Self {
    //     Self {
    //         attributes: builder.into_attributes()
    //     }
    // }

    // fn add_attribute(&mut self, pa: PathAttribute)
    //     -> Result<(), ComposeError>
    // {
    //     if let PathAttribute::Invalid(..) = pa {
    //         warn!(
    //             "adding Invalid attribute to UpdateBuilder: {}",
    //               &pa.type_code()
    //         );
    //     }
    //     if let Some(existing_pa) = self.attributes.get_mut(&pa.type_code()) {
    //         *existing_pa = pa;
    //     } else {
    //         self.attributes.insert(pa.type_code(), pa);
    //     }
        
    //     Ok(())
    // }
}

    //-------- Specific path attribute methods -------------------------------
    //
//     pub fn set_origin(&mut self, origin: OriginType)
//         -> Result<(), ComposeError>
//     {
//         self.add_attribute(Origin::new(origin).into())
//     }

//     pub fn set_aspath(&mut self , aspath: HopPath)
//         -> Result<(), ComposeError>
//     {
//         // XXX there should be a HopPath::compose_len really, instead of
//         // relying on .to_as_path() first.
//         if let Ok(wireformat) = aspath.to_as_path::<Vec<u8>>() {
//             if wireformat.compose_len() > u16::MAX.into() {
//                 return Err(ComposeError::AttributeTooLarge(
//                      PathAttributeType::AsPath,
//                      wireformat.compose_len()
//                 ));
//             }
//         } else {
//             return Err(ComposeError::InvalidAttribute)
//         }

//         self.add_attribute(AsPath::new(aspath).into())
//     }

//     pub fn prepend_to_aspath(&mut self, asn: Asn) -> Result<(), ComposeError> {
//         if let Some(PathAttribute::AsPath(as_path)) = self.attributes.get_mut(&PathAttributeType::AsPath) {
//             as_path.0.prepend(
//                 asn,
//             )
//         };

//         Ok(())
//     }

//     pub fn aspath(&self) -> Option<HopPath> {
//         self.attributes.get(&PathAttributeType::AsPath).and_then(|pa| 
//             if let PathAttribute::AsPath(as_path) = pa { 
//                 Some(as_path.clone().inner())
//             } else { 
//                 None 
//             })
//     }

//     pub fn set_multi_exit_disc(&mut self, med: MultiExitDisc)
//     -> Result<(), ComposeError>
//     {
//         self.add_attribute(med.into())
//     }

//     pub fn set_local_pref(&mut self, local_pref: LocalPref)
//     -> Result<(), ComposeError>
//     {
//         self.add_attribute(local_pref.into())
//     }
// }


pub trait FromAttribute {
    fn from_attribute(_value: PathAttribute) -> Option<Self>
    where
        Self: Sized {
            None
    }

    fn attribute_type() -> Option<PathAttributeType> {
        None
    }

}

impl From<AttributesMap> for PaMap {
    fn from(attributes: AttributesMap) -> Self {
        Self { attributes }
    }
}


macro_rules! path_attributes {
    (
        $(
            $type_code:expr => $name:ident($data:ty), $flags:expr
        ),+ $(,)*
    ) => {

//------------ PathAttribute -------------------------------------------------

        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize))]
        pub enum PathAttribute {
            $( $name($data) ),+,
            Unimplemented(UnimplementedPathAttribute),
            Invalid(Flags, u8, Vec<u8>),
        }

        impl PathAttribute {
            pub fn compose<Target: OctetsBuilder>(
                &self,
                target: &mut Target
            ) -> Result<(), Target::AppendError> {

                match self {
                $(
                    PathAttribute::$name(i) => {
                        i.compose(target)
                    }
                ),+
                    PathAttribute::Unimplemented(u) => {
                        u.compose(target)
                    }
                    PathAttribute::Invalid(flags, tc, val) => {
                        debug!("composing invalid path attribute {tc}");
                        target.append_slice(&[flags.0 | Flags::PARTIAL, *tc])?;
                        if val.len() > 255 {
                            target.append_slice(&u16::try_from(val.len()).unwrap_or(u16::MAX).to_be_bytes())?;
                        } else {
                            target.append_slice(&u8::try_from(val.len()).unwrap_or(u8::MAX).to_be_bytes())?;
                        }
                        target.append_slice(&val)
                    }
                }
            }

            pub fn compose_len(&self) -> usize {
                match self {
                    $(
                        PathAttribute::$name(i) => i.compose_len()
                    ),+,
                    PathAttribute::Unimplemented(u) => u.compose_len(),
                    PathAttribute::Invalid(_, _, val) => if val.len() > 255 {
                        2 + 2 + val.len()
                    } else {
                        2 + 1 + val.len()

                    }
                }
            }

            pub fn type_code(&self) -> u8 {
                match self {
                    $(
                    PathAttribute::$name(_pa) =>
                        <$data>::TYPE_CODE
                    ),+,
                    PathAttribute::Unimplemented(u) => {
                        u.type_code()
                    }
                    PathAttribute::Invalid(_, tc, _) => {
                        *tc
                    }
                }
            }
        }

        $(
        impl From<$data> for PathAttribute {
            fn from(value: $data) -> Self {
                PathAttribute::$name(value)
            }
        }
        )+


//------------ WireformatPathAttribute --------------------------------------

        #[derive(Debug)]
        pub struct EncodedPathAttribute<'a, Octs: Octets> {
            parser: Parser<'a, Octs>,
            pdu_parse_info: PduParseInfo,
        }
        impl<'a, Octs: Octets> EncodedPathAttribute<'a, Octs> {
            fn new(
                parser: Parser<'a, Octs>,
                ppi: PduParseInfo,
            ) -> Self {
                Self { parser, pdu_parse_info: ppi }
            }

            pub fn pdu_parse_info(&self) -> PduParseInfo {
                self.pdu_parse_info
            }

            pub fn flags(&self) -> Flags {
                self.parser.peek_all()[0].into()
            }

            pub fn type_code(&self) -> u8 {
                self.parser.peek_all()[1]
            }

            pub fn length(&self) -> usize {
                if self.flags().is_extended_length() {
                    let raw = self.parser.peek(4).unwrap();
                    u16::from_be_bytes([raw[2], raw[3]]).into()
                } else {
                    self.parser.peek_all()[2].into()
                }
            }

            //pub fn value(&self) -> Octs::Range<'_> {
            //    let mut p = self.value_into_parser();
            //    p.parse_octets(p.remaining()).unwrap()
            //}

            pub fn value_into_parser(&self) -> Parser<'a, Octs> {
                let mut res = self.parser;
                if self.flags().is_extended_length() {
                    res.advance(4).unwrap();
                } else {
                    res.advance(3).unwrap();
                }
                res
            }

        }

        impl<'a, Octs: Octets> AsRef<[u8]> for EncodedPathAttribute<'a, Octs> {
            fn as_ref(&self) -> &[u8] {
                self.parser.peek_all()
            }
        }

        #[derive(Debug)]
        pub enum WireformatPathAttribute<'a, Octs: Octets> {
            $( $name(EncodedPathAttribute<'a, Octs>) ),+, 
            Unimplemented(UnimplementedWireformat<'a, Octs>),
            Invalid(Flags, u8, Parser<'a, Octs>),
        }


        impl<'a, Octs: Octets> WireformatPathAttribute<'a, Octs> {
            fn parse(parser: &mut Parser<'a, Octs>, ppi: PduParseInfo) 
                -> Result<WireformatPathAttribute<'a, Octs>, ParseError>
            {
                let start_pos = parser.pos();
                let flags = parser.parse_u8()?;
                let type_code = parser.parse_u8()?;
                let (header_len, len) = match flags & 0x10 == 0x10 {
                    true => (4, parser.parse_u16_be()? as usize),
                    false => (3, parser.parse_u8()? as usize),
                };

                let mut pp = parser.parse_parser(len)?;

                let res = match type_code {
                    $(
                    $type_code => {
                        if let Err(e) = <$data>::validate(
                            flags.into(), &mut pp, ppi
                        ) {
                            debug!("failed to parse path attribute: {e}");
                            if $type_code == 14 {
                                return Err(ParseError::form_error(
                                        "invalid MP_REACH_NLRI"
                                ))
                            } else if $type_code == 15 {
                                return Err(ParseError::form_error(
                                        "invalid MP_UNREACH_NLRI"
                                ))
                            } else {
                                pp.seek(start_pos + header_len)?;
                                WireformatPathAttribute::Invalid(
                                    $flags.into(), $type_code, pp
                                )
                            }
                        } else {
                            pp.seek(start_pos)?;
                            WireformatPathAttribute::$name(
                                EncodedPathAttribute::new(pp, ppi)
                            )
                        }
                    }
                    ),+
                    ,
                    _ => {
                        pp.seek(start_pos /* + header_len */)?;
                        WireformatPathAttribute::Unimplemented(
                            UnimplementedWireformat::new(
                                flags.into(), type_code, pp
                            )
                        )
                    }
                };

                Ok(res)
            }

            // XXX this method is the reason we have fn parse as part of
            // the trait, forcing us the pass a SessionConfig to all of
            // the parse() implementations.
            pub fn to_owned(&self) -> Result<PathAttribute, ParseError> 
            where
                Vec<u8>: OctetsFrom<Octs::Range<'a>>
            {
                match self {
                    $(
                    WireformatPathAttribute::$name(epa) => {
                        Ok(PathAttribute::$name(
                            <$data>::parse(
                                &mut epa.value_into_parser(),
                                epa.pdu_parse_info()
                            )?
                        ))
                    }
                    ),+,
                    WireformatPathAttribute::Unimplemented(u) => {
                        Ok(PathAttribute::Unimplemented(
                            UnimplementedPathAttribute::new(
                                u.flags(),
                                u.type_code(),
                                u.value().to_vec()
                            )
                        ))
                    },
                    WireformatPathAttribute::Invalid(f, tc, p) => {
                        Ok(PathAttribute::Invalid(
                            *f, *tc, p.peek_all().to_vec()
                        ))
                    }
                }
            }

            pub fn type_code(&self) -> u8 {
                match self {
                    $(
                        WireformatPathAttribute::$name(_) =>
                            $type_code
                    ),+,
                    WireformatPathAttribute::Unimplemented(u) => {
                        u.type_code()
                    }
                    WireformatPathAttribute::Invalid(_, tc, _) => {
                        *tc
                    }
                }
            }


            pub fn flags(&self) -> Flags {
                match self {
                    $( Self::$name(epa) => { epa.flags() }),+,
                    Self::Unimplemented(u) => u.flags,
                    Self::Invalid(f, _, _) => *f,
                }
            }

            /// Returns the length of the value.
            pub fn length(&self) -> usize {
                match self {
                    $(
                        Self::$name(epa) => epa.length()
                    ),+,
                    Self::Unimplemented(u) => u.value.len(),
                    Self::Invalid(_, _, v) => v.remaining() //FIXME incorrect
                }
            }
        }

        impl<'a, Octs: Octets> AsRef<[u8]> for WireformatPathAttribute<'a, Octs> {
            fn as_ref(&self) -> &[u8] {
                match self {
                    $(
                        WireformatPathAttribute::$name(epa) => {
                            epa.as_ref()
                    }
                    ),+,
                        WireformatPathAttribute::Unimplemented(u) => {
                            u.value()
                        }
                        WireformatPathAttribute::Invalid(_, _, pp) => {
                            pp.peek_all()
                        }

                }
            }
        }


//------------ PathAttributeType ---------------------------------------------

        #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize))]
        pub enum PathAttributeType {
            $( $name ),+,
            Unimplemented(u8),
            Invalid(u8),
        }

        impl fmt::Display for PathAttributeType {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    $(
                        PathAttributeType::$name => {
                            write!(f, stringify!($name))
                        }
                     )+
                    PathAttributeType::Unimplemented(tc) => {
                        write!(f, "Unimplemented-PA-{}", tc)
                    }
                    PathAttributeType::Invalid(tc) => {
                        write!(f, "Invalid-PA-{}", tc)
                    }
                }
            }
        }

        impl From<u8> for PathAttributeType {
            fn from(code: u8) -> PathAttributeType {
                match code {
                    $( $type_code => PathAttributeType::$name ),+,
                    u => PathAttributeType::Unimplemented(u)
                }
            }
        }

        impl From<PathAttributeType> for u8 {
            fn from(pat: PathAttributeType) -> u8 {
                match pat {
                    $( PathAttributeType::$name => $type_code ),+,
                    PathAttributeType::Unimplemented(i) => i,
                    PathAttributeType::Invalid(i) => i,
                }
            }
        }

        $(
        impl AttributeHeader for $data {
            const FLAGS: u8 = $flags;
            const TYPE_CODE: u8 = $type_code;
        }
        )+

        // You might think that the Attribute trait (implemented for all path
        // attributes with the attribute! macro above this comment), can be
        // merged with the FromAttribute trait down here. There are however
        // types that do not and should not implement `Attribute`, but they
        // should implement `FromAttribute`, namely types that are usable by
        // end-users, but are internally reworked to be stored in multiple
        // path attributes, e.g. Vec<Community>, or a value that can be stored
        // in one of several path attributes, e.g. NextHop.
        $(
        impl FromAttribute for $data {
            fn from_attribute(value: PathAttribute) -> Option<$data> {
                if let PathAttribute::$name(pa) = value {
                    Some(pa)
                } else {
                    None
                }
            }

            fn attribute_type() -> Option<PathAttributeType> {
                Some(PathAttributeType::$name)
            }
        }
        )+
    }
}

path_attributes!(
    1   => Origin(crate::bgp::types::Origin), Flags::WELLKNOWN,
    2   => AsPath(crate::bgp::aspath::HopPath), Flags::WELLKNOWN,
    3   => ConventionalNextHop(crate::bgp::types::ConventionalNextHop), Flags::WELLKNOWN,
    4   => MultiExitDisc(crate::bgp::types::MultiExitDisc), Flags::OPT_NON_TRANS,
    5   => LocalPref(crate::bgp::types::LocalPref), Flags::WELLKNOWN,
    6   => AtomicAggregate(crate::bgp::types::AtomicAggregate), Flags::WELLKNOWN,
    7   => Aggregator(crate::bgp::path_attributes::AggregatorInfo), Flags::OPT_TRANS,
    8   => StandardCommunities(crate::bgp::message::update_builder::StandardCommunitiesList), Flags::OPT_TRANS,
    9   => OriginatorId(crate::bgp::types::OriginatorId), Flags::OPT_NON_TRANS,
    10  => ClusterList(crate::bgp::path_attributes::ClusterIds), Flags::OPT_NON_TRANS,
    //14  => MpReachNlri(crate::bgp::message::update_builder::MpReachNlriBuilder), Flags::OPT_NON_TRANS,
    //15  => MpUnreachNlri(crate::bgp::message::update_builder::MpUnreachNlriBuilder), Flags::OPT_NON_TRANS,
    16  => ExtendedCommunities(crate::bgp::path_attributes::ExtendedCommunitiesList), Flags::OPT_TRANS,
    17  => As4Path(crate::bgp::types::As4Path), Flags::OPT_TRANS,
    18  => As4Aggregator(crate::bgp::types::As4Aggregator), Flags::OPT_TRANS,
    20  => Connector(crate::bgp::types::Connector), Flags::OPT_TRANS,
    21  => AsPathLimit(crate::bgp::path_attributes::AsPathLimitInfo), Flags::OPT_TRANS,
    //22  => PmsiTunnel(todo), Flags::OPT_TRANS,
    25  => Ipv6ExtendedCommunities(crate::bgp::path_attributes::Ipv6ExtendedCommunitiesList), Flags::OPT_TRANS,
    32  => LargeCommunities(crate::bgp::path_attributes::LargeCommunitiesList), Flags::OPT_TRANS,
    // 33 => BgpsecAsPath,
    35 => Otc(crate::bgp::types::Otc), Flags::OPT_TRANS,
    //36 => BgpDomainPath(TODO), Flags:: , // https://datatracker.ietf.org/doc/draft-ietf-bess-evpn-ipvpn-interworking/06/
    //40 => BgpPrefixSid(TODO), Flags::OPT_TRANS, // https://datatracker.ietf.org/doc/html/rfc8669#name-bgp-prefix-sid-attribute
    128 => AttrSet(crate::bgp::path_attributes::AttributeSet), Flags::OPT_TRANS,
    255 => Reserved(crate::bgp::path_attributes::ReservedRaw), Flags::OPT_TRANS,
);

// Default implementation is needed to be able to take() an attribute. When
// done so it gets replaced with Unimplemented.
/*
impl Default for PathAttribute {
    fn default() -> Self {
        Self::Unimplemented(UnimplementedPathAttribute{flags: Flags(0), type_code: 0, value: vec![]})
    }
}
*/


//------------ UnimplementedPathAttribute ------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct UnimplementedPathAttribute {
    flags: Flags,
    type_code: u8,
    value: Vec<u8>,
}

impl UnimplementedPathAttribute {
    pub fn new(flags: Flags, type_code: u8, value: Vec<u8>) -> Self {
        Self { flags, type_code, value }
    }

    pub fn type_code(&self) -> u8 {
        self.type_code
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    pub fn value_len(&self) -> usize {
        self.value.len()
    }

    pub fn compose_len(&self) -> usize {
        let value_len = self.value_len();
        if value_len > 255 {
            4 + value_len
        } else {
            3 + value_len
        }
    }
}

impl From<UnimplementedPathAttribute> for PathAttribute {
    fn from(u: UnimplementedPathAttribute) -> PathAttribute {
        PathAttribute::Unimplemented(u)
    }
}

pub struct UnimplementedWireformat<'a, Octs: Octets> {
    flags: Flags,
    type_code: u8,
    value: Parser<'a, Octs>,
}

impl<'a, Octs: Octets> fmt::Debug for UnimplementedWireformat<'a, Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08b} {} {:02x?}",
           u8::from(self.flags()), self.type_code(), self.value()
        )
    }
}

impl<'a, Octs: Octets> UnimplementedWireformat<'a, Octs> {
    pub fn new(flags: Flags, type_code: u8, value: Parser<'a, Octs>) -> Self {
        Self { flags, type_code, value }
    }
    pub fn type_code(&self) -> u8 {
        self.type_code
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn value(&self) -> &[u8] {
        if self.flags().is_extended_length() {
            &self.value.peek_all()[4..]
        } else {
            &self.value.peek_all()[3..]
        }
    }
}


//------------ Attribute trait -----------------------------------------------

pub trait Attribute: AttributeHeader + Clone {
    fn compose_len(&self) -> usize {
        self.header_len() + self.value_len()
    }

    fn is_extended(&self) -> bool {
        self.value_len() > 255
    }

    fn header_len(&self) -> usize {
        if self.is_extended() {
            4
        } else {
            3
        }
    }

    fn value_len(&self) -> usize;

    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        self.compose_header(target)?;
        self.compose_value(target)
    }

    fn compose_header<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        if self.is_extended() {
            target.append_slice(&[
                Self::FLAGS | Flags::EXTENDED_LEN,
                Self::TYPE_CODE,
            ])?;
            target.append_slice(
                &u16::try_from(self.value_len()).unwrap_or(u16::MAX)
                .to_be_bytes()
            )
        } else {
            target.append_slice(&[
                Self::FLAGS,
                Self::TYPE_CODE,
                u8::try_from(self.value_len()).unwrap_or(u8::MAX)
            ])
        }
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>;

    fn validate<Octs: Octets>(
        flags: Flags,
        parser: &mut Parser<'_, Octs>,
        ppi: PduParseInfo
    )
        -> Result<(), ParseError>;

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    where 
        Self: Sized,
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    ;
    
}

//------------ PathAttributes ------------------------------------------------

#[derive(Debug)]
pub struct PathAttributes<'a, Octs> {
    pub parser: Parser<'a, Octs>,
    pub pdu_parse_info: PduParseInfo,
}

impl<'a, Octs> Clone for PathAttributes<'a, Octs> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, Octs> Copy for PathAttributes<'a, Octs> { }

impl<'a, Octs: Octets> PathAttributes<'a, Octs> {
    pub fn new(parser: Parser<'_, Octs>, pdu_parse_info: PduParseInfo)
        -> PathAttributes<'_, Octs>
    {
        PathAttributes { parser, pdu_parse_info }
    }
    
    pub fn get(&self, pat: PathAttributeType)
        -> Option<WireformatPathAttribute<'a, Octs>>
    {
        let mut iter = *self;
        iter.find(|pa|
              //XXX We need Rust 1.70 for is_ok_and()
              //pa.as_ref().is_ok_and(|pa| pa.type_code() == pat)
              if let Ok(pa) = pa.as_ref() {
                  pat == pa.type_code().into()
              } else {
                  false
              }
        ).map(|res| res.unwrap()) // res is Ok(pa), so we can unwrap.
    }
}

impl<'a, Octs: Octets> Iterator for PathAttributes<'a, Octs> {
    type Item = Result<WireformatPathAttribute<'a, Octs>, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }

        let res = WireformatPathAttribute::parse(
            &mut self.parser,
            self.pdu_parse_info
        );
        Some(res)
    }
}

macro_rules! check_len_exact {
    ($p:expr, $len:expr, $name:expr) => {
        if $p.remaining() != $len {
            Err(ParseError::form_error(
                "wrong length for $name, expected $len "
            ))
        } else {
            Ok(())
        }
    }
}

pub struct UncheckedPathAttributes<'a, Octs> {
    parser: Parser<'a, Octs>,
}

impl<'a, Octs> UncheckedPathAttributes<'a, Octs> {
    pub fn from_parser(parser: Parser<'a, Octs>) -> Self {
        Self { parser }
    }
}

impl<'a, Octs: Octets> Iterator for UncheckedPathAttributes<'a, Octs> {
    type Item = EncodedPathAttribute<'a, Octs>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        let pos = self.parser.pos();
        let flags = self.parser.parse_u8().ok()?;
        let _type_code = self.parser.parse_u8().ok()?;
        let (header_len, len) = match flags & 0x10 == 0x10 {
            true => (4, self.parser.parse_u16_be().ok()? as usize),
            false => (3, self.parser.parse_u8().ok()? as usize),
        };

        let _ = self.parser.seek(pos);
        let pp = self.parser.parse_parser(header_len + len).ok()?;
        Some(EncodedPathAttribute::new(pp, PduParseInfo::default()))
    }
}


//--- Origin

impl Attribute for crate::bgp::types::Origin {
    fn value_len(&self) -> usize { 1 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[self.0.into()]) 
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'_, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self(parser.parse_u8()?.into()))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 1, "ORIGIN")
    }
}

//--- AsPath (HopPath)

impl Attribute for crate::bgp::aspath::HopPath {
    fn value_len(&self) -> usize {
        self.to_as_path::<Vec<u8>>().unwrap().into_inner().len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
       target.append_slice(
           self.to_as_path::<Vec<u8>>().unwrap().into_inner().as_ref()
        )
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        // XXX reusing the old/existing AsPath here for the time being
        let asp = crate::bgp::aspath::AsPath::new(
            parser.peek_all().to_vec(),
            ppi.has_four_octet_asn()
        ).map_err(|_| ParseError::form_error("invalid AS_PATH"))?;

        Ok(asp.to_hop_path())
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        let asn_size = if pdu_parse_info.has_four_octet_asn() {
            4
        } else {
            2
        };
        while parser.remaining() > 0 {
            let segment_type = parser.parse_u8()?;
            if !(1..=4).contains(&segment_type) {
                return Err(ParseError::form_error(
                    "illegal segment type in AS_PATH"
                ));
            }
            let len = usize::from(parser.parse_u8()?); // ASNs in segment
            parser.advance(len * asn_size)?; // ASNs.
        }
        Ok(())
    }
}

//--- NextHop

impl Attribute for crate::bgp::types::ConventionalNextHop {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self(parse_ipv4addr(parser)?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 4, "NEXT_HOP")
    }
}

//--- MultiExitDisc

impl Attribute for crate::bgp::types::MultiExitDisc {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.to_be_bytes()) 
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self(parser.parse_u32_be()?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 4, "MULTI_EXIT_DISC")
    }
}

//--- LocalPref

impl Attribute for crate::bgp::types::LocalPref {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.to_be_bytes()) 
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self(parser.parse_u32_be()?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 4, "LOCAL_PREF")
    }
}

//--- AtomicAggregate

impl Attribute for crate::bgp::types::AtomicAggregate {
    fn value_len(&self) -> usize { 0 }

    fn compose_value<Target: OctetsBuilder>(&self, _target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(_parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self)
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 0, "ATOMIC_AGGREGATE")
    }
}

impl Display for crate::bgp::types::AtomicAggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ATOMIC_AGGREGATE")
    }
}

//--- Aggregator

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregatorInfo {
    asn: Asn,
    address: Ipv4Addr,
}

impl AggregatorInfo {
    pub fn new(asn: Asn, address: Ipv4Addr) -> AggregatorInfo {
        AggregatorInfo { asn, address }
    }
    pub fn asn(&self) -> Asn {
        self.asn
    }
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
}


impl Attribute for AggregatorInfo {
    // FIXME for legacy 2-byte ASNs, this should be 6.
    // Should we pass a (&)SessionConfig to this method as well?
    // Note that `fn compose_len` would then also need a SessionConfig,
    // which, sort of makes sense anyway.
    fn value_len(&self) -> usize { 
        8
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.asn().to_raw())?;
        target.append_slice(&self.address().octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let asn = if ppi.has_four_octet_asn() {
            Asn::from_u32(parser.parse_u32_be()?)
        } else {
            Asn::from_u32(parser.parse_u16_be()?.into())
        };

        let address = parse_ipv4addr(parser)?;
        Ok(Self::new(asn, address))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        //if flags != Self::FLAGS.into() {
        //        return Err(ParseError::form_error("invalid flags"));
        //}
        if pdu_parse_info.has_four_octet_asn() {
            check_len_exact!(parser, 8, "AGGREGATOR")?;
        } else {
            check_len_exact!(parser, 6, "AGGREGATOR")?;
        }
        Ok(())
    }
}

impl Display for AggregatorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.asn, self.address)
    }
}

//--- StandardCommunities

impl Attribute for crate::bgp::message::update_builder::StandardCommunitiesList {
    fn value_len(&self) -> usize { 
        self.communities().len() * 4
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in self.communities() {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let mut builder = StandardCommunitiesList::with_capacity(
            parser.remaining() / 4
        );
        while parser.remaining() > 0 {
            builder.add_community(parser.parse_u32_be()?.into());
        }

        Ok(builder)
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        if parser.remaining() % 4 != 0 {
            return Err(ParseError::form_error(
                "unexpected length for COMMUNITIES"
            ));
        }
        Ok(())
    }
}

impl StandardCommunitiesList {
    pub fn fmap<T, F: Fn(&StandardCommunity) -> T>(self, fmap: F) -> Vec<T> {
        self.communities().iter().map(fmap).collect::<Vec<T>>()
    }
}


//--- OriginatorId

impl Attribute for crate::bgp::types::OriginatorId {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self(parse_ipv4addr(parser)?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 4, "ORIGINATOR_ID")
    }
}

//--- ClusterList

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BgpIdentifier([u8; 4]);

impl From<[u8; 4]> for BgpIdentifier {
    fn from(raw: [u8; 4]) -> BgpIdentifier {
        BgpIdentifier(raw)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ClusterIds {
    cluster_ids: Vec<BgpIdentifier>
}

impl ClusterIds {
    fn new(cluster_ids: Vec<BgpIdentifier>) -> ClusterIds {
        ClusterIds {cluster_ids }
    }
    pub fn cluster_ids(&self) -> &Vec<BgpIdentifier> {
        &self.cluster_ids
    }
}


impl Attribute for ClusterIds {
    fn value_len(&self) -> usize { 
        self.cluster_ids.len() * 4
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.cluster_ids {
            target.append_slice(&c.0)?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let mut cluster_ids = Vec::with_capacity(parser.remaining() / 4);
        while parser.remaining() > 0 {
            cluster_ids.push(parser.parse_u32_be()?.to_be_bytes().into());
        }
        Ok(ClusterIds::new(cluster_ids))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        if parser.remaining() % 4 != 0 {
            return Err(ParseError::form_error(
                "unexpected length for CLUSTER_LIST"
            ));
        }
        Ok(())
    }
}

//--- MpReachNlri
impl<A> AttributeHeader for MpReachNlriBuilder<A> {
    const FLAGS: u8 = Flags::OPT_NON_TRANS;
    const TYPE_CODE: u8 = 14;
}
impl<A> FromAttribute for MpReachNlriBuilder<A> {
    fn from_attribute(_value: PathAttribute) -> Option<MpReachNlriBuilder<A>> {
        None
    }

    fn attribute_type() -> Option<PathAttributeType> {
        None
        //Some(PathAttributeType::MpReachNlriBuilder
    }
}


impl<A: Clone + NlriCompose> Attribute for MpReachNlriBuilder<A> {
    fn value_len(&self) -> usize { 
        self.value_len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        self.compose_value(target)
    }

    fn parse<'a, Octs: 'a + Octets>(
        _parser: &mut Parser<'a, Octs>,
        //sc: SessionConfig,
        _ppi: PduParseInfo,
    ) -> Result<Self, ParseError>
        where
            Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        todo!()
            /*
        let afi = parser.parse_u16_be()?;
        let safi= parser.parse_u8()?;
        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;
        let nexthop = crate::bgp::types::NextHop::parse(parser, afisafi)?;
        if let crate::bgp::types::NextHop::Unimplemented(..) =  nexthop {
            debug!("Unsupported NextHop: {:?}", nexthop);
            return Err(ParseError::Unsupported);
        }
        parser.advance(1)?; // reserved byte
        
        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;

        let mut builder = MpReachNlriBuilder::<afisafi>::new(
            afisafi,
            nexthop,
            //sc.rx_addpath(afisafi),
            ppi.mp_reach_addpath(),
        );

        todo!()
            */
        // TODO figure out how much sense it actually makes to create an
        // MpReachNlriBuilder here. 

            /*
        let nlri_iter = crate::bgp::message::update::Nlris::new(
            *parser,
            ppi,
            afisafi
        ).iter();

        for nlri in nlri_iter {
            builder.add_announcement(&nlri?);
        }

        Ok(builder)
            */
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _ppi: PduParseInfo
    ) -> Result<(), ParseError> {
        // We only check for the bare minimum here, as most checks are
        // better done upon (creation of the) Nlri iterator based on the
        // value of this path attribute.
        if parser.remaining() < 5 {
            return Err(ParseError::form_error(
                "length for MP_REACH_NLRI less than minimum"
            ))
        }
        Ok(())
        
         
        /*
        let afi = parser.parse_u16_be()?;
        let safi = parser.parse_u8()?;
        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;
        let _nexthop = crate::bgp::types::NextHop::parse(parser, afisafi)?;
        //if let crate::bgp::types::NextHop::Unimplemented(..) =  nexthop {
        //    debug!("Unsupported NextHop: {:?}", nexthop);
        //    return Err(ParseError::Unsupported);
        //}
        parser.advance(1)?; // reserved byte

        let expect_path_id = session_config.mp_reach_addpath();

        use AfiSafi::*;
        match (afisafi, expect_path_id) {
            (Ipv4Unicast, false) => FixedNlriIter::ipv4unicast(parser).validate(),
            (Ipv4Unicast, true) => FixedNlriIter::ipv4unicast_addpath(parser).validate(),
            (Ipv6Unicast, false) => FixedNlriIter::ipv6unicast(parser).validate(),
            (Ipv6Unicast, true) => FixedNlriIter::ipv6unicast_addpath(parser).validate(),
            

            (Ipv4Multicast, false) => FixedNlriIter::ipv4multicast(parser).validate(),
            (Ipv4Multicast, true) => FixedNlriIter::ipv4multicast_addpath(parser).validate(),
            (Ipv6Multicast, false) => FixedNlriIter::ipv6multicast(parser).validate(),
            (Ipv6Multicast, true) => FixedNlriIter::ipv6multicast_addpath(parser).validate(),


            (Ipv4MplsUnicast, false) => FixedNlriIter::ipv4mpls_unicast(parser).validate(),
            (Ipv4MplsUnicast, true) => FixedNlriIter::ipv4mpls_unicast_addpath(parser).validate(),
            (Ipv6MplsUnicast, false) => FixedNlriIter::ipv6mpls_unicast(parser).validate(),
            (Ipv6MplsUnicast, true) => FixedNlriIter::ipv6mpls_unicast_addpath(parser).validate(),


            (Ipv4MplsVpnUnicast, false) => FixedNlriIter::ipv4mpls_vpn_unicast(parser).validate(),
            (Ipv4MplsVpnUnicast, true) => FixedNlriIter::ipv4mpls_vpn_unicast_addpath(parser).validate(),
            (Ipv6MplsVpnUnicast, false) => FixedNlriIter::ipv6mpls_vpn_unicast(parser).validate(),
            (Ipv6MplsVpnUnicast, true) => FixedNlriIter::ipv6mpls_vpn_unicast_addpath(parser).validate(),

            (Ipv4RouteTarget, false) => FixedNlriIter::ipv4route_target(parser).validate(),

            (Ipv4FlowSpec, false) => FixedNlriIter::ipv4flowspec(parser).validate(),
            (Ipv6FlowSpec, false) => FixedNlriIter::ipv6flowspec(parser).validate(),

            (L2VpnVpls, false) => FixedNlriIter::l2vpn_vpls(parser).validate(),
            (L2VpnEvpn, false) => FixedNlriIter::l2vpn_evpn(parser).validate(),

            // It's unclear to what extent the following address families
            // are used in combination with PathIDs. For now we print a
            // warning so it does not go unnoticed, and we do not return an
            // Error.
            
            (Ipv4RouteTarget, true) |
            (Ipv4FlowSpec, true) | (Ipv6FlowSpec, true) |
            (L2VpnVpls, true) |
            (L2VpnEvpn, true)  => {
                warn!(
                    "unimplemented: {} with ADDPATH MP_REACH_NLRI",
                    afisafi
                );
                Ok(())
            }
        }
        */
    }
}


//--- MpUnreachNlri
impl<A> AttributeHeader for MpUnreachNlriBuilder<A> {
    const FLAGS: u8 = Flags::OPT_NON_TRANS;
    const TYPE_CODE: u8 = 15;
}

impl<A: Clone + NlriCompose> Attribute for MpUnreachNlriBuilder<A> {
    fn value_len(&self) -> usize { 
        self.value_len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        self.compose_value(target)
    }

    fn parse<'a, Octs: 'a + Octets>(_parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    where
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        todo!()
            /*
        let afi = parser.parse_u16_be()?;
        let safi = parser.parse_u8()?;

        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;

        let mut builder = MpUnreachNlriBuilder::new(
            afisafi,
            //sc.rx_addpath(afisafi),
            ppi.mp_unreach_addpath(),
        );
        todo!()
            */
        // TODO figure out how much sense it makes to actually make an
        // MpUnreachBuilder here.

        /*
        let nlri_iter = crate::bgp::message::update::Nlris::new(
            *parser,
            ppi,
            afisafi,
        ).iter();

        for nlri in nlri_iter {
            builder.add_withdrawal(&nlri?);
        }
        Ok(builder)
        */
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        // We only check for the bare minimum here, as most checks are
        // better done upon (creation of the) Nlri iterator based on the
        // value of this path attribute.
        if parser.remaining() < 3 {
            return Err(ParseError::form_error(
                "length for MP_UNREACH_NLRI less than minimum"
            ))
        }
        Ok(())
        /*


        let afi = parser.parse_u16_be()?;
        let safi = parser.parse_u8()?;

        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;
        let expect_path_id = session_config.mp_unreach_addpath();

        use AfiSafi::*;
        match (afisafi, expect_path_id) {
            (Ipv4Unicast, false) => FixedNlriIter::ipv4unicast(parser).validate(),
            (Ipv4Unicast, true) => FixedNlriIter::ipv4unicast_addpath(parser).validate(),
            (Ipv6Unicast, false) => FixedNlriIter::ipv6unicast(parser).validate(),
            (Ipv6Unicast, true) => FixedNlriIter::ipv6unicast_addpath(parser).validate(),
            

            (Ipv4Multicast, false) => FixedNlriIter::ipv4multicast(parser).validate(),
            (Ipv4Multicast, true) => FixedNlriIter::ipv4multicast_addpath(parser).validate(),
            (Ipv6Multicast, false) => FixedNlriIter::ipv6multicast(parser).validate(),
            (Ipv6Multicast, true) => FixedNlriIter::ipv6multicast_addpath(parser).validate(),


            (Ipv4MplsUnicast, false) => FixedNlriIter::ipv4mpls_unicast(parser).validate(),
            (Ipv4MplsUnicast, true) => FixedNlriIter::ipv4mpls_unicast_addpath(parser).validate(),
            (Ipv6MplsUnicast, false) => FixedNlriIter::ipv6mpls_unicast(parser).validate(),
            (Ipv6MplsUnicast, true) => FixedNlriIter::ipv6mpls_unicast_addpath(parser).validate(),


            (Ipv4MplsVpnUnicast, false) => FixedNlriIter::ipv4mpls_vpn_unicast(parser).validate(),
            (Ipv4MplsVpnUnicast, true) => FixedNlriIter::ipv4mpls_vpn_unicast_addpath(parser).validate(),
            (Ipv6MplsVpnUnicast, false) => FixedNlriIter::ipv6mpls_vpn_unicast(parser).validate(),
            (Ipv6MplsVpnUnicast, true) => FixedNlriIter::ipv6mpls_vpn_unicast_addpath(parser).validate(),

            (Ipv4RouteTarget, false) => FixedNlriIter::ipv4route_target(parser).validate(),

            (Ipv4FlowSpec, false) => FixedNlriIter::ipv4flowspec(parser).validate(),
            (Ipv6FlowSpec, false) => FixedNlriIter::ipv6flowspec(parser).validate(),

            (L2VpnVpls, false) => FixedNlriIter::l2vpn_vpls(parser).validate(),
            (L2VpnEvpn, false) => FixedNlriIter::l2vpn_evpn(parser).validate(),

            // It's unclear to what extent the following address families
            // are used in combination with PathIDs. For now we print a
            // warning so it does not go unnoticed, and we do not return an
            // Error.
            
            (Ipv4RouteTarget, true) |
            (Ipv4FlowSpec, true) | (Ipv6FlowSpec, true) |
            (L2VpnVpls, true) |
            (L2VpnEvpn, true)  => {
                warn!(
                    "unimplemented: {} with ADDPATH in MP_UNREACH_NLRI",
                    afisafi
                );
                Ok(())
            }
        }
    */
    }
}

//--- ExtendedCommunities

use crate::bgp::communities::ExtendedCommunity;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExtendedCommunitiesList {
    communities: Vec<ExtendedCommunity>
}

impl ExtendedCommunitiesList {
    pub fn new(communities: Vec<ExtendedCommunity>)
        -> ExtendedCommunitiesList
    {
        ExtendedCommunitiesList {communities }
    }

    pub fn communities(&self) -> &Vec<ExtendedCommunity> {
        &self.communities
    }

    pub fn fmap<T, F: Fn(ExtendedCommunity) -> T>(self, fmap: F) -> Vec<T> {
        self.communities.into_iter().map(fmap).collect::<Vec<T>>()
    }

    pub fn add_community(&mut self, comm: ExtendedCommunity) {
        self.communities.push(comm);
    }
}


impl Attribute for crate::bgp::path_attributes::ExtendedCommunitiesList {
    fn value_len(&self) -> usize { 
        self.communities.len() * 8
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let mut communities = Vec::with_capacity(parser.remaining() / 8);
        let mut buf = [0u8; 8];
        while parser.remaining() > 0 {
            parser.parse_buf(&mut buf)?;
            communities.push(buf.into());
        }
        Ok(Self::new(communities))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        if parser.remaining() % 8 != 0 {
            return Err(ParseError::form_error(
                "unexpected length for EXTENDED_COMMUNITIES"
            ));
        }
        Ok(())
    }
}

//--- As4Path (see bgp::aspath)

impl Attribute for crate::bgp::types::As4Path {
    fn value_len(&self) -> usize {
        self.0.to_as_path::<Vec<u8>>().unwrap().into_inner().len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(
            self.0.to_as_path::<Vec<u8>>().unwrap().into_inner().as_ref()
        )
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        // XXX Same as with AsPath, reusing the old/existing As4Path here
        let asp = crate::bgp::aspath::AsPath::new(
            parser.peek_all().to_vec(),
            ppi.has_four_octet_asn()
        ).map_err(|_| ParseError::form_error("invalid AS4_PATH"))?;
        Ok(Self(asp.to_hop_path()))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        while parser.remaining() > 0 {
            let segment_type = parser.parse_u8()?;
            if !(1..=4).contains(&segment_type) {
                return Err(ParseError::form_error(
                    "illegal segment type in AS4_PATH"
                ));
            }
            let len = usize::from(parser.parse_u8()?); // ASNs in segment
            parser.advance(len * 4)?; // ASNs.
        }
        Ok(())
    }

}

//--- As4Aggregator 

impl Attribute for crate::bgp::types::As4Aggregator {
    fn value_len(&self) -> usize { 8 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.asn().to_raw())?;
        target.append_slice(&self.0.address().octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let asn = Asn::from_u32(parser.parse_u32_be()?);
        let address = parse_ipv4addr(parser)?;
        Ok(Self(AggregatorInfo::new(asn, address)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 8, "AS4_AGGREGATOR")
    }
}


//--- Connector (deprecated)

impl Attribute for crate::bgp::types::Connector {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self(parse_ipv4addr(parser)?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _ppi: PduParseInfo
    )
        -> Result<(), ParseError>
    {
        check_len_exact!(parser, 4, "CONNECTOR")
    }
}

//--- AsPathLimit (deprecated)

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AsPathLimitInfo {
    upper_bound: u8,
    attacher: Asn,
}

impl AsPathLimitInfo {
    pub fn new(upper_bound: u8, attacher: Asn) -> AsPathLimitInfo {
        AsPathLimitInfo { upper_bound, attacher }
    }
}

impl Attribute for AsPathLimitInfo {
    fn value_len(&self) -> usize { 5 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[self.upper_bound])?;
        target.append_slice(&self.attacher.to_raw())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let info = AsPathLimitInfo {
            upper_bound: parser.parse_u8()?,
            attacher: Asn::from_u32(parser.parse_u32_be()?)
        };

        Ok(info)
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _ppi: PduParseInfo
    )
    -> Result<(), ParseError>
    {
        check_len_exact!(parser, 5, "AS_PATHLIMIT")
    }
}

//--- Ipv6ExtendedCommunities

use crate::bgp::communities::Ipv6ExtendedCommunity;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ipv6ExtendedCommunitiesList {
    communities: Vec<Ipv6ExtendedCommunity>
}

impl Ipv6ExtendedCommunitiesList {
    pub fn new(communities: Vec<Ipv6ExtendedCommunity>)
        -> Ipv6ExtendedCommunitiesList
    {
        Ipv6ExtendedCommunitiesList {communities }
    }

    pub fn communities(&self) -> &Vec<Ipv6ExtendedCommunity> {
        &self.communities
    }

    pub fn fmap<T, F: Fn(Ipv6ExtendedCommunity) -> T>(self, fmap: F) -> Vec<T> {
        self.communities.into_iter().map(fmap).collect::<Vec<T>>()
    }

    pub fn add_community(&mut self, comm: Ipv6ExtendedCommunity) {
        self.communities.push(comm);
    }
}

impl Attribute for Ipv6ExtendedCommunitiesList {
    fn value_len(&self) -> usize { 
        self.communities.len() * 20
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let mut communities = Vec::with_capacity(parser.remaining() / 20);
        let mut buf = [0u8; 20];
        while parser.remaining() > 0 {
            parser.parse_buf(&mut buf)?;
            communities.push(buf.into());
        }
        Ok(Ipv6ExtendedCommunitiesList::new(communities))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        if parser.remaining() % 20 != 0 {
            return Err(ParseError::form_error(
                "unexpected length for IPV6_EXTENDED_COMMUNITIES"
            ));
        }
        Ok(())
    }
}

//--- LargeCommunities

use crate::bgp::communities::LargeCommunity;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LargeCommunitiesList {
    communities: Vec<LargeCommunity>
}

impl LargeCommunitiesList {
    fn new(communities: Vec<LargeCommunity>)
        -> LargeCommunitiesList
    {
        LargeCommunitiesList {communities }
    }

    pub fn communities(&self) -> &Vec<LargeCommunity> {
        &self.communities
    }

    pub fn fmap<T, F: Fn(LargeCommunity) -> T>(self, fmap: F) -> Vec<T> {
        self.communities.into_iter().map(fmap).collect::<Vec<T>>()
    }
    
    pub fn add_community(&mut self, comm: LargeCommunity) {
        self.communities.push(comm)
    }
}


impl Attribute for LargeCommunitiesList {
    fn value_len(&self) -> usize { 
        self.communities.len() * 12
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let mut communities = Vec::with_capacity(parser.remaining() / 12);
        let mut buf = [0u8; 12];
        while parser.remaining() > 0 {
            parser.parse_buf(&mut buf)?;
            communities.push(buf.into());
        }
        Ok(Self::new(communities))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _pdu_parse_info: PduParseInfo
    ) -> Result<(), ParseError> {
        if parser.remaining() % 12 != 0 {
            return Err(ParseError::form_error(
                "unexpected length for LARGE_COMMUNITIES"
            ));
        }
        Ok(())
    }
}

//--- Otc 

impl Attribute for crate::bgp::types::Otc {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.to_raw())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        Ok(Self(Asn::from_u32(parser.parse_u32_be()?)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _ppi: PduParseInfo
    )
    -> Result<(), ParseError>
    {
        check_len_exact!(parser, 4, "OTC")
    }
}

//--- AttributeSet

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AttributeSet {
    origin: Asn,
    attributes: Vec<u8>,
}

impl AttributeSet {
    pub fn new(origin: Asn, attributes: Vec<u8>) -> AttributeSet {
        AttributeSet { origin, attributes }
    }
}

impl Attribute for AttributeSet {
    fn value_len(&self) -> usize {
        4 + self.attributes.len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.origin.to_raw())?;
        target.append_slice(&self.attributes)
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let origin = Asn::from_u32(parser.parse_u32_be()?);
        let attributes = parser.peek_all().to_vec();
        Ok(Self::new(origin, attributes))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _ppi: PduParseInfo
    )
    -> Result<(), ParseError>
    {
        // XXX we do not validate the actual content (i.e. the attributes)
        // here. Whoever wishes to process these will need to iterate over
        // them with a PathAttributes anyway.
        if parser.remaining() < 4 {
            return Err(ParseError::form_error(
                "length for ATTR_SET less than minimum"
            ))
        }
        Ok(())
    }
}

//--- ReservedRaw

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ReservedRaw {
    raw: Vec<u8>,
}

impl ReservedRaw {
    pub fn new(raw: Vec<u8>) -> ReservedRaw {
        ReservedRaw { raw }
    }
}

impl Attribute for ReservedRaw {
    fn value_len(&self) -> usize {
        self.raw.len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.raw)
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _ppi: PduParseInfo) 
        -> Result<Self, ParseError>
    {
        let raw = parser.peek_all().to_vec();
        Ok(Self::new(raw))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        _parser: &mut Parser<'_, Octs>,
        _ppi: PduParseInfo
    )
    -> Result<(), ParseError>
    {
        // Not anything we can validate here, really.
        Ok(())
    }
}


//--- Unimplemented
// 
// XXX implementing the Attribute trait requires to implement the
// AttributeHeader trait to be implemented as well. But, we have no const
// FLAGS and type_code for an UnimplementedPathAttribute, so that does not
// fly.
//
// Let's try to go without the trait.

impl UnimplementedPathAttribute {
    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = self.value().len();
        // We did not recognize this attribute, so we set the Partial flag.
        let flags = self.flags() | Flags::PARTIAL;
        target.append_slice(
            &[flags.into(), self.type_code()]
        )?;
        if flags.is_extended_length() {
            target.append_slice(
                &u16::try_from(len).unwrap_or(u16::MAX)
                .to_be_bytes()
            )?;
        } else {
            target.append_slice(&[
                u8::try_from(len).unwrap_or(u8::MAX)
            ])?;
        }
        target.append_slice(self.value())
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    use crate::asn::Asn;
    use crate::bgp::communities::Wellknown;
    use crate::bgp::aspath::HopPath;
    use crate::bgp::types::OriginType;

    #[test]
    fn wireformat_to_owned_and_back() {
        use super::PathAttribute as PA;
        fn check(raw: Vec<u8>, owned: PathAttribute) {
            let mut parser = Parser::from_ref(&raw);
            let sc = PduParseInfo::modern();
            let pa = WireformatPathAttribute::parse(&mut parser, sc)
                .unwrap();
            assert_eq!(owned, pa.to_owned().unwrap());
            let mut target = Vec::new();
            owned.compose(&mut target).unwrap();
            assert_eq!(target, raw);
        }

        check(vec![0x40, 0x01, 0x01, 0x00], PA::Origin(OriginType::Igp.into()));

        check(
            vec![0x40, 0x02, 10,
            0x02, 0x02, // SEQUENCE of length 2
            0x00, 0x00, 0x00, 100,
            0x00, 0x00, 0x00, 200,
            ],
            PA::AsPath(HopPath::from(vec![
                Asn::from_u32(100),
                Asn::from_u32(200)]
            ))
        );

        check(
            vec![0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04],
            PA::ConventionalNextHop(crate::bgp::types::ConventionalNextHop("1.2.3.4".parse().unwrap()))
        );

        check(
            vec![0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff],
            PA::MultiExitDisc(crate::bgp::types::MultiExitDisc(255))
        );

        check(
            vec![0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x0a],
            PA::LocalPref(crate::bgp::types::LocalPref(10))
        );

        check(
            vec![0x40, 0x06, 0x00],
            PA::AtomicAggregate(crate::bgp::types::AtomicAggregate)
        );
        
        check(
            vec![
                0xc0, 0x07, 0x08, 0x00, 0x00, 0x00, 0x65, 0xc6,
                0x33, 0x64, 0x01
            ],
            PA::Aggregator(AggregatorInfo::new(
                    Asn::from_u32(101),
                    "198.51.100.1".parse().unwrap()
            ))
        );

        check(
            vec![
                0xc0, 0x08, 0x10, 0x00, 0x2a, 0x02, 0x06, 0xff,
                0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x02, 0xff,
                0xff, 0xff, 0x03
            ],
            {
                let mut builder = StandardCommunitiesList::new();
                builder.add_community("AS42:518".parse().unwrap());
                builder.add_community(Wellknown::NoExport.into());
                builder.add_community(Wellknown::NoAdvertise.into());
                builder.add_community(Wellknown::NoExportSubconfed.into());
                PA::StandardCommunities(builder)
            }
        );

        check(
            vec![0x80, 0x09, 0x04, 0x0a, 0x00, 0x00, 0x04],
            crate::bgp::types::OriginatorId("10.0.0.4".parse().unwrap()).into()
        );

        check(
            vec![0x80, 0x0a, 0x04, 0x0a, 0x00, 0x00, 0x03],
            ClusterIds::new(vec![[10, 0, 0, 3].into()]).into()
        );
        
        /*
        // MpBuilders are not variants of PathAttribute anymore...
        check(
            vec![
                0x80, 0x0e, 0x1c,
                0x00, 0x02, 0x01,
                0x10,
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
                0x00,
                0x30, 0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb
            ],
            {
            let mut builder = MpReachNlriBuilder::<Ipv6UnicastNlri>::for_nexthop(
                NextHop::Unicast("2001:db8::1234".parse().unwrap()),
            );
            builder.add_announcement(
                Ipv6UnicastNlri::try_from(
                    Prefix::from_str("2001:db8:aabb::/48").unwrap()
                ).unwrap()
            );

            builder.into()
            }
        );

        check(
            vec![
                0x80, 0x0f, 0x27, 0x00, 0x02, 0x02, 0x40, 0x20,
                0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x40,
                0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01,
                0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
                0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff,
                0x00, 0x03
            ],
            {
            let mut builder = MpUnreachNlriBuilder::new(
                Afi::Ipv6,
                Safi::Multicast,
                false // no addpath
            );
            [
                "2001:db8:ffff::/64",
                "2001:db8:ffff:1::/64",
                "2001:db8:ffff:2::/64",
                "2001:db8:ffff:3::/64",
            ].into_iter().for_each(|s|{
                builder.add_withdrawal(
                    &Nlri::Multicast::<&[u8]>(
                        Prefix::from_str(s).unwrap().into()
                    )
                );
            });

            builder.into()
            }
        );
        */

        check(
            vec![
                0xc0, 0x10, 0x08, 0x00, 0x02, 0xfc, 0x85, 0x00,
                0x00, 0xcf, 0x08
            ],
            ExtendedCommunitiesList::new(vec![
                "rt:64645:53000".parse().unwrap()
            ]).into()
        );

        check(
            vec![
                0xc0, 0x11, 10,
                0x02, 0x02, // SEQUENCE of length 2
                0x00, 0x00, 0x00, 100,
                0x00, 0x00, 0x00, 200,
            ],
            PA::As4Path(crate::bgp::types::As4Path(HopPath::from(vec![
                Asn::from_u32(100),
                Asn::from_u32(200)]
            )))
        );

        check(
            vec![
                0xc0, 0x12, 0x08, 0x00, 0x00, 0x04, 0xd2,
                10, 0, 0, 99
            ],
            crate::bgp::types::As4Aggregator(AggregatorInfo::new(
                Asn::from_u32(1234),
                "10.0.0.99".parse().unwrap()
            )).into()
        );

        check(
            vec![0xc0, 0x14, 0x04, 1, 2, 3, 4],
            crate::bgp::types::Connector("1.2.3.4".parse().unwrap()).into()
        );

        check(
            vec![0xc0, 0x15, 0x05, 0x14, 0x00, 0x00, 0x04, 0xd2],
            AsPathLimitInfo::new(20, Asn::from_u32(1234)).into()
        );

        //TODO 22 PmsiTunnel
        //TODO 25 Ipv6ExtendedCommunities

        check(
            vec![
                0xc0, 0x20, 0x3c, 0x00, 0x00, 0x20, 0x5b, 0x00,
                0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x00,
                0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x64, 0x00,
                0x00, 0x0b, 0x62, 0x00, 0x00, 0xe2, 0x0a, 0x00,
                0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x64, 0x00,
                0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x67, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0xe2, 0x0a, 0x00,
                0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x1f
            ],
            LargeCommunitiesList::new(
                vec![
                    "AS8283:6:15".parse().unwrap(),
                    "AS57866:100:2914".parse().unwrap(),
                    "AS57866:101:100".parse().unwrap(),
                    "AS57866:103:1".parse().unwrap(),
                    "AS57866:104:31".parse().unwrap(),
                ]
            ).into()
        );

        check(
            vec![0xc0, 0x23, 0x04, 0x00, 0x00, 0x04, 0xd2],
            crate::bgp::types::Otc(Asn::from_u32(1234)).into()
        );

        // TODO AttrSet
        // TODO Reserved?

        // UnimplementedPathAttribute
        // Note that we need to set the Partial flag on the input already,
        // otherwise the first assert_eq in fn check fails. 
        let flags = Flags::OPT_TRANS | Flags::PARTIAL;
        check(
            vec![flags, 254, 0x04, 0x01, 0x02, 0x03, 0x04],
            UnimplementedPathAttribute::new(
                flags.into(),
                254,
                vec![0x01, 0x02, 0x03, 0x04]
            ).into()
        );
    }

    #[test]
    fn iter_and_find() {
        let raw = vec![
            0x40, 0x01, 0x01, 0x00, // ORIGIN
            0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, // NEXTHOP
            0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff // MED 
        ];
        let pas = PathAttributes::new(
            Parser::from_ref(&raw), PduParseInfo::modern()
        );
        //for _ in 0..4 {
        //    let pa = pas.next();
        //    println!("{pa:?}");
        //}

        assert!(pas.get(PathAttributeType::Origin).is_some());
        assert!(pas.get(PathAttributeType::AsPath).is_none());
        assert!(pas.get(PathAttributeType::MultiExitDisc).is_some());
        assert!(pas.get(PathAttributeType::ConventionalNextHop).is_some());
    }

    #[test]
    fn unimplemented_path_attributes() {
        let raw = vec![
            0xc0, 254, 0x04, 0x01, 0x02, 0x03, 0x04
        ];
        let mut parser = Parser::from_ref(&raw);
        let sc = PduParseInfo::modern();
        let pa = WireformatPathAttribute::parse(&mut parser, sc);

        if let Ok(WireformatPathAttribute::Unimplemented(u)) = pa {
            assert_eq!(u.type_code(), 254);
            assert!(u.flags().is_optional());
            assert!(u.flags().is_transitive());
            assert_eq!(u.value(), &[0x01, 0x02, 0x03, 0x04]);
        } else {
            panic!("fail");
        }

    }

    #[test]
    fn parse_unexpected_two_octet_asn() {
        let raw = vec![
            0xc0, 0x07, 0x06, 0x00, 0x65, 0xc6,
            0x33, 0x64, 0x01
        ];
        let mut parser = Parser::from_ref(&raw);
        let pa = WireformatPathAttribute::parse(
                &mut parser, PduParseInfo::modern()
        ).unwrap();
        assert!(matches!(pa, WireformatPathAttribute::Invalid(_,_,_)));
    }

    /*
    #[test]
    fn deref_mut() {
        // AS_PATH: AS_SEQUENCE(AS100, AS200)
        let raw = vec![0x40, 0x02, 10,
            0x02, 0x02, // SEQUENCE of length 2
            0x00, 0x00, 0x00, 100,
            0x00, 0x00, 0x00, 200,
        ];

        let pa = WireformatPathAttribute::parse(
            &mut Parser::from_ref(&raw), SessionConfig::modern()
        ).unwrap();
        let mut owned = pa.to_owned().unwrap();
        if let PathAttribute::AsPath(ref mut asp) = owned  {
            assert_eq!(format!("{}", **asp), "AS100 AS200");
            asp.prepend(Asn::from_u32(50));
            assert_eq!(format!("{}", **asp), "AS50 AS100 AS200");
            assert_eq!(3, asp.hop_count());
        }

        let mut composed = Vec::new();
        owned.compose(&mut composed).unwrap();
        assert!(composed != raw);
    }
    */

    #[test]
    fn as_ref_as_mut() {
        // AS_PATH: AS_SEQUENCE(AS100, AS200)
        let raw = vec![0x40, 0x02, 10,
            0x02, 0x02, // SEQUENCE of length 2
            0x00, 0x00, 0x00, 100,
            0x00, 0x00, 0x00, 200,
        ];

        let pa = WireformatPathAttribute::parse(
            &mut Parser::from_ref(&raw), PduParseInfo::modern()
        ).unwrap();
        let mut owned = pa.to_owned().unwrap();
        if let PathAttribute::AsPath(ref mut asp) = owned  {
            assert_eq!(format!("{}", asp), "AS100 AS200");
            asp.prepend(Asn::from_u32(50));
            assert_eq!(format!("{}", asp), "AS50 AS100 AS200");
            assert_eq!(3, asp.hop_count());
        }

        let mut composed = Vec::new();
        owned.compose(&mut composed).unwrap();
        assert!(composed != raw);
    }

    #[test]
    fn pamap() {
        use crate::bgp::types::LocalPref as LP;
        use crate::bgp::types::MultiExitDisc as MED;

        let mut pamap = PaMap::empty();
        pamap.set(LP(100));
        pamap.set::<MED>(MED(12));

        let _lp1 = pamap.remove::<LP>();
        //let _lp2 = pamap.take::<LP>();
        dbg!(&pamap);

        //pamap.set(NH::new(AfiSafi::Ipv4Unicast));
        //let nh = pamap.get::<NH>();
        //dbg!(nh);

        dbg!(&pamap);

        let asp = HopPath::new();
        pamap.set(asp);
        dbg!(&pamap);
    }
}
