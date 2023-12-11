use std::fmt;
use std::net::Ipv4Addr;

use log::debug;
use octseq::{Octets, OctetsBuilder, OctetsFrom, Parser};

use crate::asn::Asn;
use crate::bgp::aspath::HopPath;
use crate::bgp::message::{
    nlri::FixedNlriIter,
    SessionConfig
};
use crate::bgp::message::update_builder::{
    MpReachNlriBuilder,
    MpUnreachNlriBuilder,
    StandardCommunitiesBuilder
};
use crate::bgp::types::{AFI, SAFI, AfiSafi};
use crate::util::parser::{ParseError, parse_ipv4addr};


#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Flags(u8);

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

macro_rules! attribute {
    ($name:ident($data:ty),
     $flags:expr,
     $type_code:expr
     ) => {

        // TODO Serialize
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize))]
        pub struct $name($data);
        impl $name {
            pub fn new(data: $data) -> $name {
                $name(data)
            }

            pub fn inner(self) -> $data {
                self.0
            }
        }

        impl std::convert::AsRef<$data> for $name {
            fn as_ref(&self) -> &$data {
                &self.0
            }
        }

        impl std::convert::AsMut<$data> for $name {
            fn as_mut(&mut self) -> &mut $data {
                &mut self.0
            }
        }

        /*
        impl std::ops::Deref for $name {
            type Target = $data;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
        */

        impl AttributeHeader for $name {
            const FLAGS: u8 = $flags;
            const TYPE_CODE: u8 = $type_code;
        }
    }
}

macro_rules! path_attributes {
    (
        $(
            $type_code:expr => $name:ident($data:ty), $flags:expr
        ),+ $(,)*
    ) => {

//------------ PathAttribute -------------------------------------------------

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub enum PathAttribute {
            $( $name($name) ),+,
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

            pub fn type_code(&self) -> PathAttributeType {
                match self {
                    $(
                    PathAttribute::$name(_) =>
                        PathAttributeType::$name
                    ),+,
                    PathAttribute::Unimplemented(u) => {
                        PathAttributeType::Unimplemented(u.type_code())
                    }
                    PathAttribute::Invalid(_, tc, _) => {
                        PathAttributeType::Invalid(*tc)
                    }
                }
            }
        }

        $(
        impl From<$name> for PathAttribute {
            fn from(pa: $name) -> PathAttribute {
                PathAttribute::$name(pa)
            }
        }
        )+

        impl From<UnimplementedPathAttribute> for PathAttribute {
            fn from(u: UnimplementedPathAttribute) -> PathAttribute {
                PathAttribute::Unimplemented(u)
            }
        }
//------------ WireformatPathAttribute --------------------------------------

        #[derive(Debug)]
        pub struct EncodedPathAttribute<'a, Octs: Octets> {
            parser: Parser<'a, Octs>,
            session_config: SessionConfig,
        }
        impl<'a, Octs: Octets> EncodedPathAttribute<'a, Octs> {
            fn new(
                parser: Parser<'a, Octs>,
                session_config: SessionConfig
            ) -> Self {
                Self { parser, session_config }
            }

            pub fn session_config(&self) -> SessionConfig {
                self.session_config
            }

            fn flags(&self) -> Flags {
                self.parser.peek_all()[0].into()
            }

            fn length(&self) -> usize {
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
            //$( $name(Parser<'a, Octs>, SessionConfig) ),+,
            $( $name(EncodedPathAttribute<'a, Octs>) ),+, 
            Unimplemented(UnimplementedWireformat<'a, Octs>),
            Invalid(Flags, u8, Parser<'a, Octs>),
        }


        impl<'a, Octs: Octets> WireformatPathAttribute<'a, Octs> {
            fn parse(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
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
                        if let Err(e) = $name::validate(
                            flags.into(), &mut pp, sc
                        ) {
                            debug!("failed to parse path attribute: {e}");
                            pp.seek(start_pos + header_len)?;
                            WireformatPathAttribute::Invalid(
                                $flags.into(), $type_code, pp
                            )
                        } else {
                            pp.seek(start_pos/* + header_len */)?;
                            //WireformatPathAttribute::$name(pp, sc)
                            WireformatPathAttribute::$name(
                                EncodedPathAttribute::new(pp, sc)
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
                    //WireformatPathAttribute::$name(p, sc) => {
                    WireformatPathAttribute::$name(epa) => {
                        Ok(PathAttribute::$name(
                            //$name::parse(&mut p.clone(), *sc)?
                            $name::parse(
                                &mut epa.value_into_parser(),
                                epa.session_config()
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

            pub fn type_code(&self) -> PathAttributeType {
                match self {
                    $(
                        WireformatPathAttribute::$name(..) =>
                            PathAttributeType::$name
                    ),+,
                    WireformatPathAttribute::Unimplemented(u) => {
                        PathAttributeType::Unimplemented(u.type_code())
                    }
                    WireformatPathAttribute::Invalid(_, tc, _) => {
                        PathAttributeType::Invalid(*tc)
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
                        //Self::$name(pa, _sc) => pa.remaining()
                        Self::$name(epa) => epa.length()
                    ),+,
                    Self::Unimplemented(u) => u.value.len(),
                    Self::Invalid(_, _, v) => v.remaining() //FIXME incorrect
                }
            }

            /*
            pub fn _into_value_parser(self) -> Result<Parser<'a, Octs>, ParseError> {
                match self {
                $(
                    Self::$name(p, _) => {
                        Ok(p)
                    }
                ),+,
                    _ => todo!()
                }
            }
            */
        }

        impl<'a, Octs: Octets> AsRef<[u8]> for WireformatPathAttribute<'a, Octs> {
            fn as_ref(&self) -> &[u8] {
                match self {
                    $(
                        WireformatPathAttribute::$name(epa) => {
                            // this one is maybe fixed this way?
                        //p.peek_all()
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
        attribute!($name($data), $flags, $type_code);
        )+
    }
}

path_attributes!(
    1   => Origin(OriginType), Flags::WELLKNOWN,
    2   => AsPath(HopPath), Flags::WELLKNOWN,
    3   => NextHop(Ipv4Addr), Flags::WELLKNOWN,
    4   => MultiExitDisc(u32), Flags::OPT_NON_TRANS,
    5   => LocalPref(u32), Flags::WELLKNOWN,
    6   => AtomicAggregate(()), Flags::WELLKNOWN,
    7   => Aggregator(AggregatorInfo), Flags::OPT_TRANS,
    8   => Communities(StandardCommunitiesBuilder), Flags::OPT_TRANS,
    9   => OriginatorId(Ipv4Addr), Flags::OPT_NON_TRANS,
    10  => ClusterList(ClusterIds), Flags::OPT_NON_TRANS,
    14  => MpReachNlri(MpReachNlriBuilder), Flags::OPT_NON_TRANS,
    15  => MpUnreachNlri(MpUnreachNlriBuilder), Flags::OPT_NON_TRANS,
    16  => ExtendedCommunities(ExtendedCommunitiesList), Flags::OPT_TRANS,
    17  => As4Path(HopPath), Flags::OPT_TRANS,
    18  => As4Aggregator(AggregatorInfo), Flags::OPT_TRANS,
    20  => Connector(Ipv4Addr), Flags::OPT_TRANS,
    21  => AsPathLimit(AsPathLimitInfo), Flags::OPT_TRANS,
    //22  => PmsiTunnel(todo), Flags::OPT_TRANS,
    25  => Ipv6ExtendedCommunities(Ipv6ExtendedCommunitiesList), Flags::OPT_TRANS,
    32  => LargeCommunities(LargeCommunitiesList), Flags::OPT_TRANS,
    // 33 => BgpsecAsPath,
    35 => Otc(Asn), Flags::OPT_TRANS,
    //36 => BgpDomainPath(TODO), Flags:: , // https://datatracker.ietf.org/doc/draft-ietf-bess-evpn-ipvpn-interworking/06/
    //40 => BgpPrefixSid(TODO), Flags::OPT_TRANS, // https://datatracker.ietf.org/doc/html/rfc8669#name-bgp-prefix-sid-attribute
    128 => AttrSet(AttributeSet), Flags::OPT_TRANS,
    255 => Reserved(ReservedRaw), Flags::OPT_TRANS,

);

#[derive(Clone, Debug, Eq, PartialEq)]
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
        sc: SessionConfig
    )
        -> Result<(), ParseError>;

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
        -> Result<Self, ParseError>
    where 
        Self: Sized,
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    ;
    
}

#[derive(Debug)]
pub struct PathAttributes<'a, Octs> {
    pub parser: Parser<'a, Octs>,
    pub session_config: SessionConfig,
}

impl<'a, Octs> Clone for PathAttributes<'a, Octs> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, Octs> Copy for PathAttributes<'a, Octs> { }

impl<'a, Octs: Octets> PathAttributes<'a, Octs> {
    pub fn new(parser: Parser<'_, Octs>, session_config: SessionConfig)
        -> PathAttributes<'_, Octs>
    {
        PathAttributes { parser, session_config }
    }
    
    pub fn get(&self, pat: PathAttributeType)
        -> Option<WireformatPathAttribute<'a, Octs>>
    {
        let mut iter = *self;
        iter.find(|pa|
              //XXX We need Rust 1.70 for is_ok_and()
              //pa.as_ref().is_ok_and(|pa| pa.type_code() == pat)
              if let Ok(pa) = pa.as_ref() {
                  pa.type_code() == pat
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
            self.session_config
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

//--- Origin

use crate::bgp::message::update::OriginType;

impl Attribute for Origin {
    fn value_len(&self) -> usize { 1 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[self.0.into()]) 
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'_, Octs>, _sc: SessionConfig) 
        -> Result<Origin, ParseError>
    {
        Ok(Origin(parser.parse_u8()?.into()))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 1, "ORIGIN")
    }
}


//--- AsPath (see bgp::aspath)

impl Attribute for AsPath {
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

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
        -> Result<AsPath, ParseError>
    {
        // XXX reusing the old/existing AsPath here for the time being
        let asp = crate::bgp::aspath::AsPath::new(
            parser.peek_all().to_vec(),
            sc.has_four_octet_asn()
        ).map_err(|_| ParseError::form_error("invalid AS_PATH"))?;

        Ok(AsPath(asp.to_hop_path()))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        session_config: SessionConfig
    ) -> Result<(), ParseError> {
        let asn_size = if session_config.has_four_octet_asn() {
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

impl Attribute for NextHop {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<NextHop, ParseError>
    {
        Ok(NextHop(parse_ipv4addr(parser)?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 4, "NEXT_HOP")
    }
}

//--- MultiExitDisc

impl Attribute for MultiExitDisc {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.to_be_bytes()) 
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<MultiExitDisc, ParseError>
    {
        Ok(MultiExitDisc(parser.parse_u32_be()?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 4, "MULTI_EXIT_DISC")
    }
}

//--- LocalPref

impl Attribute for LocalPref {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.to_be_bytes()) 
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<LocalPref, ParseError>
    {
        Ok(LocalPref(parser.parse_u32_be()?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 4, "LOCAL_PREF")
    }
}

//--- AtomicAggregate

impl Attribute for AtomicAggregate {
    fn value_len(&self) -> usize { 0 }

    fn compose_value<Target: OctetsBuilder>(&self, _target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(_parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<AtomicAggregate, ParseError>
    {
        Ok(AtomicAggregate(()))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 0, "ATOMIC_AGGREGATE")
    }
}

impl Copy for AtomicAggregate { }

//--- Aggregator

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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


impl Attribute for Aggregator {
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
        target.append_slice(&self.0.asn().to_raw())?;
        target.append_slice(&self.0.address().octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
        -> Result<Aggregator, ParseError>
    {
        let asn = if sc.has_four_octet_asn() {
            Asn::from_u32(parser.parse_u32_be()?)
        } else {
            Asn::from_u32(parser.parse_u16_be()?.into())
        };

        let address = parse_ipv4addr(parser)?;
        Ok(Aggregator(AggregatorInfo::new(asn, address)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        session_config: SessionConfig
    ) -> Result<(), ParseError> {
        //if flags != Self::FLAGS.into() {
        //        return Err(ParseError::form_error("invalid flags"));
        //}
        if session_config.has_four_octet_asn() {
            check_len_exact!(parser, 8, "AGGREGATOR")?;
        } else {
            check_len_exact!(parser, 6, "AGGREGATOR")?;
        }
        Ok(())
    }
}

//--- Communities

impl Attribute for Communities {
    fn value_len(&self) -> usize { 
        self.0.communities().len() * 4
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in self.0.communities() {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<Communities, ParseError>
    {
        let mut builder = StandardCommunitiesBuilder::with_capacity(
            parser.remaining() / 4
        );
        while parser.remaining() > 0 {
            builder.add_community(parser.parse_u32_be()?.into());
        }

        Ok(Communities(builder))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
    ) -> Result<(), ParseError> {
        if parser.remaining() % 4 != 0 {
            return Err(ParseError::form_error(
                "unexpected length for COMMUNITIES"
            ));
        }
        Ok(())
    }
}

//--- OriginatorId

impl Attribute for OriginatorId {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<OriginatorId, ParseError>
    {
        Ok(OriginatorId(parse_ipv4addr(parser)?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
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

/*
impl From<u32> for BgpIdentifier {
    fn from(raw: u32) -> BgpIdentifier {
        BgpIdentifier(raw.to_be_bytes())
    }
}
*/

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


impl Attribute for ClusterList {
    fn value_len(&self) -> usize { 
        self.0.cluster_ids.len() * 4
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.0.cluster_ids {
            target.append_slice(&c.0)?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<ClusterList, ParseError>
    {
        let mut cluster_ids = Vec::with_capacity(parser.remaining() / 4);
        while parser.remaining() > 0 {
            cluster_ids.push(parser.parse_u32_be()?.to_be_bytes().into());
        }
        Ok(ClusterList(ClusterIds::new(cluster_ids)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
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
impl Attribute for MpReachNlri {
    fn value_len(&self) -> usize { 
        self.0.value_len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        self.0.compose_value(target)
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
        -> Result<MpReachNlri, ParseError>
        where
            Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        let afi: AFI = parser.parse_u16_be()?.into();
        let safi: SAFI = parser.parse_u8()?.into();
        let nexthop = crate::bgp::types::NextHop::parse(parser, afi, safi)?;
        if let crate::bgp::types::NextHop::Unimplemented(..) =  nexthop {
            debug!("Unsupported NextHop: {:?}", nexthop);
            return Err(ParseError::Unsupported);
        }
        parser.advance(1)?; // reserved byte
        
        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;

        let mut builder = MpReachNlriBuilder::new(
            afi,
            safi,
            nexthop,
            sc.rx_addpath(afisafi)
        );

        // This is what using the FixedNlriIter would look like:
        /*
        match(afi, safi, sc.addpath_enabled()) {
            (AFI::Ipv4, SAFI::Unicast, false) => {
                for n in FixedNlriIter::ipv4unicast(parser) {
                    builder.add_announcement(&n?)
                }
            }
            (AFI::Ipv4, SAFI::Unicast, true) => {
                for n in FixedNlriIter::ipv4unicast_addpath(parser) {
                    builder.add_announcement(&n?)
                }
            }
            (AFI::Ipv6, SAFI::Unicast, false) => {
                for n in FixedNlriIter::ipv6unicast(parser) {
                    builder.add_announcement(&n?)
                }
            }
            (AFI::Ipv6, SAFI::Unicast, true) => {
                for n in FixedNlriIter::ipv6unicast_addpath(parser) {
                    builder.add_announcement(&n?)
                }
            }
            _ => {
                todo!("afi safi {:?} {:?}", afi, safi);
            }
        }
        */
        let nlri_iter = crate::bgp::message::update::Nlris::new(
            *parser,
            sc,
            afisafi
        ).iter();

        for nlri in nlri_iter {
            builder.add_announcement(&nlri?);
        }

        Ok(MpReachNlri(builder))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        session_config: SessionConfig
    ) -> Result<(), ParseError> {
        // We only check for the bare minimum here, as most checks are
        // better done upon (creation of the) Nlri iterator based on the
        // value of this path attribute.
        if parser.remaining() < 5 {
            return Err(ParseError::form_error(
                "length for MP_REACH_NLRI less than minimum"
            ))
        }
        
         
        let afi: AFI = parser.parse_u16_be()?.into();
        let safi: SAFI = parser.parse_u8()?.into();
        let _nexthop = crate::bgp::types::NextHop::parse(parser, afi, safi)?;
        //if let crate::bgp::types::NextHop::Unimplemented(..) =  nexthop {
        //    debug!("Unsupported NextHop: {:?}", nexthop);
        //    return Err(ParseError::Unsupported);
        //}
        parser.advance(1)?; // reserved byte

        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;
        let expect_path_id = session_config.rx_addpath(afisafi);

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

            _ => { debug!("TODO implement validation for this afi/safi"); Ok(()) }
            /* TODO

            (Ipv4MplsVpnUnicast, false) => FixedNlriIter::ipv4mpls_vpn_unicast(parser).validate()?,
            (Ipv4MplsVpnUnicast, true) => FixedNlriIter::ipv4mpls_vpn_unicast_addpath(parser).validate()?,
            (Ipv6MplsVpnUnicast, false) => FixedNlriIter::ipv6mpls_vpn_unicast(parser).validate()?,
            (Ipv6MplsVpnUnicast, true) => FixedNlriIter::ipv6mpls_vpn_unicast_addpath(parser).validate()?,

            // XXX does addpath come into play here?
            (Ipv4RouteTarget, false) => FixedNlriIter::ipv4routetarget(parser).validate()?,
            (Ipv4RouteTarget, true) => FixedNlriIter::ipv4routetarget_addpath(parser).validate()?,

            (Ipv4FlowSpec, _) => FixedNlriIter::ipv4flowspec(parser).validate()?,
            (Ipv6FlowSpec, _) => FixedNlriIter::ipv6flowspec(parser).validate()?,

            // XXX does addpath come into play here?
            (L2VpnVpls, false) => FixedNlriIter::l2vpn_vpls(parser).validate()?,
            (L2VpnVpls, true) => FixedNlriIter::l2vpn_vpls_addpath(parser).validate()?,
            (L2VpnEvpn, false) => FixedNlriIter::l2vpn_evpn(parser).validate()?,
            (L2VpnEvpn, true) => FixedNlriIter::l2vpn_evpn_addpath(parser).validate()?,
            */
        }
    }
}

//--- MpUnreachNlri
impl Attribute for MpUnreachNlri {
    fn value_len(&self) -> usize { 
        self.0.value_len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        self.0.compose_value(target)
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
        -> Result<MpUnreachNlri, ParseError>
    where
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        let afi: AFI = parser.parse_u16_be()?.into();
        let safi: SAFI = parser.parse_u8()?.into();

        let afisafi = AfiSafi::try_from((afi, safi))
            .map_err(|_| ParseError::Unsupported)?;

        let mut builder = MpUnreachNlriBuilder::new(
            afi,
            safi,
            sc.rx_addpath(afisafi)
        );
        let nlri_iter = crate::bgp::message::update::Nlris::new(
            *parser,
            sc,
            afisafi,
        ).iter();

        for nlri in nlri_iter {
            builder.add_withdrawal(&nlri?);
        }
        Ok(MpUnreachNlri(builder))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
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
    fn new(communities: Vec<ExtendedCommunity>)
        -> ExtendedCommunitiesList
    {
        ExtendedCommunitiesList {communities }
    }

    pub fn communities(&self) -> &Vec<ExtendedCommunity> {
        &self.communities
    }
}


impl Attribute for ExtendedCommunities {
    fn value_len(&self) -> usize { 
        self.0.communities.len() * 8
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.0.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<ExtendedCommunities, ParseError>
    {
        let mut communities = Vec::with_capacity(parser.remaining() / 8);
        let mut buf = [0u8; 8];
        while parser.remaining() > 0 {
            parser.parse_buf(&mut buf)?;
            communities.push(buf.into());
        }
        Ok(ExtendedCommunities(ExtendedCommunitiesList::new(communities)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
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

impl Attribute for As4Path {
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

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, sc: SessionConfig) 
        -> Result<As4Path, ParseError>
    {
        // XXX Same as with AsPath, reusing the old/existing As4Path here
        let asp = crate::bgp::aspath::AsPath::new(
            parser.peek_all().to_vec(),
            sc.has_four_octet_asn()
        ).map_err(|_| ParseError::form_error("invalid AS4_PATH"))?;
        Ok(As4Path(asp.to_hop_path()))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
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

impl Attribute for As4Aggregator {
    fn value_len(&self) -> usize { 8 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.asn().to_raw())?;
        target.append_slice(&self.0.address().octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<As4Aggregator, ParseError>
    {
        let asn = Asn::from_u32(parser.parse_u32_be()?);
        let address = parse_ipv4addr(parser)?;
        Ok(As4Aggregator(AggregatorInfo::new(asn, address)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
    ) -> Result<(), ParseError> {
        check_len_exact!(parser, 8, "AS4_AGGREGATOR")
    }
}


//--- Connector (deprecated)

impl Attribute for Connector {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.octets())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<Connector, ParseError>
    {
        Ok(Connector(parse_ipv4addr(parser)?))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _sc: SessionConfig
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

impl Attribute for AsPathLimit {
    fn value_len(&self) -> usize { 5 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[self.0.upper_bound])?;
        target.append_slice(&self.0.attacher.to_raw())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<AsPathLimit, ParseError>
    {
        let info = AsPathLimitInfo {
            upper_bound: parser.parse_u8()?,
            attacher: Asn::from_u32(parser.parse_u32_be()?)
        };

        Ok(AsPathLimit(info))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _sc: SessionConfig
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
    fn new(communities: Vec<Ipv6ExtendedCommunity>)
        -> Ipv6ExtendedCommunitiesList
    {
        Ipv6ExtendedCommunitiesList {communities }
    }

    pub fn communities(&self) -> &Vec<Ipv6ExtendedCommunity> {
        &self.communities
    }
}


impl Attribute for Ipv6ExtendedCommunities {
    fn value_len(&self) -> usize { 
        self.0.communities.len() * 20
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.0.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<Ipv6ExtendedCommunities, ParseError>
    {
        let mut communities = Vec::with_capacity(parser.remaining() / 20);
        let mut buf = [0u8; 20];
        while parser.remaining() > 0 {
            parser.parse_buf(&mut buf)?;
            communities.push(buf.into());
        }
        Ok(Ipv6ExtendedCommunities(Ipv6ExtendedCommunitiesList::new(communities)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
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
}


impl Attribute for LargeCommunities {
    fn value_len(&self) -> usize { 
        self.0.communities.len() * 12
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        for c in &self.0.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<LargeCommunities, ParseError>
    {
        let mut communities = Vec::with_capacity(parser.remaining() / 12);
        let mut buf = [0u8; 12];
        while parser.remaining() > 0 {
            parser.parse_buf(&mut buf)?;
            communities.push(buf.into());
        }
        Ok(LargeCommunities(LargeCommunitiesList::new(communities)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _session_config: SessionConfig
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

impl Attribute for Otc {
    fn value_len(&self) -> usize { 4 }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.to_raw())
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<Otc, ParseError>
    {
        Ok(Otc(Asn::from_u32(parser.parse_u32_be()?)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _sc: SessionConfig
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

impl Attribute for AttrSet {
    fn value_len(&self) -> usize {
        4 + self.0.attributes.len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.origin.to_raw())?;
        target.append_slice(&self.0.attributes)
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<AttrSet, ParseError>
    {
        let origin = Asn::from_u32(parser.parse_u32_be()?);
        let attributes = parser.peek_all().to_vec();
        Ok(AttrSet(AttributeSet::new(origin, attributes)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        parser: &mut Parser<'_, Octs>,
        _sc: SessionConfig
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

impl Attribute for Reserved {
    fn value_len(&self) -> usize {
        self.0.raw.len()
    }

    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&self.0.raw)
    }

    fn parse<'a, Octs: 'a + Octets>(parser: &mut Parser<'a, Octs>, _sc: SessionConfig) 
        -> Result<Reserved, ParseError>
    {
        let raw = parser.peek_all().to_vec();
        Ok(Reserved(ReservedRaw::new(raw)))
    }

    fn validate<Octs: Octets>(
        _flags: Flags,
        _parser: &mut Parser<'_, Octs>,
        _sc: SessionConfig
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
        target.append_slice(
            &[self.flags().into(), self.type_code()]
        )?;
        if self.flags().is_extended_length() {
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
    use crate::bgp::message::nlri::Nlri;
    use crate::bgp::message::update::NextHop;

    #[test]
    fn wireformat_to_owned_and_back() {
        use super::PathAttribute as PA;
        fn check(raw: Vec<u8>, owned: PathAttribute) {
            let mut parser = Parser::from_ref(&raw);
            let sc = SessionConfig::modern();
            let pa = WireformatPathAttribute::parse(&mut parser, sc)
                .unwrap();
            assert_eq!(owned, pa.to_owned().unwrap());
            let mut target = Vec::new();
            owned.compose(&mut target).unwrap();
            assert_eq!(target, raw);
        }

        check(vec![0x40, 0x01, 0x01, 0x00], PA::Origin(Origin::new(0.into())));

        check(
            vec![0x40, 0x02, 10,
            0x02, 0x02, // SEQUENCE of length 2
            0x00, 0x00, 0x00, 100,
            0x00, 0x00, 0x00, 200,
            ],
            PA::AsPath(AsPath(HopPath::from(vec![
                Asn::from_u32(100),
                Asn::from_u32(200)]
            )))
        );

        check(
            vec![0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04],
            PA::NextHop(NextHop("1.2.3.4".parse().unwrap()))
        );

        check(
            vec![0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff],
            PA::MultiExitDisc(MultiExitDisc::new(255))
        );

        check(
            vec![0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x0a],
            PA::LocalPref(LocalPref::new(10))
        );

        check(
            vec![0x40, 0x06, 0x00],
            PA::AtomicAggregate(AtomicAggregate::new(()))
        );
        
        check(
            vec![
                0xc0, 0x07, 0x08, 0x00, 0x00, 0x00, 0x65, 0xc6,
                0x33, 0x64, 0x01
            ],
            PA::Aggregator(Aggregator(AggregatorInfo::new(
                    Asn::from_u32(101),
                    "198.51.100.1".parse().unwrap()
            )))
        );

        check(
            vec![
                0xc0, 0x08, 0x10, 0x00, 0x2a, 0x02, 0x06, 0xff,
                0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x02, 0xff,
                0xff, 0xff, 0x03
            ],
            {
                let mut builder = StandardCommunitiesBuilder::new();
                builder.add_community("AS42:518".parse().unwrap());
                builder.add_community(Wellknown::NoExport.into());
                builder.add_community(Wellknown::NoAdvertise.into());
                builder.add_community(Wellknown::NoExportSubconfed.into());
                PA::Communities(Communities(builder))
            }
        );

        check(
            vec![0x80, 0x09, 0x04, 0x0a, 0x00, 0x00, 0x04],
            OriginatorId("10.0.0.4".parse().unwrap()).into()
        );

        check(
            vec![0x80, 0x0a, 0x04, 0x0a, 0x00, 0x00, 0x03],
            ClusterList(ClusterIds::new(
                    vec![[10, 0, 0, 3].into()]
            )).into()
        );
        
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
            let mut builder = MpReachNlriBuilder::new(
                AFI::Ipv6,
                SAFI::Unicast,
                NextHop::Unicast("2001:db8::1234".parse().unwrap()),
                false // no addpath
            );
            builder.add_announcement(
                &Nlri::unicast_from_str("2001:db8:aabb::/48").unwrap()
            );

            MpReachNlri(builder).into()
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
                use crate::addr::Prefix;
                use std::str::FromStr;
            let mut builder = MpUnreachNlriBuilder::new(
                AFI::Ipv6,
                SAFI::Multicast,
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

            MpUnreachNlri(builder).into()
            }
        );

        check(
            vec![
                0xc0, 0x10, 0x08, 0x00, 0x02, 0xfc, 0x85, 0x00,
                0x00, 0xcf, 0x08
            ],
            ExtendedCommunities(ExtendedCommunitiesList::new(vec![
                "rt:64645:53000".parse().unwrap()
            ])).into()
        );

        check(
            vec![
                0xc0, 0x11, 10,
                0x02, 0x02, // SEQUENCE of length 2
                0x00, 0x00, 0x00, 100,
                0x00, 0x00, 0x00, 200,
            ],
            PA::As4Path(As4Path::new(HopPath::from(vec![
                Asn::from_u32(100),
                Asn::from_u32(200)]
            )))
        );

        check(
            vec![
                0xc0, 0x12, 0x08, 0x00, 0x00, 0x04, 0xd2,
                10, 0, 0, 99
            ],
            As4Aggregator(AggregatorInfo::new(
                Asn::from_u32(1234),
                "10.0.0.99".parse().unwrap()
            )).into()
        );

        check(
            vec![0xc0, 0x14, 0x04, 1, 2, 3, 4],
            Connector("1.2.3.4".parse().unwrap()).into()
        );

        check(
            vec![0xc0, 0x15, 0x05, 0x14, 0x00, 0x00, 0x04, 0xd2],
            AsPathLimit(
                AsPathLimitInfo::new(20, Asn::from_u32(1234))
            ).into()
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
            LargeCommunities(LargeCommunitiesList::new(
                vec![
                    "AS8283:6:15".parse().unwrap(),
                    "AS57866:100:2914".parse().unwrap(),
                    "AS57866:101:100".parse().unwrap(),
                    "AS57866:103:1".parse().unwrap(),
                    "AS57866:104:31".parse().unwrap(),
                ]
            )).into()
        );

        check(
            vec![0xc0, 0x23, 0x04, 0x00, 0x00, 0x04, 0xd2],
            Otc::new(Asn::from_u32(1234)).into()
        );

        // TODO AttrSet
        // TODO Reserved?

        // UnimplementedPathAttribute
        check(
            vec![0xc0, 254, 0x04, 0x01, 0x02, 0x03, 0x04],
            UnimplementedPathAttribute::new(
                Flags::OPT_TRANS.into(),
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
            Parser::from_ref(&raw), SessionConfig::modern()
        );
        //for _ in 0..4 {
        //    let pa = pas.next();
        //    println!("{pa:?}");
        //}

        assert!(pas.get(PathAttributeType::Origin).is_some());
        assert!(pas.get(PathAttributeType::AsPath).is_none());
        assert!(pas.get(PathAttributeType::MultiExitDisc).is_some());
        assert!(pas.get(PathAttributeType::NextHop).is_some());
    }

    #[test]
    fn unimplemented_path_attributes() {
        let raw = vec![
            0xc0, 254, 0x04, 0x01, 0x02, 0x03, 0x04
        ];
        let mut parser = Parser::from_ref(&raw);
        let sc = SessionConfig::modern();
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
                &mut parser, SessionConfig::modern()
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
            &mut Parser::from_ref(&raw), SessionConfig::modern()
        ).unwrap();
        let mut owned = pa.to_owned().unwrap();
        if let PathAttribute::AsPath(ref mut asp) = owned  {
            assert_eq!(format!("{}", asp.as_ref()), "AS100 AS200");
            asp.as_mut().prepend(Asn::from_u32(50));
            assert_eq!(format!("{}", asp.as_ref()), "AS50 AS100 AS200");
            assert_eq!(3, asp.as_ref().hop_count());
        }

        let mut composed = Vec::new();
        owned.compose(&mut composed).unwrap();
        assert!(composed != raw);
    }

}
