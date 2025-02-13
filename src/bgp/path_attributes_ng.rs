//! Path Attributes, revised, once again
//!
//! Yet another attempt at doing Path Attributes in a nice way. This attempt
//! is designed around the following requirements, observations and lessons
//! learned:
//! - we want typed getters, a la attributes.get::<Communities>() 
//! - all attribute types have an immutable, non-allocating wireformat version
//! - and, a mutable, possibly allocating associated type
//! - perhaps for some, it makes sense to introduce Cow variants at some point
//! - everything is based on a PathAttributes blob, implementating Iterator,
//!   yielding `RawAttribute`s. For attribute types we support,
//!   TryFrom<RawAttribute> is implemented and serves as the 'parser'.
//! - we do not want Cow on the immutable vs mutable level, because that
//!   introduces an enum match for every single action while we probably do
//!   99% read actions on immutable attributes.
//! - maybe we want to multiple types of getters:
//!     - one returning Option<T> 
//!     - one returning Option<Result<T, RawAttribute<_>>
//!       the first one returns None in case of a parse fail, the latter
//!       returns the raw attribute that apparently had the typecode of the
//!       requested thing, but is somehow considered invalid. the caller can
//!       then decide what to do with it. And we can make a 'verify all
//!       attributes' method based on it.
//! - From the perspective of an UPDATE PDU, the path attributes need to be
//!   'split up' for the explosion into MP announcements, MP withdrawals, and
//!   the conventional announcements/withdrawals:
//!     - the explosion returns 'nlri -> (nexthop + path attributes)' in case
//!       of announcements, or only 'nlri' in case of withdrawals
//!     - as such, NEXT_HOP, MP_REACH_NLRI and UNREACH should be removed from
//!       the attributes in all cases
//!     - note that there is ongoing IDR work on a thing call 'MultiNexthop'
//!     - note that the nexthop for MP is part of MP_REACH_NLRI, 
//! - For stateful parsing, we have
//!     - 2 vs 4 byte asns (known at start of UPDATE PDU parsing). Used in
//!         - AS_PATH
//!         - AggregatorInfo
//!     - addpath (per address family, so for MP we only know whether to
//!       expect PathIds once we actually parse the MP attributes. For
//!       conventional v4, we 'know upfront' so to speak)
//!     - multi label: pertains to (MPLS) labels on NLRI, for Labeled address
//!       families (1/4 and 2/4, perhaps others). So, presumably quite exotic
//!       in global routing. 
//! - Would it make sense to make AsPath generic over TwoByte vs FourByte, and
//!   perhaps even FourByteSingleSequence (as that will be 99.99% of observed
//!   paths)? That enables efficient .origin_as() and .peer_as(), and
//!   .path_length().
//!
//! - wrt Validation:
//!   - on the PathAttributes level, check whether all individual lengths add
//!     up
//!   - on the Wireformat level (RawAttributes TryInto proper types), check
//!     length to create the proper type, i.e. a MED must have length 4. But
//!     no content checks
//!   - on the proper type, perhaps via a trait, implement content-level
//!     checks. e.g. on AsPath, check length of segments etc. On
//!     MP_REACH_NLRI, check afi/safi, next hop, jump over all NLRI lengths
//!   - perhaps let the call to .validate return a new (associated) type,
//!     ValidatedAsPath, ValidatedMpReachNlri etc.?
//! 
//! Open issues:
//! - similarly, we want to pass a 'StrictnessLevel' around
//!     - should this be on the PathAttributes (iterator) level, or on an
//!       individual level?
//! - perhaps on the iterator level it allows for more flexible recovery, i.e.
//!   one can attempt to iterate again with a different level / ppi
//! - similar to the Cow enum, maybe we want to make the StrictnessLevel a
//!   full type instead of matching on it in runtime
//!
//!
#![allow(dead_code)]

use core::ops::Range;
use std::borrow::Cow;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
use crate::typeenum;

use super::message::SessionConfig;

typeenum!(
    PathAttributeType, u8,
    {
        1 => Origin,
        2 => AsPath,
        8 => Communities,
        14 => MpReachNlri,
    }
);

/// Marker trait to ensure nothing is missing at compile time
/// XXX is this helpful or just cumbersome? We need multiple markings for e.g.
/// AsPath, as that has two possible ASLs
//pub trait PathAttribute<'a, ASL>: Wireformat<'a> + TryFromRaw<'a, ASL> + Validate { }
//impl<'a, ASL> PathAttribute<'a, ASL> for Origin { }
//impl<'a> PathAttribute<'a, FourByteAsns> for AsPath<&'a [u8]> { }

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Origin(pub u8);


#[derive(Debug)]
pub struct AsPath<ASL, T: AsRef<[u8]>> {
    asn_length: std::marker::PhantomData<ASL>,
    pub raw: T
}

/// ASL marker type for 32bit ASNs;
#[derive(Copy, Clone, Debug, Hash, PartialEq)]
struct FourByteAsns;

/// ASL marker type for 16bit ASNs;
#[derive(Copy, Clone, Debug, Hash, PartialEq)]
struct TwoByteAsns;



#[derive(Debug, PartialEq)]
pub struct Communities<T: AsRef<[u8]>>(pub T);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Community(u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedCommunities(pub Vec<Community>);

impl OwnedCommunities {
    pub fn foo(&mut self) -> usize {
        self.0.push(Community(12));
        12
    }
}


#[derive(Debug, PartialEq)]
pub struct MpReachNlri<T: AsRef<[u8]>> {
    raw: T,
}


#[derive(Clone, Debug, PartialEq)]
pub struct PathAttributes<'sc, ASL, T: AsRef<[u8]>>{
    asl: std::marker::PhantomData::<ASL>,
    // XXX perhaps session_config should not live here
    // - 'stand alone path attributes' (i.e., stored in the store or on disk)
    //   will not include MP_REACH_NLRI, so no ADD_PATH or multilabel info is
    //   required for parsing
    // - this info is necessary at explosion time, where we have the full PDU
    //   at hand anyway, including session info.
    // - if we really want a stand alone owned version of things, a classic
    //   PduParseInfo (Copy) should suffice
    session_config: Cow<'sc, SessionConfig>,
    raw: T,
}

/// Overlay/cache over immutable PathAttributes
///
/// Allows for quick access without repetitively iterating over the entire
/// underlying blob of bytes.
///
/// TODO make sure PathAttributesOverlay can only be constructed over a
/// checked blob so we can safely unwrap based on the stored ranges.
///
/// XXX: Option<Range<usize>> vs Option<RawAttribute> vs Option<ProperType> ?
/// Perhaps this thing can double as a builder if we go Option<Cow<_>> ?
pub struct PathAttributesOverlay<'sc, ASL, T: AsRef<[u8]>> {
    path_attributes: PathAttributes<'sc, ASL, T>,
    origin: Option<Range<usize>>,
    as_path: Option<Range<usize>>,
    //...
    //...
    //...
    //...
    communities: Option<Range<usize>>,
}

impl<'sc, ASL, T: AsRef<[u8]>> PathAttributesOverlay<'sc, ASL, T> {
    fn raw(&self) -> &[u8] {
        self.path_attributes.raw.as_ref()
    }
    pub fn get<'a, PA: 'a + Wireformat<'a> + TryFromRaw<'a>>(&'a self) -> Option<PA> {
        match PathAttributeType::from(PA::TYPECODE) {
            PathAttributeType::Origin => self.origin.as_ref().map(|r| PA::try_from_raw(RawAttribute{raw: &self.raw()[r.start..r.end]}).unwrap()),
            PathAttributeType::AsPath => todo!(),
            PathAttributeType::Communities => todo!(),
            PathAttributeType::MpReachNlri => todo!(),
            PathAttributeType::Unimplemented(_) => todo!(),
        }
    }
    //pub fn get<Origin>(&self) -> Option<Origin> {
    //    None
    //}
    //pub fn get<AsPath>(&self) -> Option<AsPath> {
    //    None
    //}
}

impl<'sc, ASL, T: AsRef<[u8]>> PathAttributesOverlay<'sc, ASL, T> {
    //pub fn get<AsPath>(&self) -> Option<AsPath> {
    //    None
    //}
}

impl<'sc, ASL, T: AsRef<[u8]>> PathAttributes<'sc, ASL, T> {
    pub fn owned(&self) -> PathAttributes<'sc, ASL, Vec<u8>> {
        PathAttributes {
            asl: std::marker::PhantomData::<ASL>,
            session_config: self.session_config.to_owned(),
            raw: self.raw.as_ref().to_vec()
        }
    }
}

impl<'sc, ASL, T: AsRef<[u8]>> From<PathAttributes<'sc, ASL, T>> for Vec<u8> {
    fn from(pas: PathAttributes<'sc, ASL, T>) -> Self {
        pas.raw.as_ref().to_vec()
    }
}
impl<'sc, ASL> From<Vec<u8>> for PathAttributes<'sc, ASL, Vec<u8>> {
    fn from(raw: Vec<u8>) -> Self {
        PathAttributes {
            asl: std::marker::PhantomData::<ASL>,
            session_config: Cow::Owned(SessionConfig::modern()),
            raw
        }
    }
}

impl<'sc> PathAttributes<'sc, FourByteAsns, Vec<u8>> {

    pub fn modern() -> Self {
        PathAttributes {
            asl: std::marker::PhantomData::<FourByteAsns>,
            session_config: Cow::Owned(SessionConfig::modern()),
            raw: Vec::new()
        }
    }
}

impl<'sc, ASL> PathAttributes<'sc, ASL, Vec<u8>> {

    pub fn append<PA: ToWireformat>(&mut self, pa: PA) {
        pa.write(&mut self.raw);
    }
}


pub struct PathAttributesIter<'a, 'sc, ASL, T: 'a + AsRef<[u8]>> {
    raw_attributes: &'a PathAttributes<'sc, ASL, T>,
    idx: usize,
}

#[derive(Copy, Clone, Debug)]
pub struct RawAttribute<T: AsRef<[u8]>> {
    raw: T
}

impl<T: AsRef<[u8]>> RawAttribute<T> {
    pub fn flags(&self) -> super::path_attributes::Flags {
        self.raw.as_ref()[0].into()
    }
    pub fn type_code(&self) -> PathAttributeType {
        self.raw.as_ref()[1].into()
    }

    pub fn length(&self) -> usize {
        if self.flags().is_extended_length() {
            usize::from(
                u16::from_be_bytes(
                    [self.raw.as_ref()[2], self.raw.as_ref()[3]]
                )
            )
        } else {
            usize::from(self.raw.as_ref()[2])
        }
    }

    pub fn value(&self) -> &[u8] {
        if self.flags().is_extended_length() {
            &self.raw.as_ref()[4..] 
        } else {
            &self.raw.as_ref()[3..] 
        }
    }
}

impl<'a> RawAttribute<&'a [u8]> {
    pub fn into_value(self) -> &'a [u8] {
        if self.flags().is_extended_length() {
            &self.raw[4..] 
        } else {
            &self.raw[3..] 
        }
    }
}

impl<'a, 'sc, ASL, T: 'a + AsRef<[u8]>> Iterator for PathAttributesIter<'a, 'sc, ASL, T> {
    type Item = RawAttribute<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == self.raw_attributes.raw.as_ref().len() {
            return None
        }
        if self.idx + 3 > self.raw_attributes.raw.as_ref().len() {
            // XXX: incomplete path attribute. fuse and, somehow, error?
            return None
        }
        let raw = &self.raw_attributes.raw.as_ref()[self.idx..];

        let flags = super::path_attributes::Flags::from(raw[0]);
        //let _type_code = raw[1];

        let (len, offset): (usize, usize) = if flags.is_extended_length() {
            if raw.len() < 4 {
                return None; // XXX same as above
            }
            (u16::from_be_bytes([raw[2], raw[3]]).into(), 4)
        } else {
            (raw[2].into(), 3)
        };
        let res = &raw[..offset+len];
        self.idx += offset + len;
        Some(RawAttribute{raw: res})
    }    
}

impl<'a, T: AsRef<[u8]>> PathAttributes<'a, FourByteAsns, T> {
    pub fn new(raw: T, session_config: &'a SessionConfig) -> Self {
        Self {
            asl: std::marker::PhantomData,
            session_config: Cow::Borrowed(session_config),
            raw
        }
        
    }
}
impl<'a, T: AsRef<[u8]>> PathAttributes<'a, TwoByteAsns, T> {
    pub fn legacy(raw: T, session_config: &'a SessionConfig) -> Self {
        Self {
            asl: std::marker::PhantomData,
            session_config: Cow::Borrowed(session_config),
            raw
        }
        
    }
}

impl<'a, 'sc, ASL, T: 'a + AsRef<[u8]>> PathAttributes<'sc, ASL, T> {
    pub fn iter(&self) -> PathAttributesIter<ASL, T> {
        PathAttributesIter {
            raw_attributes: self,
            idx: 0
        }
    }
    pub fn get_by_type_code(&'a self, type_code: impl Into<PathAttributeType>) -> Option<RawAttribute<&'a [u8]>> {
        let type_code = type_code.into();
        self.iter().find(|raw| raw.type_code() == type_code) 
    }

    // XXX can we return a PathAttributes<Cow<[u8]>> here?
    // that way, multiple calls to this method are cheap / no-op.
    // Not sure whether that's actually worth it...
    //
    // And ideally, we can specify an order, e.g. by typecode.
    pub fn pure_mp_attributes(&self) -> Option<PathAttributes<'sc, ASL, Vec<u8>>> {
        self.get_by_type_code(MpReachNlri::TYPECODE)?;
        
        let mut res = Vec::with_capacity(self.raw.as_ref().len());
        for pa in self.iter() {
            match pa.type_code() {
                PathAttributeType::MpReachNlri => continue, // TODO or NEXT_HOP, or UnReach
                _ => res.extend_from_slice(pa.raw)
            }
        }
        Some(PathAttributes {
            asl: std::marker::PhantomData,
            session_config: self.session_config.clone(),
            raw: res
        })
    }
}

impl<'a, T: 'a + AsRef<[u8]>> PathAttributes<'_, FourByteAsns, T> {
    pub fn get_aspath(&'a self) -> Option<AsPath<FourByteAsns, &'a [u8]>> {
        self.get_by_type_code(PathAttributeType::AsPath).and_then(|raw|
            AsPath::<FourByteAsns, &[u8]>::try_from_raw(raw).ok()
        )
    }
}

impl<'a, ASL, T: 'a + AsRef<[u8]>> PathAttributes<'_, ASL, T> {
    /// Returns `Some(PA)` if it exists and is valid, otherwise returns None.
    pub fn get_lossy<PA: 'a + Wireformat<'a> + TryFromRaw<'a>>(&'a self) -> Option<PA> {
        self.get_by_type_code(PA::TYPECODE).and_then(|raw|
            PA::try_from_raw(raw).ok()
        )
    }
    /// Returns the (possibly invalid) PA, if it exists.
    pub fn get<PA: 'a + Wireformat<'a> + TryFromRaw<'a>>(&'a self) -> Option<Result<PA, RawError<'a>>> {
        self.get_by_type_code(PA::TYPECODE).map(|raw|
            PA::try_from_raw(raw)
        )
    }
}

//------------ Test with fake Update msg --------------------------------------

struct UpdateMsg<'a, 'sc, ASL, T: 'a + AsRef<[u8]>> {
    path_attributes: PathAttributes<'a, ASL, T>,
    session_config: &'sc SessionConfig,
}

impl <'a, 'sc, ASL, T: AsRef<[u8]>> UpdateMsg<'a, 'sc, ASL, T> {
    pub fn path_attributes(&self) -> &PathAttributes<'a, ASL, T> {
        &self.path_attributes
    }

    pub fn mp_reach(&self) -> Option<Result<MpReachNlri<&[u8]>, Cow<'_, str>>> {
        self.path_attributes.get_lossy::<MpReachNlri<_>>().map(|mp|{
            mp.validate_with_session_config(
                ValidationLevel::Medium,
                self.session_config
            ).map_err(|e| e.1)
        })
    }

}

//-----------------------------------------------------------------------------


// This macro is called within the `match` in fn validate, so we can leverage
// the exhaustiveness check.
macro_rules! validate_match {
    ($raw:ident, $level:ident, $name:ident) => {
            $name::try_from_raw($raw).map(|a| a.validate($level)).is_ok()
    }
}

macro_rules! validate_for_asl {
    ($asl:ident) => {
    impl<'a, T: 'a + AsRef<[u8]>> PathAttributes<'a, $asl, T> {
        pub fn validate(&self, level: ValidationLevel) -> bool {
            use PathAttributeType as PAT;
            self.iter().all(|raw|{
                match raw.type_code() {
                    PAT::Origin => validate_match!(raw, level, Origin),
                    PAT::AsPath => AsPath::<$asl, &[u8]>::try_from_raw(raw).map(|a| a.validate(level)).is_ok(),
                    PAT::Communities => validate_match!(raw, level, Communities),
                    PAT::MpReachNlri => validate_match!(raw, level, MpReachNlri),
                    PAT::Unimplemented(_) => todo!(),
                }
            })
        }
    }
}
}

validate_for_asl!(TwoByteAsns);
validate_for_asl!(FourByteAsns);

pub type RawError<'a> = (RawAttribute<&'a[u8]>, Cow<'static, str>);

pub trait TryFromRaw<'a> : Sized {
    fn try_from_raw(raw: RawAttribute<&'a [u8]>) -> Result<Self, RawError<'a>>;
}

impl<'a> TryFromRaw<'a> for Origin {
    fn try_from_raw(raw: RawAttribute<&'a[u8]>) -> Result<Self, RawError<'a>> {
        if raw.length() != 1 {
            return Err((raw, "wrong length for Origin".into()));
        }

        Ok(Origin(raw.value()[0]))
    }
}


impl<'a> TryFromRaw<'a> for AsPath<TwoByteAsns, &'a [u8]> {
    fn try_from_raw(raw: RawAttribute<&'a [u8]>) -> Result<Self, RawError<'a>> {
        Ok(Self{asn_length: std::marker::PhantomData, raw: raw.into_value()})
    }
}
impl<'a> TryFromRaw<'a> for AsPath<FourByteAsns, &'a [u8]> {
    fn try_from_raw(raw: RawAttribute<&'a [u8]>) -> Result<Self, RawError<'a>> {
        Ok(Self{asn_length: std::marker::PhantomData, raw: raw.into_value()})
    }
}

impl<'a> TryFromRaw<'a> for Communities<&'a [u8]> {
    fn try_from_raw(raw: RawAttribute<&'a [u8]>) -> Result<Self, RawError<'a>> {
        if raw.length() % 4 != 0 {
            Err((raw, format!("invalid length {} for Communities", raw.length()).into()))?;
        }
        Ok(Communities(raw.into_value()))
    }
}

impl<'a> TryFromRaw<'a> for MpReachNlri<&'a [u8]> {
    fn try_from_raw(raw: RawAttribute<&'a [u8]>) -> Result<Self, RawError<'a>> {
        // Expected at least:
        // afi + safi == 2 + 1
        // nh len + v4 addr (or larger) == 1 + 4 
        // rsvd byte == 1
        // ---------------
        //              == 9
        if raw.length() < 9 {
            return Err((raw, "".into()));
        }

        Ok(MpReachNlri{raw: raw.into_value()})
    }
}


pub trait Wireformat<'a> {
    const TYPECODE: u8; // or PathAttributeType ?
    const FLAGS: u8;
    type Owned;
    
    fn owned(&self) -> Self::Owned;

}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValidationLevel {
    Minimal,
    Medium,
    Strict,
}

pub trait Validate: Sized {
    type Validated;

    fn validate(self, level: ValidationLevel)
        -> Result<Self::Validated, (Self, Cow<'static, str>)>;

    fn validate_with_session_config(
        self,
        level: ValidationLevel,
        _sc: &SessionConfig
    ) -> Result<Self::Validated, (Self, Cow<'static, str>)> {
            self.validate(level)
    }
}


impl Wireformat<'_> for Origin {
    const TYPECODE: u8 = 1;
    const FLAGS: u8 = super::path_attributes::Flags::WELLKNOWN;
    type Owned = Self;

    fn owned(&self) -> Self::Owned {
        *self
    }

}

impl Validate for Origin {
    type Validated = Self;

    fn validate(self, _level: ValidationLevel) -> Result<Self::Validated, (Self, Cow<'static, str>)> {
        if self.0 > 2 {
            return Err((self, "wrong value for Origin".into()));
        }
        Ok(self)
    }
}

impl<'a> Wireformat<'a> for AsPath<TwoByteAsns, &'a [u8]> {
    const TYPECODE: u8 = 2;
    const FLAGS: u8 = super::path_attributes::Flags::WELLKNOWN;

    type Owned = super::aspath::HopPath;

    fn owned(&self) -> Self::Owned {
        super::aspath::HopPath::new() // from two_bytes
    }
}
impl<'a> Wireformat<'a> for AsPath<FourByteAsns, &'a [u8]> {
    const TYPECODE: u8 = 2;
    const FLAGS: u8 = super::path_attributes::Flags::WELLKNOWN;

    type Owned = super::aspath::HopPath;

    fn owned(&self) -> Self::Owned {
        super::aspath::HopPath::new() // from four_bytes
    }
}

impl<'a> Validate for AsPath<TwoByteAsns, &'a[u8]> {
    type Validated = Self;

    fn validate(self, level: ValidationLevel)
        -> Result<Self::Validated, (Self, Cow<'static, str>)> {
        todo!()
    }

}

impl<'a> Validate for AsPath<FourByteAsns, &'a[u8]> {
    type Validated = Self;

    fn validate(self, level: ValidationLevel)
        -> Result<Self::Validated, (Self, Cow<'static, str>)> {
        todo!()
    }

}

impl<'a, T: 'a + AsRef<[u8]>> Wireformat<'a> for Communities<T> {
    const TYPECODE: u8 = 8;
    const FLAGS: u8 = super::path_attributes::Flags::OPT_TRANS;

    type Owned = OwnedCommunities;

    fn owned(&self) -> Self::Owned {
        OwnedCommunities(
            self.0.as_ref()
                .chunks_exact(4)
                .map(|c| Community(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
                .collect::<Vec<_>>()
        )
    }
}

impl<'a> Validate for Communities<&'a[u8]> {
    type Validated = Self;

    fn validate(self, level: ValidationLevel)
        -> Result<Self::Validated, (Self, Cow<'static, str>)> {
        todo!()
    }

    
}

impl<'a> Wireformat<'a> for MpReachNlri<&'a [u8]> {
    const TYPECODE: u8 = 14;
    const FLAGS: u8 = super::path_attributes::Flags::OPT_NON_TRANS;

    type Owned = bool; //super::message::update_builder::MpReachNlriBuilder;

    fn owned(&self) -> Self::Owned {
        todo!()
    }
}

impl<T: AsRef<[u8]>> Validate for MpReachNlri<T> {
    type Validated = Self;

    fn validate(self, level: ValidationLevel)
        -> Result<Self::Validated, (Self, Cow<'static, str>)> {
        todo!()
    }

}

//-----------------------------------------------------------------------------


pub trait ToWireformat {
    fn write(&self, dst: &mut Vec<u8>);
}

impl ToWireformat for Origin {
    fn write(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&[Self::FLAGS, Self::TYPECODE, 1, self.0]);
    }
}

//impl ToWireformat for Communities<&[u8]> {
//    fn write(&self, dst: &mut Vec<u8>) {
//        dst.extend_from_slice(&[Self::FLAGS, Self::TYPECODE, u8::try_from(self.0.len()).unwrap_or(u8::MAX)]);
//        dst.extend_from_slice(self.0);
//    }
//}

impl<T: AsRef<[u8]>> ToWireformat for Communities<T> {
    fn write(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&[Self::FLAGS, Self::TYPECODE, u8::try_from(self.0.as_ref().len()).unwrap_or(u8::MAX)]);
        dst.extend_from_slice(self.0.as_ref());
    }
}

impl ToWireformat for OwnedCommunities {
    fn write(&self, dst: &mut Vec<u8>) {
        let len = u8::try_from(self.0.len() * 4).unwrap_or(u8::MAX);
        dst.extend_from_slice(&[Communities::<&[u8]>::FLAGS, Communities::<&[u8]>::TYPECODE, len]);
        for c in &self.0 {
            dst.extend_from_slice(&c.0.to_be_bytes());
        }
    }
}

//trait ComposeAttribute {
//    fn compose_len(&self) -> usize {
//        self.header_len() + self.value_len()
//    }
//    
//    fn is_extended(&self) -> bool {
//        self.value_len() > 255
//    }
//    
//    fn header_len(&self) -> usize {
//        if self.is_extended() {
//            4
//        } else {
//            3
//        }
//    }
//    
//    fn value_len(&self) -> usize;
//    fn compose(&self, target: &mut Vec<u8>) -> Result<(), MyError>;
//    
//    /*
//    fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
//        -> Result<(), Target::AppendError>
//    {
//        self.compose_header(target)?;
//        self.compose_value(target)
//    }
//
//    
//    fn compose_header<Target: OctetsBuilder>(&self, target: &mut Target)
//        -> Result<(), Target::AppendError>
//    {
//        if self.is_extended() {
//            target.append_slice(&[
//                Self::FLAGS | Flags::EXTENDED_LEN,
//                Self::TYPE_CODE,
//            ])?;
//            target.append_slice(
//                &u16::try_from(self.value_len()).unwrap_or(u16::MAX)
//                .to_be_bytes()
//            )
//        } else {
//            target.append_slice(&[
//                Self::FLAGS,
//                Self::TYPE_CODE,
//                u8::try_from(self.value_len()).unwrap_or(u8::MAX)
//            ])
//        }
//    }
//    
//    fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
//        -> Result<(), Target::AppendError>;
//    */
//}


/*
impl ComposeAttribute for Origin {
    fn value_len(&self) -> usize {
        1
    }
    fn compose(&self, target: &mut Vec<u8>) -> Result<(), MyError> {
        target.push(self.0);
        Ok(())
    }
}

impl ComposeAttribute for Communities {
    fn value_len(&self) -> usize {
        self.0.len() * 4
    }
    fn compose(&self, target: &mut Vec<u8>) -> Result<(), MyError> {
        self.0.iter().for_each(|c| target.push(*c));
        Ok(())
    }
}

impl ComposeAttribute for OwnedCommunities {
    fn value_len(&self) -> usize {
        self.0.len() * 4
    }
    fn compose(&self, target: &mut Vec<u8>) -> Result<(), MyError> {
        self.0.iter().for_each(|c| target.push(c.0.to_be_bytes()[0]));
        Ok(())
    }
}
*/



#[derive(Debug)]
pub struct MyError;


//-----------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn first_go() {
        //let o = Origin(1);
        //let c1 = Communities(vec![1,2,3,4]);
        //let c2 = OwnedCommunities((1..4).map(Community).collect());
        //let mut output = Vec::new();
        //let _ = o.compose(&mut output);
        //let _ = c1.compose(&mut output);
        //let _ = c2.compose(&mut output);
        
        //let c2_2 = c1.into_owned();
        let raw = vec![
            0,1,1,  1,      // Origin
            0,8,4,  1,2,3,4 // Communities
        ];
        let sc = SessionConfig::modern();

        let attributes = PathAttributes::new(&raw, &sc);
        assert_eq!(attributes.iter().count(), 2);

        let attributes = PathAttributes::new(&raw[..], &sc);
        assert_eq!(attributes.iter().count(), 2);

        let attributes = PathAttributes::new(bytes::Bytes::copy_from_slice(&raw[..]), &sc);
        assert_eq!(attributes.iter().count(), 2);

        let attributes = PathAttributes::new(raw, &sc);
        assert_eq!(attributes.iter().count(), 2);

        assert_eq!(attributes.get_lossy::<Origin>(), Some(Origin(1)));
        assert!(attributes.get_lossy::<Communities<_>>().is_some());
    }

    #[test]
    fn origin_invalid_length() {
        let raw = vec![0, 1, 2, 1, 2]; // Origin with length 2 is invalid
        let sc = SessionConfig::modern();
        let pas = PathAttributes::new(&raw, &sc);
        if let Some(Err((_attr, _e))) = pas.get::<Origin>() {

        } else {
            panic!()
        }
    }


    #[test]
    fn aspath() {
        //single SEQUENCE
        let raw = vec![
            0, 2, 18,
        0x02, 0x04, 0x00, 0x00, 0x07, 0xeb, 0x00, 0x00,
        0x89, 0xd0, 0x00, 0x04, 0x06, 0xdf, 0x00, 0x04,
        0x24, 0x0d
        ];
        let sc = SessionConfig::modern();
        let attrs = PathAttributes::new(&raw, &sc);
        //let _asp = attrs.get_lossy::<AsPath>().unwrap();
        let _asp = attrs.get_aspath().unwrap();
    }

    #[test]
    fn full_cycle_wireformat() {
        let owned = OwnedCommunities(
            vec![Community(1), Community(2), Community(3)]
        );

        let mut raw = Vec::new();
        owned.write(&mut raw);

        let sc = SessionConfig::modern();
        let pas = PathAttributes::new(&raw, &sc);
        dbg!(&pas);
        assert_eq!(pas.iter().count(), 1);
        let comms = pas.get_lossy::<Communities<_>>().unwrap();
        let owned2 = comms.owned();
        assert_eq!(owned, owned2);


        let wireformat = &[
            0b1100_0000, 8, 12,
            0, 0, 0, 1,
            0, 0, 0, 2,
            0, 0, 0, 3,
        ];

        let pas2 = PathAttributes::new(&wireformat, &sc);
        assert_eq!(pas.owned(), pas2.owned());

        let comms2 = pas2.get_lossy::<Communities<_>>().unwrap();
        assert_eq!(comms, comms2);


        let owned_pas = pas2.owned();
        assert_eq!(owned_pas.iter().count(), 1);
    }


    #[test]
    fn from_into_vec_u8() {
        let mut pas = PathAttributes::modern();
        let comms = OwnedCommunities(
            vec![Community(1), Community(2), Community(3)]
        );
        pas.append(comms);

        let raw = Vec::<u8>::from(pas.clone());

        let pas_again = PathAttributes::<'_, FourByteAsns, _>::from(raw);
        assert_eq!(pas.owned(), pas_again.owned());

    }


}
