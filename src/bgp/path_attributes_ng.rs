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
//! 
//! Open issues:
//! - we need to pass 'PduParseInfo' kind of stuff around, e.g. 2 vs 4 byte
//!   ASNs
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

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
use crate::typeenum;

use super::message::PduParseInfo;


//#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
//pub enum PathAttributeType {
//    Origin = 1,
//    Communities = 8,
//}

typeenum!(
    PathAttributeType, u8,
    {
        1 => Origin,
        2 => AsPath,
        8 => Communities,
    }
);

#[derive(Debug, PartialEq)]
pub struct Origin(pub u8);

#[derive(Debug)]
pub struct AsPath<T: AsRef<[u8]>> {
    four_byte_asns: bool,
    pub raw: T
}


#[derive(Debug, PartialEq)]
pub struct Communities<T: AsRef<[u8]>>(pub T);

#[derive(Copy, Clone, Debug)]
pub struct Community(u32);

#[derive(Clone, Debug)]
pub struct OwnedCommunities(pub Vec<Community>);

impl OwnedCommunities {
    pub fn foo(&mut self) -> usize {
        self.0.push(Community(12));
        12
    }
}

pub struct PathAttributes<T: AsRef<[u8]>>{
    ppi: PduParseInfo,
    raw: T,
}

pub struct PathAttributesIter<'a, T: 'a + AsRef<[u8]>> {
    raw_attributes: &'a PathAttributes<T>,
    idx: usize,
}

#[derive(Copy, Clone, Debug)]
pub struct RawAttribute<T: AsRef<[u8]>> {
    raw: T
}

impl<T: AsRef<[u8]>> RawAttribute<T> {
    pub fn flags(&self) -> u8 {
        self.raw.as_ref()[0]
    }
    pub fn type_code(&self) -> PathAttributeType {
        self.raw.as_ref()[1].into()
    }
    pub fn length(&self) -> usize {
        usize::from(self.raw.as_ref()[2])
    }

    pub fn value(&self) -> &[u8] {
        &self.raw.as_ref()[3..] // FIXME shortcut, len can be 2 bytes
    }
}

impl<'a> RawAttribute<&'a [u8]> {
    pub fn into_value(self) -> &'a [u8] {
        &self.raw[3..]
    }
}

impl<'a, T: 'a + AsRef<[u8]>> Iterator for PathAttributesIter<'a, T> {
    type Item = RawAttribute<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == self.raw_attributes.raw.as_ref().len() {
            return None
        }
        let raw = &self.raw_attributes.raw.as_ref()[self.idx..];
        let _flags = raw[0];
        // TODO get actual len, might be 2 bytes
        let _type_code = raw[1];
        let len: usize = raw[2].into();
        let res = &raw[..3+len];
        self.idx += 3 + len;
        Some(RawAttribute{raw: res})
    }    
}

impl<'a, T: 'a + AsRef<[u8]>> PathAttributes<T> {
    
    pub fn new(raw: T) -> Self {
        Self {
            ppi: PduParseInfo::modern(),
            raw
        }
        
    }
    
    pub fn get<PA: 'a + Wireformat<'a>>(&'a self) -> Option<PA> {
        self.get_by_type_code(PA::TYPECODE).and_then(|raw|
            PA::try_from(raw).ok()
        )
    }

    pub fn get_or_raw<PA: 'a + Wireformat<'a>>(&'a self) -> Option<Result<PA, PA::Error>> {
        self.get_by_type_code(PA::TYPECODE).map(|raw|
            PA::try_from(raw)
        )
    }
    
    pub fn get_by_type_code(&'a self, type_code: impl Into<PathAttributeType>) -> Option<RawAttribute<&'a [u8]>> {
        let type_code = type_code.into();
        self.iter().find(|raw| raw.type_code() == type_code) 
    }

    pub fn iter(&self) -> PathAttributesIter<T> {
        PathAttributesIter {
            raw_attributes: self,
            idx: 0
        }
    }

    pub fn validate(&self) -> bool {
        self.iter().all(|raw|{
            match raw.type_code() {
                PathAttributeType::Origin => Origin::try_from(raw).is_ok(),
                PathAttributeType::AsPath => AsPath::try_from(raw).is_ok(),
                PathAttributeType::Communities => Communities::try_from(raw).is_ok(),
                PathAttributeType::Unimplemented(_) => false, // TODO maybe
                                                              // true
                                                              // depending on
                                                              // strictnesslevel
            }
        })
    }
}

impl<'a> TryFrom<RawAttribute<&'a[u8]>> for Origin {
    type Error = (RawAttribute<&'a[u8]>, &'static str);

    fn try_from(raw: RawAttribute<&'a[u8]>) -> Result<Self, Self::Error> {
        if raw.length() != 1 {
            return Err((raw, "wrong length for Origin"));
        }
        Ok(Origin(raw.value()[0]))
    }
}

impl<'a> TryFrom<RawAttribute<&'a[u8]>> for AsPath<&'a [u8]> {
    type Error = (RawAttribute<&'a[u8]>, &'static str);

    fn try_from(raw: RawAttribute<&'a[u8]>) -> Result<Self, Self::Error> {
        Ok(AsPath{four_byte_asns: true, raw: raw.into_value()})
    }
}

impl<'a> TryFrom<RawAttribute<&'a [u8]>> for Communities<&'a [u8]> {
    type Error = &'static str;

    fn try_from(raw: RawAttribute<&'a [u8]>) -> Result<Self, Self::Error> {
        if raw.length() % 4 != 0 {
            return Err("invalid length for Communities");
        }
        Ok(Communities(raw.into_value()))
    }
}


pub trait Wireformat<'a> : TryFrom<RawAttribute<&'a [u8]>> {
    const TYPECODE: u8; // or PathAttributeType ?
    //const FLAGS;
    type Owned;
    
    //fn parse<T: AsRef<[u8]>>(p: T) -> Result<Self, MyError> where Self:  Sized;
    fn parse(p: &'a [u8]) -> Result<Self, MyError> where Self:  'a + Sized;
    
    fn parse_owned(p: impl AsRef<[u8]>) -> Result<Self::Owned, MyError>;

}

trait ComposeAttribute {
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
    fn compose(&self, target: &mut Vec<u8>) -> Result<(), MyError>;
    
    /*
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
    */
}

impl Wireformat<'_> for Origin {
    const TYPECODE: u8 = 1;
    type Owned = Self;
    
    fn parse(p: &[u8]) -> Result<Self, MyError> {
        Ok(Self(*p.as_ref().get(0).unwrap()))
    }

    fn parse_owned(_p: impl AsRef<[u8]>) -> Result<Self::Owned, MyError> {
        todo!()
    }
    
    //fn parse_owned(p: impl AsRef<[u8]>) -> Result<Self::Owned, MyError> {
    //    Self::parse(p)
    //}
}


impl<'a> Wireformat<'a> for Communities<&'a [u8]> {
    const TYPECODE: u8 = 8;
    type Owned = OwnedCommunities;
    
    fn parse(p: &'a [u8]) -> Result<Communities<&'a [u8]>, MyError> {
        if p.as_ref().len() % 4 != 0 {
            return Err(MyError);
        }
        Ok(Communities(p))
        //Ok(Communities(p))
        //todo!()
    }
    
    fn parse_owned(_p: impl AsRef<[u8]>) -> Result<Self::Owned, MyError> {
        todo!()
        //Ok(
        //    OwnedCommunities(
        //        p.as_ref()[0..4].iter()
        //        .map(|b| Community(*b))
        //        .collect::<Vec<_>>()
        //    )
        //)
    }
}


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

        let attributes = PathAttributes::new(&raw);
        assert_eq!(attributes.iter().count(), 2);

        let attributes = PathAttributes::new(&raw[..]);
        assert_eq!(attributes.iter().count(), 2);

        let attributes = PathAttributes::new(bytes::Bytes::copy_from_slice(&raw[..]));
        assert_eq!(attributes.iter().count(), 2);

        let attributes = PathAttributes::new(raw);
        assert_eq!(attributes.iter().count(), 2);

        assert_eq!(attributes.get::<Origin>(), Some(Origin(1)));
        //assert_eq!(attributes.get::<Communities>(), Some(TODO));
    }

    #[test]
    fn parse_origin() {
        let raw = vec![0, 1, 1, 1];
        let raw_attr = RawAttribute{raw: &raw};
        assert_eq!(raw_attr.type_code(), Origin::TYPECODE.into());
        let origin = Origin::parse(raw_attr.value()).unwrap();
        assert_eq!(origin, Origin(1));
    }

    #[test]
    fn origin_invalid_length() {
        let raw = vec![0, 1, 2, 1, 2]; // Origin with length 2 is invalid
        let pas = PathAttributes::new(&raw);
        if let Some(Err((_attr, _e))) = pas.get_or_raw::<Origin>() {

        } else {
            panic!()
        }
    }

}
