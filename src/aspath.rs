//! AS Path generic over Octets
//!
//! Using Hop etc etc

use crate::asn::Asn;
use octseq::{Octets, Parser};
use std::{error, fmt};


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SegmentType {
    Set,
    Sequence,
    ConfedSequence,
    ConfedSet,
}

//--- TryFrom and From

impl TryFrom<u8> for SegmentType {
    type Error = InvalidSegmentTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SegmentType::Set),
            2 => Ok(SegmentType::Sequence),
            3 => Ok(SegmentType::ConfedSequence),
            4 => Ok(SegmentType::ConfedSet),
            _ => Err(InvalidSegmentTypeError)
        }
    }
}

impl From<SegmentType> for u8 {
    fn from(value: SegmentType) -> u8 {
        match value {
            SegmentType::Set => 1,
            SegmentType::Sequence => 2,
            SegmentType::ConfedSequence => 3,
            SegmentType::ConfedSet => 4,
        }
    }
}

#[derive(Debug)]
pub struct Segment<'a, Octs> {
    stype: SegmentType,
    parser: Parser<'a, Octs>,
}

#[derive(Debug)]
pub enum Hop<'a, Octs> {
    Asn(Asn),
    Segment(Segment<'a, Octs>),
}


pub struct Path<Octets> {
    octets: Octets,
}

impl <'a, Octs: Octets>Path<Octs> {
    pub fn iter(&'a self) -> PathIterator<'a, Octs> {
        let parser = Parser::from_ref(&self.octets);
        PathIterator { segments: SegmentIterator { parser }, current: None }
    }
}

//--- PathIterator -----------------------------------------------------------
/// Iterators over `Hop`s in a Path.
pub struct PathIterator<'a, Octs> {
    segments: SegmentIterator<'a, Octs>,
    current: Option<AsnIterator<'a, Octs>>,
}

impl<'a, Octs: Octets> Iterator for PathIterator<'a, Octs> {
    type Item = Hop<'a, Octs>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(sequence) = &mut self.current {
            if let Some(asn) = sequence.next() {
                return Some(Hop::Asn(asn))
            }
            self.current = None
        }
        if let Some(seg) = self.segments.next() {
            if seg.stype == SegmentType::Sequence {
                let mut asn_iter = seg.into_iter();
                if let Some(asn) = asn_iter.next() {
                    self.current = Some(asn_iter);
                    return Some(Hop::Asn(asn))
                } else {
                    return None
                }
            } else {
                return Some(Hop::Segment(seg))
            }
        }


        None
    }
}

//--- SegmentIterator --------------------------------------------------------
/// Iterates over Segments in a Path.
pub struct SegmentIterator<'a, Octs> {
    parser: Parser<'a, Octs>
}

impl<'a, Octs: Octets> Iterator for SegmentIterator<'a, Octs> {
    type Item = Segment<'a, Octs>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let stype = self.parser.parse_u8().expect("parsed before")
            .try_into().expect("illegally encoded AS path");

        let len = self.parser.parse_u8().expect("parsed before");
        // XXX 4 for 32bit ASNs, how can we support 16bit ASNs nicely?
        let parser = self.parser.parse_parser(len as usize * 4).expect("parsed before");
        Some(Segment { stype, parser } )
    }
}

/// Iterates over ASNs in a Segment.
pub struct AsnIterator<'a, Octs> {
    parser: Parser<'a, Octs>
}

impl<'a, Octs: Octets> Iterator for AsnIterator<'a, Octs> {
    type Item = Asn;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        let n = self.parser.parse_u32().expect("parsed before");
        Some(Asn::from(n))
    }
}

impl<'a, Octs: Octets> IntoIterator for Segment<'a, Octs> {
    type Item = Asn;
    type IntoIter = AsnIterator<'a, Octs>;
    fn into_iter(self) -> Self::IntoIter {
        AsnIterator { parser: self.parser }
    }
}


//--- Building / composing ---------------------------------------------------


pub struct PathBuilder {
    //hops: Vec<Hop<Vec<u8>>>,
}


/*
/// A segment of an AS path.
#[derive(Debug, Clone, Copy)]
pub struct PathSegment<Octs> {
    /// The type of the path segment.
    stype: SegmentType,

    /// The elements of the path segment.
    octets: Octs,
}



pub enum Hop<Octs> {
    Asn(Asn),
    Segment(PathSegment(Octs)),
}


pub struct AsPathBuilder {
    hops: Vec<Hop<Vec<u8>>,
}

impl AsPathBuilder {
    pub fn append(&mut self, hop: Hop<Vec<u8>>) {
	self.hops.append(hop);
    }

    pub fn append_asn(&mut self, asn: Asn) { }

    pub fn append_set(&mut self, set: impl IntoIterator<Item = Asn>) {
        self.append(Hop::Segment(PathSegment::new_set(set)))
    }

    pub fn to_path<Octs>(
        &self
    ) -> Result<
        AsPath<Octs>,
         <<Octs as FromBuilder> as OctetsBuilder>::AppendError
    >
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
    {
        let mut target = EmptyBuilder::empty();
        self.compose(&mut target);
        Ok(unsafe { AsPath::from_octets_unchecked(Octs::from_builder(target)) })
    }

    pub fn compose<Target: OctetsBuilder>(
        impl Iterator<Hop>", target: &mut Target
    ) -> Result<(), Target::AppendError> {
    }
}


impl<Octs> AsPath<Octs> {
    pub fn from_hops<H>(hops: H) -> Result<Self, <....>::AppendError>
    where ALL THE THINGS
    {
    }
}



prepend_n repeat n chain existing iterator
prepend_n move self
nostd:
olny use traits from OctSeq for all the building things
cant use a vec

*/


//============ Error Types ===================================================

//------------ InvalidSegmentTypeError ---------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct InvalidSegmentTypeError;

impl fmt::Display for InvalidSegmentTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid segment type")
    }
}

impl error::Error for InvalidSegmentTypeError { }



mod tests {
    use super::*;

    #[test]
    fn path_iter() {
        // AS path comprised of a single segment:
        // AS_SEQUENCE(AS2027, AS35280, AS263903, AS271373)
        let raw = vec![
            0x02, 0x04, 0x00, 0x00, 0x07, 0xeb, 0x00, 0x00,
            0x89, 0xd0, 0x00, 0x04, 0x06, 0xdf, 0x00, 0x04,
            0x24, 0x0d
        ];

        let path = Path{ octets: &raw };
        for hop in path.iter() {
            println!("{hop:?}");
        }
    }

    #[test]
    fn path_iter_with_set() {
        //AS_SEQUENCE(AS6447, AS38880, AS9002, AS12956, AS22927), 
        //  AS_SET(AS52367, AS262175, AS264810, AS267786)
        let raw = vec![
            0x02, 0x05, 0x00, 0x00,
            0x19, 0x2f, 0x00, 0x00, 0x97, 0xe0, 0x00, 0x00,
            0x23, 0x2a, 0x00, 0x00, 0x32, 0x9c, 0x00, 0x00,
            0x59, 0x8f, 0x01, 0x04, 0x00, 0x00, 0xcc, 0x8f,
            0x00, 0x04, 0x00, 0x1f, 0x00, 0x04, 0x0a, 0x6a,
            0x00, 0x04, 0x16, 0x0a
        ];

        let path = Path{ octets: &raw };
        for hop in path.iter() {
            println!("{hop:?}");
        }
    }
}
