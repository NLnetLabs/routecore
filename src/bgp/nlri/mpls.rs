use inetnum::addr::Prefix;
use octseq::OctetsFrom;
use std::cmp;
use std::fmt;

use octseq::{Octets, OctetsBuilder, Parser};
use crate::util::parser::ParseError;
use super::common::{compose_prefix_without_len, parse_prefix_for_len, prefix_bits_to_bytes};
use super::afisafi::Afi;

/// NLRI comprised of a [`Prefix`] and MPLS `Labels`.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MplsNlri<Octs> {
    prefix: Prefix,
    labels: Labels<Octs>,
}

impl<O> MplsNlri<O> {
    pub fn new(prefix: Prefix, labels: Labels<O>) -> Self {
        Self { prefix, labels }
    }
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    pub fn labels(&self) -> &Labels<O> {
        &self.labels
    }
}

impl<Octs: Octets> MplsNlri<Octs> {
    pub fn parse<'a, R>( parser: &mut Parser<'a, R>,
        afi: Afi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let (prefix, labels) = parse_labels_prefix(parser, afi)?;
        Ok(
            MplsNlri::new(prefix,labels,)
        )
    }
}

fn parse_labels_prefix<'a, R, Octs>(
    parser: &mut Parser<'a, R>,
    afi: Afi,
) -> Result<(Prefix, Labels<Octs>), ParseError>
where
    Octs: Octets,
    R: Octets<Range<'a> = Octs>
{
    let mut prefix_bits = parser.parse_u8()?;
    let labels = Labels::<Octs>::parse(parser)?;

    // Check whether we can safely subtract the labels length from the
    // prefix size. If there is an unexpected path id, we might silently
    // subtract too much, because there is no 'subtract with overflow'
    // warning when built in release mode.

    if u8::try_from(8 * labels.len())
        .map_err(|_| ParseError::form_error("MplsNlri labels too long"))?
        > prefix_bits {
        return Err(ParseError::ShortInput);
    }

    prefix_bits -= 8 * labels.len() as u8;

    let prefix = parse_prefix_for_len(
        parser,
        prefix_bits,
        afi,
    )?;

    Ok((prefix, labels))
}

impl<Octs: AsRef<[u8]>> MplsNlri<Octs> {
    pub(super) fn compose_len(&self) -> usize {
        self.labels.len() + prefix_bits_to_bytes(self.prefix.len())
    }

    pub(super) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = u8::try_from(8 * self.labels.len()) .unwrap_or(u8::MAX) +
            self.prefix.len();
        target.append_slice(&[len])?;
        target.append_slice(self.labels.as_ref())?;
        compose_prefix_without_len(self.prefix, target)
    }
}

impl<Octs: AsRef<[u8]>> Eq for MplsNlri<Octs> { }

impl<Octs, Other> PartialEq<MplsNlri<Other>> for MplsNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &MplsNlri<Other>) -> bool {
        self.prefix == other.prefix && self.labels == other.labels
    }
}

impl<Octs> PartialOrd for MplsNlri<Octs>
where Octs: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &MplsNlri<Octs>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Octs: AsRef<[u8]>> Ord for MplsNlri<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.prefix.cmp(&other.prefix).then(self.labels.as_ref().cmp(other.labels.as_ref()))
    }
}


impl<T> fmt::Display for MplsNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MPLS:{}", self.prefix())
    }
}

impl<Octs, SrcOcts: Octets> OctetsFrom<MplsNlri<SrcOcts>> for MplsNlri<Octs>
    where Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: MplsNlri<SrcOcts>
    ) -> Result<Self, Self::Error> {
        Ok(MplsNlri {
            prefix: source.prefix,
            labels: Labels::try_octets_from(source.labels)?
        })
    }
}

//------------ Labels --------------------------------------------------------

/// One or more MPLS labels, part of [`MplsNlri`] and [`MplsVpnNlri`].
///
/// Note that the wireformat for MPLS labels in BGP NLRI does not carry the
/// TTL field. As such, the raw value within `Labels` is a multiple of 3
/// bytes instead of 4 bytes.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Labels<Octs> {
    octets: Octs
}
impl<Octs: AsRef<[u8]>> Labels<Octs> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.octets.as_ref().len()
    }
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Label
//|                Label                  | Exp |S|       TTL     | Stack
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Entry
//
//                    Label:  Label Value, 20 bits
//                    Exp:    Experimental Use, 3 bits
//                    S:      Bottom of Stack, 1 bit
//                    TTL:    Time to Live, 8 bits
/// Single MPLS label.
///
/// Note that a `Label` can exist in multiple forms: when used in BGP NLRI,
/// no TTL is present and all info is comprised in 3 bytes. When used in
/// actual MPLS, the TTL is present making the entire label 4 bytes long.
/// `Label` is used for both occasions: whenever there is no TTL to be parsed
/// such as in the BGP NLRI case, it will be stored as 0 and returned as such
/// from the [`ttl`] method.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct Label {
    data: u32
}

impl Label {
    pub fn value(self) -> u32 {
        self.data >> 12
    }

    pub fn experimental(self) -> u8 {
        ((self.data >> 9) as u8) & 0x07
    }

    pub fn bottom(self) -> bool {
        self.data & 0x100 == 0x100
    }

    pub fn ttl(self) -> u8 {
        self.data as u8
    }

}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())?;
        if self.bottom() {
            write!(f, " (bottom)")?
        }
        Ok(())
    }
}

impl<Octs: Octets> Labels<Octs> {
    // There are two cases for Labels:
    // - in an announcement, it describes one or more MPLS labels
    // - in a withdrawal, it's a compatibility value without meaning
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs> + ?Sized,
    {
        let pos = parser.pos();
        
        let mut stop = false;
        let mut buf = [0u8; 3];

        while !stop {
            //20bits label + 3bits rsvd + S bit
            parser.parse_buf(&mut buf)?;

            /*
            // The actual label:
            let _lbl =
                (buf[0] as u32) << 12 |
                (buf[1] as u32) << 4  |
                (buf[2] as u32) >> 4;
            */

            if buf[2] & 0x01 == 0x01  ||     // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00]    // or RFC 8277 2.4
            {
                stop = true;
            }
        }

        let len = parser.pos() - pos;
        parser.seek(pos)?;
        let res = parser.parse_octets(len)?;
        Ok(
            Labels { octets: res }
        )
    }
}

impl<Octs: AsRef<[u8]>> Labels<Octs> {
    pub fn iter(&self) -> LabelsIterator<'_, Octs> {
        LabelsIterator { parser: Parser::from_ref(&self.octets) }
    }
}

pub struct LabelsIterator<'a, Octs> {
    parser: Parser<'a, Octs>
}

/// Iterate over MPLS labels as they occur in BGP NLRI.
///
/// These are the 3 byte, no-TTL style labels.
impl<O: AsRef<[u8]>> Iterator for LabelsIterator<'_, O> {
    type Item = Label;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let mut buf = [0u8; 4];
        self.parser.parse_buf(&mut buf[0..3]).expect("must be multiple of 3 bytes left");
        Some(Label { data: u32::from_be_bytes(buf) } )
    }
}

impl<O: AsRef<[u8]>> fmt::Display for Labels<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.iter(); 
        if let Some(first) = iter.next() {
            write!(f, "{}", first)?;
        }
        for l in iter {
            write!(f, ", {}", l)?;
        }
        Ok(())
    }
}


impl<Octs: AsRef<[u8]>> Eq for Labels<Octs> { }

impl<Octs, Other> PartialEq<Labels<Other>> for Labels<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &Labels<Other>) -> bool {
        self.octets.as_ref() == other.octets.as_ref()
    }
}

impl<Octs: AsRef<[u8]>> AsRef<[u8]> for Labels<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octs, SrcOcts: Octets> OctetsFrom<Labels<SrcOcts>> for Labels<Octs>
    where Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Labels<SrcOcts>
    ) -> Result<Self, Self::Error> {
        Ok(Labels {
            octets: Octs::try_octets_from(source.octets)?
        })
    }
}

#[cfg(test)]
mod tests {
    use octseq::Parser;
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse() {
        // 5 IPv4 MPLS NLRI
        let raw = vec![
            0x38, 0x01, 0xf4, 0x01, 0x0a, 0x00, 0x00, 0x09,
            0x32, 0x01, 0xf4, 0x11, 0xc6, 0x33, 0x64, 0x00,
            0x32, 0x01, 0xf4, 0x21, 0xc6, 0x33, 0x64, 0x40,
            0x32, 0x01, 0xf4, 0x31, 0xc6, 0x33, 0x64, 0x80,
            0x32, 0x01, 0xf4, 0x91, 0xc6, 0x33, 0x64, 0xc0
        ];
        let mut parser = Parser::from_ref(&raw);
        let mut res = vec![];
        while parser.remaining() > 0 {
            res.push(MplsNlri::parse(&mut parser, Afi::Ipv4).unwrap());
        }
        assert_eq!(res.len(), 5);
        assert_eq!(res[0].prefix(), Prefix::from_str("10.0.0.9/32").unwrap());
    }

    #[test]
    fn label() {
        let label = Label { data: 0x00012aff};
        assert_eq!(label.value(), 18);
        assert_eq!(label.experimental(), 0b101);
        assert!(!label.bottom());
        assert_eq!(label.ttl(), 255);
        assert_eq!(label.to_string(), "18");

        let label = Label { data: 0x00010bff};
        assert_eq!(label.value(), 16);
        assert_eq!(label.experimental(), 0b101);
        assert!(label.bottom());
        assert_eq!(label.ttl(), 255);
        assert_eq!(label.to_string(), "16 (bottom)");

    }

    #[test]
    fn labels() {

        // 1 IPv4 MPLS NLRI with two labels
        let raw = vec![
            0x50,
            0x01, 0x3a, 0x70,
            0x01, 0x3a, 0x81,
            0x0a, 0x00, 0x00, 0x09,
        ];
        let mut parser = Parser::from_ref(&raw);
        let mut res = vec![];
        while parser.remaining() > 0 {
            res.push(MplsNlri::parse(&mut parser, Afi::Ipv4).unwrap());
        }

        assert_eq!(res.len(), 1);
        let labels = res[0].labels();
        assert_eq!(labels.iter().count(), 2);

        assert_eq!(
            format!("{}", labels),
            "5031, 5032 (bottom)"
        );
        
    }
}
