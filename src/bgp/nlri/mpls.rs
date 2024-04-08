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
    pub(super) fn parse_labels_and_prefix<'a, R>( parser: &mut Parser<'a, R>,
        afi: Afi,
    ) -> Result<(Prefix, Labels<Octs>), ParseError>
    where
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

/// MPLS labels, part of [`MplsNlri`] and [`MplsVpnNlri`].
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

impl<Octs: Octets> Labels<Octs> {
    // XXX check all this Label stuff again
    pub fn skip<'a, R>(parser: &mut Parser<'a, R>) -> Result<usize, ParseError>
        where
            R: Octets<Range<'a> = Octs>
    {
        let mut res = 0;
        let mut stop = false;
        let mut buf = [0u8; 3];

        while !stop {
            //20bits label + 3bits rsvd + S bit
            parser.parse_buf(&mut buf)?;
            res += 3;

            if buf[2] & 0x01 == 0x01  || // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00] // or RFC 8277 2.4
            {
                stop = true;
            }
        }

        Ok(res)
    }

    // There are two cases for Labels:
    // - in an announcement, it describes one or more MPLS labels
    // - in a withdrawal, it's a compatibility value without meaning
    // XXX consider splitting up the parsing for this for announcements vs
    // withdrawals? Perhaps via another fields in the (currently so-called)
    // SessionConfig...
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
            let _lbl =
                (buf[0] as u32) << 12 |
                (buf[1] as u32) << 4  |
                (buf[2] as u32) >> 4;

            if buf[2] & 0x01 == 0x01  || // actual label with stop bit
                buf == [0x80, 0x00, 0x00] || // Compatibility value 
                buf == [0x00, 0x00, 0x00] // or RFC 8277 2.4
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

