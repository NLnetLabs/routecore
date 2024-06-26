use inetnum::addr::Prefix;
use std::cmp;
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use octseq::{Octets, OctetsBuilder, Parser};

use crate::util::parser::ParseError;
use super::afisafi::Afi;
use super::common::{compose_prefix_without_len, parse_prefix_for_len, prefix_bits_to_bytes};
use super::mpls::Labels;

/// NLRI comprised of a [`BasicNlri`], MPLS `Labels` and a VPN
/// `RouteDistinguisher`.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MplsVpnNlri<Octs> {
    prefix: Prefix,
    labels: Labels<Octs>,
    rd: RouteDistinguisher,
}

impl<T> MplsVpnNlri<T> {
    pub(super) fn new(
        prefix: Prefix,
        labels: Labels<T>,
        rd: RouteDistinguisher
    ) -> Self {
        Self { prefix, labels, rd }
    }

    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    pub fn labels(&self) -> &Labels<T> {
        &self.labels
    }

    pub fn rd(&self) -> RouteDistinguisher {
        self.rd
    }
}

impl<Octs: Octets> MplsVpnNlri<Octs> {
    pub fn parse<'a, R>( parser: &mut Parser<'a, R>,
        afi: Afi,
    ) -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs>
    {
        let (prefix, labels, rd) = parse_labels_rd_prefix(parser, afi)?;
        Ok(
            Self::new(rd, prefix, labels)
        )
    }
}

pub(super) fn parse_labels_rd_prefix<'a, R, Octs: Octets>(
    parser: &mut Parser<'a, R>,
    afi: Afi,
) -> Result<(Labels<Octs>, RouteDistinguisher, Prefix), ParseError>
where
    R: Octets<Range<'a> = Octs>
{
    let mut prefix_bits = parser.parse_u8()?;
    let labels = Labels::<Octs>::parse(parser)?;

    // 8 for the RouteDistinguisher, plus byte length of labels,
    // times 8 to go from bytes to bits
    let rd_label_len = u8::try_from(8 * (8 + labels.len()))
            .map_err(|_| ParseError::form_error(
                    "MplsVpnNlri labels/rd too long"
            ))?;

    if rd_label_len > prefix_bits {
        return Err(ParseError::ShortInput);
    }

    let rd = RouteDistinguisher::parse(parser)?;
    prefix_bits -= rd_label_len;

    let prefix = parse_prefix_for_len(parser, prefix_bits, afi)?;

    Ok((labels, rd, prefix))
}

impl<Octs: AsRef<[u8]>> MplsVpnNlri<Octs> {
    pub(super) fn compose_len(&self) -> usize {
        8 + self.labels.len() + prefix_bits_to_bytes(self.prefix.len())
    }

    pub(super) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        let len = 
            u8::try_from(8 * (8 + self.labels.len())).unwrap_or(u8::MAX) + self.prefix.len();
        target.append_slice(&[len])?;
        target.append_slice(self.labels.as_ref())?;
        target.append_slice(self.rd.as_ref())?;
        compose_prefix_without_len(self.prefix, target)
    }
}

impl<Octs: AsRef<[u8]>> Eq for MplsVpnNlri<Octs> { }

impl<Octs, Other> PartialEq<MplsVpnNlri<Other>> for MplsVpnNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &MplsVpnNlri<Other>) -> bool {
        self.prefix == other.prefix
            && self.labels == other.labels
            && self.rd == other.rd
    }
}

impl<Octs> PartialOrd for MplsVpnNlri<Octs>
where Octs: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &MplsVpnNlri<Octs>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Octs: AsRef<[u8]>> Ord for MplsVpnNlri<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.prefix.cmp(&other.prefix)
            .then(self.labels.as_ref().cmp(other.labels.as_ref()))
            .then(self.rd.cmp(&other.rd))
    }
}

impl<T> fmt::Display for MplsVpnNlri<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MPLS-VPN:{}", self.prefix())

    }
}

//------------ RouteDistinguisher --------------------------------------------

/// Route Distinguisher (RD) as defined in RFC4364.
///
/// Used in [`MplsVpnNlri`], [`VplsNlri`] and [`NextHop`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteDistinguisher {
    bytes: [u8; 8]
}

impl RouteDistinguisher {
    pub fn check<Octs: Octets>(parser: &mut Parser<Octs>)
        -> Result<(), ParseError>
    {
        parser.advance(8)?;
        Ok(())
    }

    pub fn parse<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let mut b = [0u8; 8];
        parser.parse_buf(&mut b)?;

        Ok(
            RouteDistinguisher{ bytes: b }
        )
    }

    pub fn skip<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        Ok(parser.advance(8)?)
    }
}

impl RouteDistinguisher {
    /// Create a new RouteDistinguisher from a slice.
    pub fn new(bytes: [u8; 8]) -> Self {
        RouteDistinguisher { bytes }
    }

    pub fn zeroes() -> Self {
        RouteDistinguisher::new([0_u8; 8])
    }

    /// Returns the type this RouteDistinguisher.
    pub fn typ(&self) -> RouteDistinguisherType {
        match self.bytes[0..2] {
            [0x00, 0x00] => RouteDistinguisherType::Type0,
            [0x00, 0x01] => RouteDistinguisherType::Type1,
            [0x00, 0x02] => RouteDistinguisherType::Type2,
            _ => RouteDistinguisherType::UnknownType,
        }
    }

    /// Returns the raw value of this RouteDistinguisher.
    pub fn value(&self) -> &[u8] {
        &self.bytes[2..8]
    }
}

impl AsRef<[u8]> for RouteDistinguisher {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self.bytes)
    }
}

/// Route Distinguisher types as defined in RFC4364.
#[derive(Eq, PartialEq, Debug)]
pub enum RouteDistinguisherType {
    Type0,
    Type1,
    Type2,
    UnknownType,
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use octseq::Parser;
    use super::*;

    #[test]
    fn parse() {

        let raw = vec![
            0xd8, 0x00, 0x7d, 0xc1, 0x00, 0x00, 0x00, 0x64,
            0x00, 0x00, 0x00, 0x01, 0xfc, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01
        ];
        let mut parser = Parser::from_ref(&raw);
        let nlri = MplsVpnNlri::parse(&mut parser, Afi::Ipv6).unwrap();
        assert_eq!(nlri.labels().iter().next().unwrap().value(), 2012);
        assert_eq!(
            nlri.rd(),
            RouteDistinguisher::new([0, 0, 0, 100, 0, 0, 0, 1])
        );
        assert_eq!(nlri.prefix(), Prefix::from_str("fc00::1/128").unwrap());
    }
}
