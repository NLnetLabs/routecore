use inetnum::addr::Prefix;
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use octseq::{Octets, Parser};
use crate::util::parser::ParseError;
use super::common::parse_prefix_for_len;
use super::afisafi::Afi;
use super::mpls::Labels;

/// NLRI comprised of a [`BasicNlri`], MPLS `Labels` and a VPN
/// `RouteDistinguisher`.
#[derive(Copy, Clone, Debug, Hash)]
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
        b[..8].copy_from_slice(parser.peek(8)?);
        parser.advance(8)?;
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
    pub fn new(bytes: &[u8]) -> Self {
        RouteDistinguisher { bytes: bytes.try_into().expect("parsed before") }
    }

    pub fn zeroes() -> Self {
        RouteDistinguisher::new(&[0_u8; 8])
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
    pub fn value(&self) -> [u8; 6] {
        self.bytes[2..8].try_into().expect("parsed before")
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
