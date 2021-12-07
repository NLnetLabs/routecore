//! IP address resources.

use std::{error, fmt};
use std::cmp::Ordering;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;


//------------ Bits ----------------------------------------------------------

/// The value of an IP address.
///
/// This private type holds the content of an IP address. It is big enough to
/// hold either an IPv4 and IPv6 address as it keeps the address internally
/// as a 128 bit unsigned integer. IPv6 addresses are kept in all bits in host
/// byte order while IPv4 addresses are kept in the upper four bytes and are
/// right-padded with zero bits. This makes it possible to count prefix
/// lengths the same way for both addresses, i.e., starting from the top of
/// the raw integer.
///
/// There is no way of distinguishing between IPv4 and IPv6 from just a value
/// of this type. This information needs to be carried separately.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Bits(u128);

impl Bits {
    /// Creates a new address from 128 raw bits in host byte order.
    pub fn new(bits: u128) -> Self {
        Bits(bits)
    }

    /// Creates a new address value for an IPv4 address.
    pub fn from_v4(addr: Ipv4Addr) -> Self {
        Self::new(u128::from(u32::from(addr)) << 96)
    }

    /// Creates a new address value for an IPv6 address.
    pub fn from_v6(addr: Ipv6Addr) -> Self {
        Self::new(u128::from(addr))
    }

    /// Returns the raw bits of the underlying integer.
    pub fn into_int(self) -> u128 {
        self.0
    }

    /// Converts the address value into an IPv4 address.
    ///
    /// The methods disregards the lower twelve bytes of the value.
    pub fn into_v4(self) -> Ipv4Addr {
        ((self.0 >> 96) as u32).into()
    }

    /// Converts the address value into an IPv6 address.
    pub fn into_v6(self) -> Ipv6Addr {
        self.0.into()
    }

    /// Checks whether the host portion of the bits used in a prefix is zero.
    fn is_host_zero(self, len: u8) -> bool {
        self.0.trailing_zeros() >= 128u32.saturating_sub(len.into())
    }

    /// Clears the bits in the host portion of a prefix.
    fn clear_host(self, len: u8) -> Self {
        Bits(self.0 & (u128::MAX << (128u8.saturating_sub(len))))
    }

    /// Returns a value with all but the first `prefix_len` bits set.
    ///
    /// The first `prefix_len` bits are retained. Thus, the returned address
    /// is the largest address in a prefix of this length.
    fn into_max(self, prefix_len: u8) -> Self {
        if prefix_len >= 128 {
            self
        }
        else {
            Self(self.0 | (u128::MAX >> prefix_len as usize))
        }
    }
}


//--- From

impl From<u128> for Bits {
    fn from(addr: u128) -> Self {
        Self::new(addr)
    }
}

impl From<Ipv4Addr> for Bits {
    fn from(addr: Ipv4Addr) -> Self {
        Self::from_v4(addr)
    }
}

impl From<Ipv6Addr> for Bits {
    fn from(addr: Ipv6Addr) -> Self {
        Self::from_v6(addr)
    }
}

impl From<IpAddr> for Bits {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Self::from(addr),
            IpAddr::V6(addr) => Self::from(addr)
        }
    }
}

impl From<Bits> for u128 {
    fn from(addr: Bits) -> u128 {
        addr.into_int()
    }
}

impl From<Bits> for Ipv4Addr {
    fn from(addr: Bits) -> Ipv4Addr {
        addr.into_v4()
    }
}

impl From<Bits> for Ipv6Addr {
    fn from(addr: Bits) -> Ipv6Addr {
        addr.into_v6()
    }
}


//--- Debug

impl fmt::Debug for Bits {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Bits")
        .field(&format_args!("{}", self.into_v6()))
        .finish()
    }
}


//------------ FamilyAndLen --------------------------------------------------

/// The address family and prefix length stored in a single byte.
///
/// This private types wraps a `u8` and uses it to store both the address
/// family – i.e., whether this is an IPv4 or IPv6 prefix –, and the prefix
/// length.
///
/// The encoding is as follows: Values up to 32 represent IPv4 prefixes with
/// the value as their prefix length. If the left-most bit is set, the value
/// is a IPv6 prefix with the length encoded by flipping all the bits. The
/// value of 64 stands in for an IPv6 prefix with length 128.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FamilyAndLen(u8);

impl FamilyAndLen {
    /// Creates a value for an IPv4 prefix.
    pub fn new_v4(len: u8) -> Result<Self, PrefixError> {
        if len > 32 {
            Err(PrefixError::LenOverflow)
        }
        else {
            Ok(Self(len))
        }
    }

    /// Creates a value for an IPv6 prefix.
    pub fn new_v6(len: u8) -> Result<Self, PrefixError> {
        match len.cmp(&128) {
            Ordering::Greater => Err(PrefixError::LenOverflow),
            Ordering::Equal => Ok(Self(0x40)),
            Ordering::Less => Ok(Self(len ^ 0xFF))
        }
    }

    /// Returns whether this a IPv4 prefix.
    pub fn is_v4(self) -> bool {
        self.0 & 0xc0 == 0
    }

    /// Returns whether this a IPv6 prefix.
    pub fn is_v6(self) -> bool {
        self.0 & 0xc0 != 0
    }

    /// Returns the prefix length.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> u8 {
        match self.0 & 0xc0 {
            0x00 => self.0,
            0x40 => 128,
            _ => self.0 ^ 0xFF
        }
    }

    /// Returns the family and length squeezed into a result.
    ///
    /// This is used to simplify trait implementations below. `Ok(_)` is for
    /// IPv4, `Err(_)` is for IPv6. This choice does _not_ indicate any kind
    /// of preference.
    fn into_result(self) -> Result<u8, u8> {
        match self.0 & 0xc0 {
            0x00 => Ok(self.0),
            0x40 => Err(128),
            _ => Err(self.0 ^ 0xFF)
        }
    }
}


//--- PartialOrd and Ord

impl PartialOrd for FamilyAndLen {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FamilyAndLen {
    fn cmp(&self, other: &Self) -> Ordering {
        self.into_result().cmp(&other.into_result())
    }
}


//------------ Prefix --------------------------------------------------------

/// An IP address prefix: an IP address and a prefix length.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Prefix {
    /// The actual bits of the prefix.
    bits: Bits,

    /// The address family and prefix length all in one.
    family_and_len: FamilyAndLen,
}

impl Prefix {
    /// Creates a new prefix from an address and a length.
    ///
    /// The function returns an error if `len` is too large for the address
    /// family of `addr`.
    ///
    /// Use `saturating_new` if you want the prefix length to be capped
    /// instead.
    pub fn new(addr: IpAddr, len: u8) -> Result<Self, PrefixError> {
        match addr {
            IpAddr::V4(addr) => Self::new_v4(addr, len),
            IpAddr::V6(addr) => Self::new_v6(addr, len),
        }
    }

    /// Creates a new prefix from an IPv4 address and a prefix length.
    ///
    /// The function returns an error if `len` is greater than 32.
    ///
    /// Use `saturating_new_v4` if you want the prefix length to be capped
    /// instead.
    pub fn new_v4(addr: Ipv4Addr, len: u8) -> Result<Self, PrefixError> {
        let family_and_len = FamilyAndLen::new_v4(len)?;

        // Check that host bits are zero.
        let bits = Bits::from_v4(addr);
        if !bits.is_host_zero(len) {
            return Err(PrefixError::NonZeroHost)
        }

        Ok(Prefix { bits, family_and_len })
    }

    /// Creates a new prefix from an IPv6 adddress and a prefix length.
    ///
    /// The function returns an error if `len` is greater than 128.
    ///
    /// Use `saturating_new_v6` if you want the prefix length to be capped
    /// instead.
    pub fn new_v6(addr: Ipv6Addr, len: u8) -> Result<Self, PrefixError> {
        let family_and_len = FamilyAndLen::new_v6(len)?;

        // Check that host bits are zero.
        let bits = Bits::from_v6(addr);
        if !bits.is_host_zero(len) {
            return Err(PrefixError::NonZeroHost)
        }

        Ok(Prefix { bits, family_and_len })
    }

    /// Creates a new prefix zeroing out host bits.
    pub fn new_relaxed(addr: IpAddr, len: u8) -> Result<Self, PrefixError> {
        match addr {
            IpAddr::V4(addr) => Self::new_v4_relaxed(addr, len),
            IpAddr::V6(addr) => Self::new_v6_relaxed(addr, len),
        }
    }

    /// Creates a new prefix zeroing out host bits.
    pub fn new_v4_relaxed(
        addr: Ipv4Addr, len: u8
    ) -> Result<Self, PrefixError> {
        let family_and_len = FamilyAndLen::new_v4(len)?;
        Ok(Prefix {
            bits: Bits::from_v4(addr).clear_host(len),
            family_and_len
        })
    }

    /// Creates a new prefix zeroing out host bits.
    pub fn new_v6_relaxed(
        addr: Ipv6Addr, len: u8
    ) -> Result<Self, PrefixError> {
        let family_and_len = FamilyAndLen::new_v6(len)?;
        Ok(Prefix {
            bits: Bits::from_v6(addr).clear_host(len),
            family_and_len
        })
    }

    /// Returns whether the prefix is for an IPv4 address.
    pub fn is_v4(self) -> bool {
        self.family_and_len.is_v4()
    }

    /// Returns whether the prefix is for an IPv6 address.
    pub fn is_v6(self) -> bool {
        self.family_and_len.is_v6()
    }

    /// Returns the IP address part of a prefix.
    pub fn addr(self) -> IpAddr {
        if self.is_v4() {
            self.bits.into_v4().into()
        }
        else {
            self.bits.into_v6().into()
        }
    }

    /// Returns the length part of a prefix.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> u8 {
        self.family_and_len.len()
    }

    /// Returns the prefix as a pair of the address and length.
    pub fn addr_and_len(self) -> (IpAddr, u8) {
        (self.addr(), self.len())
    }

    /// Returns the smallest address of the prefix.
    ///
    /// This is the same as [`addr`][Self::addr].
    pub fn min_addr(self) -> IpAddr {
        self.addr()
    }

    /// Returns the largest address of the prefix.
    pub fn max_addr(self) -> IpAddr {
        let bits = self.bits.into_max(self.len());
        if self.is_v4() {
            bits.into_v4().into()
        }
        else {
            bits.into_v6().into()
        }
    }

    /// Returns whether the prefix `self` covers the prefix `other`.
    pub fn covers(self, other: Self) -> bool {
        // Differing families? Not covering.
        if self.is_v4() != other.is_v4() {
            return false
        }

        // If self is more specific than other, it can’t cover it.
        if self.len() > other.len() {
            return false
        }

        // If we have two host prefixes, they need to be identical.
        // (This needs to be extra because the bit shifting below doesn’t
        // work at least in the v6 case.)
        if self.is_v4() {
            if self.len() == 32 && other.len() == 32 {
                return self == other
            }
        }
        else if self.len() == 128 && other.len() == 128 {
            return self == other
        }

        // other now needs to start with the same bits as self.
        self.bits.into_int()
            ==  other.bits.into_int() & !(u128::MAX >> self.len())
    }
}


//--- From

#[cfg(feature = "repository")]
impl From<crate::repository::roa::FriendlyRoaIpAddress> for Prefix {
    fn from(addr: crate::repository::roa::FriendlyRoaIpAddress) -> Self {
        Prefix::new(
            addr.address(), addr.address_length()
        ).expect("ROA IP address with illegal prefix length")
    }
}

#[cfg(feature = "repository")]
impl From<Prefix> for crate::repository::resources::IpBlock {
    fn from(src: Prefix) -> Self {
        crate::repository::resources::Prefix::new(
            src.addr(), src.len()
        ).into()
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Prefix;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "a string with an IPv4 or IPv6 prefix")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                Prefix::from_str(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Prefix {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}


//--- FromStr and Display

impl FromStr for Prefix {
    type Err = ParsePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParsePrefixError::Empty)
        }
        let slash = s.find('/').ok_or(ParsePrefixError::MissingLen)?;
        let addr = IpAddr::from_str(&s[..slash]).map_err(
            ParsePrefixError::InvalidAddr
        )?;
        let len = u8::from_str(&s[slash + 1..]).map_err(
            ParsePrefixError::InvalidLen
        )?;
        Prefix::new(addr, len).map_err(ParsePrefixError::InvalidPrefix)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.len())
    }
}



//------------ MaxLenPrefix --------------------------------------------------

/// The pair of a prefix and an optional max-len.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MaxLenPrefix {
    /// The prefix.
    prefix: Prefix,

    /// The optional maximum prefix length.
    max_len: Option<u8>,
}

impl MaxLenPrefix {
    /// Creates a new value.
    ///
    /// The function returns an error if `max_len` is present and smaller than
    /// `prefix.len()` or larger than the maximum prefix length of the
    /// prefix’s address family.
    pub fn new(
        prefix: Prefix, max_len: Option<u8>
    ) -> Result<Self, MaxLenError> {
        if let Some(max_len) = max_len {
            if
                (prefix.is_v4() && max_len > 32)
                || max_len > 128
            {
                return Err(MaxLenError::Overflow)
            }
            if prefix.len() > max_len {
                return Err(MaxLenError::Underflow)
            }
        }
        Ok(MaxLenPrefix { prefix, max_len })
    }

    /// Creates a value curtailing any out-of-bounds max-len.
    pub fn saturating_new(prefix: Prefix, max_len: Option<u8>) -> Self {
        let max_len = max_len.map(|max_len| {
            if prefix.len() > max_len {
                prefix.len()
            }
            else if prefix.is_v4() && max_len > 32 {
                32
            }
            else if max_len > 128 {
                128
            }
            else {
                max_len
            }
        });
        MaxLenPrefix { prefix, max_len }
    }

    /// Returns the actual prefix.
    pub fn prefix(self) -> Prefix {
        self.prefix
    }

    /// Returns the address of the prefix.
    pub fn addr(self) -> IpAddr {
        self.prefix.addr()
    }

    /// Returns the prefix length.
    pub fn prefix_len(self) -> u8 {
        self.prefix.len()
    }

    /// Returns the max-length.
    pub fn max_len(self) -> Option<u8> {
        self.max_len
    }

    /// Returns the max-length or the prefix-length if there is no max-length.
    pub fn resolved_max_len(self) -> u8 {
        self.max_len.unwrap_or_else(|| self.prefix.len())
    }
}


//--- From

impl From<Prefix> for MaxLenPrefix {
    fn from(prefix: Prefix) -> Self {
        MaxLenPrefix { prefix, max_len: None }
    }
}


//--- FromStr and Display

impl FromStr for MaxLenPrefix {
    type Err = ParseMaxLenPrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (prefix, max_len) = match s.find('-') {
            Some(dash) => {
                (
                    Prefix::from_str(&s[..dash]).map_err(
                        ParseMaxLenPrefixError::InvalidPrefix
                    )?,
                    Some(u8::from_str(&s[dash + 1..]).map_err(
                        ParseMaxLenPrefixError::InvalidMaxLenFormat
                    )?)
                )
            }
            None => {
                let prefix = Prefix::from_str(s).map_err(
                    ParseMaxLenPrefixError::InvalidPrefix
                )?;
                (prefix, None)
            }
        };
        Self::new(prefix, max_len).map_err(
            ParseMaxLenPrefixError::InvalidMaxLenValue
        )
    }
}


//============ Errors ========================================================

//------------ PrefixError ---------------------------------------------------

/// Creating a prefix has failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrefixError {
    /// The prefix length is longer than allowed for the address family.
    LenOverflow,

    /// The host portion of the address has non-zero bits set.
    NonZeroHost,
}

impl PrefixError {
    /// Returns a static error message.
    pub fn static_description(self) -> &'static str {
        match self {
            PrefixError::LenOverflow => "prefix length too large",
            PrefixError::NonZeroHost => "non-zero host portion",
        }
    }
}

impl From<PrefixError> for &'static str {
    fn from(err: PrefixError) -> Self {
        err.static_description()
    }
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.static_description())
    }
}

impl error::Error for PrefixError { }


//------------ ParsePrefixError ----------------------------------------------

/// Creating an IP address prefix from a string has failed.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParsePrefixError {
    /// The value parsed was empty.
    Empty,

    /// The length portion after a slash was missing.
    MissingLen,

    /// The address portion is invalid.
    InvalidAddr(AddrParseError),

    /// The length portion is invalid.
    InvalidLen(ParseIntError),

    /// The combined prefix is invalid.
    InvalidPrefix(PrefixError),
}

impl fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParsePrefixError::Empty => f.write_str("empty string"),
            ParsePrefixError::MissingLen => {
                f.write_str("missing length portion")
            }
            ParsePrefixError::InvalidAddr(err) => {
                write!(f, "invalid address: {}", err)
            }
            ParsePrefixError::InvalidLen(err) => {
                write!(f, "invalid length: {}", err)
            }
            ParsePrefixError::InvalidPrefix(err) => err.fmt(f),
        }
    }
}

impl error::Error for ParsePrefixError { }


//------------ MaxLenError ---------------------------------------------------

/// A max-len prefix was constructed from illegal components.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MaxLenError {
    /// The max-len is larger than allowed for the address family.
    Overflow,

    /// The max-len is smaller than the prefix length.
    Underflow,
}

impl MaxLenError {
    /// Returns a static error message.
    pub fn static_description(self) -> &'static str {
        match self {
            MaxLenError::Overflow => "max-length too large",
            MaxLenError::Underflow => "max-length smaller than prefix length",
        }
    }
}

impl From<MaxLenError> for &'static str {
    fn from(err: MaxLenError) -> Self {
        err.static_description()
    }
}

impl fmt::Display for MaxLenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MaxLenError::Overflow => {
                f.write_str("max-length too large")
            }
            MaxLenError::Underflow => {
                f.write_str("max-length smaller than prefix length")
            }
        }
    }
}

impl error::Error for MaxLenError { }


//------------ ParseMaxLenPrefixError ----------------------------------------

/// Creating an max-len prefix from a string has failed.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseMaxLenPrefixError {
    /// Parsing the prefix portion failed.
    InvalidPrefix(ParsePrefixError),

    /// The max-len portion is invalid.
    InvalidMaxLenFormat(ParseIntError),

    /// The max-len value is invalid.
    InvalidMaxLenValue(MaxLenError)
}

impl fmt::Display for ParseMaxLenPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseMaxLenPrefixError::InvalidPrefix(err) => {
                err.fmt(f)
            }
            ParseMaxLenPrefixError::InvalidMaxLenFormat(err) => {
                write!(f, "invalid max length: {}", err)
            }
            ParseMaxLenPrefixError::InvalidMaxLenValue(err) => {
                err.fmt(f)
            }
        }
    }
}

impl error::Error for ParseMaxLenPrefixError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn good_family_and_len() {
        for i in 0..=32 {
            let fal = FamilyAndLen::new_v4(i).unwrap();
            assert!(fal.is_v4());
            assert!(!fal.is_v6());
            assert_eq!(fal.len(), i)
        }
        for i in 0..=128 {
            let fal = FamilyAndLen::new_v6(i).unwrap();
            assert!(!fal.is_v4());
            assert!(fal.is_v6());
            assert_eq!(fal.len(), i)
        }
    }

    #[test]
    fn bad_family_and_len() {
        for i in 33..=255 {
            assert_eq!(
                FamilyAndLen::new_v4(i),
                Err(PrefixError::LenOverflow)
            );
        }
        for i in 129..=255 {
            assert_eq!(
                FamilyAndLen::new_v6(i),
                Err(PrefixError::LenOverflow)
            );
        }
    }

    #[test]
    fn prefix_from_str() {
        assert_eq!(
            Prefix::from_str("127.0.0.0/12").unwrap().addr_and_len(),
            (IpAddr::from_str("127.0.0.0").unwrap(), 12)
        );
        assert_eq!(
            Prefix::from_str("127.0.0.0"),
            Err(ParsePrefixError::MissingLen)
        );
        assert!(
            matches!(
                Prefix::from_str("127.0.0.0/"),
                Err(ParsePrefixError::InvalidLen(_))
            )
        );
    }
}

