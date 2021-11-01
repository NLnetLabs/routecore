use num::PrimInt;
use std::fmt::Debug;

//------------ AddressFamily (trait) --------------------------------------------------------
/// The address family of an IP address as a Trait.
/// 
/// The idea of this trait is that each family will have a separate type to be
/// able to only take the amount of memory needs. Useful when building trees
/// with large amounts of addresses/prefixes. Used by rotonda-store for this
/// purpose.
pub trait AddressFamily: PrimInt + Debug {
    /// The byte representation of the family filled with 1s.
    const BITMASK: Self;
    /// The number of bits in the byte representation of the family.
    const BITS: u8;
    fn fmt_net(net: Self) -> String;
    // returns the specified nibble from `start_bit` to (and
    // including) `start_bit + len` and shifted to the right.
    fn get_nibble(net: Self, start_bit: u8, len: u8) -> u32;

    #[cfg(feature = "dynamodb")]
    fn from_addr(net: Addr) -> Self;

    #[cfg(feature = "dynamodb")]
    fn into_addr(self) -> Addr;

    fn into_ipaddr(self) -> std::net::IpAddr;
}


//-------------- Ipv4 Type ---------------------------------------------------------------------

pub type IPv4 = u32;

impl AddressFamily for IPv4 {
    const BITMASK: u32 = 0x1u32.rotate_right(1);
    const BITS: u8 = 32;

    fn fmt_net(net: Self) -> String {
        std::net::Ipv4Addr::from(net).to_string()
    }

    fn get_nibble(net: Self, start_bit: u8, len: u8) -> u32 {
        (net << start_bit) >> ((32 - len) % 32)
    }

    #[cfg(feature = "dynamodb")]
    fn from_addr(net: Addr) -> u32 {
        net.to_bits() as u32
    }

    #[cfg(feature = "dynamodb")]
    fn into_addr(self) -> Addr {
        Addr::from_bits(self as u128)
    }

    fn into_ipaddr(self) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(self))
    }
}


//-------------- Ipv6 Type ---------------------------------------------------------------------

pub type IPv6 = u128;

impl AddressFamily for IPv6 {
    const BITMASK: u128 = 0x1u128.rotate_right(1);
    const BITS: u8 = 128;
    fn fmt_net(net: Self) -> String {
        std::net::Ipv6Addr::from(net).to_string()
    }

    fn get_nibble(net: Self, start_bit: u8, len: u8) -> u32 {
        ((net << start_bit) >> ((128 - len) % 128)) as u32
    }

    #[cfg(feature = "dynamodb")]
    fn from_addr(net: Addr) -> u128 {
        net.to_bits()
    }

    #[cfg(feature = "dynamodb")]
    fn into_addr(self) -> Addr {
        Addr::from_bits(self)
    }

    fn into_ipaddr(self) -> std::net::IpAddr {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(self))
    }
}
