use num::PrimInt;
use std::fmt::{Debug};

//------------ Address Family (trait) --------------------------------------------------------

pub trait AddressFamily: PrimInt + Debug {
    const BITMASK: Self;
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

//------------ Addr ----------------------------------------------------------

// #[derive(Clone, Copy, Debug)]
// pub enum Addr {
//     V4(u32),
//     V6(u128),
// }

// impl Addr {
//     pub fn to_bits(&self) -> u128 {
//         match self {
//             Addr::V4(addr) => *addr as u128,
//             Addr::V6(addr) => *addr,
//         }
//     }

//     pub fn to_ipaddr(&self) -> std::net::IpAddr {
//         match self {
//             Addr::V4(addr) => IpAddr::V4(std::net::Ipv4Addr::from(*addr)),
//             Addr::V6(addr) => IpAddr::V6(std::net::Ipv6Addr::from(*addr)),
//         }
//     }
// }

// impl From<Ipv4Addr> for Addr {
//     fn from(addr: Ipv4Addr) -> Self {
//         Self::V4(addr.into())
//     }
// }

// impl From<Ipv6Addr> for Addr {
//     fn from(addr: Ipv6Addr) -> Self {
//         Self::V6(addr.into())
//     }
// }

// impl From<IpAddr> for Addr {
//     fn from(addr: IpAddr) -> Self {
//         match addr {
//             IpAddr::V4(addr) => addr.into(),
//             IpAddr::V6(addr) => addr.into(),
//         }
//     }
// }
// impl From<u32> for Addr {
//     fn from(addr: u32) -> Self {
//         addr.into()
//     }
// }

// impl FromStr for Addr {
//     type Err = <IpAddr as FromStr>::Err;

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         IpAddr::from_str(s).map(Into::into)
//     }
// }

// impl fmt::Display for Addr {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             Addr::V4(addr) => write!(f, "{}", std::net::Ipv4Addr::from(*addr)),
//             Addr::V6(addr) => write!(f, "{}", std::net::Ipv6Addr::from(*addr)),
//         }
//     }
// }