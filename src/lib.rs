//! A library for IP routing primitives.

pub mod addr;
pub mod asn;
#[cfg(feature = "bgp")]
pub mod bgp;
pub mod bgpsec;
#[cfg(feature = "bmp")]
pub mod bmp;
#[cfg(feature = "bgp")]
pub mod flowspec;

#[cfg(feature = "bmp")]
pub use octseq::Octets;
pub use octseq::Parser;

//--- Private modules

mod util;
