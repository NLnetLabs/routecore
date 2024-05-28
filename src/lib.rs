//! A library for IP routing primitives.

pub mod bgp;
#[cfg(feature = "bgpsec")]
pub mod bgpsec;

#[cfg(feature = "bmp")]
pub mod bmp;

pub mod flowspec;

pub use octseq::Octets;

//--- Private modules

mod util;
