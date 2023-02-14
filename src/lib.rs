//! A library for IP routing primitives.

pub mod addr;
pub mod asn;
#[cfg(feature = "bmp")]
pub mod bmp;
#[cfg(feature = "bgp")]
pub mod bgp;
pub mod bgpsec;
#[cfg(feature = "bgp")]
pub mod flowspec;
pub mod record;


//--- Private modules

mod util;
