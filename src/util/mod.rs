pub mod hex;

#[cfg(any(feature = "bgp", feature = "bmp"))]
#[macro_use]
pub(crate) mod macros;

#[cfg(any(feature = "bgp", feature = "bmp"))]
pub(crate) mod parser;
