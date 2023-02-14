/// Generate enums for codepoints in protocols.
///
/// # Example 
///
/// ```rust
/// # #[cfg(feature = "serde")]
/// # use serde::{Serialize, Deserialize};
/// # #[macro_use] extern crate routecore;
/// # fn main() {
/// typeenum!(AFI, u16,
///     1 => Ipv4,
///     2 => Ipv6,
///     25 => L2Vpn,
/// );
/// # }
/// ```
/// This will create a `pub enum AFI`, comprised of variants `IPv4`, `IPv6`
/// and `L2Vpn`. On this enum, the [`From`] (for conversion between the
/// variants and `u16`) and [`std::fmt::Display`] traits are implemented.
///
#[macro_export]
macro_rules! typeenum {
    ($(#[$attr:meta])* $name:ident, $ty:ty, $($x:expr => $y:ident),+ $(,)*) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        pub enum $name {
            $($y),+,
            Unimplemented($ty),
        }

        impl From<$ty> for $name {
            fn from(f: $ty) -> $name {
                match f {
                    $($x => $name::$y,)+
                    u => $name::Unimplemented(u),
                }
            }
        }

        impl From<$name> for $ty {
            fn from(s: $name) -> $ty {
                match s {
                    $($name::$y => $x,)+
                    $name::Unimplemented(u) => u,
                }
            }

        }
		impl std::fmt::Display for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter)
				-> Result<(), std::fmt::Error>
			{
				match self {
                    $($name::$y => write!(f, stringify!($y))),+,
					$name::Unimplemented(u) =>
                        write!(f, "unknown-{}-{}", stringify!($name), u)
				}
			}
		}
    }
}
