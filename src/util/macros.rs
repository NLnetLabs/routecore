/// Generate enums for codepoints in protocols.
///
/// # Example 
///
/// ```rust
/// # #[cfg(feature = "serde")]
/// # use serde::{Serialize, Deserialize};
/// # #[macro_use] extern crate routecore;
/// # fn main() {
/// typeenum!(
///     AFI, u16,
///     {
///         1 => Ipv4,
///         2 => Ipv6,
///         25 => L2Vpn
///     }
/// );
/// # }
/// ```
/// This will create a `pub enum AFI`, comprised of variants `IPv4`, `IPv6`
/// and `L2Vpn`. On this enum, the [`From`] (for conversion between the
/// variants and `u16`) and [`std::fmt::Display`] traits are implemented.
///
/// You can also specify ranges as like so:
/// 
/// ```rust
/// # #[cfg(feature = "serde")]
/// # use serde::{Serialize, Deserialize};
/// # #[macro_use] extern crate routecore;
/// # fn main() {
/// typeenum!(
///     PeerType, u8,
///     {
///         0 => GlobalInstance,
///         1 => RdInstance,
///         2 => LocalInstance,
///         3 => LocalRibInstance,
///     },
///     {
///         4..=250 => Unassigned,
///         251..=254 => Experimental,
///         255 => Reserved,
///     }
/// );
/// # }
/// ```
/// Note that match lines with ranges are come in a separate block after
/// the block with single selector values. Range variants have a data
/// field with the specified value. Specifying an half-open range to the
/// right or specifying the matches exhaustively will disable the default 
/// `Unimplemented` variant.
#[macro_export]
macro_rules! typeenum {
    ( $(#[$attr:meta])* 
        $name:ident,
        $ty:ty,
        {
            $($x:expr => $y:ident),+ $(,)*
        }
        $(,{
            $( $x1:pat => $y1:ident ),* $(,)*
        })?
    ) => {
            #[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            $(#[$attr])*
            pub enum $name {
                $($y),+,
                $($($y1($ty),)?)?
                Unimplemented($ty),
            }

            impl From<$ty> for $name {
                #[allow(unreachable_patterns)]
                fn from(f: $ty) -> $name {
                    match f {
                        $($x => $name::$y,)+
                        $($($x1 => $name::$y1(f),)?)?
                        u => $name::Unimplemented(u),
                    }
                }
            }

            impl From<$name> for $ty {
                fn from(s: $name) -> $ty {
                    match s {
                        $($name::$y => $x,)+
                        $($($name::$y1(u) => u,)?)?
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
                        $($($name::$y1(u) => write!(f, "{} ({})", stringify!($u), u),)?)?
                        $name::Unimplemented(u) =>
                            write!(f, "unknown-{}-{}", stringify!($name), u)
                    }
                }
            }
        }
}
