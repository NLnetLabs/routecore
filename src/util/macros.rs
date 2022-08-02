#[macro_export]
macro_rules! typeenum {
    ($(#[$attr:meta])* $name:ident, $ty:ty, $($x:expr => $y:ident),+ $(,)*) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
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
