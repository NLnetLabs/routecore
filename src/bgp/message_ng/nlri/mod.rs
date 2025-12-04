mod common;

mod ipv4unicast;
mod ipv6unicast;
mod flowspec;
mod bgp_ls;

// XXX figure out what to actually re-export at some point
pub use ipv4unicast::*;
pub use ipv6unicast::*;
pub use flowspec::*;
pub use bgp_ls::*;

pub use common::{Nlri, NlriIter, NlriIterator, NlriAddPathIter, NlriHints, CustomNlriIter, CustomNlriAddPathIter, PathId};
