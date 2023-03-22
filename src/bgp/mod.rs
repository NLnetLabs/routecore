//! Record types and traits for BGP packets
//!
//! These type and traits built on top of the `Record` type specifically to
//! handle BGP packets.
//!
//! example:
//! BGP packet → disassemble into records → turn into message will translate
//! into:
//!
//! ```BGP { NLRI; AS_PATH; MP_REACH_NLRI; MP_UNREACH_NLRI; etc } →```
//!
//! | Record | Content |
//! |--------|---------|
//! | 1      | { key: WITHDRAW_Prefix; meta: NoMeta } |
//! | 2      | { key: NLRI; meta: Bgpttributes } |
//! | 3      | { key: MP_REACH_NLRI; meta: BgpExtAttributes } |
//! | 4      | { key: MP_UNREACH_NLRI; meta: BgpExtAttributes } |
//!
//! --- or ---
//!
//! | Record | Content |
//! |--------|---------|
//! | 1 | { key: WITHDRAW_Prefix; meta: NoMeta } |
//! | 2 | { key: NLRI_Prefix#1; meta: &Bgpttributes } |
//! | 3 | { key: NLRI_Prefix#2; meta: &Bgpttributes } |
//! | 4 | { key: NLRI_Prefix#3; meta: &Bgpttributes } |
//! | 5 | { key: MP_REACH_NLRI_Prefix#1; meta: BgpExtAttributes } |
//! | 6 | { key: MP_REACH_NLRI_Prefix#2; meta: BgpExtAttributes } |
//! | 4 | { key: MP_UNREACH_NLRI_Prefix#1; meta: NoMeta } |

mod meta;
mod prefix_record;
mod route;

pub mod aspath;
pub mod communities;
pub mod types;

pub mod message;
pub use crate::util::parser::ParseError;

pub use self::meta::*;
pub use self::prefix_record::*;
pub use self::route::*;
