use octseq::OctetsBuilder;

use crate::bgp::message::nlri::Nlri;
use crate::bgp::message::update::{AFI, SAFI, NextHop};

use super::update::ComposeError;

// just drafting ideas, not used right now
#[allow(dead_code)]
pub mod new_pas {

    // eventually we work towards
    // enum PathAttribute {
    //     ...
    //     ...
    //     MpUnreachNlri(MpUnreachNlri),
    //     ...
    // }
    // and we macro_rules! all the enum variants and boilerplate for the
    // struct they carry in their data field.
    // 
    // We can get rid off PathAttributeType, and have one or multiple impl
    // blocks for the specific types.

    use octseq::OctetsBuilder;

    pub struct Flags { }

    impl Flags {
        // 0 1 2 3 4 5 6 7
        //
        // 0: optional (1 == optional)
        // 1: transitive (1 == transitive) (well-known attr are transitive)
        // 2: partial 
        // 3: extended length (0 -> 1 byte length, 1 -> 2 byte length)
        // 4-7: MUST be 0 when sent, ignored when received
        const OPT_NON_TRANS: u8 = 0b1000_0000;
        const OPT_NON_TRANS_EXT: u8 = 0b1001_0000;
        const WELLKNOWN: u8 = 0b0100_0000;
    }

    pub struct MpUnreachNlri { }

    impl MpUnreachNlri {
        // optional non-transitive attribute
        const TYPECODE: u8 = 15;
    }

    //--- Origin

    use crate::bgp::message::update::OriginType;
    #[derive(Debug)]
    pub struct Origin(OriginType);

    impl Origin {
        const TYPECODE: u8 = 1;
        fn value_len() -> u8 { 1 }

        pub fn new(origin_type: OriginType) -> Origin {
            Origin(origin_type)
        }

        pub fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&[
                Flags::WELLKNOWN,
                Self::TYPECODE,
                Self::value_len(),
                self.0.into()
            ]) 
        }
    }

    //--- AsPath (TODO, also see bgp::aspath)

    //--- NextHop

    use std::net::Ipv4Addr;
    #[derive(Debug)]
    pub struct NextHop(Ipv4Addr);

    impl NextHop {
        const TYPECODE: u8 = 3;
        fn value_len() -> u8 { 4 }

        pub fn new(addr: Ipv4Addr) -> NextHop {
            NextHop(addr)
        }

        pub fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
            -> Result<(), Target::AppendError>
        {
            target.append_slice(&[
                Flags::WELLKNOWN,
                Self::TYPECODE,
                Self::value_len()
            ])?;
            target.append_slice(&self.0.octets())
        }
    }


}


//------------ MpReachNlriBuilder --------------------------------------------
// See notes at MpUnreachNlriBuilder, these also apply here.
//
// Additionally, the MpReachNlri attribute contains the nexthop information.
// The nexthop semantics can not always be derived from the AFI/SAFI tuple,
// i.e. for IPv6 unicast the nexthop might contain two addresses (one global
// and one link-local). The global address will always be there, the
// link-local is optional. 
//
// Now whether or not the additional link-local is necessary might not be
// known at the time we build the UPDATE PDU. Therefore we reserve 16 bytes
// for a LL address, to prevent ending up with a PDU larger than the max pdu
// size allowed on the BGP session.


#[derive(Debug)]
pub struct MpReachNlriBuilder {
    announcements: Vec<Nlri<Vec<u8>>>,
    len: usize, // size of value, excluding path attribute flags+typecode+len
    extended: bool,
    afi: AFI,
    safi: SAFI,
    nexthop: NextHop,
    addpath_enabled: bool,
}

impl MpReachNlriBuilder {
    pub fn new(
        afi: AFI,
        safi: SAFI,
        nexthop: NextHop,
        addpath_enabled: bool,
    ) -> Self {
        // For now, we only do v4/v6 unicast and multicast.
        if !matches!(
            (afi, safi),
            (AFI::Ipv4 | AFI::Ipv6, SAFI::Unicast | SAFI::Multicast)
            )
        {
            unimplemented!()
        }

        MpReachNlriBuilder {
            announcements: vec![],
            // 3 bytes for AFI+SAFI, nexthop len, reserved byte
            len: 3 + nexthop.compose_len() + 1,
            extended: false,
            afi,
            safi,
            nexthop,
            addpath_enabled
        }
    }

    pub fn afi_safi(&self) -> (AFI, SAFI) {
        (self.afi, self.safi)
    }

    pub fn addpath_enabled(&self) -> bool {
        self.addpath_enabled
    }

    pub fn set_nexthop(&mut self, nexthop: NextHop) {
        self.nexthop = nexthop;
    }

    pub fn add_announcement(&mut self, announcement: &Nlri<Vec<u8>>)
        -> Result<(), ComposeError>
    {
        let announcement_len = announcement.compose_len();
        if !self.extended && self.len + announcement_len > 255 {
            self.extended = true;
        }
        self.len += announcement_len;
        self.announcements.push(announcement.clone());
        Ok(())
    }

    pub fn compose_len(&self, announcement: &Nlri<Vec<u8>>) -> usize {
        let announcement_len = announcement.compose_len();
        if self.announcements.is_empty() {
            // First announcement to be added, so the total number of
            // required octets includes the path attribute flags and
            // length, the AFI/SAFI, the nexthop field, and the reserved byte.
            let nh_len = self.nexthop.compose_len();
            return announcement_len + 3 + 3 + nh_len + 1;
        }

        if !self.extended && self.len + announcement_len > 255 {
            // Adding this announcement would make the path attribute exceed
            // 255 and thus require the Extended Length bit to be set.
            // This adds a second byte to the path attribute length field,
            // so we need to account for that.
            return announcement_len + 1;
        }
        announcement_len
    }

    pub fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = self.len.to_be_bytes();

        if self.extended {
            // FIXME this assumes usize is 64bits
            target.append_slice(&[0b1001_0000, 14, len[6], len[7]])
        } else {
            target.append_slice(&[0b1000_0000, 14, len[7]])
        }?;

        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;
        self.nexthop.compose(target)?;

        // Reserved byte:
        target.append_slice(&[0x00])?;

        for w in &self.announcements {
            match w {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!()
            }
        }
        Ok(())
    }
}

// **NB:** This is bgp::message::update::NextHop, _not_ new_pas::NextHop
impl NextHop {
    fn compose_len(&self) -> usize {
        // 1 byte for the length, plus:
        1 + match *self {
            NextHop::Ipv4(_) => 4, 
            NextHop::Ipv6(_) => 16,
            NextHop::Ipv6LL(_, _) => 32,
            _ => unimplemented!()
            //NextHop::Ipv4MplsVpnUnicast(RouteDistinguisher, Ipv4Addr),
            //NextHop::Ipv6MplsVpnUnicast(RouteDistinguisher, Ipv6Addr),
            //NextHop::Empty, // FlowSpec
            //NextHop::Unimplemented(AFI, SAFI),
        }
    }

    pub fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[u8::try_from(self.compose_len()).unwrap() - 1])?;
        match *self {
            NextHop::Ipv4(a) => target.append_slice(&a.octets())?,
            NextHop::Ipv6(a) => target.append_slice(&a.octets())?,
            NextHop::Ipv6LL(a, ll) => {
                target.append_slice(&a.octets())?;
                target.append_slice(&ll.octets())?;
            }
            _ => unimplemented!()
        }

        Ok(())
    }

}


//------------ MpUnreachNlriBuilder ------------------------------------------

// Note that all to-be-withdrawn NLRI should either have no PathID, or have a
// PathID. We can not mix non-addpath and addpath NLRI.
// Note that:
//  - add path works on a afi/safi level for a session, so a peer could do
//    addpath for v4 unicast but not for v6 unicast.
//  - in the Capability in the BGP OPEN, a peer can signal to be able to
//    receive, send, or receive+send add path NLRI. So, if we create methods
//    that take a NegotiatedConfig, the modification methods like
//    add_withdrawal should check whether the remote side is able to receive
//    path ids if the Nlri passed to add_withdrawal contains Some(PathId).
//
#[derive(Debug)]
pub struct MpUnreachNlriBuilder {
    withdrawals: Vec<Nlri<Vec<u8>>>,
    len: usize, // size of value, excluding path attribute flags+typecode+len
    extended: bool,
    afi: AFI,
    safi: SAFI,
    addpath_enabled: bool,
}

impl MpUnreachNlriBuilder {
    pub fn new(afi: AFI, safi: SAFI, addpath_enabled: bool) -> Self {
        MpUnreachNlriBuilder {
            withdrawals: vec![],
            len: 3, // 3 bytes for AFI+SAFI
            extended: false,
            afi,
            safi,
            addpath_enabled
        }
    }

    pub fn afi_safi(&self) -> (AFI, SAFI) {
        (self.afi, self.safi)
    }

    pub fn addpath_enabled(&self) -> bool {
        self.addpath_enabled
    }

    pub fn add_withdrawal(&mut self, withdrawal: &Nlri<Vec<u8>>)
        -> Result<(), ComposeError>
    {
        let withdrawal_len = withdrawal.compose_len();
        if !self.extended && self.len + withdrawal_len > 255 {
            self.extended = true;
        }
        self.len += withdrawal_len;
        self.withdrawals.push(withdrawal.clone());
        Ok(())
    }

    pub fn compose_len(&self, withdrawal: &Nlri<Vec<u8>>) -> usize {
        let withdrawal_len = withdrawal.compose_len();
        if self.withdrawals.is_empty() {
            // First withdrawal to be added, so the total number of
            // required octets includes the path attribute flags and
            // length, and the AFI/SAFI.
            return withdrawal_len + 3 + 3;
        }

        if !self.extended && self.len + withdrawal_len > 255 {
            // Adding this withdrawal would make the path attribute exceed
            // 255 and thus require the Extended Length bit to be set.
            // This adds a second byte to the path attribute length field,
            // so we need to account for that.
            return withdrawal_len + 1;
        }
        withdrawal_len
    }

    pub fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = self.len.to_be_bytes();

        if self.extended {
            // FIXME this assumes usize is 64bits
            target.append_slice(&[0b1001_0000, 15, len[6], len[7]])
        } else {
            target.append_slice(&[0b1000_0000, 15, len[7]])
        }?;

        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;

        for w in &self.withdrawals {
            match w {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!()
            }
        }
        Ok(())
    }
}
