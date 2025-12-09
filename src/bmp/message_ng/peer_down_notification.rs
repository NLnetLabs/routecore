use std::borrow::Cow;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::{bgp::message_ng::Update, bmp::message_ng::common::{CommonHeader, PerPeerHeader, Tlvs}};

#[derive(TryFromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct PeerDownNotification {
    pub common: CommonHeader,
    pub pph: PerPeerHeader,
    pub reason: PeerDownReason,
    pub data: [u8],
}
impl PeerDownNotification {
    pub fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>> {
        //TODO all kinds of length checks
        Self::try_ref_from_bytes(&raw).map_err(|e| e.to_string().into())
    }

    pub fn reason(&self) -> PeerDownReason {
        self.reason
    }

    pub fn notification(&self) -> Option<Result<&Update, Cow<'static, str>>> {
        if self.reason() == PeerDownReason::LOCAL_NOTIFICATION ||
            self.reason() == PeerDownReason::REMOTE_NOTIFICATION
        {
            Some(Update::try_from_full_pdu(&self.data))
        } else {
            None
        }

    }
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeerDownReason(u8);
impl PeerDownReason {
    pub const RESERVED: Self = Self(0);
    pub const LOCAL_NOTIFICATION: Self = Self(1);
    pub const LOCAL_FSM: Self = Self(2);
    pub const REMOTE_NOTIFICATION: Self = Self(3);
    pub const REMOTE_NO_DATA: Self = Self(4);
    pub const PEER_DECONFIGURED: Self = Self(5);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_down_notification() {

        // BMP PeerDownNotification type 3, containing a BGP NOTIFICATION.
        let buf = vec![
            0x03, 0x00, 0x00, 0x00, 0x46, 0x02, 0x00, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x0a,
            0x62, 0x2d, 0xea, 0x80, 0x00, 0x05, 0x58, 0x22,
            0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x00, 0x15, 0x03, 0x06, 0x02
        ];
        let msg = PeerDownNotification::try_from_full_pdu(&buf).unwrap();
        assert_eq!(msg.reason(), PeerDownReason::REMOTE_NOTIFICATION);
        assert!(msg.notification().is_some());
        //assert_eq!(msg.fsm(), None);

        //let bgp_notification = msg.notification().unwrap();
        //assert_eq!(
        //    bgp_notification.details(),
        //    CeaseSubcode::AdministrativeShutdown.into()
        //);
    }
}
