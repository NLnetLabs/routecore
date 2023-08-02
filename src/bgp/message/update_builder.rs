use octseq::OctetsBuilder;

use crate::bgp::message::nlri::Nlri;
use crate::bgp::message::update::{AFI, SAFI};

use super::update::ComposeError;

// just drafting ideas, not used right now
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
    }

    pub struct MpUnreachNlri { }

    impl MpUnreachNlri {
        // optional non-transitive attribute
        const TYPECODE: u8 = 15;
    }

}

//------------ MpUnreachNlriBuilder ------------------------------------------

#[derive(Debug)]
pub struct MpUnreachNlriBuilder {
    withdrawals: Vec<Nlri<Vec<u8>>>,
    len: usize, // len of value, excluding other path attribute bytes
    extended: bool,
    afi: AFI,
    safi: SAFI,
}

impl MpUnreachNlriBuilder {
    pub fn new(afi: AFI, safi: SAFI) -> MpUnreachNlriBuilder {
        MpUnreachNlriBuilder {
            withdrawals: vec![],
            len: 3, // 3 bytes for AFI+SAFI
            extended: false,
            afi,
            safi
        }
    }

    pub fn afi_safi(&self) -> (AFI, SAFI) {
        (self.afi, self.safi)
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
            target.append_slice(&[0b1001_0000, 15, len[6], len[7]])
        } else {
            target.append_slice(&[0b1000_0000, 15, len[7]])
        }?;

        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;

        for w in &self.withdrawals {
            match w {
                Nlri::Basic(b) => {
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
