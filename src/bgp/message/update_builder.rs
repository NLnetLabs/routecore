use std::convert::Infallible;
use std::fmt;
use std::iter::Peekable;
use std::net::{IpAddr, Ipv6Addr};

use bytes::BytesMut;
use octseq::{FreezeBuilder, Octets, OctetsBuilder, ShortBuf};

use crate::bgp::aspath::AsPath;
use crate::bgp::communities::StandardCommunity;
use crate::bgp::message::{Header, MsgType, SessionConfig, UpdateMessage};
use crate::bgp::message::attr_change_set::AttrChangeSet;
use crate::bgp::message::nlri::Nlri;
use crate::bgp::message::update::{AFI, SAFI, NextHop};
use crate::bgp::types::OriginType;
use crate::util::parser::ParseError;

//use rotonda_fsm::bgp::session::AgreedConfig;

use crate::bgp::path_attributes as new_pas;
use new_pas::PathAttributeType;
use new_pas::Attribute; // trait

//------------ UpdateBuilder -------------------------------------------------
#[derive(Debug)]
pub struct UpdateBuilder<Target> {
    target: Target,
    //config: AgreedConfig, //FIXME this lives in rotonda_fsm, but that
    //depends on routecore. Sounds like a depedency hell.
    announcements: Vec<Nlri<Vec<u8>>>,
    announcements_len: usize,
    withdrawals: Vec<Nlri<Vec<u8>>>,
    withdrawals_len: usize,
    addpath_enabled: Option<bool>, // for conventional nlri (unicast v4)
    //attributes: Vec<PathAttribute<'a, Vec<u8>>>, // XXX this lifetime is..
                                                    //not nice
    // attributes:
    origin: Option<new_pas::Origin>,
    aspath: Option<AsPath<Vec<u8>>>,
    nexthop: Option<new_pas::NextHop>,
    multi_exit_disc: Option<new_pas::MultiExitDisc>,
    local_pref: Option<new_pas::LocalPref>,

    standard_communities_builder: Option<StandardCommunitiesBuilder>,

    attributes_len: usize,
    total_pdu_len: usize,

    // MP_REACH_NLRI and MP_UNREACH_NLRI can only occur once (like any path
    // attribute), and can carry only a single tuple of (AFI, SAFI).
    // My interpretation of RFC4760 means one can mix conventional
    // NLRI/withdrawals (so, v4 unicast) with one other (AFI, SAFI) in an
    // MP_(UN)REACH_NLRI path attribute.
    // Question is: can one also put (v4, unicast) in an MP_* attribute, and,
    // then also in the conventional part (at the end of the PDU)? 
    mp_reach_nlri_builder: Option<MpReachNlriBuilder>,
    mp_unreach_nlri_builder: Option<MpUnreachNlriBuilder>,
}

impl<Target: OctetsBuilder> UpdateBuilder<Target> {

    const MAX_PDU: usize = 4096; // XXX should come from NegotiatedConfig

    pub fn from_target(mut target: Target) -> Result<Self, ShortBuf> {
        //target.truncate(0);
        let mut h = Header::<&[u8]>::new();
        h.set_length(19 + 2 + 2);
        h.set_type(MsgType::Update);
        let _ =target.append_slice(h.as_ref());

        Ok(UpdateBuilder {
            target,
            announcements: Vec::new(),
            announcements_len: 0,
            withdrawals: Vec::new(),
            withdrawals_len: 0,
            addpath_enabled: None,

            //attributes:
            origin: None,
            aspath: None,
            nexthop: None,
            multi_exit_disc: None,
            local_pref: None,

            standard_communities_builder: None,

            attributes_len: 0,
            total_pdu_len: 19 + 2 + 2,
            mp_reach_nlri_builder: None,
            mp_unreach_nlri_builder: None,
        })
    }

    //--- Withdrawals

    pub fn add_withdrawal(&mut self, withdrawal: &Nlri<Vec<u8>>)
        -> Result<(), ComposeError>
    {
        //println!("add_withdrawal for {}", withdrawal.prefix().unwrap());
        match *withdrawal {
            Nlri::Unicast(b) => {
                if b.is_v4() {
                    if let Some(addpath_enabled) = self.addpath_enabled {
                        if addpath_enabled != b.is_addpath() {
                            return Err(ComposeError::IllegalCombination)
                        }
                    } else {
                        self.addpath_enabled = Some(b.is_addpath());
                    }

                    let new_bytes_num = withdrawal.compose_len();
                    let new_total = self.total_pdu_len + new_bytes_num;
                    if new_total > Self::MAX_PDU {
                        return Err(ComposeError::PduTooLarge(new_total));
                    }
                    self.withdrawals.push(withdrawal.clone());
                    self.withdrawals_len += new_bytes_num;
                    self.total_pdu_len = new_total;
                } else {
                    // Nlri::Unicast only holds IPv4 and IPv6, so this must be
                    // IPv6.
                    let new_bytes_num = match self.mp_unreach_nlri_builder {
                        None => {
                            let builder = MpUnreachNlriBuilder::new(
                                AFI::Ipv6, SAFI::Unicast,
                                b.is_addpath()
                            );
                            let res = builder.compose_len(withdrawal);
                            self.mp_unreach_nlri_builder = Some(builder);
                            res
                            
                        }
                        Some(ref builder) => {
                            if !builder.valid_combination(
                                AFI::Ipv6, SAFI::Unicast, b.is_addpath()
                            ) {
                                // We are already constructing a
                                // MP_UNREACH_NLRI but for a different
                                // AFI,SAFI than the prefix in `withdrawal`,
                                // or we are mixing addpath with non-addpath.
                                return Err(ComposeError::IllegalCombination);
                            }
                            builder.compose_len(withdrawal)
                        }
                    };

                    let new_total = self.total_pdu_len + new_bytes_num;

                    if new_total > Self::MAX_PDU {
                        return Err(ComposeError::PduTooLarge(new_total));
                    }

                    if let Some(ref mut builder) = self.mp_unreach_nlri_builder {
                        builder.add_withdrawal(withdrawal);
                        self.attributes_len += new_bytes_num;
                        self.total_pdu_len = new_total;
                    } else {
                        // We always have Some builder at this point.
                        unreachable!()
                    }
                }

            }
            _ => todo!() // TODO use the MpUnreachNlriBuilder for these
        };
        Ok(())
    }

    pub fn withdrawals_from_iter<I>(&mut self, withdrawals: &mut Peekable<I>)
        -> Result<(), ComposeError>
    where I: Iterator<Item = Nlri<Vec<u8>>>
    {
        while let Some(w) = withdrawals.peek() {
            match self.add_withdrawal(w) {
                Ok(_) => { withdrawals.next(); }
                Err(e) => return Err(e)
            }
        }
        Ok(())
    }

    pub fn append_withdrawals(&mut self, withdrawals: &mut Vec<Nlri<Vec<u8>>>)
        -> Result<(), ComposeError>
    {
        for (idx, w) in withdrawals.iter().enumerate() {
            if let Err(e) = self.add_withdrawal(w) {

                *withdrawals = withdrawals[idx..].to_vec();
                return Err(e);
            }
        }
        Ok(())
    }

    //--- Path Attributes

    pub fn set_origin(&mut self, origin: OriginType)
        -> Result<(), ComposeError>
    {
        if self.origin.is_none() {
            // Check if this goes over the total PDU len. That will happen
            // before we will go over the u16 for Total Path Attributes Length
            // so we don't have to check for that.
            let new_total = self.total_pdu_len + 4; // XXX should this 4 come
                                                    // from a
                                                    // `fn compose_len()` on
                                                    // the attribute itself
                                                    // perhaps?
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            } else {
                self.total_pdu_len = new_total;
                self.attributes_len += 4
            }
        }
        self.origin = Some(new_pas::Origin::new(origin));
        Ok(())
    }

    pub fn set_aspath<Octs>(&mut self , aspath: AsPath<Vec<u8>>)
        -> Result<(), ComposeError>
    {
        if aspath.compose_len() > u16::MAX.into()  {
            return Err(ComposeError::AttributeTooLarge(
                 new_pas::PathAttributeType::AsPath, aspath.compose_len()
            ));
        }
        if let Some(old_aspath) = &self.aspath {
            let new_total = self.total_pdu_len
                - old_aspath.compose_len()
                + aspath.compose_len();
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            } else {
                self.total_pdu_len -= old_aspath.compose_len();
                self.attributes_len -= old_aspath.compose_len();
            }
        }
        self.attributes_len += aspath.compose_len();
        self.total_pdu_len += aspath.compose_len();
        self.aspath = Some(aspath);
        Ok(())
    }

    pub fn set_nexthop(&mut self, addr: IpAddr) -> Result<(), ComposeError> {
        // Depending on the variant of `addr` we add/update either:
        // - the conventional NEXT_HOP path attribute (IPv4); or
        // - we update/create a MpReachNlriBuilder (IPv6)
        match addr {
            IpAddr::V4(a) => {
                if self.nexthop.is_none() {
                    // NEXT_HOP path attribute is 7 bytes long.
                    let new_total = self.total_pdu_len + 7;
                    if new_total > Self::MAX_PDU {
                        return Err(ComposeError::PduTooLarge(new_total));
                    } else {
                        self.total_pdu_len = new_total;
                        self.attributes_len += 7
                    }
                    self.nexthop = Some(new_pas::NextHop::new(a));
                }
            }
            IpAddr::V6(a) => {
                if let Some(ref mut builder) = self.mp_reach_nlri_builder {
                    // Given that we have a builder, there is already either a
                    // NextHop::Ipv6 or a NextHop::Ipv6LL. Setting the
                    // non-link-local address does not change the length of
                    // the next hop part, so there is no need to update the
                    // total_pdu_len and the attributes_len.
                    builder.set_nexthop(a);
                } else {
                    let builder = MpReachNlriBuilder::new(
                        AFI::Ipv6, SAFI::Unicast, NextHop::Ipv6(a), false
                        );
                    let new_bytes = builder.compose_len_empty();
                    let new_total = self.total_pdu_len + new_bytes;
                    if new_total > Self::MAX_PDU {
                        return Err(ComposeError::PduTooLarge(new_total));
                    }
                    self.attributes_len += new_bytes;
                    self.total_pdu_len = new_total;
                    self.mp_reach_nlri_builder = Some(builder);
                }
            }
        }
        Ok(())
    }

    pub fn set_nexthop_ll(&mut self, addr: Ipv6Addr)
        -> Result<(), ComposeError>
    {
        // XXX We could/should check for addr.is_unicast_link_local() once
        // that lands in stable.
        
        if let Some(ref mut builder) = self.mp_reach_nlri_builder {
            let new_bytes = match builder.get_nexthop() {
                NextHop::Ipv6(_) => 16,
                NextHop::Ipv6LL(_,_) => 0,
                _ => unreachable!()
            };

            let new_total = self.total_pdu_len + new_bytes;
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            }
            builder.set_nexthop_ll(addr);
            self.attributes_len += new_bytes;
            self.total_pdu_len = new_total;
        } else {
            let builder = MpReachNlriBuilder::new(
                AFI::Ipv6, SAFI::Unicast, NextHop::Ipv6LL(0.into(), addr),
                false
            );
            let new_bytes = builder.compose_len_empty();
            let new_total = self.total_pdu_len + new_bytes;
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            }
            self.attributes_len += new_bytes;
            self.total_pdu_len = new_total;
            self.mp_reach_nlri_builder = Some(builder);
        }

        Ok(())
    }

    pub fn set_multi_exit_disc(&mut self, med: new_pas::MultiExitDisc)
    -> Result<(), ComposeError>
    {
        let new_bytes = med.compose_len();
        let new_total = self.total_pdu_len + new_bytes;
        if new_total > Self::MAX_PDU {
            return Err(ComposeError::PduTooLarge(new_total));
        }
        self.multi_exit_disc = Some(med);
        self.total_pdu_len = new_total;
        self.attributes_len += new_bytes;
        Ok(())
    }

    pub fn set_local_pref(&mut self, local_pref: new_pas::LocalPref)
    -> Result<(), ComposeError>
    {
        let new_bytes = local_pref.compose_len();
        let new_total = self.total_pdu_len + new_bytes;
        if new_total > Self::MAX_PDU {
            return Err(ComposeError::PduTooLarge(new_total));
        }
        self.local_pref = Some(local_pref);
        self.total_pdu_len = new_total;
        self.attributes_len += new_bytes;
        Ok(())
    }


    //--- Announcements

    pub fn add_announcement(&mut self, announcement: &Nlri<Vec<u8>>)
        -> Result<(), ComposeError>
    {
        match *announcement {
            Nlri::Unicast(b) => {
                if b.is_v4() {
                    if let Some(addpath_enabled) = self.addpath_enabled {
                        if addpath_enabled != b.is_addpath() {
                            return Err(ComposeError::IllegalCombination)
                        }
                    } else {
                        self.addpath_enabled = Some(b.is_addpath());
                    }

                    let new_bytes_num = announcement.compose_len();
                    let new_total = self.total_pdu_len + new_bytes_num;
                    if new_total > Self::MAX_PDU {
                        return Err(ComposeError::PduTooLarge(new_total));
                    }
                    self.announcements.push(announcement.clone());
                    self.announcements_len += new_bytes_num;
                    self.total_pdu_len = new_total;
                    
                } else {
                    // Nlri::Unicast only holds IPv4 and IPv6, so this must be
                    // IPv6 unicast.

                    let new_bytes_num = match self.mp_reach_nlri_builder {
                        None => {
                            let nexthop = NextHop::Ipv6(0.into());
                            let builder = MpReachNlriBuilder::new(
                                AFI::Ipv6, SAFI::Unicast,
                                nexthop,
                                b.is_addpath()
                            );
                            let res = builder.compose_len_empty() + 
                                builder.compose_len(announcement);
                            self.mp_reach_nlri_builder = Some(builder);
                            res
                            
                        }
                        Some(ref builder) => {
                            //TODO we should allow multicast here, but then we
                            //should also check whether a prefix is_multicast.
                            //Similarly, should we check for is_unicast?
                            //Or should we handle anything other than unicast
                            //in the outer match anyway, as that is never a
                            //conventional announcement anyway?
                            
                            if !builder.valid_combination(
                                AFI::Ipv6, SAFI::Unicast, b.is_addpath()
                            ) {
                                return Err(ComposeError::IllegalCombination);
                            }

                            builder.compose_len(announcement)
                        }
                    };

                    let new_total = self.total_pdu_len + new_bytes_num;

                    if new_total > Self::MAX_PDU {
                        return Err(ComposeError::PduTooLarge(new_total));
                    }

                    if let Some(ref mut builder) = self.mp_reach_nlri_builder {
                        builder.add_announcement(announcement);
                        self.attributes_len += new_bytes_num;
                        self.total_pdu_len = new_total;
                    } else {
                        // We always have Some builder at this point.
                        unreachable!()
                    }
                }
            }
            _ => todo!() // TODO use MpReachNlriBuilder once we have that.
        }

        Ok(())
    }

    pub fn announcements_from_iter<I>(
        &mut self, announcements: &mut Peekable<I>
    ) -> Result<(), ComposeError>
        where I: Iterator<Item = Nlri<Vec<u8>>>
    {
        while let Some(a) = announcements.peek() {
            match self.add_announcement(a) {
                Ok(_) => { announcements.next(); }
                Err(e) => return Err(e)
            }
        }
        Ok(())
    }

    //--- Standard communities
    
    pub fn add_community(&mut self, community: StandardCommunity)
        -> Result<(), ComposeError>
    {

        if let Some(ref mut builder) = self.standard_communities_builder {
            let new_bytes = builder.compose_len(community);
            let new_total = self.total_pdu_len + new_bytes;
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            }
            builder.add_community(community);
            self.attributes_len += new_bytes;
            self.total_pdu_len = new_total;
        } else {
            let mut builder = StandardCommunitiesBuilder::new();
            let new_bytes = builder.compose_len_empty()
                + builder.compose_len(community); 
            let new_total = self.total_pdu_len + new_bytes;
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            }
            builder.add_community(community);
            self.standard_communities_builder = Some(builder);
            self.attributes_len += new_bytes;
            self.total_pdu_len = new_total;
        }

        Ok(())
    }

}

impl<Target: OctetsBuilder + AsMut<[u8]>> UpdateBuilder<Target>
where Infallible: From<<Target as OctetsBuilder>::AppendError>
{
    #[deprecated]
    pub fn build_acs(mut self, acs: AttrChangeSet)
        -> Result<Target, ComposeError>
    {
        // Withdrawals
        let withdraw_len = 0_usize;
        // placeholder
        let _ = self.target.append_slice(&(withdraw_len as u16).to_be_bytes());
        //self.target.as_mut()[19..=20].copy_from_slice(
        //    &(withdraw_len as u16).to_be_bytes()
        //);
        // TODO actual withdrawals


        // Path Attributes
            // flags (from msb to lsb):
            // optional
            // transitive
            // partial
            // extended_length (2 octet length)
        
        let mut total_pa_len = 0_usize;
        // Total Path Attribute len place holder:
        let _ = self.target.append_slice(&[0x00, 0x00]);

        if let Some(origin) = acs.origin_type.into_opt() {
            let attr_flags = 0b0100_0000;
            let attr_typecode = PathAttributeType::Origin.into();
            let attr_len = 1_u8; 
            let _ = self.target.append_slice(
                &[attr_flags, attr_typecode, attr_len, origin.into()]);
            total_pa_len += 2 + 1 + usize::from(attr_len);
        }

        if let Some(as_path) = acs.as_path.into_opt() {
            let attr_flags = 0b0101_0000;
            let attr_typecode = PathAttributeType::AsPath.into();
            let asp = as_path.into_inner();
            let attr_len = asp.len();
            if u16::try_from(attr_len).is_err() {
                return Err(ComposeError::AttributeTooLarge(
                    PathAttributeType::AsPath,
                    attr_len
                ));
            }
            let _ = self.target.append_slice(&[attr_flags, attr_typecode]);
            let _ = self.target.append_slice(&(attr_len as u16).to_be_bytes());
            let _ = self.target.append_slice(&asp);

            total_pa_len += 2 + 2 + attr_len;
        }


        // XXX the next_hop is either a (conventional, for v4/unicast) path
        // attribute, or, it is part of MP_REACH_NLRI.
        // Should/must v4/unicast always go in MP_REACH_NLRI when both peers
        // sent such capability though?
        if let Some(next_hop) = acs.next_hop.into_opt() {
            match next_hop {
                NextHop::Ipv4(v4addr) => {
                    let attr_flags = 0b0100_0000;
                    let attr_typecode = PathAttributeType::NextHop.into();
                    let attr_len = 4_u8; 

                    let _ = self.target.append_slice(
                        &[attr_flags, attr_typecode, attr_len]
                    );
                    let _ = self.target.append_slice(&v4addr.octets());

                    total_pa_len += 2 + 1 + usize::from(attr_len);
                }
                _ => todo!() // this is MP_REACH_NLRI territory
            }
        }


        if let Some(comms) = acs.standard_communities.into_opt() {
            let attr_flags = 0b0100_0000;
            let attr_typecode = PathAttributeType::Communities.into();
            let attr_len = match u8::try_from(4 * comms.len()) {
                Ok(n) => n,
                Err(..) => {
                    return Err(ComposeError::AttributeTooLarge(
                        PathAttributeType::Communities,
                        4 * comms.len()
                    ));
                }
            };

            let _ = self.target.append_slice(
                &[attr_flags, attr_typecode, attr_len]
            );

            for c in comms {
                let _ = self.target.append_slice(&c.to_raw());
            }
            total_pa_len += 2 + 1 + usize::from(attr_len);
        }


        if u16::try_from(total_pa_len).is_err() {
            return Err(ComposeError::AttributesTooLarge(total_pa_len));
        }

        // update total path attribute len:
        self.target.as_mut()[21+withdraw_len..21+withdraw_len+2]
            .copy_from_slice(&(total_pa_len as u16).to_be_bytes());


        // NLRI
        // TODO this all needs to be a lot more sophisticated:
        //  - prefixes can not occur in both withdrawals and nlris, so check
        //  for that;
        //  - non v4/unicast NLRI should go in MP_REACH_NLRI, not here (at the
        //  end of the PDU);
        //  - we should be able to put multiple NLRI in one UPDATE, though
        //  currently the AttrChangeSet only holds one;
        //  - probably more
        
        let mut nlri_len = 0;

        if let Some(nlri) = acs.nlri.into_opt() {
            match nlri {
                Nlri::Unicast(b) => {
                    if let Some(id) = b.path_id() {
                        let _ = self.target.append_slice(&id.to_raw());
                        nlri_len += 4;
                    }
                    match b.prefix().addr_and_len() {
                        (std::net::IpAddr::V4(addr), len) => {
                            let _ = self.target.append_slice(&[len]);
                            let len_bytes = (usize::from(len)-1) / 8 + 1;
                            let _ = self.target.append_slice(
                                &addr.octets()[0..len_bytes]
                            );
                            nlri_len += 1 + len_bytes;
                        }
                        _ => todo!()
                    }
                }
                _ => todo!()
            }
        }

        // update pdu len
        let msg_len = 19 
            + 2 + withdraw_len 
            + 2 + total_pa_len
            + nlri_len
        ;

        if msg_len > 4096 {
            // TODO handle Extended Messages (max pdu size 65535)
            return Err(ComposeError::PduTooLarge(msg_len));
        }

        //if u16::try_from(msg_len).is_err() {
        //    return Err(ComposeError::PduTooLarge(msg_len));
        //}

        self.target.as_mut()[16..=17].copy_from_slice(
            &(msg_len as u16).to_be_bytes()
        );

        Ok(self.target)
    }
}

impl<Target> UpdateBuilder<Target>
where
    Target: OctetsBuilder + FreezeBuilder + AsMut<[u8]>,
    <Target as FreezeBuilder>::Octets: Octets,
{
    pub fn into_message(self) ->
        Result<UpdateMessage<<Target as FreezeBuilder>::Octets>, ComposeError>
    where
        Target: FreezeBuilder,
        <Target as FreezeBuilder>::Octets: Octets,
    {
        self.is_valid()?;
        Ok(UpdateMessage::from_octets(
            self.finish().map_err(|_| ShortBuf)?, SessionConfig::modern()
        )?)
    }

    // Check whether the combination of NLRI and attributes would produce a
    // valid UPDATE pdu.
    fn is_valid(&self) -> Result<(), ComposeError> {
        // If we have builders for MP_(UN)REACH_NLRI, they should carry
        // prefixes.
        if let Some(ref builder) = self.mp_reach_nlri_builder {
            if builder.is_empty() {
                return Err(ComposeError::EmptyMpReachNlri);
            }
        }
        if let Some(ref builder) = self.mp_unreach_nlri_builder {
            if builder.is_empty() {
                return Err(ComposeError::EmptyMpUnreachNlri);
            }
        }

        Ok(())
    }

    fn finish(mut self)
        -> Result<<Target as FreezeBuilder>::Octets, Target::AppendError>
    {
        let mut header = Header::for_slice_mut(self.target.as_mut());
        header.set_length(u16::try_from(self.total_pdu_len).unwrap());

        // `withdrawals_len` is checked to be <= 4096 or <= 65535
        // so it will always fit in a u16.
        self.target.append_slice(
            &u16::try_from(self.withdrawals_len).unwrap().to_be_bytes()
        )?;

        for w in &self.withdrawals {
            match w {
                Nlri::Unicast(b) => {
                    if b.is_v4() {
                        b.compose(&mut self.target)?;
                    } else {
                        // Other withdrawals should not go here, but in
                        // MP_UNREACH_NLRI. Handling these ones below in the
                        // path attributes.
                    }
                },
                _ => todo!(),
            }
        }



        // XXX we can do these unwraps because of the checks in the add/append
        // methods

        // `attributes_len` is checked to be <= 4096 or <= 65535
        // so it will always fit in a u16.
        let _ = self.target.append_slice(
            &u16::try_from(self.attributes_len).unwrap().to_be_bytes()
        );

        // TODO write all path attributes, if any, in order of typecode

        if let Some(origin) = self.origin {
            origin.compose(&mut self.target)?
        }

        if let Some(aspath) = self.aspath {
            aspath.compose(&mut self.target)?
        }

        if let Some(nexthop) = self.nexthop {
            nexthop.compose(&mut self.target)?
        }

        if let Some(med) = self.multi_exit_disc {
            med.compose(&mut self.target)?
        }

        if let Some(local_pref) = self.local_pref {
            local_pref.compose(&mut self.target)?
        }

        if let Some(builder) = self.standard_communities_builder {
            builder.compose(&mut self.target)?
        }

        if let Some(builder) = self.mp_reach_nlri_builder {
            builder.compose(&mut self.target)?
        }

        if let Some(builder) = self.mp_unreach_nlri_builder {
            builder.compose(&mut self.target)?
        }

        // XXX Here, in the conventional NLRI field at the end of the PDU, we
        // write IPv4 Unicast announcements. But what if we have agreed to do
        // MP for v4/unicast, should these announcements go in the
        // MP_REACH_NLRI attribute then instead?
        for a in &self.announcements {
            match a {
                Nlri::Unicast(b) => {
                    if b.is_v4() {
                        b.compose(&mut self.target)?;
                    } else {
                        // Other announcements should not go here, but in
                        // MP_REACH_NLRI, handled before in the path
                        // attributes.
                    }
                },
                _ => todo!(),
            }
        }

        Ok(self.target.freeze())
    }
}

impl UpdateBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::from_target(Vec::with_capacity(23)).unwrap()
    }
}

impl UpdateBuilder<BytesMut> {
    pub fn new_bytes() -> Self {
        Self::from_target(BytesMut::new()).unwrap()
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


#[derive(Debug, Eq, PartialEq)]
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


    // Minimal required size for a meaningful MP_REACH_NLRI. This comprises
    // the attribute flags/size/type (3 bytes), a IPv6 nexthop (17), reserved
    // byte (1) and then space for at least an IPv6 /48 announcement (7)
    //pub const MIN_SIZE: usize = 3 + 17 + 1 + 7;

    pub(crate) fn new(
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

    pub(crate) fn value_len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }

    pub(crate) fn get_nexthop(&self) -> &NextHop {
        &self.nexthop
    }

    pub(crate) fn set_nexthop(&mut self, addr: Ipv6Addr) {
        match self.nexthop {
            NextHop::Ipv6(_) => self.nexthop = NextHop::Ipv6(addr),
            NextHop::Ipv6LL(_, ll) => {
                self.nexthop = NextHop::Ipv6LL(addr, ll)
            }
            _ => unimplemented!()
        }
    }

    pub(crate) fn set_nexthop_ll(&mut self, addr: Ipv6Addr) {
        match self.nexthop {
            NextHop::Ipv6(a) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
                self.len += 16;
            }
            NextHop::Ipv6LL(a, _ll) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
            }
            _ => unreachable!()
        }
    }

    pub(crate) fn valid_combination(
        &self, afi: AFI, safi: SAFI, is_addpath: bool
    ) -> bool {
        self.afi == afi
        && self.safi == safi
        && (self.announcements.is_empty()
             || self.addpath_enabled == is_addpath)
    }

    pub(crate) fn add_announcement(&mut self, announcement: &Nlri<Vec<u8>>)
        //-> Result<(), ComposeError>
    {
        let announcement_len = announcement.compose_len();
        if !self.extended && self.len + announcement_len > 255 {
            self.extended = true;
        }
        self.len += announcement_len;
        self.announcements.push(announcement.clone());
        //Ok(())
    }

    pub(crate) fn compose_len_empty(&self) -> usize {
        3 + 3 + self.nexthop.compose_len() + 1
    }


    pub(crate) fn compose_len(&self, announcement: &Nlri<Vec<u8>>) -> usize {
        let announcement_len = announcement.compose_len();
        if !self.extended && self.len + announcement_len > 255 {
            // Adding this announcement would make the path attribute exceed
            // 255 and thus require the Extended Length bit to be set.
            // This adds a second byte to the path attribute length field,
            // so we need to account for that.
            return announcement_len + 1;
        }
        announcement_len
    }

    pub(crate) fn compose_value<Target: OctetsBuilder>(
        &self,
        target: &mut Target
    ) -> Result<(), Target::AppendError>
    {
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

    // XXX can we get rid of this once MpReachNlri is supported in the new_pas
    // PathAttribute enum?
    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
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

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
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
#[derive(Debug, Eq, PartialEq)]
pub struct MpUnreachNlriBuilder {
    withdrawals: Vec<Nlri<Vec<u8>>>,
    len: usize, // size of value, excluding path attribute flags+typecode+len
    extended: bool,
    afi: AFI,
    safi: SAFI,
    addpath_enabled: bool,
}

impl MpUnreachNlriBuilder {
    pub(crate) fn new(afi: AFI, safi: SAFI, addpath_enabled: bool) -> Self {
        MpUnreachNlriBuilder {
            withdrawals: vec![],
            len: 3, // 3 bytes for AFI+SAFI
            extended: false,
            afi,
            safi,
            addpath_enabled
        }
    }

    pub(crate) fn value_len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.withdrawals.is_empty()
    }

    pub(crate) fn valid_combination(
        &self, afi: AFI, safi: SAFI, is_addpath: bool
    ) -> bool {
        self.afi == afi
        && self.safi == safi
        && (self.withdrawals.is_empty()
             || self.addpath_enabled == is_addpath)
    }

    pub(crate) fn add_withdrawal(&mut self, withdrawal: &Nlri<Vec<u8>>)
        //-> Result<(), ComposeError>
    {
        let withdrawal_len = withdrawal.compose_len();
        if !self.extended && self.len + withdrawal_len > 255 {
            self.extended = true;
        }
        self.len += withdrawal_len;
        self.withdrawals.push(withdrawal.clone());
        //Ok(())
    }

    pub(crate) fn compose_len(&self, withdrawal: &Nlri<Vec<u8>>) -> usize {
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

    pub(crate) fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
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

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
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

//------------ StandardCommunitiesBuilder ------------------------------------
//
//

#[derive(Debug)]
pub(crate) struct StandardCommunitiesBuilder {
    communities: Vec<StandardCommunity>,
    len: usize, // size of value, excluding path attribute flags+typecode+len
    extended: bool,
}

impl StandardCommunitiesBuilder {
    pub(crate) fn new() -> StandardCommunitiesBuilder {
        StandardCommunitiesBuilder {
            communities: Vec::new(),
            len: 0,
            extended: false
        }
    }

    pub(crate) fn compose_len_empty(&self) -> usize {
        3
    }

    pub(crate) fn compose_len(&self, _community: StandardCommunity) -> usize {
        if !self.extended && self.len + 4 > 255 {
            4 +1
        } else {
            4
        }
    }

    pub(crate) fn add_community(&mut self, community: StandardCommunity) {
        if !self.extended && self.len + 4 > 255 {
            self.extended = true;
        }
        self.len += 4;
        self.communities.push(community);
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        let len = self.len.to_be_bytes();
        if self.extended {
            // FIXME this assumes usize is 64bits
            target.append_slice(&[0b1001_0000, 8, len[6], len[7]])
        } else {
            target.append_slice(&[0b1000_0000, 8, len[7]])
        }?;

        for c in &self.communities {
            target.append_slice(&c.to_raw())?;
        }
        Ok(())
    }
}

//------------ Errors --------------------------------------------------------

#[derive(Debug)]
pub enum ComposeError{
    /// Exceeded maximum PDU size, data field carries the violating length.
    PduTooLarge(usize),

    // TODO proper docstrings, first see how/if we actually use these.
    AttributeTooLarge(new_pas::PathAttributeType, usize),
    AttributesTooLarge(usize),
    IllegalCombination,
    EmptyMpReachNlri,
    EmptyMpUnreachNlri,
    WrongAddressType,

    InvalidAttribute,

    /// Variant for `octseq::builder::ShortBuf`
    ShortBuf,
    /// Wrapper for util::parser::ParseError, used in `fn into_message`
    ParseError(ParseError)
}

impl From<ShortBuf> for ComposeError {
    fn from(_: ShortBuf) -> ComposeError {
        ComposeError::ShortBuf
    }
}
impl From<ParseError> for ComposeError {
    fn from(pe: ParseError) -> ComposeError {
        ComposeError::ParseError(pe)
    }
}


impl std::error::Error for ComposeError { }
impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ComposeError::PduTooLarge(n) => {
                write!(f, "oversized PDU: {n} bytes")
            }
            ComposeError::AttributeTooLarge(attr, n) => {
                write!(f, "oversized attribute {attr}: {n} bytes")
            }
            ComposeError::AttributesTooLarge(n) => {
                write!(f, "total path attributes too large: {n} bytes")
            }
            ComposeError::IllegalCombination => {
                write!(f, "illegal combination of prefixes/attributes")
            }
            ComposeError::EmptyMpReachNlri => {
                write!(f, "missing NLRI in MP_REACH_NLRI")
            }
            ComposeError::EmptyMpUnreachNlri => {
                write!(f, "missing NLRI in MP_UNREACH_NLRI")
            }
            ComposeError::WrongAddressType => {
                write!(f, "wrong address type")
            }
            ComposeError::InvalidAttribute => {
                write!(f, "invalid attribute")
            }
            ComposeError::ShortBuf => {
                ShortBuf.fmt(f)
            }
            ComposeError::ParseError(pe) => {
                write!(f, "parse error in builder: {}", pe)
            }

        }
    }
}
