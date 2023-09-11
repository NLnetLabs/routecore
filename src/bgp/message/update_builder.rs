use std::convert::Infallible;
use std::fmt;
use std::iter::Peekable;
use std::net::{IpAddr, Ipv6Addr};
use std::collections::BTreeMap;

use bytes::BytesMut;
use octseq::{FreezeBuilder, Octets, OctetsBuilder, ShortBuf};

use crate::bgp::aspath::HopPath;
use crate::bgp::communities::StandardCommunity;
use crate::bgp::message::{Header, MsgType, SessionConfig, UpdateMessage};
use crate::bgp::message::attr_change_set::AttrChangeSet;
use crate::bgp::message::nlri::Nlri;
use crate::bgp::message::update::{AFI, SAFI, NextHop};
use crate::bgp::types::OriginType;
use crate::util::parser::ParseError;

//use rotonda_fsm::bgp::session::AgreedConfig;

use crate::bgp::path_attributes as new_pas;
use new_pas::{PathAttribute, PathAttributeType};

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
                                   //
    // attributes:
    //attributes: Vec<new_pas::PathAttribute>,
    attributes: BTreeMap<PathAttributeType, new_pas::PathAttribute>,

    //standard_communities_builder: Option<StandardCommunitiesBuilder>,

    attributes_len: usize,
    total_pdu_len: usize,

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
            attributes: BTreeMap::new(),
            //standard_communities_builder: None,

            attributes_len: 0,
            total_pdu_len: 19 + 2 + 2,
        })
    }

    /// Creates an UpdateBuilder with Path Attributes from an UpdateMessage
    ///
    ///
    pub fn from_update_message<Octs: Octets>(
        pdu: UpdateMessage<Octs>, 
        _session_config: SessionConfig,
        target: Target
    ) -> Result<UpdateBuilder<Target>, ComposeError> {
        
        let mut builder = UpdateBuilder::from_target(target)
            .map_err(|_| ComposeError::ShortBuf)?;

        // Add all path attributes, except for MP_(UN)REACH_NLRI, ordered by
        // their typecode.
        for pa in pdu.new_path_attributes()? {
            if let Ok(pa) = pa {
                if pa.typecode() != PathAttributeType::MpReachNlri
                    && pa.typecode() != PathAttributeType::MpUnreachNlri
                {
                    builder.add_attribute(pa.to_owned()?)?;
                }
            } else {
                return Err(ComposeError::InvalidAttribute);
            }
        }


        Ok(builder)
    }

    //--- Withdrawals

    pub fn add_withdrawal(&mut self, withdrawal: &Nlri<Vec<u8>>)
        -> Result<(), ComposeError>
    {
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

                    // Check if we have an attribute in self.attributes
                    // Again, like with Communities, we cant rely on
                    // entry().or_insert(), because that does not do a max pdu
                    // length check and it does not allow us to error out.
                    
                    if !self.attributes.contains_key(
                        &PathAttributeType::MpUnreachNlri
                    ) {
                        self.add_attribute(new_pas::MpUnreachNlri::new(
                                MpUnreachNlriBuilder::new(
                                    AFI::Ipv6, SAFI::Unicast,
                                    b.is_addpath()
                                )
                        ).into())?;
                    }
                    let pa = self.attributes.get_mut(&PathAttributeType::MpUnreachNlri)
                        .unwrap(); // Just added it, so we know it is there.
            
                    if let PathAttribute::MpUnreachNlri(ref mut pa) = pa {
                        let builder = pa.as_mut();

                        let new_bytes = builder.compose_len(withdrawal);
                        let new_total = self.total_pdu_len + new_bytes;
                        if new_total > Self::MAX_PDU {
                            return Err(ComposeError::PduTooLarge(new_total));
                        }
                        if !builder.valid_combination(
                            AFI::Ipv6, SAFI::Unicast, b.is_addpath()
                        ) {
                            // We are already constructing a
                            // MP_UNREACH_NLRI but for a different
                            // AFI,SAFI than the prefix in `withdrawal`,
                            // or we are mixing addpath with non-addpath.
                            return Err(ComposeError::IllegalCombination);
                        }

                        builder.add_withdrawal(withdrawal);
                        self.total_pdu_len = new_total;
                        self.attributes_len += new_bytes;
                    } else {
                        unreachable!()
                    }
                }

            }
            _ => todo!() // TODO 
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


    /// Upsert a Path Attribute.
    ///
    /// Insert a new, or update an existing Path Attribute in this builder. If
    /// the new Path Attribute would cause the total PDU length to exceed the
    /// maximum, a `ComposeError::PduTooLarge` is returned.

    pub fn add_attribute(&mut self, pa: PathAttribute)
        -> Result<(), ComposeError>
    {
        if let Some(existing_pa) = self.attributes.get_mut(&pa.typecode()) {

            let new_total = self.total_pdu_len
                - existing_pa.compose_len()
                + pa.compose_len();
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            }
            self.attributes_len -=  existing_pa.compose_len();
            self.attributes_len += pa.compose_len();
            self.total_pdu_len = new_total;
            *existing_pa = pa;
        } else {
            let new_bytes = pa.compose_len();
            let new_total = self.total_pdu_len + new_bytes;
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            }
            self.total_pdu_len = new_total;
            self.attributes_len += new_bytes;

            self.attributes.insert(pa.typecode(), pa);
        }
        
        Ok(())
    }

    pub fn set_origin(&mut self, origin: OriginType)
        -> Result<(), ComposeError>
    {
        self.add_attribute(new_pas::Origin::new(origin).into())
    }

    pub fn set_aspath(&mut self , aspath: HopPath)
        -> Result<(), ComposeError>
    {
        // XXX there should be a HopPath::compose_len really, instead of
        // relying on .to_as_path() first.
        if let Ok(wireformat) = aspath.to_as_path::<Vec<u8>>() {
            if wireformat.compose_len() > u16::MAX.into() {
                return Err(ComposeError::AttributeTooLarge(
                     new_pas::PathAttributeType::AsPath,
                     wireformat.compose_len()
                ));
            }
        } else {
            return Err(ComposeError::InvalidAttribute)
        }

        self.add_attribute(new_pas::AsPath::new(aspath).into())
    }

    pub fn set_nexthop(&mut self, addr: IpAddr) -> Result<(), ComposeError> {
        // Depending on the variant of `addr` we add/update either:
        // - the conventional NEXT_HOP path attribute (IPv4); or
        // - we update/create a MpReachNlriBuilder (IPv6)
        match addr {
            IpAddr::V4(a) => {
                self.add_attribute(new_pas::NextHop::new(a).into())?;
            }
            IpAddr::V6(a) => {
                if let Some(ref mut pa) = self.attributes.get_mut(
                    &PathAttributeType::MpReachNlri
                ) {
                    if let PathAttribute::MpReachNlri(ref mut pa) = pa {
                        let builder = pa.as_mut();
                        builder.set_nexthop(a);
                    } else {
                        unreachable!()
                    }
                } else {
                    self.add_attribute(new_pas::MpReachNlri::new(
                        MpReachNlriBuilder::new(
                            AFI::Ipv6, SAFI::Unicast, NextHop::Ipv6(a), false
                        )
                    ).into())?;
                }
            }
        }
        Ok(())
    }

    pub fn set_nexthop_ll(&mut self, addr: Ipv6Addr)
        -> Result<(), ComposeError>
    {
        // We could/should check for addr.is_unicast_link_local() once that
        // lands in stable.
        
        if let Some(ref mut pa) = self.attributes.get_mut(
            &PathAttributeType::MpReachNlri
        ) {
            if let PathAttribute::MpReachNlri(ref mut pa) = pa {
                let builder = pa.as_mut();
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
                unreachable!()
            }
        } else {
            self.add_attribute(new_pas::MpReachNlri::new(
                MpReachNlriBuilder::new(
                    AFI::Ipv6, SAFI::Unicast, NextHop::Ipv6LL(0.into(), addr),
                    false
                )
            ).into())?;
        }

        Ok(())
    }

    pub fn set_multi_exit_disc(&mut self, med: new_pas::MultiExitDisc)
    -> Result<(), ComposeError>
    {
        self.add_attribute(med.into())
    }

    pub fn set_local_pref(&mut self, local_pref: new_pas::LocalPref)
    -> Result<(), ComposeError>
    {
        self.add_attribute(local_pref.into())
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

                    if !self.attributes.contains_key(&PathAttributeType::MpReachNlri) {
                        self.add_attribute(new_pas::MpReachNlri::new(
                            MpReachNlriBuilder::new(
                                AFI::Ipv6, SAFI::Unicast,
                                NextHop::Ipv6(0.into()), b.is_addpath()
                            )
                        ).into())?;
                    }
                    let pa = self.attributes.get_mut(&PathAttributeType::MpReachNlri)
                        .unwrap(); // Just added it, so we know it is there.
            
                    if let PathAttribute::MpReachNlri(ref mut pa) = pa {
                        let builder = pa.as_mut();

                        let new_bytes = builder.compose_len(announcement);
                        let new_total = self.total_pdu_len + new_bytes;
                        if new_total > Self::MAX_PDU {
                            return Err(ComposeError::PduTooLarge(new_total));
                        }
                        if !builder.valid_combination(
                            AFI::Ipv6, SAFI::Unicast, b.is_addpath()
                        ) {
                            // We are already constructing a
                            // MP_UNREACH_NLRI but for a different
                            // AFI,SAFI than the prefix in `announcement`,
                            // or we are mixing addpath with non-addpath.
                            return Err(ComposeError::IllegalCombination);
                        }

                        builder.add_announcement(announcement);
                        self.total_pdu_len = new_total;
                        self.attributes_len += new_bytes;
                    } else {
                        unreachable!()
                    }
                }
            }
            _ => todo!() // TODO
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
        if !self.attributes.contains_key(&PathAttributeType::Communities) {
            self.add_attribute(new_pas::Communities::new(
                    StandardCommunitiesBuilder::new()
            ).into())?;
        }
        let pa = self.attributes.get_mut(&PathAttributeType::Communities)
            .unwrap(); // Just added it, so we know it is there.
            
        if let PathAttribute::Communities(ref mut pa) = pa {
            let builder = pa.as_mut();
            let new_bytes = builder.compose_len(community);
            let new_total = self.total_pdu_len + new_bytes;
            if new_total > Self::MAX_PDU {
                return Err(ComposeError::PduTooLarge(new_total));
            }
            builder.add_community(community);
            self.total_pdu_len = new_total;
            self.attributes_len += new_bytes;
            Ok(())
        } else {
            unreachable!()
        }
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
        // FIXME this SessionConfig::modern should come from self
        Ok(UpdateMessage::from_octets(
            self.finish().map_err(|_| ShortBuf)?, SessionConfig::modern()
        )?)
    }

    // Check whether the combination of NLRI and attributes would produce a
    // valid UPDATE pdu.
    fn is_valid(&self) -> Result<(), ComposeError> {
        // If we have builders for MP_(UN)REACH_NLRI, they should carry
        // prefixes.

        if let Some(pa) = self.attributes.get(
            &PathAttributeType::MpReachNlri
        ) {
            if let PathAttribute::MpReachNlri(pa) = pa {
                if pa.as_ref().is_empty() {
                    return Err(ComposeError::EmptyMpReachNlri);
                }
            } else {
                unreachable!()
            }
        }

        if let Some(pa) = self.attributes.get(
            &PathAttributeType::MpUnreachNlri
        ) {
            if let PathAttribute::MpUnreachNlri(pa) = pa {
                if pa.as_ref().is_empty() {
                    return Err(ComposeError::EmptyMpUnreachNlri);
                }
            } else {
                unreachable!()
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



        // We can do these unwraps because of the checks in the add/append
        // methods.

        // attributes_len` is checked to be <= 4096 or <= 65535
        // so it will always fit in a u16.
        let _ = self.target.append_slice(
            &u16::try_from(self.attributes_len).unwrap().to_be_bytes()
        );

        // XXX again them struggles with Target::AppendError and converting..
        if let Err(e) = self.attributes.iter().try_for_each(
            |(_tc, pa)| pa.compose(&mut self.target)
        ) {
            unreachable!("{e}");
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
                _ => unreachable!(),
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
    // MP_REACH_NLRI and MP_UNREACH_NLRI can only occur once (like any path
    // attribute), and can carry only a single tuple of (AFI, SAFI).
    // My interpretation of RFC4760 means one can mix conventional
    // NLRI/withdrawals (so, v4 unicast) with one other (AFI, SAFI) in an
    // MP_(UN)REACH_NLRI path attribute.
    // Question is: can one also put (v4, unicast) in an MP_* attribute, and,
    // then also in the conventional part (at the end of the PDU)? 

    // Minimal required size for a meaningful MP_REACH_NLRI. This comprises
    // the attribute flags/size/type (3 bytes), a IPv6 nexthop (17), reserved
    // byte (1) and then space for at least an IPv6 /48 announcement (7)

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

}

//------------ StandardCommunitiesBuilder ------------------------------------
//
//

#[derive(Debug, Eq, PartialEq)]
pub struct StandardCommunitiesBuilder {
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

    pub(crate) fn with_capacity(c: usize) -> StandardCommunitiesBuilder {
        StandardCommunitiesBuilder {
            communities: Vec::with_capacity(c),
            len: 0,
            extended: false
        }
    }

    pub(crate) fn communities(&self) -> &Vec<StandardCommunity> {
        &self.communities
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

    // TODO fn add_community_from_iter() 
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

    InvalidAttribute, // XXX perhaps carry the typecode here?

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


//------------ Tests ----------------------------------------------------------
#[cfg(test)]
mod tests {

    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use crate::addr::Prefix;
    use crate::asn::Asn;
    use crate::bgp::communities::Wellknown;
    use crate::bgp::message::nlri::BasicNlri;
    use super::*;

    fn print_pcap<T: AsRef<[u8]>>(buf: T) {
        print!("000000 ");
        for b in buf.as_ref() {
            print!("{:02x} ", b);
        }
        println!();
    }


    #[test]
    fn empty_nlri_iterators() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("2001:db8::/32").unwrap()
        ).unwrap();

        let msg = builder.into_message().unwrap();
        print_pcap(msg.as_ref());
        assert_eq!(msg.all_withdrawals_iter().count(), 1);

        let mut builder2 = UpdateBuilder::new_vec();
        builder2.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();

        let msg2 = builder2.into_message().unwrap();
        print_pcap(msg2.as_ref());
        assert_eq!(msg2.all_withdrawals_iter().count(), 1);
    }

    #[test]
    fn build_empty() {
        let builder = UpdateBuilder::new_vec();
        let msg = builder.finish().unwrap();
        //print_pcap(&msg);
        assert!(
            UpdateMessage::from_octets(msg, SessionConfig::modern()).is_ok()
        );
    }

    #[test]
    fn build_withdrawals_basic_v4() {
        let mut builder = UpdateBuilder::new_vec();

        let withdrawals = [
            "0.0.0.0/0",
            "10.2.1.0/24",
            "10.2.2.0/24",
            "10.2.0.0/23",
            "10.2.4.0/25",
            "10.0.0.0/7",
            "10.0.0.0/8",
            "10.0.0.0/9",
        ].map(|s| Nlri::unicast_from_str(s).unwrap())
         .into_iter()
         .collect::<Vec<_>>();

        let _ = builder.append_withdrawals(&mut withdrawals.clone());
        let msg = builder.finish().unwrap();
        assert!(
            UpdateMessage::from_octets(&msg, SessionConfig::modern())
            .is_ok()
        );
        print_pcap(&msg);


        let mut builder2 = UpdateBuilder::new_vec();
        for w in &withdrawals {
            builder2.add_withdrawal(w).unwrap();
        }

        let msg2 = builder2.finish().unwrap();
        assert!(
            UpdateMessage::from_octets(&msg2, SessionConfig::modern())
            .is_ok()
        );
        print_pcap(&msg2);

        assert_eq!(msg, msg2);
    }

    #[test]
    fn build_withdrawals_from_iter() {
        let mut builder = UpdateBuilder::new_vec();

        let withdrawals = [
            "0.0.0.0/0",
            "10.2.1.0/24",
            "10.2.2.0/24",
            "10.2.0.0/23",
            "10.2.4.0/25",
            "10.0.0.0/7",
            "10.0.0.0/8",
            "10.0.0.0/9",
        ].map(|s| Nlri::unicast_from_str(s).unwrap().into())
         .into_iter()
         .collect::<Vec<_>>();

        let _ = builder.withdrawals_from_iter(&mut withdrawals.into_iter().peekable());
        let msg = builder.into_message().unwrap();
        print_pcap(msg);
    }

    #[test]
    #[should_panic]
    fn build_too_many_withdrawals() {
        let mut builder = UpdateBuilder::new_vec();
        for i in 0..1024 {
            builder.add_withdrawal(
                &Nlri::unicast_from_str(&format!("2001:db:{:04}::/48", i))
                    .unwrap()
            ).unwrap();
        }
    }

    #[test]
    fn build_too_many_withdrawals_remainder() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Nlri<Vec<u8>>> = vec![];
        for i in 1..1024_u32 {
            prefixes.push(
                Nlri::Unicast(
                    Prefix::new_v4(
                        Ipv4Addr::from((i << 10).to_be_bytes()),
                        22
                    ).unwrap().into()
                )
            );
        }
        let prefixes_len = prefixes.len();
        assert!(builder.append_withdrawals(&mut prefixes).is_err());
        assert!(prefixes.len() < prefixes_len);
        let pdu = builder.into_message().unwrap();
        assert_eq!(
            pdu.withdrawals().iter().count(),
            prefixes_len - prefixes.len()
        );
    }

    #[test]
    fn build_too_many_withdrawals_from_iter() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Nlri<Vec<u8>>> = vec![];
        for i in 1..1024_u32 {
            prefixes.push(
                Nlri::Unicast(
                    Prefix::new_v4(
                        Ipv4Addr::from((i << 10).to_be_bytes()),
                        22
                    ).unwrap().into()
                )
            );
        }
        let mut prefix_iter = prefixes.into_iter().peekable();

        assert!(builder.withdrawals_from_iter(&mut prefix_iter).is_err());
        let msg = builder.into_message().unwrap();
        assert_eq!(
            prefix_iter.count() + msg.withdrawals().iter().count(),
            1023
        );
    }



    #[test]
    fn build_withdrawals_basic_v4_addpath() {
        use crate::bgp::message::nlri::PathId;
        let mut builder = UpdateBuilder::new_vec();
        let mut withdrawals = [
            "0.0.0.0/0",
            "10.2.1.0/24",
            "10.2.2.0/24",
            "10.2.0.0/23",
            "10.2.4.0/25",
            "10.0.0.0/7",
            "10.0.0.0/8",
            "10.0.0.0/9",
        ].iter().enumerate().map(|(idx, s)| Nlri::Unicast(BasicNlri {
            prefix: Prefix::from_str(s).unwrap(),
            path_id: Some(PathId::from_u32(idx.try_into().unwrap()))})
        ).collect::<Vec<_>>();
        let _ = builder.append_withdrawals(&mut withdrawals);
        let msg = builder.finish().unwrap();
        assert!(
            UpdateMessage::from_octets(&msg, SessionConfig::modern_addpath())
            .is_ok()
        );
        print_pcap(&msg);
    }

    #[test]
    fn build_withdrawals_basic_v6_single() {
        let mut builder = UpdateBuilder::new_vec();
        let mut withdrawals = vec![
            Nlri::unicast_from_str("2001:db8::/32").unwrap()
        ];

        let _ = builder.append_withdrawals(&mut withdrawals);

        let msg = builder.finish().unwrap();
        println!("msg raw len: {}", &msg.len());
        print_pcap(&msg);
        
        UpdateMessage::from_octets(&msg, SessionConfig::modern()).unwrap();
    }

    #[test]
    fn build_withdrawals_basic_v6_from_iter() {
        let mut builder = UpdateBuilder::new_vec();

        let mut withdrawals: Vec<Nlri<Vec<u8>>> = vec![];
        for i in 1..512_u128 {
            withdrawals.push(
                Nlri::Unicast(
                    Prefix::new_v6(
                        Ipv6Addr::from((i << 64).to_be_bytes()),
                        64
                    ).unwrap().into()
                )
            );
        }

        let _ = builder.withdrawals_from_iter(&mut withdrawals.into_iter().peekable());
        let raw = builder.finish().unwrap();
        print_pcap(&raw);
        UpdateMessage::from_octets(&raw, SessionConfig::modern()).unwrap();
    }

    #[test]
    fn build_mixed_withdrawals() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("2001:db8::/32").unwrap()
        ).unwrap();
        let msg = builder.into_message().unwrap();
        print_pcap(msg.as_ref());

        assert_eq!(msg.all_withdrawals_iter().count(), 2);
    }

    #[test]
    fn build_mixed_addpath_conventional() {
        use crate::bgp::message::nlri::PathId;
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();
        let res = builder.add_withdrawal(
            &Nlri::Unicast(
                (Prefix::from_str("10.0.0.0/8").unwrap(),
                Some(PathId::from_u32(123))
                ).into())
        );
        assert!(matches!(res, Err(ComposeError::IllegalCombination)));
    }

    #[test]
    fn build_mixed_addpath_mp() {
        use crate::bgp::message::nlri::PathId;
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("2001:db8::/32").unwrap()
        ).unwrap();
        let res = builder.add_withdrawal(
            &Nlri::Unicast(
                (Prefix::from_str("2001:db8::/32").unwrap(),
                Some(PathId::from_u32(123))
                ).into())
        );
        assert!(matches!(res, Err(ComposeError::IllegalCombination)));
    }

    #[test]
    fn build_mixed_addpath_ok() {
        use crate::bgp::message::nlri::PathId;
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();
        let res = builder.add_withdrawal(
            &Nlri::Unicast(
                (Prefix::from_str("2001:db8::/32").unwrap(),
                Some(PathId::from_u32(123))
                ).into())
        );
        assert!(res.is_ok());
        print_pcap(builder.finish().unwrap());
    }

    #[test]
    fn build_conv_mp_mix() {
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x88 + 8, // adding length for the conv NLRI
            0x02, 0x00, 0x00, 0x00, 0x71, 0x80,
            0x0e, 0x5a, 0x00, 0x02, 0x01, 0x20, 0xfc, 0x00,
            0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xfe, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80,
            0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00,
            0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff,
            0x00, 0x01, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff,
            0xff, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8,
            0xff, 0xff, 0x00, 0x03, 0x40, 0x01, 0x01, 0x00,
            0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00,
            0xc8, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
            // manually adding two conv NLRI here
            24, 1, 1, 1,
            24, 1, 1, 2

        ];

        let upd = UpdateMessage::from_octets(&buf, SessionConfig::modern()).unwrap();
        print_pcap(upd.as_ref());

        assert!(upd.has_conventional_nlri() && upd.has_mp_nlri());
        assert_eq!(upd.unicast_announcements().count(), 7);
    }

    #[test]
    fn build_announcements_conventional() {
        use crate::bgp::aspath::HopPath;
        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "1.0.1.0/24",
            "1.0.2.0/24",
            "1.0.3.0/24",
            "1.0.4.0/24",
        ].map(|p| Nlri::unicast_from_str(p).unwrap());
        let mut iter = prefixes.into_iter().peekable();
        builder.announcements_from_iter(&mut iter).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop("1.2.3.4".parse().unwrap()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(123); 70
        ]);

        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        let raw = builder.finish().unwrap();
        print_pcap(&raw);

        //let pdu = builder.into_message().unwrap();
        //print_pcap(pdu);
    }

    #[test]
    fn build_announcements_mp() {
        use crate::bgp::aspath::HopPath;

        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "2001:db8:1::/48",
            "2001:db8:2::/48",
            "2001:db8:3::/48",
        ].map(|p| Nlri::unicast_from_str(p).unwrap());
        let mut iter = prefixes.into_iter().peekable();
        builder.announcements_from_iter(&mut iter).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop("fe80:1:2:3::".parse().unwrap()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        let raw = builder.finish().unwrap();
        print_pcap(&raw);
    }

    #[test]
    fn build_announcements_mp_missing_nlri() {
        use crate::bgp::aspath::HopPath;

        let mut builder = UpdateBuilder::new_vec();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop("fe80:1:2:3::".parse().unwrap()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        builder.set_aspath(path).unwrap();

        assert!(matches!(
                builder.into_message(),
                Err(ComposeError::EmptyMpReachNlri)
        ));
    }

    #[test]
    fn build_announcements_mp_link_local() {
        use crate::bgp::aspath::HopPath;

        let mut builder = UpdateBuilder::new_vec();

        let prefixes = [
            "2001:db8:1::/48",
            "2001:db8:2::/48",
            "2001:db8:3::/48",
        ].map(|p| Nlri::unicast_from_str(p).unwrap());


        let mut iter = prefixes.into_iter().peekable();

        builder.announcements_from_iter(&mut iter).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        //builder.set_nexthop("2001:db8::1".parse().unwrap()).unwrap();
        builder.set_nexthop_ll("fe80:1:2:3::".parse().unwrap()).unwrap();


        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        //let unchecked = builder.finish().unwrap();
        //print_pcap(unchecked);
        let msg = builder.into_message().unwrap();
        msg.print_pcap();
    }

    #[test]
    fn build_announcements_mp_ll_no_nlri() {
        use crate::bgp::aspath::HopPath;

        let mut builder = UpdateBuilder::new_vec();
        builder.set_origin(OriginType::Igp).unwrap();
        //builder.set_nexthop("2001:db8::1".parse().unwrap()).unwrap();
        builder.set_nexthop_ll("fe80:1:2:3::".parse().unwrap()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        builder.set_aspath(path).unwrap();

        assert!(matches!(
                builder.into_message(),
                Err(ComposeError::EmptyMpReachNlri)
        ));
    }

    #[test]
    fn build_standard_communities() {
        use crate::bgp::aspath::HopPath;
        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "1.0.1.0/24",
            "1.0.2.0/24",
            "1.0.3.0/24",
            "1.0.4.0/24",
        ].map(|p| Nlri::unicast_from_str(p).unwrap());
        let mut iter = prefixes.into_iter().peekable();
        builder.announcements_from_iter(&mut iter).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop("1.2.3.4".parse().unwrap()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();


        builder.add_community("AS1234:666".parse().unwrap()).unwrap();
        builder.add_community("NO_EXPORT".parse().unwrap()).unwrap();
        for n in 1..100 {
            builder.add_community(format!("AS999:{n}").parse().unwrap()).unwrap();
        }

        builder.into_message().unwrap();
        //let raw = builder.finish().unwrap();
        //print_pcap(&raw);
    }

    #[test]
    fn build_other_attributes() {
        use crate::bgp::aspath::HopPath;
        let mut builder = UpdateBuilder::new_vec();
        let prefixes = [
            "1.0.1.0/24",
            "1.0.2.0/24",
            "1.0.3.0/24",
            "1.0.4.0/24",
        ].map(|p| Nlri::unicast_from_str(p).unwrap());
        let mut iter = prefixes.into_iter().peekable();
        builder.announcements_from_iter(&mut iter).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop("1.2.3.4".parse().unwrap()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        builder.set_multi_exit_disc(new_pas::MultiExitDisc::new(1234)).unwrap();
        builder.set_local_pref(new_pas::LocalPref::new(9876)).unwrap();

        let msg = builder.into_message().unwrap();
        msg.print_pcap();
    }

    #[test]
    fn from_update_message() {
        let raw = vec![
            // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02,
            0x00, 0x00, 0x00, 0x1b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02,
            0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04,
            0x0a, 0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00,
            0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ];
        let sc = SessionConfig::modern();
        let upd = UpdateMessage::from_octets(&raw, sc).unwrap();
        let target = BytesMut::new();
        let mut builder = UpdateBuilder::from_update_message(upd, sc, target).unwrap();

        assert_eq!(builder.attributes.len(), 4);

        builder.add_announcement(
            &Nlri::unicast_from_str("10.10.10.2/32").unwrap()
        ).unwrap();

        let upd2 = builder.into_message().unwrap();
        assert_eq!(&raw, upd2.as_ref());
    }

    #[test]
    fn build_overwriting_attributes() {
        // TODO test that when setting and overwriting the same attribute in
        // an UpdateBuilder, the resulting PDU contains the lastly set
        // attribute and that all the lengths are correct etc
        
        let raw = vec![
            // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02,
            0x00, 0x00, 0x00, 0x1b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02,
            0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04,
            0x0a, 0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00,
            0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ];
        let sc = SessionConfig::modern();
        let upd = UpdateMessage::from_octets(&raw, sc).unwrap();
        for pa in upd.clone().new_path_attributes().unwrap() {
            eprintln!("{:?}", pa.unwrap().to_owned().unwrap());
        }
        let target = BytesMut::new();
        let mut builder = UpdateBuilder::from_update_message(upd, sc, target).unwrap();

        
        assert_eq!(builder.attributes.len(), 4);

        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_origin(OriginType::Egp).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();

        assert_eq!(builder.attributes.len(), 4);

        builder.add_announcement(
            &Nlri::unicast_from_str("10.10.10.2/32").unwrap()
        ).unwrap();

        let upd2 = builder.into_message().unwrap();
        assert_eq!(&raw, upd2.as_ref());
    }

    #[test]
    fn build_ordered_attributes() {
        let mut builder = UpdateBuilder::new_vec();
        builder.add_community(
            StandardCommunity::from_str("AS1234:999").unwrap()
        ).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.add_community(
            StandardCommunity::from_str("AS1234:1000").unwrap()
        ).unwrap();

        assert_eq!(builder.attributes.len(), 2);

        let pdu = builder.into_message().unwrap();
        let mut prev_typecode = 0_u8;
        for pa in pdu.new_path_attributes().unwrap() {
            let typecode = u8::from(pa.unwrap().typecode());
            assert!(prev_typecode < typecode);
            prev_typecode = typecode; 
        }
        assert_eq!(pdu.communities().unwrap().count(), 2);
    }

    #[test]
    #[allow(deprecated)]
    fn build_acs() {
        use crate::bgp::aspath::HopPath;
        use crate::bgp::message::nlri::PathId;

        let builder = UpdateBuilder::new_vec();
        let mut acs = AttrChangeSet::empty();

        // ORIGIN
        acs.origin_type.set(OriginType::Igp);

        // AS_PATH
        let mut hp = HopPath::new();
        hp.prepend(Asn::from_u32(100));
        hp.prepend(Asn::from_u32(101));
        acs.as_path.set(hp.to_as_path().unwrap());

        // NEXT_HOP
        acs.next_hop.set(NextHop::Ipv4(Ipv4Addr::from_str("192.0.2.1").unwrap()));


        // now for some NLRI
        // XXX currently ACS only holds one single Nlri
        acs.nlri.set(Nlri::Unicast(BasicNlri{
            prefix: Prefix::from_str("1.2.0.0/25").unwrap(),
            path_id: Some(PathId::from_u32(123))
        }));

        acs.standard_communities.set(vec![
            Wellknown::NoExport.into(),
            Wellknown::Blackhole.into(),
        ]);

        let _msg = builder.build_acs(acs).unwrap();
        //print_pcap(&msg);
    }



}
