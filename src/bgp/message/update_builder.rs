use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::collections::BTreeMap;

use bytes::BytesMut;
use octseq::{FreezeBuilder, Octets, OctetsBuilder, OctetsFrom, OctetsInto, ShortBuf};
use log::warn;

use crate::bgp::aspath::HopPath;
use crate::bgp::communities::StandardCommunity;
use crate::bgp::message::{Header, MsgType, SessionConfig, UpdateMessage};
use crate::bgp::message::nlri::Nlri;
use crate::bgp::message::update::{AFI, SAFI, NextHop};
use crate::bgp::types::OriginType;
use crate::util::parser::ParseError;

//use rotonda_fsm::bgp::session::AgreedConfig;

use crate::bgp::path_attributes::{
    AsPath,
    Communities,
    LocalPref,
    MpReachNlri,
    MpUnreachNlri,
    MultiExitDisc,
    NextHop as NextHopAttribute,
    Origin,
    PathAttribute, PathAttributeType
};

//------------ UpdateBuilder -------------------------------------------------
#[derive(Debug)]
pub struct UpdateBuilder<Target> {
    target: Target,
    //config: AgreedConfig, //FIXME this lives in rotonda_fsm, but that
    //depends on routecore. Sounds like a depedency hell.
    announcements: Vec<Nlri<Vec<u8>>>,
    withdrawals: Vec<Nlri<Vec<u8>>>,
    addpath_enabled: Option<bool>, // for conventional nlri (unicast v4)
    // attributes:
    attributes: BTreeMap<PathAttributeType, PathAttribute>,
}

impl<T> UpdateBuilder<T> {
    const MAX_PDU: usize = 4096; // XXX should come from NegotiatedConfig
}

impl<Target: OctetsBuilder> UpdateBuilder<Target>
where Target: octseq::Truncate
{

    pub fn from_target(mut target: Target) -> Result<Self, ShortBuf> {
        target.truncate(0);
        let mut h = Header::<&[u8]>::new();
        h.set_length(19 + 2 + 2);
        h.set_type(MsgType::Update);
        let _ =target.append_slice(h.as_ref());

        Ok(UpdateBuilder {
            target,
            announcements: Vec::new(),
            withdrawals: Vec::new(),
            addpath_enabled: None,
            attributes: BTreeMap::new(),
        })
    }

    /// Creates an UpdateBuilder with Path Attributes from an UpdateMessage
    ///
    ///
    pub fn from_update_message<'a, Octs: 'a + Octets>(
        pdu: &'a UpdateMessage<Octs>, 
        _session_config: SessionConfig,
        target: Target
    ) -> Result<UpdateBuilder<Target>, ComposeError>
    where
        Vec<u8>: OctetsFrom<Octs::Range<'a>>
    {
        
        let mut builder = UpdateBuilder::from_target(target)
            .map_err(|_| ComposeError::ShortBuf)?;

        // Add all path attributes, except for MP_(UN)REACH_NLRI, ordered by
        // their type_code.
        for pa in pdu.path_attributes()? {
            if let Ok(pa) = pa {
                if pa.type_code() != PathAttributeType::MpReachNlri
                    && pa.type_code() != PathAttributeType::MpUnreachNlri
                {
                    if let PathAttributeType::Invalid(n) = pa.type_code() {
                        warn!("invalid PA {}:\n{}", n, pdu.fmt_pcap_string());
                    }
                    builder.add_attribute(pa.to_owned()?)?;
                }
            } else {
                return Err(ComposeError::InvalidAttribute);
            }
        }

        Ok(builder)
    }

    //--- Withdrawals

    pub fn add_withdrawal<T>(
        &mut self,
        withdrawal: &Nlri<T>
    ) -> Result<(), ComposeError>
        where
            Vec<u8>: OctetsFrom<T>,
            T: Octets,
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

                    self.withdrawals.push(
                        <&Nlri<T> as OctetsInto<Nlri<Vec<u8>>>>::try_octets_into(withdrawal).map_err(|_| ComposeError::todo() )?
                    );
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
                        self.add_attribute(MpUnreachNlri::new(
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

                    } else {
                        unreachable!()
                    }
                }

            }
            _ => todo!() // TODO 
        };
        Ok(())
    }

    pub fn withdrawals_from_iter<I>(&mut self, withdrawals: I)
        -> Result<(), ComposeError>
    where I: IntoIterator<Item = Nlri<Vec<u8>>>
    {
        withdrawals.into_iter().try_for_each(|w| self.add_withdrawal(&w) )?;
        Ok(())
    }

    pub fn append_withdrawals<T>(&mut self, withdrawals: &mut Vec<Nlri<T>>)
        -> Result<(), ComposeError>
    where
        Vec<u8>: OctetsFrom<T>,
        T: Octets,
    {
        for (idx, w) in withdrawals.iter().enumerate() {
            if let Err(e) = self.add_withdrawal(w) {
                withdrawals.drain(..idx);
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
        if let PathAttribute::Invalid(..) = pa {
            warn!(
                "adding Invalid attribute to UpdateBuilder: {}",
                  &pa.type_code()
            );
        }
        if let Some(existing_pa) = self.attributes.get_mut(&pa.type_code()) {
            *existing_pa = pa;
        } else {
            self.attributes.insert(pa.type_code(), pa);
        }
        
        Ok(())
    }

    pub fn set_origin(&mut self, origin: OriginType)
        -> Result<(), ComposeError>
    {
        self.add_attribute(Origin::new(origin).into())
    }

    pub fn set_aspath(&mut self , aspath: HopPath)
        -> Result<(), ComposeError>
    {
        // XXX there should be a HopPath::compose_len really, instead of
        // relying on .to_as_path() first.
        if let Ok(wireformat) = aspath.to_as_path::<Vec<u8>>() {
            if wireformat.compose_len() > u16::MAX.into() {
                return Err(ComposeError::AttributeTooLarge(
                     PathAttributeType::AsPath,
                     wireformat.compose_len()
                ));
            }
        } else {
            return Err(ComposeError::InvalidAttribute)
        }

        self.add_attribute(AsPath::new(aspath).into())
    }

    pub fn set_nexthop(
        &mut self,
        nexthop: NextHop
    ) -> Result<(), ComposeError> {
        // Depending on the variant of `addr` we add/update either:
        // - the conventional NEXT_HOP path attribute (IPv4); or
        // - we update/create a MpReachNlriBuilder (IPv6)

        match nexthop {
            NextHop::Unicast(IpAddr::V4(a)) => {
                self.add_attribute(NextHopAttribute::new(a).into())?;
            }
            n => {
                if let Some(PathAttribute::MpReachNlri(ref mut pa)) = self.attributes.get_mut(
                    &PathAttributeType::MpReachNlri
                ) {
                    let builder = pa.as_mut();
                    builder.set_nexthop(n)?;
                } else {
                    self.add_attribute(MpReachNlri::new(
                        MpReachNlriBuilder::new_for_nexthop(n)
                    ).into())?;
                }
            }

        }
        Ok(())
    }
    pub fn set_nexthop_unicast(&mut self, addr: IpAddr) -> Result<(), ComposeError> {
        self.set_nexthop(NextHop::Unicast(addr))
    }

    pub fn set_nexthop_ll_addr(&mut self, addr: Ipv6Addr)
        -> Result<(), ComposeError>
    {
        // We could/should check for addr.is_unicast_link_local() once that
        // lands in stable.
        
        if let Some(ref mut pa) = self.attributes.get_mut(
            &PathAttributeType::MpReachNlri
        ) {
            if let PathAttribute::MpReachNlri(ref mut pa) = pa {
                let builder = pa.as_mut();
                match builder.get_nexthop() {
                    NextHop::Unicast(a) if a.is_ipv6() => { } ,
                    NextHop::Ipv6LL(_,_) => { },
                    _ => return Err(ComposeError::IllegalCombination),
                }
                
                builder.set_nexthop_ll_addr(addr);
            } else {
                unreachable!()
            }
        } else {
            self.add_attribute(MpReachNlri::new(
                MpReachNlriBuilder::new(
                    AFI::Ipv6, SAFI::Unicast, NextHop::Ipv6LL(0.into(), addr),
                    false
                )
            ).into())?;
        }

        Ok(())
    }

    pub fn set_multi_exit_disc(&mut self, med: MultiExitDisc)
    -> Result<(), ComposeError>
    {
        self.add_attribute(med.into())
    }

    pub fn set_local_pref(&mut self, local_pref: LocalPref)
    -> Result<(), ComposeError>
    {
        self.add_attribute(local_pref.into())
    }


    //--- Announcements

    pub fn add_announcement<T>(&mut self, announcement: &Nlri<T>)
        -> Result<(), ComposeError>
    where
        Vec<u8>: OctetsFrom<T>,
        T: Octets,
    {
        match announcement {
            Nlri::Unicast(b) if b.is_v4() => {
                // These go in the conventional NLRI part at the end of the
                // PDU.
                if let Some(addpath_enabled) = self.addpath_enabled {
                    if addpath_enabled != b.is_addpath() {
                        return Err(ComposeError::IllegalCombination)
                    }
                } else {
                    self.addpath_enabled = Some(b.is_addpath());
                }

                self.announcements.push(
                    <&Nlri<T> as OctetsInto<Nlri<Vec<u8>>>>::try_octets_into(announcement).map_err(|_| ComposeError::todo() ).unwrap()
                );
            }
            n => {
                if !self.attributes.contains_key(&PathAttributeType::MpReachNlri) {
                    self.add_attribute(MpReachNlri::new(
                            MpReachNlriBuilder::new_for_nlri(n)
                    ).into())?;
                }

                let pa = self.attributes.get_mut(&PathAttributeType::MpReachNlri)
                    .unwrap(); // Just added it, so we know it is there.
        
                if let PathAttribute::MpReachNlri(ref mut pa) = pa {
                    let builder = pa.as_mut();

                    if !builder.valid_combination(n) {
                        // We are already constructing a
                        // MP_UNREACH_NLRI but for a different
                        // AFI,SAFI than the prefix in `announcement`,
                        // or we are mixing addpath with non-addpath.
                        return Err(ComposeError::IllegalCombination);
                    }

                    builder.add_announcement(announcement);
                } else {
                    unreachable!()
                }
            }
        }

        Ok(())
    }

    pub fn announcements_from_iter<I, T>(
        &mut self, announcements: I
    ) -> Result<(), ComposeError>
    where
        I: IntoIterator<Item = Nlri<T>>,
        Vec<u8>: OctetsFrom<T>,
        T: Octets,
    {
        announcements.into_iter().try_for_each(|w| self.add_announcement(&w) )?;
        Ok(())
    }

    //--- Standard communities
    
    pub fn add_community(&mut self, community: StandardCommunity)
        -> Result<(), ComposeError>
    {
        if !self.attributes.contains_key(&PathAttributeType::Communities) {
            self.add_attribute(Communities::new(
                    StandardCommunitiesBuilder::new()
            ).into())?;
        }
        let pa = self.attributes.get_mut(&PathAttributeType::Communities)
            .unwrap(); // Just added it, so we know it is there.
            
        if let PathAttribute::Communities(ref mut pa) = pa {
            let builder = pa.as_mut();
            builder.add_community(community);
            Ok(())
        } else {
            unreachable!()
        }
    }
}

/*
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
            let attr_type_code = PathAttributeType::Origin.into();
            let attr_len = 1_u8; 
            let _ = self.target.append_slice(
                &[attr_flags, attr_type_code, attr_len, origin.into()]);
            total_pa_len += 2 + 1 + usize::from(attr_len);
        }

        if let Some(as_path) = acs.as_path.into_opt() {
            let attr_flags = 0b0101_0000;
            let attr_type_code = PathAttributeType::AsPath.into();
            let asp = as_path.into_inner();
            let attr_len = asp.len();
            if u16::try_from(attr_len).is_err() {
                return Err(ComposeError::AttributeTooLarge(
                    PathAttributeType::AsPath,
                    attr_len
                ));
            }
            let _ = self.target.append_slice(&[attr_flags, attr_type_code]);
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
                    let attr_type_code = PathAttributeType::NextHop.into();
                    let attr_len = 4_u8; 

                    let _ = self.target.append_slice(
                        &[attr_flags, attr_type_code, attr_len]
                    );
                    let _ = self.target.append_slice(&v4addr.octets());

                    total_pa_len += 2 + 1 + usize::from(attr_len);
                }
                _ => todo!() // this is MP_REACH_NLRI territory
            }
        }


        if let Some(comms) = acs.standard_communities.into_opt() {
            let attr_flags = 0b0100_0000;
            let attr_type_code = PathAttributeType::Communities.into();
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
                &[attr_flags, attr_type_code, attr_len]
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
*/

impl<Target> UpdateBuilder<Target>
{
    pub fn into_message(self) ->
        Result<UpdateMessage<<Target as FreezeBuilder>::Octets>, ComposeError>
    where
        Target: OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
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
                // FIXME an empty MP_UNREACH_NLRI can be valid when signaling
                // EoR, but then it has to be the only path attribute.
                if pa.as_ref().is_empty() {
                    return Err(ComposeError::EmptyMpUnreachNlri);
                }
            } else {
                unreachable!()
            }
        }

        Ok(())
    }

    fn calculate_pdu_length(&self) -> usize {
        // Marker, length and type.
        let mut res: usize = 16 + 2 + 1;

        // Withdrawals, 2 bytes for length + N bytes for NLRI:
        res += 2 + self.withdrawals.iter()
            .fold(0, |sum, w| sum + w.compose_len());

        // Path attributes, 2 bytes for length + N bytes for attributes:
        res += 2 + self.attributes.values()
            .fold(0, |sum, pa| sum + pa.compose_len());

        // Announcements, no length bytes:
        res += self.announcements.iter()
            .fold(0, |sum, a| sum + a.compose_len());

        res
    }

    fn larger_than(&self, max: usize) -> bool {
        // TODO add more 'quick returns' here, e.g. for MpUnreachNlri or
        // conventional withdrawals/announcements.

        if let Some(PathAttribute::MpReachNlri(b)) = self.attributes.get(&PathAttributeType::MpReachNlri) {
            if b.as_ref().announcements.len() * 2 > max {
                return true
            }
        }
        self.calculate_pdu_length() > max
    }

    /// Compose the PDU, returns the builder if it exceeds the max PDU size.
    ///
    /// 
    pub fn take_message(mut self) -> (
        Result<UpdateMessage<<Target as FreezeBuilder>::Octets>, ComposeError>,
        Option<Self>
    )
    where
        Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
        <Target as FreezeBuilder>::Octets: Octets
    {
        if !self.larger_than(Self::MAX_PDU) {
            return (self.into_message(), None)

        }

        // It does not fit in a single PDU. Figure out where to split things.
        //
        // Scenarios where we can expect large PDUs:
        // - many withdrawals of an entire RIB (e.g. when a session goes down)
        // - many announcements when a new session is established, or doing a
        // route refresh
        //
        // There might be specific scenarios where both many withdrawals and
        // announcements need to be built. But we should be able to split
        // those up in withdrawal-only and announcement-only PDUs, presumably?

        // Withdrawals come without path attributes. But, MP_UNREACH_NLRI
        // contains (non v4-unicast) withdrawals which are... represented as a
        // path attribute.


        // Scenario 1: many conventional withdrawals
        // If we have any withdrawals, they can go by themselves.
        // First naive approach: we split off at most 450 NLRI. In the extreme
        // case of AddPathed /32's this would still fit in a 4096 PDU.

        if !self.withdrawals.is_empty() {
            //let withdrawal_len = self.withdrawals.iter()
            //    .fold(0, |sum, w| sum + w.compose_len());

            let split_at = std::cmp::min(self.withdrawals.len() / 2,  450);
            let this_batch = self.withdrawals.drain(..split_at);
            let mut builder = Self::from_target(self.target.clone()).unwrap();
            
            builder.withdrawals = this_batch.collect();

            return (builder.into_message(), Some(self));
        }

        // Scenario 2: many withdrawals in MP_UNREACH_NLRI
        // At this point, we have no conventional withdrawals anymore.
        
        let maybe_pdu = 
            if let Some(PathAttribute::MpUnreachNlri(b)) = self.attributes.get_mut(&PathAttributeType::MpUnreachNlri) {
                let unreach_builder = b.as_mut();
                let mut split_at = 0;
                if !unreach_builder.withdrawals.is_empty() {
                    let mut compose_len = 0;
                    for (idx, w) in unreach_builder.withdrawals.iter().enumerate() {
                        compose_len += w.compose_len();
                        if compose_len > 4000 {
                            split_at = idx;
                            break;
                        }
                    }

                    let this_batch = unreach_builder.split(split_at);
                    let mut builder = Self::from_target(self.target.clone()).unwrap();
                    builder.add_attribute(MpUnreachNlri::new(this_batch).into()).unwrap();

                    Some(builder.into_message())
                } else {
                    None
                }
            } else {
                None
            }
        ;
        // Bit of a clumsy workaround as we can not return Some(self) from
        // within the if let ... self.attributes.get_mut above
        if let Some(pdu) = maybe_pdu {
            return (pdu, Some(self))
        }

        // Scenario 3: many conventional announcements
        // Similar but different to the scenario of many withdrawals, as
        // announcements are tied to the attributes. At this point, we know we
        // have no conventional withdrawals left, and no MP_UNREACH_NLRI.

        if !self.announcements.is_empty() {
            //let announcement_len = self.announcements.iter()
            //    .fold(0, |sum, a| sum + a.compose_len());

            let split_at = std::cmp::min(self.announcements.len() / 2,  450);
            let this_batch = self.announcements.drain(..split_at);
            let mut builder = Self::from_target(self.target.clone()).unwrap();

            builder.announcements = this_batch.collect();
            builder.attributes = self.attributes.clone();

            return (builder.into_message(), Some(self));

        }

        // Scenario 4: many MP_REACH_NLRI announcements
        // This is tricky: we need to split the MP_REACH_NLRI attribute, and
        // clone the other attributes.
        // At this point, we have no conventional withdrawals/announcements or
        // MP_UNREACH_NLRI path attribute.

        // FIXME this works, but is still somewhat slow for very large input
        // sets. The first PDUs take longer to construct than the later ones.
        // Flamegraph currently hints at the fn split on MpReachNlriBuilder.

        let maybe_pdu = 
            if let Some(PathAttribute::MpReachNlri(b)) = self.attributes.remove(&PathAttributeType::MpReachNlri) {
                let mut reach_builder = b.inner();
                let mut split_at = 0;

                let other_attrs_len = self.attributes.values().fold(0, |sum, pa| sum + pa.compose_len());
                let limit = Self::MAX_PDU 
                    // marker/len/type, wdraw len, total pa len
                    - (16 + 2 + 1 + 2 + 2)
                    // MP_REACH_NLRI flags/type/len/afi/safi/rsrved, next_hop
                    - 8 - reach_builder.get_nexthop().compose_len()
                    - other_attrs_len;

                if !reach_builder.announcements.is_empty() {
                    let mut compose_len = 0;
                    for (idx, a) in reach_builder.announcements.iter().enumerate() {
                        compose_len += a.compose_len();
                        if compose_len > limit {
                            split_at = idx;
                            break;
                        }
                    }

                    let this_batch = reach_builder.split(split_at);
                    let mut builder = Self::from_target(self.target.clone()).unwrap();
                    builder.attributes = self.attributes.clone();
                    self.add_attribute(MpReachNlri::new(reach_builder).into()).unwrap();
                    builder.add_attribute(MpReachNlri::new(this_batch).into()).unwrap();

                    Some(builder.into_message())
                } else {
                    None
                }
            } else {
                None
            }
        ;
        if let Some(pdu) = maybe_pdu {
            return (pdu, Some(self))
        }


        // If we end up here, there is something other than
        // announcements/withdrawals causing very large PDUs. The only thing
        // that comes to mind is any type of Communities, but we can not split
        // those without altering the information that the user intends to
        // convey. So, we error out.

        let pdu_len = self.calculate_pdu_length();
        (Err(ComposeError::PduTooLarge(pdu_len)), None)

    }


    fn into_messages(self) -> Result<
        Vec<UpdateMessage<<Target as FreezeBuilder>::Octets>>,
        ComposeError
    >
    where
        Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
        <Target as FreezeBuilder>::Octets: Octets
    {
        let mut res = Vec::new();
        let mut remainder = Some(self);
        loop {
            if remainder.is_none() {
                return Ok(res);
            }
            let (pdu, new_remainder) = remainder.take().unwrap().take_message();
            match pdu {
                Ok(pdu) => {
                    res.push(pdu);
                    remainder = new_remainder;
                }
                Err(e) => {
                    warn!("error in into_messages(): {}", e);
                    return Err(e)
                }
            }
        }
    }

    fn finish(mut self)
        -> Result<<Target as FreezeBuilder>::Octets, Target::AppendError>
    where
        Target: OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate
    {
        let total_pdu_len = self.calculate_pdu_length();
        let mut header = Header::for_slice_mut(self.target.as_mut());
        header.set_length(u16::try_from(total_pdu_len).unwrap());

        // `withdrawals_len` is checked to be <= 4096 or <= 65535
        // so it will always fit in a u16.
        let withdrawals_len = self.withdrawals.iter()
            .fold(0, |sum, w| sum + w.compose_len());
        self.target.append_slice(
            &u16::try_from(withdrawals_len).unwrap().to_be_bytes()
        )?;

        for w in &self.withdrawals {
            match w {
                Nlri::Unicast(b) if b.is_v4() => {
                    b.compose(&mut self.target)?;
                },
                _ => todo!(),
            }
        }


        // We can do these unwraps because of the checks in the add/append
        // methods.

        // attributes_len` is checked to be <= 4096 or <= 65535
        // so it will always fit in a u16.
        let attributes_len = self.attributes.values()
            .fold(0, |sum, a| sum + a.compose_len());
        let _ = self.target.append_slice(
            &u16::try_from(attributes_len).unwrap().to_be_bytes()
        );

        self.attributes.iter().try_for_each(
            |(_tc, pa)| pa.compose(&mut self.target)
        )?;

        // XXX Here, in the conventional NLRI field at the end of the PDU, we
        // write IPv4 Unicast announcements. But what if we have agreed to do
        // MP for v4/unicast, should these announcements go in the
        // MP_REACH_NLRI attribute then instead?
        for a in &self.announcements {
            match a {
                Nlri::Unicast(b) if b.is_v4() => {
                        b.compose(&mut self.target)?;
                },
                _ => unreachable!(),
            }
        }

        Ok(self.target.freeze())
    }
}

pub struct PduIterator<Target> {
    builder: Option<UpdateBuilder<Target>>
}

impl<Target> Iterator for PduIterator<Target>
where
    Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
    <Target as FreezeBuilder>::Octets: Octets
{
    type Item = Result<
        UpdateMessage<<Target as FreezeBuilder>::Octets>,
        ComposeError
    >;

    fn next(&mut self) -> Option<Self::Item> {
        self.builder.as_ref()?;
        let (res, remainder) = self.builder.take().unwrap().take_message();
        self.builder = remainder;
        Some(res)
    }

}
impl<Target> IntoIterator for UpdateBuilder<Target>
    where
    Target: Clone + OctetsBuilder + FreezeBuilder + AsMut<[u8]> + octseq::Truncate,
    <Target as FreezeBuilder>::Octets: Octets
{
    type Item = Result<
        UpdateMessage<<Target as FreezeBuilder>::Octets>,
        ComposeError
    >;
    type IntoIter = PduIterator<Target>;

    fn into_iter(self) -> Self::IntoIter {
        PduIterator { builder: Some(self) }
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


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpReachNlriBuilder {
    announcements: Vec<Nlri<Vec<u8>>>,
    len: usize, // size of value, excluding path attribute flags+type_code+len
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

    pub(crate) fn split(&mut self, n: usize) -> Self {
        let this_batch = self.announcements.drain(..n).collect();
        MpReachNlriBuilder {
            announcements: this_batch,
            ..*self
        }
    }

    fn new_for_nlri<T>( nlri: &Nlri<T>) -> Self
    where T: Octets,
          Vec<u8>: OctetsFrom<T>
    {
        let (afi, safi) = nlri.afi_safi();
        let addpath_enabled = nlri.is_addpath();
        let nexthop = NextHop::new(afi, safi);
        Self::new(afi, safi, nexthop, addpath_enabled)
    }

    fn new_for_nexthop(nexthop: NextHop) -> Self {
        let (afi, safi) = nexthop.afi_safi();
        let addpath_enabled = false;
        Self::new(afi, safi, nexthop, addpath_enabled)
    }

    pub(crate) fn value_len(&self) -> usize {
        2 + 1 + 1  // afi, safi + 1 reserved byte
          + self.nexthop.compose_len() 
          + self.announcements.iter().fold(0, |sum, w| sum + w.compose_len())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }

    pub(crate) fn get_nexthop(&self) -> &NextHop {
        &self.nexthop
    }

    pub(crate) fn set_nexthop(&mut self, nexthop: NextHop) -> Result<(), ComposeError> {

        if !self.announcements.is_empty() &&
            self.nexthop.afi_safi() != nexthop.afi_safi()
        {
                return Err(ComposeError::IllegalCombination);
        }

        self.len -= self.nexthop.compose_len();
        self.nexthop = nexthop;
        self.len += self.nexthop.compose_len();
        Ok(())
    }

    pub(crate) fn set_nexthop_ll_addr(&mut self, addr: Ipv6Addr) {
        match self.nexthop {
            NextHop::Unicast(IpAddr::V6(a)) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
                self.len += 16;
            }
            NextHop::Ipv6LL(a, _ll) => {
                self.nexthop = NextHop::Ipv6LL(a, addr);
            }
            _ => unreachable!()
        }
    }

     fn valid_combination<T>(
        &self, nlri: &Nlri<T>
    ) -> bool {
        (self.afi, self.safi) == nlri.afi_safi()
        && (self.announcements.is_empty()
             || self.addpath_enabled == nlri.is_addpath())
    }

    pub(crate) fn add_announcement<T>(&mut self, announcement: &Nlri<T>)
    where
        T: Octets,
        Vec<u8>: OctetsFrom<T>,
    {
        let announcement_len = announcement.compose_len();
        if !self.extended && self.len + announcement_len > 255 {
            self.extended = true;
        }
        self.len += announcement_len;
        self.announcements.push(
            <&Nlri<T> as OctetsInto<Nlri<Vec<u8>>>>::try_octets_into(announcement).map_err(|_| ComposeError::todo() ).unwrap()
        );
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

        for a in &self.announcements {
            match a {
                Nlri::Unicast(b) => {
                    if !b.is_v4() {
                        b.compose(target)?;
                    } else {
                        // v4 unicast does not go in the MP_REACH_NLRI path
                        // attribute but at the end of the UDPATE PDU. The
                        // MpReachNlriBuilder should never contain v4 unicast
                        // announcements in its current implementation.
                        unreachable!();
                    }
                }
                Nlri::Multicast(b) => b.compose(target)?,
                Nlri::FlowSpec(f) => f.compose(target)?,
                _ => todo!("{:?}", a)
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
            NextHop::Unicast(IpAddr::V4(_)) | NextHop::Multicast(IpAddr::V4(_)) => 4, 
            NextHop::Unicast(IpAddr::V6(_)) | NextHop::Multicast(IpAddr::V6(_)) => 16, 
            NextHop::Ipv6LL(_, _) => 32,
            //NextHop::Ipv4MplsVpnUnicast(RouteDistinguisher, Ipv4Addr),
            //NextHop::Ipv6MplsVpnUnicast(RouteDistinguisher, Ipv6Addr),
            NextHop::Empty => 0, // FlowSpec
            //NextHop::Unimplemented(AFI, SAFI),
            n => unimplemented!("{}", n)
        }
    }

    pub(crate) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&[u8::try_from(self.compose_len()).unwrap() - 1])?;
        match *self {
            NextHop::Unicast(IpAddr::V4(a)) | NextHop::Multicast(IpAddr::V4(a)) => 
                target.append_slice(&a.octets())?,
            NextHop::Unicast(IpAddr::V6(a)) | NextHop::Multicast(IpAddr::V6(a)) => 
                target.append_slice(&a.octets())?,
            NextHop::Ipv6LL(a, ll) => {
                target.append_slice(&a.octets())?;
                target.append_slice(&ll.octets())?;
            }
            NextHop::Empty => { },

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpUnreachNlriBuilder {
    withdrawals: Vec<Nlri<Vec<u8>>>,
    afi: AFI,
    safi: SAFI,
    addpath_enabled: bool,
}

impl MpUnreachNlriBuilder {
    pub(crate) fn new(afi: AFI, safi: SAFI, addpath_enabled: bool) -> Self {
        MpUnreachNlriBuilder {
            withdrawals: vec![],
            afi,
            safi,
            addpath_enabled
        }
    }

    pub(crate) fn split(&mut self, n: usize) -> Self {
        let this_batch = self.withdrawals.drain(..n).collect();
        MpUnreachNlriBuilder {
            withdrawals: this_batch,
            ..*self
        }
    }

    pub(crate) fn value_len(&self) -> usize {
        3 + self.withdrawals.iter().fold(0, |sum, w| sum + w.compose_len())
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

    pub(crate) fn add_withdrawal<T>(&mut self, withdrawal: &Nlri<T>)
    where
        Vec<u8>: OctetsFrom<T>,
        T: Octets,

    {
        self.withdrawals.push(
            <&Nlri<T> as OctetsInto<Nlri<Vec<u8>>>>::try_octets_into(withdrawal).map_err(|_| ComposeError::todo() ).unwrap()
            );
    }

    pub(crate) fn compose_value<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError>
    {
        target.append_slice(&u16::from(self.afi).to_be_bytes())?;
        target.append_slice(&[self.safi.into()])?;

        for w in &self.withdrawals {
            match w {
                Nlri::Unicast(b) if b.is_v4() => {
                    unreachable!()
                }
                Nlri::Unicast(b) | Nlri::Multicast(b) => b.compose(target)?,
                //Nlri::Mpls(m) => m.compose(target)?,
                //Nlri::MplsVpn(m) => m.compose(target)?,
                //Nlri::Vpls(v) => v.compose(target)?,
                Nlri::FlowSpec(f) => f.compose(target)?,
                //Nlri::RouteTarget(r) => r.compose(target)?,
                _ => todo!()
            }
        }

        Ok(())
    }

}

//------------ StandardCommunitiesBuilder ------------------------------------
//
//

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardCommunitiesBuilder {
    communities: Vec<StandardCommunity>,
    len: usize, // size of value, excluding path attribute flags+type_code+len
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
    AttributeTooLarge(PathAttributeType, usize),
    AttributesTooLarge(usize),
    IllegalCombination,
    EmptyMpReachNlri,
    EmptyMpUnreachNlri,
    WrongAddressType,

    InvalidAttribute, // XXX perhaps carry the type_code here?

    /// Variant for `octseq::builder::ShortBuf`
    ShortBuf,
    /// Wrapper for util::parser::ParseError, used in `fn into_message`
    ParseError(ParseError),

    Todo,
}

impl ComposeError {
    fn todo() -> Self {
        ComposeError::Todo
    }
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
            ComposeError::Todo => {
                write!(f, "not implemented yet")
            }

        }
    }
}


//------------ Tests ----------------------------------------------------------
#[cfg(test)]
mod tests {

    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use octseq::Parser;

    use crate::addr::Prefix;
    use crate::asn::Asn;
    //use crate::bgp::communities::Wellknown;
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
        assert_eq!(msg.withdrawals().unwrap().count(), 1);

        let mut builder2 = UpdateBuilder::new_vec();
        builder2.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();

        let msg2 = builder2.into_message().unwrap();
        print_pcap(msg2.as_ref());
        assert_eq!(msg2.withdrawals().unwrap().count(), 1);
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
        ].map(|s| Nlri::unicast_from_str(s).unwrap().octets_into())
         .into_iter()
         .collect::<Vec<_>>();

        let _ = builder.withdrawals_from_iter(withdrawals);
        let msg = builder.into_message().unwrap();
        print_pcap(msg);
    }

    #[test]
    fn take_message_many_withdrawals() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Nlri<Vec<u8>>> = vec![];
        for i in 1..1500_u32 {
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
        builder.withdrawals_from_iter(prefixes).unwrap();

        let mut w_cnt = 0;
        let remainder = if let (pdu1, Some(remainder)) = builder.take_message() {
            match pdu1 {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                    remainder
                }
                Err(e) => panic!("{}", e)
            }
        } else {
            panic!("wrong");
        };

        let remainder2 = if let (pdu2, Some(remainder2)) = remainder.take_message() {
            match pdu2 {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                    remainder2
                }
                Err(e) => panic!("{}", e)
            }
        } else {
            panic!("wrong");
        };

        if let (pdu3, None) = remainder2.take_message() {
            match pdu3 {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                }
                Err(e) => panic!("{}", e)
            }
        } else {
            panic!("wrong");
        };

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn take_message_many_withdrawals_2() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Nlri<Vec<u8>>> = vec![];
        for i in 1..1500_u32 {
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
        builder.append_withdrawals(&mut prefixes).unwrap();

        let mut w_cnt = 0;
        let mut remainder = Some(builder);
        loop {
            if remainder.is_none() {
                break
            }
            let (pdu, new_remainder) = remainder.take().unwrap().take_message();
            match pdu {
                Ok(pdu) => {
                    w_cnt += pdu.withdrawals().unwrap().count();
                    remainder = new_remainder;
                }
                Err(e) => panic!("{}", e)
            }
        }

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn into_messages_many_withdrawals() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Nlri<Vec<u8>>> = vec![];
        for i in 1..1500_u32 {
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
        builder.append_withdrawals(&mut prefixes).unwrap();

        let mut w_cnt = 0;
        for pdu in builder.into_messages().unwrap() {
            w_cnt += pdu.withdrawals().unwrap().count();
        }

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn into_messages_many_announcements() {
        let mut builder = UpdateBuilder::new_vec();
        let mut prefixes: Vec<Nlri<Vec<u8>>> = vec![];
        for i in 1..1500_u32 {
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
        prefixes.iter().by_ref().for_each(|p|
            builder.add_announcement(p).unwrap()
        );

        let mut w_cnt = 0;
        for pdu in builder.into_messages().unwrap() {
            w_cnt += pdu.announcements().unwrap().count();
        }

        assert_eq!(w_cnt, prefixes_len);
    }

    #[test]
    fn into_messages_many_withdrawals_mp() {
        let mut builder = UpdateBuilder::new_vec();
        let prefixes_num = 1024;
        for i in 0..prefixes_num {
            builder.add_withdrawal(
                &Nlri::unicast_from_str(&format!("2001:db:{:04}::/48", i))
                    .unwrap()
            ).unwrap();
        }

        let mut w_cnt = 0;
        for pdu in builder.into_messages().unwrap() {
            w_cnt += pdu.withdrawals().unwrap().count();
        }

        assert_eq!(w_cnt, prefixes_num);
    }
    use crate::bgp::communities::{StandardCommunity, Tag};
    #[test]
    fn into_messages_many_announcements_mp() {
        let mut builder = UpdateBuilder::new_vec();
        let prefixes_num = 1_000_000;
        for i in 0..prefixes_num {
            builder.add_announcement(
                &Nlri::<&[u8]>::Unicast(BasicNlri::new(Prefix::new_v6((i << 96).into(), 32).unwrap()))
                //&Nlri::unicast_from_str(&format!("2001:db:{:04}::/48", i))
                //    .unwrap()
            ).unwrap();
        }
        builder.set_local_pref(LocalPref::new(123)).unwrap();
        builder.set_multi_exit_disc(MultiExitDisc::new(123)).unwrap();
        (1..=300).for_each(|n| {
            builder.add_community(StandardCommunity::new(n.into(), Tag::new(123))).unwrap();
        });

        let mut a_cnt = 0;
        for pdu in builder {
            //eprint!(".");
            let pdu = pdu.unwrap();
            assert!(pdu.as_ref().len() <= UpdateBuilder::<()>::MAX_PDU);
            a_cnt += pdu.announcements().unwrap().count();
            assert!(pdu.local_pref().unwrap().is_some());
            assert!(pdu.multi_exit_disc().unwrap().is_some());
            assert_eq!(pdu.communities().unwrap().unwrap().count(), 300);
        }

        assert_eq!(a_cnt, prefixes_num.try_into().unwrap());
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
        ].iter().enumerate().map(|(idx, s)| Nlri::<&[u8]>::Unicast(BasicNlri {
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

        let _ = builder.withdrawals_from_iter(withdrawals);
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

        assert_eq!(msg.withdrawals().unwrap().count(), 2);
    }

    #[test]
    fn build_mixed_addpath_conventional() {
        use crate::bgp::message::nlri::PathId;
        let mut builder = UpdateBuilder::new_vec();
        builder.add_withdrawal(
            &Nlri::unicast_from_str("10.0.0.0/8").unwrap()
        ).unwrap();
        let res = builder.add_withdrawal(
            &Nlri::<&[u8]>::Unicast(
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
            &Nlri::<&[u8]>::Unicast(
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
            &Nlri::<&[u8]>::Unicast(
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

        assert!(upd.has_conventional_nlri() && upd.has_mp_nlri().unwrap());
        assert_eq!(upd.unicast_announcements().unwrap().count(), 7);
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
        builder.announcements_from_iter(prefixes).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop_unicast(Ipv4Addr::from_str("1.2.3.4").unwrap().into()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(123); 70
        ]);

        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        let raw = builder.finish().unwrap();
        print_pcap(raw);

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
        builder.announcements_from_iter(prefixes).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop_unicast(Ipv6Addr::from_str("fe80:1:2:3::").unwrap().into()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        let raw = builder.finish().unwrap();
        print_pcap(raw);
    }

    #[test]
    fn build_announcements_mp_missing_nlri() {
        use crate::bgp::aspath::HopPath;

        let mut builder = UpdateBuilder::new_vec();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop_unicast(Ipv6Addr::from_str("fe80:1:2:3::").unwrap().into()).unwrap();
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

        builder.announcements_from_iter(prefixes).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop_ll_addr("fe80:1:2:3::".parse().unwrap()).unwrap();


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
        builder.set_nexthop_ll_addr("fe80:1:2:3::".parse().unwrap()).unwrap();
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
        builder.announcements_from_iter(prefixes).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop_unicast("1.2.3.4".parse::<Ipv4Addr>().unwrap().into()).unwrap();
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
        builder.announcements_from_iter(prefixes).unwrap();
        builder.set_origin(OriginType::Igp).unwrap();
        builder.set_nexthop_unicast(Ipv4Addr::from_str("1.2.3.4").unwrap().into()).unwrap();
        let path = HopPath::from([
             Asn::from_u32(100),
             Asn::from_u32(200),
             Asn::from_u32(300),
        ]);
        //builder.set_aspath::<Vec<u8>>(path.to_as_path().unwrap()).unwrap();
        builder.set_aspath(path).unwrap();

        builder.set_multi_exit_disc(MultiExitDisc::new(1234)).unwrap();
        builder.set_local_pref(LocalPref::new(9876)).unwrap();

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
        let mut builder = UpdateBuilder::from_update_message(&upd, sc, target).unwrap();

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
        for pa in upd.clone().path_attributes().unwrap() {
            eprintln!("{:?}", pa.unwrap().to_owned().unwrap());
        }
        let target = BytesMut::new();
        let mut builder = UpdateBuilder::from_update_message(&upd, sc, target).unwrap();

        
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
        let mut prev_type_code = 0_u8;
        for pa in pdu.path_attributes().unwrap() {
            let type_code = u8::from(pa.unwrap().type_code());
            assert!(prev_type_code < type_code);
            prev_type_code = type_code; 
        }
        assert_eq!(pdu.communities().unwrap().unwrap().count(), 2);
    }

    // TODO also do fn check(raw: Bytes)
    fn parse_build_compare(raw: &[u8]) {
        let sc = SessionConfig::modern();
        let original =
            match UpdateMessage::from_octets(&raw, sc) {
                Ok(msg) => msg,// UpdateMessage::from_octets(&raw, sc) {
                Err(_e) => {
                    //TODO get the ShortInput ones (and retry with a different
                    //SessionConfig)
                    //eprintln!("failed to parse input: {e:?}");
                    //print_pcap(&raw);
                    //panic!();
                    return;
                }
            };

            let target = BytesMut::new();
            let mut builder = UpdateBuilder::from_update_message(
                &original, sc, target
            ).unwrap();

            for w in original.withdrawals().unwrap() {
                builder.add_withdrawal(&w.unwrap()).unwrap();
            }

            for a in original.announcements().unwrap() {
                builder.add_announcement(&a.unwrap()).unwrap();
            }

            if let Some(nh) = original.conventional_next_hop().unwrap() {
                builder.set_nexthop(nh).unwrap();
            }
            if let Some(nh) = original.mp_next_hop().unwrap() {
                builder.set_nexthop(nh).unwrap();
            }

            //eprintln!("--");
            //print_pcap(&raw);
            //print_pcap(builder.finish().unwrap());
            //eprintln!("--");
            //panic!("hard stop");


            let calculated_len = builder.calculate_pdu_length();

            let composed = match builder.take_message() {
                (Ok(msg), None) => msg,
                (Err(e), _) => {
                    print_pcap(raw);
                    panic!("error: {e}");
                }
                (_, Some(_)) => {
                    unimplemented!("builder returning remainder")
                }
            };

            assert_eq!(composed.as_ref().len(), calculated_len);

            // XXX there are several possible reasons why our composed pdu
            // differs from the original input, especially if the attributes
            // in the original were not correctly ordered, or when attributes
            // had the extended-length bit set while not being >255 in size.
            //assert_eq!(raw, composed.as_ref());


            // compare as much as possible:
            #[allow(clippy::blocks_in_if_conditions)]
            if std::panic::catch_unwind(|| {
            assert_eq!(original.origin(), composed.origin());
            //assert_eq!(original.aspath(), composed.aspath());
            assert_eq!(original.conventional_next_hop(), composed.conventional_next_hop());
            assert_eq!(original.mp_next_hop(), composed.mp_next_hop());
            assert_eq!(original.multi_exit_disc(), composed.multi_exit_disc());
            assert_eq!(original.local_pref(), composed.local_pref());

            /*
            assert_eq!(
              original.path_attributes().iter().count(),
              composed.path_attributes().unwrap().count()
            );
            */

            let orig_pas = original.path_attributes().unwrap()
                .map(|pa| pa.unwrap().type_code()).collect::<BTreeSet<_>>();

            let composed_pas = composed.path_attributes().unwrap()
                .map(|pa| pa.unwrap().type_code()).collect::<BTreeSet<_>>();

            let diff_pas: Vec<_> = orig_pas.symmetric_difference(
                &composed_pas
            ).collect();
            if !diff_pas.is_empty() {
                for d in &diff_pas {
                    match d {
                        // FIXME: check if MPU is the _only_ attribute,
                        // perhaps we are dealing with an EoR here?
                        PathAttributeType::MpUnreachNlri => {
                            // XXX RIS data contains empty-but-non-EoR
                            // MP_UNREACH_NLRI for some reason. 
                            //assert!(original.is_eor().is_some());
                            //});

                        }
                        _ => {
                            dbg!(&diff_pas);
                            panic!("unclear why PAs differ")
                        }
                    }
                }
            }



            assert_eq!(
              original.announcements().unwrap().count(),
              composed.announcements().unwrap().count(),
            );
            assert_eq!(
              original.withdrawals().iter().count(),
              composed.withdrawals().iter().count(),
            );

            }).is_err() {
                eprintln!("--");
                print_pcap(raw);
                print_pcap(composed.as_ref());

                eprintln!("--");
                panic!("tmp");
            }

            if raw == composed.as_ref() {
                eprint!("✓");
            } else {
                eprint!("×");
            }
    }

    #[test]
    fn parse_build_compare_1() {
        eprintln!();
        parse_build_compare(&[
        // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x37, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
            0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ]
        );

        parse_build_compare(&[
            // BGP UPDATE, Ipv4 FlowSpec, empty AS_PATH, ext communities
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x46, 0x02, 0x00, 0x00, 0x00, 0x2f, 0x90,
            0x0e, 0x00, 0x12, 0x00, 0x01, 0x85, 0x00, 0x00,
            0x0c, 0x07, 0x81, 0x08, 0x08, 0x81, 0x00, 0x0b,
            0x81, 0x08, 0x0c, 0x81, 0x01, 0x40, 0x01, 0x01,
            0x00, 0x40, 0x02, 0x00, 0x40, 0x05, 0x04, 0x00,
            0x00, 0x00, 0x64, 0xc0, 0x10, 0x08, 0x80, 0x09,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        ]
        );

        // FIXME: the NextHop in MP_REACH_NLRI gets lost
        parse_build_compare(&[
            // BGP UPDATE, IPv4 Multicast, NEXT_HOP, et al.
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x52, 0x02, 0x00, 0x00, 0x00, 0x3b, 0x80,
            0x0e, 0x1d, 0x00, 0x01, 0x02, 0x04, 0x0a, 0x09,
            0x0a, 0x09, 0x00, 0x1a, 0xc6, 0x33, 0x64, 0x00,
            0x1a, 0xc6, 0x33, 0x64, 0x40, 0x1a, 0xc6, 0x33,
            0x64, 0x80, 0x1a, 0xc6, 0x33, 0x64, 0xc0, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
            0x00, 0x00, 0x01, 0xf4, 0x40, 0x03, 0x04, 0x0a,
            0x09, 0x0a, 0x09, 0x80, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x00
        ]
        );
        eprintln!("");

    }


/*
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
*/
}
