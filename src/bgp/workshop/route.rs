use std::fmt::Debug;
use std::hash::Hash;
//use std::marker::PhantomData;

use octseq::{Octets, OctetsFrom};

use crate::bgp::communities::Community;
use crate::bgp::message::update_builder::{ComposeError, /*MpReachNlriBuilder*/};
use crate::bgp::message::UpdateMessage;
use crate::bgp::path_attributes::{FromAttribute, PaMap};
use crate::bgp::{
    message::{
        //nlri::Nlri,
        update_builder::StandardCommunitiesList
    },
    path_attributes::{
        ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
        LargeCommunitiesList, PathAttribute, 
    },
};

use crate::bgp::nlri::afisafi::{AfiSafiNlri, AfiSafiType, Nlri};
use crate::bgp::nlri::nexthop::NextHop;
use crate::bgp::types::ConventionalNextHop;


//------------ TypedRoute ----------------------------------------------------

#[derive(Debug)]
pub enum TypedRoute<N: Clone + Debug + Hash> {
    Announce(Route<N>),
    Withdraw(Nlri<N>),
}


//------------ Route ---------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Route<N: Clone + Debug + Hash>(N, PaMap);

impl<N: Clone + Debug + Hash> Route<N> {
    pub fn new(nlri: N, attrs: PaMap) -> Self {
        Self(nlri, attrs)
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn get_attr<A: FromAttribute + Clone>(&self) -> Option<A> {
        if A::attribute_type().is_some() {
            self.1.get::<A>()
        } else {
            None
        }
    }

    pub fn attributes(&self) -> &PaMap {
        &self.1
    }

    pub fn attributes_mut(&mut self) -> &mut PaMap {
        &mut self.1
    }
}


//------------ From impls for PathAttribute ----------------------------------

impl From<crate::bgp::aspath::AsPath<bytes::Bytes>> for PathAttribute {
    fn from(value: crate::bgp::aspath::AsPath<bytes::Bytes>) -> Self {
        PathAttribute::AsPath(value.to_hop_path())
    }
}

impl From<crate::bgp::aspath::AsPath<Vec<u8>>> for PathAttribute {
    fn from(value: crate::bgp::aspath::AsPath<Vec<u8>>) -> Self {
        PathAttribute::AsPath(value.to_hop_path())
    }
}


//------------ The Workshop --------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RouteWorkshop<N>(N, Option<NextHop>, PaMap);

impl<N: AfiSafiNlri + Clone + Debug + Hash> RouteWorkshop<N> {

    /// Creates an empty RouteWorkshop.
    ///
    /// The resulting RouteWorkshop has its NextHop set to `None` and an empty
    /// [`PaMap`].
    pub fn new(nlri: N) -> Self {
        Self(nlri, None, PaMap::empty())
    }

    /// Creates a RouteWorkshop from one NLRI and a [`PaMap`].
    ///
    /// No logic is applied to the contents of the attributes in the PaMap.
    /// When creating a RouteWorkshop via this constructor, the caller needs
    /// to ensure the contents of the PaMap are sensible for the provided
    /// NLRI.
    ///
    /// Consider using [`RouteWorkshop::from_update_pdu`] when the original
    /// PDU is available.
    // XXX do we actually need and want this?
    pub fn from_pa_map(nlri: N, pa_map: PaMap) -> Self {
        Self(nlri, None, pa_map)
    }

        
    /// Creates a RouteWorkshop from one NLRI and its BGP [`UpdateMessage`].
    ///
    /// Based on the type of NLRI, i.e. conventional or Multi Protocol, the
    /// Next Hop from the NEXT_HOP path attribute or the field in the
    /// MP_REACH_NLRI attribute is set in the resulting RouteWorkshop.
    /// In both cases, the NEXT_HOP path attribute is omitted from the
    /// attached [`PaMap`].
    pub fn from_update_pdu<Octs: Octets>(
        nlri: N,
        pdu: &UpdateMessage<Octs>,
    ) -> Result<Self, ComposeError>
    where
        for<'a> Vec<u8>: OctetsFrom<Octs::Range<'a>>,
    {
        let mut res = Self::new(nlri);

        if N::afi_safi() == AfiSafiType::Ipv4Unicast &&
            pdu.has_conventional_nlri()
        {
            if let Ok(Some(nh)) = pdu.conventional_next_hop() {
                res.set_nexthop(nh);
                let mut pamap = PaMap::from_update_pdu(pdu)?;
                let _ = pamap.remove::<ConventionalNextHop>();
                res.set_attributes(pamap);
                return Ok(res);
            } else {
                return Err(ComposeError::InvalidAttribute);
            }
        }

        if let Ok(Some(nh)) = pdu.mp_next_hop() {
            res.set_nexthop(nh);
            let mut pamap = PaMap::from_update_pdu(pdu)?;
            let _ = pamap.remove::<ConventionalNextHop>();
            res.set_attributes(pamap);
            Ok(res)
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }


    /// Validates the contents of this RouteWorkshop.
    ///
    /// If the combination of the various pieces of content in this
    /// RouteWorkshop could produce a valid BGP UPDATE PDU, this method
    /// returns `Ok(())`. The following checks are performed:
    ///
    ///  * The NextHop is set, and is compatible with the NLRI type.
    pub fn validate(&self) -> Result<(), ComposeError> {
        match self.1 {
            None     => { return Err(ComposeError::InvalidAttribute); }
            Some(_nh) => {
                // TODO
                /*
                if !self.0.allowed_next_hops().any(|a| a == nh.afi_safi()) {
                    return Err(ComposeError::IllegalCombination);
                }
                */
            }
        }
        Ok(())
    }

    pub fn nlri(&self) -> &N {
        &self.0
    }

    pub fn nexthop(&self) -> &Option<NextHop> {
        &self.1
    }

    pub fn set_nexthop(&mut self, nh: NextHop) -> Option<NextHop> {
        self.1.replace(nh)
    }

    pub fn set_attr<WA: WorkshopAttribute<N>>(
        &mut self,
        value: WA,
    ) -> Result<(), ComposeError> {
        WA::store(value, &mut self.2)
    }

    pub fn get_attr<A: WorkshopAttribute<N>>(
        &self,
    ) -> Option<A> {
        self.2.get::<A>().or_else(|| A::retrieve(&self.2))
    }

    pub fn clone_into_route(&self) -> Route<N> {
        Route::<N>(self.0.clone(), self.2.clone())
    }

    pub fn into_route(self) -> Route<N> {
        Route::<N>(self.0, self.2)
    }

    pub fn attributes(&self) -> &PaMap {
        &self.2
    }

    pub fn set_attributes(&mut self, pa_map: PaMap) {
        self.2 = pa_map;
    }

    pub fn attributes_mut(&mut self) -> &mut PaMap {
        &mut self.2
    }
}

macro_rules! impl_workshop {
    (
        $( $attr:ty )+
    ) => {
        $(
            impl<N: Clone + Hash + Debug> WorkshopAttribute<N> for $attr {
                fn store(local_attrs: Self, attrs: &mut PaMap) ->
                    Result<(), ComposeError> { attrs.set(local_attrs); Ok(()) }
                fn retrieve(_attrs: &PaMap) ->
                    Option<Self> { None }
            }
        )+
    }
}

impl_workshop!(
    crate::bgp::aspath::HopPath
    crate::bgp::types::LocalPref
    crate::bgp::types::MultiExitDisc
    crate::bgp::types::Origin
    crate::bgp::types::OriginatorId
    crate::bgp::path_attributes::AggregatorInfo
    crate::bgp::path_attributes::ExtendedCommunitiesList
    crate::bgp::path_attributes::AsPathLimitInfo
    crate::bgp::path_attributes::Ipv6ExtendedCommunitiesList
    crate::bgp::path_attributes::LargeCommunitiesList
    crate::bgp::path_attributes::ClusterIds
    crate::bgp::message::update_builder::StandardCommunitiesList
    crate::bgp::types::Otc
    //crate::bgp::message::update_builder::MpReachNlriBuilder
);


//------------ WorkshopAttribute ---------------------------------------------

pub trait WorkshopAttribute<N>: FromAttribute {
    fn retrieve(attrs: &PaMap) -> Option<Self>
    where
        Self: Sized;
    fn store(
        local_attrs: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError>;
}

//------------ CommunitiesWorkshop -------------------------------------------

impl<N: Clone + Hash + Debug> WorkshopAttribute<N> for Vec<Community> {
    fn retrieve(attrs: &PaMap) -> Option<Self> {
        let mut c = attrs
            .get::<StandardCommunitiesList>()
            .map(|c| c.fmap(|c| Community::Standard(*c)))
            .unwrap_or_default();
        c.append(
            &mut attrs
                .get::<ExtendedCommunitiesList>()
                .map(|c| c.fmap(Community::Extended))
                .unwrap_or_default()
        );
        c.append(
            &mut attrs
                .get::<Ipv6ExtendedCommunitiesList>()
                .map(|c| c.fmap(Community::Ipv6Extended))
                .unwrap_or_default()
        );
        c.append(
            &mut attrs
                .get::<LargeCommunitiesList>()
                .map(|c| c.fmap(Community::Large))
                .unwrap_or_default()
        );

        Some(c)
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        for comm in local_attr {
            match comm {
                Community::Standard(c) => {
                    if let Some(mut b) =
                        attrs.get::<StandardCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Extended(c) => {
                    if let Some(mut b) =
                        attrs.get::<ExtendedCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Ipv6Extended(c) => {
                    if let Some(mut b) =
                        attrs.get::<Ipv6ExtendedCommunitiesList>()
                    {
                        b.add_community(c)
                    }
                }
                Community::Large(_) => todo!(),
            };
        }

        Ok(())
    }
}

impl FromAttribute for Vec<Community> { }

//------------ NlriWorkshop --------------------------------------------------

impl FromAttribute for Nlri<Vec<u8>> { }

/*
impl<N: Clone + Hash> WorkshopAttribute<N> for Nlri<Vec<u8>> {
    fn retrieve(attrs: &PaMap) -> Option<Self>
    where
        Self: Sized {
        attrs.get::<MpReachNlriBuilder>().and_then(|mr| mr.first_nlri())
    }

    fn store(
        local_attr: Self,
        attrs: &mut PaMap,
    ) -> Result<(), ComposeError> {
        if let Some(mut nlri) = attrs.get::<MpReachNlriBuilder>() {
            nlri.set_nlri(local_attr)
        } else {
            Err(ComposeError::InvalidAttribute)
        }
    }
}
*/

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::message::update::SessionConfig;

    use crate::bgp::nlri::afisafi::{
        Ipv4UnicastNlri,
        Ipv6UnicastNlri,
        Ipv6UnicastAddpathNlri,
        Ipv4FlowSpecNlri,
    };


    #[test]
    fn rws_from_pdu() {

        // UPDATE with 5 ipv6 nlri, 2 conventional, but NO conventional
        // NEXT_HOP attribute.
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            //0x00, 0x88,
            0x00, 0x88 + 6,
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
            16, 1, 2,
            16, 10, 20

        ];
        let pdu = UpdateMessage::from_octets(raw, &SessionConfig::modern())
            .unwrap();

        let mp_nlri = pdu.typed_announcements::<_, Ipv6UnicastNlri>()
            .unwrap().unwrap().next().unwrap().unwrap();
        let mp_rws = RouteWorkshop::from_update_pdu(mp_nlri, &pdu).unwrap();

        mp_rws.validate().unwrap();

        let conv_nlri = pdu.typed_announcements::<_, Ipv4UnicastNlri>()
            .unwrap().unwrap().next().unwrap().unwrap();
        assert!(RouteWorkshop::from_update_pdu(conv_nlri, &pdu).is_err());
    }


    #[test]
    fn rws_from_pdu_valid_conv() {
        let raw = vec![
            // BGP UPDATE, single conventional announcement, MultiExitDisc
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02,
            0x00, 0x00, 0x00, 0x1b, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02,
            0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04,
            0x0a, 0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00,
            0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02
        ];

        let pdu = UpdateMessage::from_octets(raw, &SessionConfig::modern())
            .unwrap();

        let conv_nlri = pdu.typed_announcements::<_, Ipv4UnicastNlri>()
            .unwrap().unwrap().next().unwrap().unwrap();
        let conv_rws =RouteWorkshop::from_update_pdu(conv_nlri, &pdu).unwrap();

        assert_eq!(
            conv_rws.1,
            Some(NextHop::Unicast("10.255.0.101".parse().unwrap()))
        );
    }
}
