use core::fmt;
use std::cmp;
use std::net;

use inetnum::asn::Asn;
use log::trace;

use super::{
    aspath::HopPath,
    path_attributes::{BgpIdentifier, ClusterIds, PaMap},
    types::{LocalPref, MultiExitDisc, Origin, OriginatorId},
};

/// Wrapper type used for comparison and path selection.
#[derive(Copy, Clone, Debug)]
pub struct OrdRoute<'a, OS> {
    pa_map: &'a PaMap,
    tiebreakers: TiebreakerInfo,
    _strategy: std::marker::PhantomData<OS>,
}

impl<'a, OS> OrdRoute<'a, OS> {
    /// Check if all required path attributes are present and valid.
    ///
    /// This checks that:
    /// * ORIGIN must be present;
    /// * AS_PATH must be present;
    /// * AS_PATH must not be empty in case of EBGP;
    fn eligible(self) -> Result<Self, DecisionError> {
        use DecisionErrorType as DET;

        // Mandatory path attribute Origin must be present.
        if !self.pa_map.contains::<Origin>() {
            return Err(DET::MissingOrigin.into());
        }

        // Mandatory path attribute AS_PATH must be present but might be
        // empty.
        if !self.pa_map.contains::<HopPath>() {
            return Err(DET::MissingAsPath.into());
        }

        // In case of EBGP it must contain a neighbour though.
        if self.tiebreakers.source == RouteSource::Ebgp
            && self
                .pa_map
                .get::<HopPath>()
                .and_then(|asp| asp.neighbor_path_selection())
                .is_none()
        {
            return Err(DET::EbgpWithoutNeighbour.into());
        }

        Ok(self)
    }
}

impl<'a, OS: OrdStrat> OrdRoute<'a, OS> {
    /// Create a comparable, orderable route to be used in path selection.
    ///
    /// This function returns an error whenever the path attributes (i.e., the
    /// contents of `pa_map`) are incomplete or invalid for the path selection
    /// process. Also see [`eligible`].
    pub fn try_new(
        pa_map: &'a PaMap,
        tiebreakers: TiebreakerInfo,
    ) -> Result<Self, DecisionError> {
        Self {
            pa_map,
            tiebreakers,
            _strategy: std::marker::PhantomData,
        }
        .eligible()
    }
}

impl<'a> OrdRoute<'a, Rfc4271> {
    /// Create a comparable route using the [`Rfc4271`] ordering strategy.
    pub fn rfc4271(
        pa_map: &'a PaMap,
        tiebreakers: TiebreakerInfo,
    ) -> Result<Self, DecisionError> {
        Self::try_new(pa_map, tiebreakers)
    }
}

impl<'a> OrdRoute<'a, SkipMed> {
    /// Create a comparable route using the [`SkipMed`] ordering strategy.
    pub fn skip_med(
        pa_map: &'a PaMap,
        tiebreakers: TiebreakerInfo,
    ) -> Result<Self, DecisionError> {
        Self::try_new(pa_map, tiebreakers)
    }
}

//------------ Traits --------------------------------------------------------

impl<'a, T> OrdRoute<'a, T> {
    pub fn into_strat<U: OrdStrat>(self) -> OrdRoute<'a, U> {
        OrdRoute {
            pa_map: self.pa_map,
            tiebreakers: self.tiebreakers,
            _strategy: std::marker::PhantomData,
        }
    }

    pub fn from_strat<U: OrdStrat>(src: OrdRoute<'a, U>) -> Self {
        OrdRoute {
            pa_map: src.pa_map,
            tiebreakers: src.tiebreakers,
            _strategy: std::marker::PhantomData,
        }
    }
}

/// Decision process `Ord` strategy.
///
/// For flexibility in the `Ord` implementation of routes, used in the BGP
/// Decision process (path selection), we wrap routes in a struct that is
/// generic over something implementing parts of the ordering strategy via
/// this trait.
pub trait OrdStrat {
    /// The RFC4271 tie breaker concerning Multi Exit Discriminator.
    fn step_c<OS>(a: &OrdRoute<OS>, b: &OrdRoute<OS>) -> cmp::Ordering;

    /// The RFC4271 tie breaker concerning interior cost.
    ///
    /// This function defaults to returning `Ordering::Equal`, effectively
    /// skipping the entire step.
    #[allow(unused_variables)]
    fn step_e<OS>(a: &OrdRoute<OS>, b: &OrdRoute<OS>) -> cmp::Ordering {
        cmp::Ordering::Equal
    }
}

/// Decision process strategy as described in RFC 4271.
#[derive(Copy, Clone, Debug)]
pub struct Rfc4271;
impl OrdStrat for Rfc4271 {
    fn step_c<OS>(a: &OrdRoute<OS>, b: &OrdRoute<OS>) -> cmp::Ordering {
        //  c: if the neighbour ASN is the same, prefer lower MED. No MED
        //     present means the lowest MED is used
        //     also, another can of worms when it comes to IBGP vs EBGP

        // First, Determine whether 'neighbour ASN is the same.
        // If true, go on and compare the MED.
        // Otherwise, consider the routes equal and go on with step d.

        if a.pa_map
            .get::<HopPath>()
            .and_then(|asp| asp.neighbor_path_selection())
            .unwrap_or(a.tiebreakers.local_asn)
            == b.pa_map
                .get::<HopPath>()
                .and_then(|asp| asp.neighbor_path_selection())
                .unwrap_or(b.tiebreakers.local_asn)
        {
            // neighbor ASN is considered equal, check the MEDs:
            trace!("checking MEDs");
            let a_med =
                a.pa_map.get::<MultiExitDisc>().unwrap_or(MultiExitDisc(0));
            let b_med =
                b.pa_map.get::<MultiExitDisc>().unwrap_or(MultiExitDisc(0));
            a_med.cmp(&b_med)
        } else {
            cmp::Ordering::Equal
        }
    }
}

/// Decision process strategy skipping comparison of Multi Exit Discriminator.
#[derive(Copy, Clone, Debug)]
pub struct SkipMed;

impl OrdStrat for SkipMed {
    fn step_c<OS>(_a: &OrdRoute<OS>, _b: &OrdRoute<OS>) -> cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}

impl<'a, OS: OrdStrat> PartialOrd for OrdRoute<'a, OS> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Ordering for routes, used for comparison and thus path selection.
///
/// The ordering is such that the most preferred route comes first. In other
/// words, RouteA < RouteB means that RouteA is preferred over RouteB. In an
/// ordered collection, the first/minimum is thus the 'best path'.
///
/// **NB**: for a route to be an actual candidate in the path selection
/// process, additional checks need to be performed beforehand. Refer to
/// [`eligible`] for the specific checks.
impl<'a, OS: OrdStrat> Ord for OrdRoute<'a, OS> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Degree of preference
        // The DoP is taken from LOCAL_PREF in case of IBGP, or when that's
        // missing or the route comes from EBGP, the DoP is 'computed based on
        // local policy information'.

        // Higher DoP is preferred over lower DoP.
        // If the DoP is explicitly passed in the OrdRoute, use that.
        // Otherwise,  check for LOCAL_PREF if ibgp. Otherwise, None/0.
        let a_dop = self
            .tiebreakers
            .degree_of_preference
            .or_else(|| {
                if self.tiebreakers.source == RouteSource::Ibgp {
                    self.pa_map.get::<LocalPref>().map(Into::into)
                } else {
                    None
                }
            })
            .unwrap_or(DegreeOfPreference(0));

        let b_dop = other
            .tiebreakers
            .degree_of_preference
            .or_else(|| {
                if other.tiebreakers.source == RouteSource::Ibgp {
                    other.pa_map.get::<LocalPref>().map(Into::into)
                } else {
                    None
                }
            })
            .unwrap_or(DegreeOfPreference(0));

        b_dop
            .cmp(&a_dop)
            .then_with(|| {
                trace!("equal after DoP");
                // Tie breakers
                //
                // Some notes/questions/remarks:
                //  - is there an actual 'default Local Pref value' or is that
                //  a vendor specific thing? many vendor docs mention 100
                //  being the default
                //  - many online explanations include a 'prefer route that is
                //  older / was learned first' between steps e and f
                //  - the 'weight' that many explanations start out with is a
                //  Cisco specific thing. e.g. a locally originated route gets
                //  the max weight of 32768 and is preferred over everything
                //  else.
                //  - after the IGP cost comparison (which we don't do
                //  currently), paths are considered 'equal-cost' and can be
                //  used in a BGP multipath scenario. Can we incorporate this
                //  in the Ord impl somehow? Perhaps introduce (another)
                //  wrapper(s) in addition to OrdRoute that compare only up to
                //  that step and after that step, respectively (which,
                //  combined, does the same as OrdRoute currently does)?
                //  - another possible 'split up point', that also comes after
                //  the IGP cost comparison: in JunOS, when the compared paths
                //  are both external and one is already active, prefer that
                //  active one to minimize route flapping.
                //
                //  seems that the big vendors all have their custom config
                //  switches to enable/disable/tune certain parts of the tie
                //  breakers. Perhaps we can come up with a way to do such
                //  fine-grained tuning (with minimal user input from say roto
                //  required).

                //  a: prefer the shorter aspath len (AS_SET counts as 1)

                match (
                    self.pa_map.get::<HopPath>(),
                    other.pa_map.get::<HopPath>(),
                ) {
                    (Some(a), Some(b)) => a
                        .hop_count_path_selection()
                        .cmp(&b.hop_count_path_selection()),
                    (_, _) => {
                        panic!("can not compare routes lacking AS_PATH");
                        //cmp::Ordering::Equal
                    }
                }
            })
            .then_with(|| {
                trace!("equal after step a");
                //  b: prefer the lower Origin
                match (
                    self.pa_map.get::<Origin>(),
                    other.pa_map.get::<Origin>(),
                ) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    (_, _) => cmp::Ordering::Equal,
                }
            })
            .then_with(|| {
                trace!("equal after step b");

                // The RFC4271 step C is as follows, and the `Rfc4271` impl of
                // `OrdStrat` does just that. The `SkipMed` strategy skips
                // this step.
                //  c: if the neighbour ASN is the same, prefer lower MED. No
                //  MED present means the lowest MED (== 0) is used.

                OS::step_c(self, other)
            })
            .then_with(|| {
                trace!("equal after step c");
                //  d: EBGP is preferred over all IBGP
                self.tiebreakers.source.cmp(&other.tiebreakers.source)
            })
            .then_with(|| {
                //  e: prefer lower interior cost, or treat all equally if we
                //  can not determine this
                OS::step_e(self, other)
            })
            .then_with(|| {
                trace!("equal after step d+e");
                //  f: prefer the lower BGP Identifier value
                //     *addition from RFC4456 (Route Reflection)*:
                //     If a route carries the ORIGINATOR_ID attribute, the
                //     ORIGINATOR_ID SHOULD be treated as the BGP Identifier
                //     of the BGP speaker that has advertised the route.
                self.pa_map
                    .get::<OriginatorId>()
                    .map(|id| id.0.octets())
                    .unwrap_or(self.tiebreakers.bgp_identifier.into())
                    .cmp(
                        &other
                            .pa_map
                            .get::<OriginatorId>()
                            .map(|id| id.0.octets())
                            .unwrap_or(
                                other.tiebreakers.bgp_identifier.into(),
                            ),
                    )
            })
            .then_with(|| {
                trace!("equal after step f");

                // RFC4456 (Route Reflection):
                // the following rule SHOULD be inserted between Steps f) and
                // g):
                // a BGP Speaker SHOULD prefer a route with the shorter
                // CLUSTER_LIST length.  The CLUSTER_LIST length is zero if a
                // route does not carry the CLUSTER_LIST attribute.
                self.pa_map
                    .get::<ClusterIds>()
                    .map(|l| l.len())
                    .unwrap_or(0)
                    .cmp(
                        &other
                            .pa_map
                            .get::<ClusterIds>()
                            .map(|l| l.len())
                            .unwrap_or(0),
                    )
            })
            .then_with(|| {
                trace!("equal after step f2");
                //  g: prefer the lower peer address
                self.tiebreakers.peer_addr.cmp(&other.tiebreakers.peer_addr)
            })
            .then_with(|| {
                // this shouldn't happen when doing actual best path
                // selection!
                trace!("equal at end of tie breakers");
                cmp::Ordering::Equal
            })
    }
}

impl<'a, OS: OrdStrat> Eq for OrdRoute<'a, OS> {}

impl<'a, OS: OrdStrat> PartialEq for OrdRoute<'a, OS> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

//------------ Tiebreaker types ----------------------------------------------

/// Additional information required for the Decision Process.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TiebreakerInfo {
    source: RouteSource,
    degree_of_preference: Option<DegreeOfPreference>,
    local_asn: Asn,
    bgp_identifier: BgpIdentifier,
    peer_addr: net::IpAddr,
}

/// Describes whether the route was learned externally or internally.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum RouteSource {
    Ebgp,
    Ibgp,
}

/// The Degree of Preference used in Phase 1 of the Decision Process.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DegreeOfPreference(pub u32);

impl From<LocalPref> for DegreeOfPreference {
    fn from(value: LocalPref) -> Self {
        Self(value.0)
    }
}

//------------ Errors --------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DecisionError {
    error_type: DecisionErrorType,
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error_type, f)
    }
}

impl std::error::Error for DecisionError {}

#[allow(unused)]
#[derive(Copy, Clone, Debug)]
enum DecisionErrorType {
    EbgpWithoutNeighbour,
    AsPathLoop,
    MissingAsPath,
    MissingOrigin,
}

impl From<DecisionErrorType> for DecisionError {
    fn from(det: DecisionErrorType) -> Self {
        DecisionError { error_type: det }
    }
}

impl fmt::Display for DecisionErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecisionErrorType as DET;
        match self {
            DET::EbgpWithoutNeighbour => {
                write!(f, "expected non-empty AS_PATH")
            }
            DET::AsPathLoop => write!(f, "AS_PATH loop"),
            DET::MissingAsPath => write!(f, "missing mandatory AS_PATH"),
            DET::MissingOrigin => write!(f, "missing mandatory ORIGIN"),
        }
    }
}


//------------ Helpers -------------------------------------------------------

pub fn preferred<'a, OS: OrdStrat>(
    a: OrdRoute<'a, OS>, b: OrdRoute<'a, OS>
) -> OrdRoute<'a, OS> {
    cmp::min(a,b)
}

pub fn best<'a, OS: 'a + OrdStrat, I>(it: I) -> Option<I::Item>
where
    I: Iterator<Item = OrdRoute<'a, OS>>
{
    it.min()
}

pub fn best_with_strat<'a, OS, AltOS, I>(it: I)
-> Option<OrdRoute<'a, AltOS>>
where
    OS: 'a + OrdStrat,
    AltOS: 'a + OrdStrat,
    I: Iterator<Item = OrdRoute<'a, OS>>,
{
    it.map(|r| r.into_strat()).min()
}


// XXX would this be convenient?
pub fn best_alt<'a, OS: OrdStrat>(
    _pamaps: impl Iterator<Item = &'a PaMap>,
    _tiebreakers: impl Iterator<Item = TiebreakerInfo>
) -> Option<OrdRoute<'a, OS>> {
    unimplemented!()
}

pub fn best_backup_vec<'a, OS: OrdStrat>(
    it: impl Iterator<Item = OrdRoute<'a, OS>>
) -> (Option<OrdRoute<'a, OS>>, Option<OrdRoute<'a, OS>>) 
{
    let mut sorted = it.collect::<Vec<_>>();
    sorted.sort();
    let mut iter = sorted.into_iter();

    let best = iter.next();
    let backup = iter.next();

    (best, backup)
}

pub fn best_backup<T: Ord>(
    it: impl Iterator<Item = T>
) -> (Option<T>, Option<T>) 
{
    let mut best = None;
    let mut backup = None; 

    for c in it {
        match best.take() {
            None => { best = Some(c); continue }
            Some(cur_best) => {
                if c < cur_best  {
                    // c is preferred over current
                    best = Some(c);
                    backup = Some(cur_best);
                    continue;
                }
                // put it back in
                best = Some(cur_best);

                // c is not better than best, now check backup
                match backup.take() {
                    None => { backup = Some(c); }
                    Some(cur_backup) => {
                        if c <  cur_backup {
                            // c is preferred over backup
                            backup = Some(c);
                        } else {
                            backup = Some(cur_backup);
                        }

                    }
                }
            }
        }
    }

    (best, backup)
}


pub fn best_multistrat<'a, OS1: 'a + OrdStrat, OS2: 'a + OrdStrat, I>(it: I)
-> Option<(OrdRoute<'a, OS1>, OrdRoute<'a, OS2>)>  
where
    I: Clone + Iterator<Item = OrdRoute<'a, OS1>>,
{
    let res1 = best(it.clone());
    let res1 = match res1 {
        Some(r) => r,
        None => return None
    };

    // Given that res1 is not None, `it` is non-empty.
    // For a non-empty collection of OrdRoutes, there is always a best, so we
    // can unwrap().
    let res2 = best_with_strat::<'_, _, OS2, _>(it).unwrap();

    Some((res1, res2))
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::bgp::types::OriginType;

    #[test]
    fn route_source_order() {
        // Order of the variants is important for the path selection tie
        // breakers.
        assert!(RouteSource::Ebgp < RouteSource::Ibgp);
    }

    #[test]
    fn rfc4271_total_ordering_fail() {
        let tiebreakers = TiebreakerInfo {
            source: RouteSource::Ebgp,
            degree_of_preference: None,
            local_asn: Asn::from_u32(100),
            bgp_identifier: [0, 0, 0, 0].into(),
            peer_addr: "::".parse().unwrap(),
        };

        let mut a_pamap = PaMap::empty();
        a_pamap.set(Origin(OriginType::Egp));
        a_pamap.set(HopPath::from([10, 20, 30]));
        a_pamap.set(MultiExitDisc(100));

        let mut b_pamap = PaMap::empty();
        b_pamap.set(Origin(OriginType::Egp));
        b_pamap.set(HopPath::from([10, 25, 30]));
        b_pamap.set(MultiExitDisc(50));

        let mut c_pamap = PaMap::empty();
        c_pamap.set(Origin(OriginType::Egp));
        c_pamap.set(HopPath::from([80, 90, 100]));

        let a = OrdRoute::rfc4271(&a_pamap, tiebreakers).unwrap();
        let b = OrdRoute::rfc4271(&b_pamap, tiebreakers).unwrap();
        let c = OrdRoute::rfc4271(&c_pamap, tiebreakers).unwrap();

        assert!(a > b);
        assert!(b == c);
        // For total ordering, one expects a > c now. But checking MEDs breaks
        // total ordering, so:
        //assert!(a > c);  // this would panic
        assert!(a == c);

        // Now if we skip that step using the SkipMed OrdStrat, we get:
        let a: OrdRoute<SkipMed> = a.into_strat();
        let b: OrdRoute<SkipMed> = b.into_strat();
        let c: OrdRoute<SkipMed> = c.into_strat();

        assert!(a == b);
        assert!(b == c);
        assert!(a == c);
    }


    #[test]
    fn helpers_ordroute() {

        let tiebreakers = TiebreakerInfo {
            source: RouteSource::Ebgp,
            degree_of_preference: None,
            local_asn: Asn::from_u32(100),
            bgp_identifier: [0, 0, 0, 0].into(),
            peer_addr: "::".parse().unwrap(),
        };

        let mut a_pamap = PaMap::empty();
        a_pamap.set(Origin(OriginType::Egp));
        a_pamap.set(HopPath::from([10, 20, 30]));
        a_pamap.set(MultiExitDisc(100));

        let mut b_pamap = PaMap::empty();
        b_pamap.set(Origin(OriginType::Egp));
        b_pamap.set(HopPath::from([10, 25, 30]));
        b_pamap.set(MultiExitDisc(50));

        let mut c_pamap = PaMap::empty();
        c_pamap.set(Origin(OriginType::Egp));
        c_pamap.set(HopPath::from([80, 90, 100]));

        let candidates = [
            OrdRoute::rfc4271(&a_pamap, tiebreakers).unwrap(),
            OrdRoute::rfc4271(&b_pamap, tiebreakers).unwrap(),
            OrdRoute::rfc4271(&c_pamap, tiebreakers).unwrap(),
        ];

        let best1 = best(candidates.into_iter());
        let (best2, backup2) = best_backup_vec(candidates.into_iter());
        let (best3, backup3) = best_backup(candidates.into_iter());

        assert_eq!(best1, best2);
        assert_eq!(best2, best3);
        assert_eq!(backup2, backup3);
        assert_ne!(best2, backup2);
        assert_ne!(best3, backup3);

        //dbg!(&best1);
        //dbg!(&backup2);
    }

    #[test]
    fn helpers_generic() {
        let (a,b,c) = ("2".to_string(), "1".to_string(), "3".to_string());
        //let (a,b,c) = (2, 1, 3);
        let values = vec![&a, &b, &c];
        let (best, backup) = best_backup(values.into_iter());
        assert_eq!(best, Some(&b));
        assert_eq!(backup, Some(&a));
    }
}
