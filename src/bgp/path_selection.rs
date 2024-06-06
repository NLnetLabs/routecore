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
///
/// Be aware that the `PartialEq` implementation of `OrdRoute` is specifically
/// tailored towards its `Ord` implementation, to do the BGP Decision Process.
/// Comparing two `OrdRoute`s, wrapping two routes with different sets of path
/// attributes, might still yield 'equal'. Instead, consider comparing on the
/// `PaMap` and/or `Tiebreakerinfo` directly (or [`fn inner`]).
#[derive(Copy, Clone, Debug, Hash)]
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


    /// Returns the `TiebreakerInfo`.
    pub fn tiebreakers(&self) -> TiebreakerInfo {
        self.tiebreakers
    }

    /// Returns a reference to the Path Attributes.
    pub fn pa_map(&self) -> &PaMap {
        self.pa_map
    }

    /// Returns a tuple of the actual content of this OrdRoute.
    pub fn inner(&self) -> (TiebreakerInfo, &PaMap) {
        (self.tiebreakers, self.pa_map())
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

impl TiebreakerInfo {
    pub fn new(
        source: RouteSource, 
        degree_of_preference: Option<DegreeOfPreference>,
        local_asn: Asn,
        bgp_identifier: BgpIdentifier,
        peer_addr: net::IpAddr,
    ) -> Self {
        Self {
            source,
            degree_of_preference,
            local_asn,
            bgp_identifier,
            peer_addr,
        }
    }
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


/// Returns the preferred route.
///
/// Note this method works on anything `T: Ord` and is thus not limited to
/// `OrdRoute`. Hence one can pass in a tuple of `(OrdRoute, L)` as long as
/// `L` implements `Ord`, to include and get back any local value like an ID.
/// This is consistent with [`fn best`] and [`fn best_backup_generic`].
pub fn preferred<T: Ord>(a: T, b: T) -> T {
    cmp::min(a,b)
}

/// Selects the preferred ('best') route.
///
/// Note this method works on an iterator yielding anything `T: Ord`, so not
/// limited to `OrdRoute`. It is in that sense consistent with [`fn
/// best_backup_generic`], i.e. one can pass in tuples of `OrdRoute` and
/// something else that implements `Ord`.
pub fn best<T, I>(it: I) -> Option<T>
where
    T: Ord,
    I: Iterator<Item = T>,
{
    it.min()
}

/// Alternative, generic version of `fn best_backup`.
///
/// This method takes any iterator yielding items implementing Ord. As such,
/// it has little to do with routes or path selection per se.
///
/// Note that because of this genericness, we have no access to methods or
/// members of `T`, and thus are unable to compare actual contents such as a
/// `PaMap` or the `TiebreakerInfo` when comparing `OrdRoute`s. This means the
/// method can not check for any duplicate route information between `T`s, and
/// really only order them.  The caller therefore has to make sure to pass in
/// an iterator that does not yield any duplicate routes.
///
/// This method enables the caller to attach additional information, as long
/// as it implements `Ord`. For example, one can pass in an iterator over
/// tuples of `OrdRoute` and something else. As long as the `OrdRoute` is the
/// first member of that tuple and no duplicates are yielded from the
/// iterator, the additional information is not used in the ordering process
/// but is returned together with the 'best' and 'backup' tuples. This can be
/// useful when the caller needs to relate routes to local IDs or something
/// alike.
pub fn best_backup_generic<I, T>(it: I) -> (Option<T>, Option<T>) 
where 
    I: Iterator<Item = T>,
    T: Ord
{
    let mut best = None;
    let mut backup = None; 

    for c in it {
        match best.take() {
            None => { best = Some(c); continue }
            Some(cur_best) => {
                if c < cur_best  {
                    // c is preferred over current best
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
                            // c is preferred over current backup
                            backup = Some(c);
                        } else {
                            // put it back in
                            backup = Some(cur_backup);
                        }

                    }
                }
            }
        }
    }

    (best, backup)
}


// Attaches an index to a (generic) T, only used internally in _best_backup.
type RouteWithIndex<T> = (usize, T);

// Internal version doing the heavy lifting for both best_backup and
// best_backup_position. Returns both the routes themselves (T) and their
// index (usize).
fn _best_backup<'a, I, T, OS>(it: I)
    -> (Option<RouteWithIndex<T>>, Option<RouteWithIndex<T>>) 
where 
    OS: OrdStrat,
    I: Iterator<Item = T>,
    T: Ord + core::borrow::Borrow<OrdRoute<'a, OS>>
{
    let mut best: Option<RouteWithIndex<T>> = None;
    let mut backup: Option<RouteWithIndex<T>> = None;

    for (idx, c) in it.enumerate() {
        match best.take() {
            None => { best = Some((idx, c)); continue }
            Some((idx_best, cur_best)) => {
                if c < cur_best  {
                    // c is preferred over current best
                    best = Some((idx, c));
                    backup = Some((idx_best, cur_best));
                    continue;
                }
                // put it back in
                best = Some((idx_best, cur_best));

                // c is not better than best, now check backup
                match backup.take() {
                    None => { 
                        // Before we set the backup route, ensure it is not
                        // the same route as best.
                        // We compare the actual contents of the OrdRoute
                        // here, i.e. the TiebreakerInfo and PaMap. If we'd
                        // simply compare the OrdRoutes themselves, we'd be
                        // testing whether or not they are considered equal in
                        // terms of path preference, NOT in terms of content.
                        // If for example we have a candidate backup path with
                        // a different AS_PATH but of equal length as the best
                        // path, the OrdRoutes are considered equal even
                        // though the actual path attributes differ.
                        //

                        // `best` is always Some(..) at this point, but we do
                        // an `if let` instead of an `unwrap` anyway.
                        if let Some((_, cur_best)) = best.as_ref() {
                            if cur_best.borrow().inner() != c.borrow().inner()
                            {
                                backup = Some((idx, c));
                            }
                        }
                    }
                    Some((idx_backup, cur_backup)) => {
                        if c <  cur_backup {
                            // c is preferred over current backup
                            // check if it is not the same route as 'best'
                            if best.as_ref().map(|t| &t.1) != Some(&c) {
                                backup = Some((idx, c));
                                continue;
                            }
                        }
                        // put it back in
                        backup = Some((idx_backup, cur_backup));
                    }
                }
            }
        }
    }

    (best, backup)
}

/// Returns the 'best' and second-best path.
///
/// If the iterator passed in contains no paths, `(None, None)` is returned.
/// If the iterator yields only a single item, that will be the 'best' path,
/// and the 'backup' will be None, i.e. `(Some(best), None)`.
///
/// In all other cases (an iterator yielding two or more non-identical
/// values), both members of the tuple should be `Some(..)`. 
/// 
/// The returned 'best' path is the same as the path returned by [`fn best`].
pub fn best_backup<'a, I, T, OS>(it: I) -> (Option<T>, Option<T>) 
where 
    OS: OrdStrat,
    I: Iterator<Item = T>,
    T: Ord + core::borrow::Borrow<OrdRoute<'a, OS>>
{
    let (best, backup) = _best_backup(it);
    (best.map(|b| b.1), backup.map(|b| b.1))
}

/// Returns the index of the best and backup paths in the passed iterator.
pub fn best_backup_position<'a, I, T, OS>(it: I)
    -> (Option<usize>, Option<usize>) 
where 
    OS: OrdStrat,
    I: Iterator<Item = T>,
    T: Ord + core::borrow::Borrow<OrdRoute<'a, OS>>
{
    let (best, backup) = _best_backup(it);
    (best.map(|b| b.0), backup.map(|b| b.0))
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
        b_pamap.set(HopPath::from([10, 25, 30, 40]));
        b_pamap.set(MultiExitDisc(50));

        let mut c_pamap = PaMap::empty();
        c_pamap.set(Origin(OriginType::Egp));
        c_pamap.set(HopPath::from([80, 90, 100, 200, 300]));

        let candidates = [
            OrdRoute::skip_med(&a_pamap, tiebreakers).unwrap(),
            OrdRoute::skip_med(&b_pamap, tiebreakers).unwrap(),
            OrdRoute::skip_med(&a_pamap, tiebreakers).unwrap(),
            //OrdRoute::skip_med(&c_pamap, tiebreakers).unwrap(),
        ];

        let best1 = best(candidates.iter().cloned()).unwrap();
        let (best2, backup2) = best_backup(candidates.iter());
        let (best2, backup2) = (best2.unwrap(), backup2.unwrap());

        assert_eq!(best1.pa_map(), best2.pa_map());
        assert_eq!(best1.tiebreakers(), best2.tiebreakers());

        dbg!(&best2);
        dbg!(&backup2);

        assert_ne!(
            (best2.pa_map(), best2.tiebreakers()),
            (backup2.pa_map(), backup2.tiebreakers())
        );

    }

    /*
    #[test]
    fn helpers_generic() {
        let (a,b,c) = ("2".to_string(), "1".to_string(), "3".to_string());
        //let (a,b,c) = (2, 1, 3);
        let values = vec![&a, &b, &c];
        let (best, backup) = best_backup(values.into_iter());
        assert_eq!(best, Some(&b));
        assert_eq!(backup, Some(&a));
    }
    */
}
