#![allow(dead_code)] // XXX this module is currently a mix of things of which many will go
                     // (elsewhere).

use std::{borrow::Cow, collections::{BTreeMap, VecDeque}, io::Read, sync::{atomic::{AtomicU16, AtomicUsize, Ordering}, Arc, RwLock}, thread, time::Duration};

use zerocopy::TryFromBytes;

use crate::{bgp::message_ng::common::{HexFormatted, SessionConfig}, bmp::message_ng::{common::{CommonHeader, MessageType, PerPeerHeaderV3}, initiation::InitiationMessage, peer_down_notification::PeerDownNotificationV3, peer_up_notification::PeerUpNotification, route_monitoring::RouteMonitoringV3, statistics_report::StatisticsReport}};


pub const MIN_MSG_SIZE: usize = std::mem::size_of::<CommonHeader>();
pub const MANY_MSGS_BUF_SIZE: usize = 1 << 18;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BmpVersion(u8);

struct MessageIter<R, const B: usize> {
    reader: R,
    buf: [u8; B],
    buf_cursor: usize,
    buf_end: usize,
}

impl<R: Read, const B: usize, > MessageIter<R, B> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: [0u8; B],
            buf_cursor: 0,
            buf_end: 0,
        }
    }
    fn remaining(&self) -> usize {
        self.buf_end - self.buf_cursor
    }

    fn read_into_buf(&mut self) -> Result<Option<usize>, Cow<'static, str>> {
        //eprintln!("read_into_buf");
        // shift the remainder to the front of the buf
        self.buf.copy_within(self.buf_cursor..self.buf_end, 0);
        self.buf_end = self.buf_end - self.buf_cursor;
        self.buf_cursor = 0;

        // and then read in as much as we can
        match self.reader.read(&mut self.buf[self.buf_end..]) {
            Ok(0) => {
                eprintln!("EOF");
                Ok(None)
            }
            Err(e) => {
                Err(e.to_string().into())
            }
            Ok(n)  => {
                //eprintln!("read {n} bytes into buf");
                self.buf_end += n;
                Ok(Some(n))
            }
        }
    }

    // Should be the very first message.
    // But if there is some other (valid) message, we return that so we can determine the version
    // of this BMP stream.
    // Note that the initiation message is not actually necessary, so we are flexible. If it is
    // missing, or not the first, we annotate it on the ingress but try to process the stream
    // nonetheless.
    fn get_initiation(&mut self) -> Result<&InitiationMessage, Result<&[u8], Cow<'static, str>>> {

        while self.remaining() < std::mem::size_of::<CommonHeader>() {
            self.read_into_buf().unwrap(); // FIXME
        }
        let (msg_len, msg_type) = {
            let (header, _) = CommonHeader::try_ref_from_prefix(&self.buf[self.buf_cursor..])
            .map_err(|_| Err("no valid CommonHeader?".into()))?;
            (header.length(), header.msg_type)
        };

        while self.remaining() < msg_len {
            self.read_into_buf().unwrap(); // FIXME 
        }

        let msg = &self.buf[self.buf_cursor..self.buf_cursor+msg_len];
        self.buf_cursor += msg_len;

        if msg_type == MessageType::INITIATION {
            //InitiationMessage for V4, the initiation message seems unchanged,
            //so we can return our version agnostic 'InitiationMessage'.
            //If the Initation Message _does_ change, our method signature will need to change into
            //something more generic.
            let msg = InitiationMessage::try_from_full_pdu(msg)
                .map_err(|e| Err(e.to_string().into()))?;

            Ok(msg)
        } else {
            Err(Ok(msg))
        }
    }

    fn get_many(&mut self) -> Result<Vec<u8>, Cow<'static, str>> {
        //eprintln!("get_many");
        let res_start = self.buf_cursor;
        while self.buf_end-self.buf_cursor >= MIN_MSG_SIZE {
            let (header, _) = CommonHeader::try_ref_from_prefix(&self.buf[self.buf_cursor..]).unwrap();
            let len: usize = header.length();
            if self.buf_cursor + len <= self.buf_end {
                self.buf_cursor += len;
            } else {
                break
            }
        }
        Ok(self.buf[res_start..self.buf_cursor].into())
    }

    fn get_one(&mut self) -> Result<&[u8], Cow<'static, str>> { 
        if self.buf_end-self.buf_cursor >= MIN_MSG_SIZE {
            let (header, _) = CommonHeader::try_ref_from_prefix(&self.buf[self.buf_cursor..]).unwrap();
            let len: usize = header.length();
            if self.buf_cursor + len <= self.buf_end {
                let res = Ok(&self.buf[self.buf_cursor..self.buf_cursor+len]);
                self.buf_cursor += len;
                return res;
            }
        }
        Err("not enough bytes".into())
    }
}



pub struct Pool {
    queue: Arc<RwLock<VecDeque<(Vec<u8>, SessionConfig)>>>,
}
impl Default for Pool {
    fn default() -> Self {
        Self { queue: Arc::new(RwLock::new(Vec::with_capacity(1024).into()))  }
    }
}

static UPDATES_TOTAL: AtomicUsize = AtomicUsize::new(0);
static NLRI_TOTAL: AtomicUsize = AtomicUsize::new(0);
static PA_BYTES_SUM: AtomicUsize = AtomicUsize::new(0);
static PA_BYTES_REDUNDANT_SUM: AtomicUsize = AtomicUsize::new(0);



impl Pool {
    pub fn start_processing(self) -> Arc<RwLock<VecDeque<(Vec<u8>, SessionConfig)>>> {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(6).build().unwrap();
        let queue = self.queue.clone();
        let sc = Arc::new(SessionConfig::default());
        for _ in 0..dbg!(pool.current_num_threads()) {
            let queue = queue.clone();
            let _sc = sc.clone();
            pool.spawn(move || {
                eprintln!("[{:?}] spawned", thread::current().id());
                loop {
                    //let Some(ManyMessages{version, msgs: buf}) = queue.write().unwrap().pop_front() else {
                    let Some((msg, sc)) = queue.write().unwrap().pop_front() else {
                        thread::park_timeout(Duration::from_millis(1));
                        //hint::spin_loop();
                        continue;
                    };
                    
                    // TODO branch on version somewhere, somehow
                    //assert!(version == BmpVersion(3));

                    // we know that msg is a ROUTE_MONITORING
                        
                    let rm = RouteMonitoringV3::try_from_full_pdu(&msg).unwrap();
                    let update = rm.bgp_update().unwrap();
                    let mut update = update.into_checked_parts(&sc).unwrap();

                    // conv stuff
                    if let Some(_attributes) = update.take_conv_attributes() {
                        // So we have path attributes for conventional NLRI

                        let conv_iter = update.conv_reach_iter_raw();
                        //routedb.insert_batch(attributes, conv_iter)

                        let _nlri_count = conv_iter.count();
                        //NLRI_TOTAL.fetch_add(nlri_count, Ordering::Relaxed);
                        //PA_BYTES_SUM.fetch_add(attributes.len(), Ordering::Relaxed);
                        //PA_BYTES_REDUNDANT_SUM.fetch_add(attributes.len() * (nlri_count - 1), Ordering::Relaxed);

                        //pph_register.get(&pph).unwrap();
                    }

                    // mp stuff
                    if let Some(_attributes) = update.take_mp_attributes() {
                        // So we have path attributes for mpentional NLRI

                        let mp_iter = update.mp_reach_iter_raw();
                        //routedb.insert_batch(attributes, mp_iter)

                        let _nlri_count = mp_iter.count();
                        //NLRI_TOTAL.fetch_add(nlri_count, Ordering::Relaxed);
                        //PA_BYTES_SUM.fetch_add(attributes.len(), Ordering::Relaxed);
                        //PA_BYTES_REDUNDANT_SUM.fetch_add(attributes.len() * (nlri_count - 1), Ordering::Relaxed);
                    }

                }
            });
        }
        queue
    }
}

pub struct BmpHandler<R> {
    msg_iter: MessageIter<R, MANY_MSGS_BUF_SIZE>,
    pph_register: PphRegister,
}

impl<R: Read> BmpHandler<R> {
    pub fn new(stream: R, pph_register: PphRegister) -> Self {
        Self { msg_iter: MessageIter::new(stream), pph_register }
    }

    // returns the version for this stream
    pub fn process_initiation(&mut self) -> BmpVersion {
        let version = match self.msg_iter.get_initiation() {
            Ok(init_msg) => {
                // got Initiation message, as expected
                // 'consume' the message, TODO go over TLVs, annotate in ingress::Register
                init_msg.common.version
            }
            Err(Ok(other_msg)) => {
                // got a different message, extract version and annotate this stream as wonky
                // we do not know what this is (hopefully a PeerUp),
                // but it will need to be processed. Do not 'consume' here.
                
                // we did a try_ref_from_prefix before in get_initation, so we can unwrap safely here.
                dbg!(&other_msg);
                let (header, _) = CommonHeader::try_ref_from_prefix(other_msg).unwrap();
                header.version
            }
            Err(Err(e)) => {
                // something else is wrong
                // TODO we should probably kill the connection here
                panic!("{}", e);
            }
        };
        log::debug!("BMP stream version {version}");
        match version {
            3|4 => { },
            _ => {
                log::error!("Unsupported BMP version {version}");
                panic!(); // TODO die more gracefully
            }
        }
        BmpVersion(version)
    }
}

impl<R> From<BmpHandler<R>> for BmpV3Handler<R> {
    fn from(h: BmpHandler<R>) -> Self {
        Self {
            msg_iter: h.msg_iter,
            pph_register: h.pph_register,
        }
    }
}

impl<R> From<BmpHandler<R>> for BmpV4Handler<R> {
    fn from(h: BmpHandler<R>) -> Self {
        Self {
            msg_iter: h.msg_iter,
            pph_register: h.pph_register,
        }
    }
}

#[derive(Copy, Clone, Debug)]
// 2 bytes id, 1 byte peer type, 1 byte peer flags
pub struct IngressId(u32);

impl IngressId {
    pub fn peer_id(&self) -> u16 {
        (self.0 >> 16) as u16
    }
    pub fn peer_type(&self) -> u8 {
        (self.0 >> 8) as u8
    }
    pub fn peer_flags(&self) -> u8 {
        self.0 as u8
    }
}

// TODO this will replace the original one in the non-ng part of routecore
pub struct PduParseInfo;

#[derive(Default)]
pub struct PphRegister {
    // based on peer type byte
    // currently, types [0..3] (inclusive) are defined
    // so we create an array of length 4
    //partitions_types: [BTreeMap<Vec<u8>, (IngressId, PduParseInfo)>; 4],
    per_peer_type: [RibViewRegister; 4], // FIXME 256? or how to prevent indexing out of bounds
}

#[derive(Debug, Default)]
pub struct RibViewRegister {
    // based on peer flags byte
    // there flags are defined per peer type
    // currently, the largest space is the peer type 0-2 one, 
    // with types [0..5] (inclusive) defined although 4 is deprecated.
    // Anyway, we use an array of 5.
    // TODO instead of keying on the full PPH, we want to key on the PPH-type-flags ?
    // FIXME make 256 as well?
    per_rib_view: [
        //RwLock<
        // the -2 is because we do not store the peer_type and peer_flags
        // TODO make a dedicated zerocopy struct for that?
            BTreeMap<[u8; std::mem::size_of::<PerPeerHeaderV3>() - 2 - 8], (IngressId, SessionConfig)>
        //s>
        ; 5
    ],
}

// XXX tmp fake peer IDs, should come from ingress::Register in rotonda
pub static PEER_ID: AtomicU16 = AtomicU16::new(0);

impl PphRegister {
    // TODO how to do V3 vs V4 ?
    pub fn get(&self, pph: &PerPeerHeaderV3) -> Option<&(IngressId, SessionConfig)> {
        //dbg!(&self.per_peer_type);
        //eprintln!("looking in partition 0x{:x} , 0x{:x}", u8::from(pph.peer_type), pph.flags);

        //eprintln!("PphRegister.getting partition 0x{:x} , 0x{:x}\n{:?}",
        //    u8::from(pph.peer_type), pph.flags,
        //    HexFormatted(&pph.as_bytes())
        //    );
        let map = 
        &self
            .per_peer_type[u8::from(pph.peer_type) as usize]
            .per_rib_view[pph.flags.reverse_bits() as usize]
        ;
        //eprintln!("entries: {}", map.len());
        map.get(pph.without_type_and_flags())
    }

    pub fn find_other_ribviews(&self, pph: &PerPeerHeaderV3) -> Option<&(IngressId, SessionConfig)> {
        //eprintln!("in find_other_ribviews to find\n{:?}", HexFormatted(pph.without_type_and_flags()));
        for peer_type in &self.per_peer_type {
            for rib_view in &peer_type.per_rib_view {
                //eprintln!("looking ribview with {} entries", rib_view.len());
                if let Some(res) = rib_view.get(pph.without_type_and_flags()) {
                    return Some(res)
                }
            }
        }
        None
    }

    pub fn insert(&mut self, pph: &PerPeerHeaderV3, session_config: SessionConfig) -> Option<(IngressId, SessionConfig)> {
        // Check whether we already registered a peer_id in the ingress::Register, by going over
        // our own cache.
        let peer_id = if let Some((ingress_id, _)) = self.find_other_ribviews(&pph) {
            eprintln!("found peer_id for this peer: {}", ingress_id.peer_id());
            ingress_id.peer_id()
        } else {
            // TODO this should be a call to ingress::Register
            PEER_ID.fetch_add(1, Ordering::Relaxed)
        };
        
        // TODO move this into the ingress::Register, that is responsible and authoritative for
        // this kind of logic
        let mui = u32::from(peer_id) << 16 | u32::from(u8::from(pph.peer_type)) << 8 | u32::from(pph.flags);

        eprintln!("inserting into partition 0x{:x} , 0x{:x}\n{:?}",
            u8::from(pph.peer_type), pph.flags,
            HexFormatted(pph.without_type_and_flags())
            );

        self
            .per_peer_type[u8::from(pph.peer_type) as usize]
            .per_rib_view[pph.flags.reverse_bits() as usize]
            .insert(pph.without_type_and_flags().try_into().unwrap(), (IngressId(mui), session_config))
    }

}

pub struct BmpV3Handler<R> {
    msg_iter: MessageIter<R, MANY_MSGS_BUF_SIZE>,
    pph_register: PphRegister,
}

pub struct ManyMessages {
    version: BmpVersion,
    //pph_register: Arc<PphRegister>, // XXX how to do this for v4? traits on the PphRegister ?
    msgs: Vec<u8>,
}


impl<R: Read> BmpV3Handler<R> {
    pub fn new(stream: R) -> Self {
        Self {
            msg_iter: MessageIter::new(stream),
            pph_register: PphRegister::default(),
        }
    }

    pub fn process_stream_batched<F>(&mut self,
        //Arc<RouteDb>,
        //Arc<ingress::Register>,
        //Fn to be execute in the thread pool
        func: F,
    )
    where F: Fn(ManyMessages) -> ()
    {
        loop {
            if let Ok(Some(_)) = self.msg_iter.read_into_buf() {
                if let Ok(msgs) = self.msg_iter.get_many() {
                    func(ManyMessages {
                        version: BmpVersion(3),
                        //pph_register: self.pph_register.clone(),
                        msgs
                    })
                }
            } else {
                break
            }

        }
    }


    pub fn process<F>(&mut self,
        _func: F,
    )
    where F: Fn(&RouteMonitoringV3, SessionConfig) -> ()
    
    {
        loop {
            // XXX the get_many here is sort of pointless currently
            // as we start processing messages individually from this thread anyway
            // what _could_ be useful, is if MessageIter gives back batches of certain types
            // e.g. only PeerUps, only PeerDowns, or only 'other'
            //print!("\r{i}");i+=1;
            if let Ok(Some(_)) = self.msg_iter.read_into_buf() {
                while let Ok(msg) = self.msg_iter.get_one() {
                    // buf is a Vec<u8> with many unchecked BMP PDUs
                    //let mut buf_cursor = 0;
                    
                    //let mut handler = BmpV3Handler::new(std::io::Cursor::new(vec![]));
                    //while buf_cursor < buf.len() {
                        let (header, _) = CommonHeader::try_ref_from_prefix(&msg).unwrap();
                        //if header.version == 4 {
                        //    handler = handler.upgrade_to_v4();
                        //}
                        //let len: usize = header.length();
                        //let msg = &msg[buf_cursor..buf_cursor+len];

                        match header.msg_type {
                            MessageType::ROUTE_MONITORING => {
                                //UPDATES_TOTAL.fetch_add(1, Ordering::Relaxed);
                                let rm = RouteMonitoringV3::try_from_full_pdu(msg).unwrap();
                                let pph = rm.per_peer_header();

                                let (_ingress_id, sc) = {
                                    if let Some(x) = self.pph_register.get(&pph) {
                                        x
                                    } else {
                                        let maybe_hit = self.pph_register.find_other_ribviews(&pph);
                                        if let Some(hit) = maybe_hit {
                                            eprint!("C");
                                            self.pph_register.insert(&pph, hit.1.clone());
                                            self.pph_register.get(&pph).unwrap()
                                        } else {
                                            eprintln!("RouteMon for which no PeerUp was received");
                                            //buf_cursor += len;
                                            continue;
                                            // TODO put in some queue?
                                            // try to process anyway?
                                            // at the very least, log and stick an error on this BMP
                                            // exporter
                                        }
                                    }
                                };

                                //eprint!("_");
                                //let rm = handler.version.try_routemon(msg).unwrap();
                                //let sc2 = sc.clone();
                                //func(rm, sc.clone());

                                
                                let update = rm.bgp_update().unwrap();
                                let mut update = update.into_checked_parts(&sc).unwrap();

                                // conv stuff
                                if let Some(_attributes) = update.take_conv_attributes() {
                                    // So we have path attributes for conventional NLRI

                                    let conv_iter = update.conv_reach_iter_raw();
                                    //routedb.insert_batch(attributes, conv_iter)

                                    let _nlri_count = conv_iter.count();
                                    //NLRI_TOTAL.fetch_add(nlri_count, Ordering::Relaxed);
                                    //PA_BYTES_SUM.fetch_add(attributes.len(), Ordering::Relaxed);
                                    //PA_BYTES_REDUNDANT_SUM.fetch_add(attributes.len() * (nlri_count - 1), Ordering::Relaxed);

                                }

                                // mp stuff
                                if let Some(_attributes) = update.take_mp_attributes() {
                                    // So we have path attributes for mpentional NLRI

                                    let mp_iter = update.mp_reach_iter_raw();
                                    //routedb.insert_batch(attributes, mp_iter)

                                    let _nlri_count = mp_iter.count();

                                    //NLRI_TOTAL.fetch_add(nlri_count, Ordering::Relaxed);
                                    //PA_BYTES_SUM.fetch_add(attributes.len(), Ordering::Relaxed);
                                    //PA_BYTES_REDUNDANT_SUM.fetch_add(attributes.len() * (nlri_count - 1), Ordering::Relaxed);
                                }
                                

                            }
                            MessageType::PEER_UP_NOTIFICATION => {
                                let peerup = PeerUpNotification::try_from_full_pdu(msg).unwrap();
                                let pph = peerup.per_peer_header();
                                let (bgp_open_sent, bgp_open_rcvd) = peerup.bgp_opens().unwrap();
                                bgp_open_sent.capabilities().count();
                                bgp_open_rcvd.capabilities().count();

                                // now, check existence of the pph in the (local?) btreemap
                                // this is executed in the thread pool
                                // so we need an Arc to the original handler?
                                // but we also need to add new PPHs to it
                                // so Arc<RwLock> ?
                                // perhaps batch up PeerUps, lock once, batch insert?

                                assert!(
                                    self.pph_register.insert(&pph, SessionConfig::default()).is_none()
                                );
                                eprint!("U");
                            }
                            MessageType::INITIATION => {
                                // This is not (should not be) the very first Initiation message.
                                let _init = InitiationMessage::try_from_full_pdu(msg).unwrap();
                            }
                            MessageType::PEER_DOWN_NOTIFICATION => {
                                let _pd = PeerDownNotificationV3::try_from_full_pdu(msg).unwrap();
                            }
                            MessageType::STATISTICS_REPORT => {
                                let _sr = StatisticsReport::try_from_full_pdu(msg).unwrap();
                            }
                            m => { todo!("implement msg type {m:?}"); }
                        }
                    }
            } else {
                break
            }

        }

    }

}



pub struct BmpV4Handler<R> {
    msg_iter: MessageIter<R, MANY_MSGS_BUF_SIZE>,
    pph_register: PphRegister,
}
//impl<R: Read> BmpV4Handler<R> {
//    pub fn new(stream: R) -> Self {
//        Self { msg_iter: MessageIter::new(stream), }
//    }
//}

//pub trait Version {
//    const VERSION: u8;
//    type PerPeerHeader;
//    type RouteMonitoring: Parseable + ?Sized;
//
//    fn try_routemon<'a>(&self, raw: &'a [u8]) -> Result<&'a Self::RouteMonitoring, Cow<'static, str>> {
//        Self::RouteMonitoring::try_from_full_pdu(&raw)
//    }
//}
//
//impl<R: Read> Version for BmpV3Handler<R> {
//    const VERSION: u8 = 3;
//    type PerPeerHeader = super::common::PerPeerHeaderV3;
//    type RouteMonitoring = RouteMonitoringV3;
//}
//impl<R> Version for BmpV4Handler<R> {
//    const VERSION: u8 = 4;
//    type PerPeerHeader = super::common::PerPeerHeaderV4;
//    type RouteMonitoring = super::route_monitoring::RouteMonitoringV4;
//}
//
pub trait Parseable {
    fn try_from_full_pdu(raw: &[u8]) -> Result<&Self, Cow<'static, str>>;
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::{fs::File, io::BufReader, time::Instant};


    //#[test]
    //fn read_from_file() {
    //    const FILENAME: &str = "/home/luuk/code/rotonda/test-data/rotonda_startup_500kpkts.bin.trimmed";
    //    //const FILENAME: &str = "/home/luuk/code/rotonda/reeds/pcaps/amsix_rs_tshoot.bmp";
    //    let f = File::open(FILENAME).unwrap();
    //    eprintln!("processing {FILENAME}");
    //    let total_size = f.metadata().unwrap().len();
    //    let reader = BufReader::new(f);
    //    let pool = Pool::default();
    //    let queue = pool.start_processing();

    //    let mut iter = MessageIter::<_, {2<<18}>::new(reader);
    //    let mut _last_capacity = queue.read().unwrap().capacity();
    //    let t0 = Instant::now();
    //    loop {
    //        if let Ok(Some(_)) = iter.read_into_buf() {
    //            if let Ok(msgs) = iter.get_many() {
    //                queue.write().unwrap().push_back(ManyMessages{ version: BmpVersion(3), msgs});
    //                //let current_cap = queue.read().unwrap().capacity();
    //                //if current_cap != last_capacity {
    //                //    eprintln!("new cap {current_cap}");
    //                //    last_capacity = current_cap;
    //                //}
    //            }
    //        } else {
    //            break
    //        }

    //    }
    //    while !queue.read().unwrap().is_empty() {
    //        //std::hint::spin_loop();
    //        thread::sleep(Duration::from_millis(100));
    //    }
    //    eprintln!("Done, CNT: {UPDATES_TOTAL:?}, \
    //            NLRI: {NLRI_TOTAL:?}, \
    //            PA_BYTES_SUM: {PA_BYTES_SUM:?}, \
    //            PA_BYTES_REDUNDANT_SUM: {:.2}MiB, \
    //            % of raw: {:.2}%
    //            ",
    //            PA_BYTES_REDUNDANT_SUM.load(Ordering::Relaxed) as f64 / 2_f64.powf(20.0),
    //            (PA_BYTES_REDUNDANT_SUM.load(Ordering::Relaxed) as f64 / total_size as f64) * 100.0
    //            );
    //    eprintln!("{:.1}GiB in {:.2}s -> {:.2}GiB/s or {:.2}Gbps",
    //        total_size as f64 / 2_f64.powf(30.0),
    //        Instant::now().duration_since(t0).as_secs_f64(),
    //        total_size as f64 / 2_f64.powf(30.0) / Instant::now().duration_since(t0).as_secs_f64(),
    //        total_size as f64 / 2_f64.powf(27.0) / Instant::now().duration_since(t0).as_secs_f64(),
    //    );
    //}

    #[test]
    fn handler() {
        const FILENAME: &str = "/home/luuk/code/rotonda/test-data/rotonda_startup_500kpkts.bin.trimmed";
        //const FILENAME: &str = "/home/luuk/code/rotonda/reeds/pcaps/amsix_rs_tshoot.bmp";
        let f = File::open(FILENAME).unwrap();
        eprintln!("processing {FILENAME}");
        let total_size = f.metadata().unwrap().len();
        let reader = BufReader::new(f);
        let pool = Pool::default();
        let queue = pool.start_processing();
        let t0 = Instant::now();
        let pph_register = PphRegister::default();
        let mut handler = BmpHandler::new(reader, pph_register);
        let v = handler.process_initiation();
        match v {
            BmpVersion(3) => {
                let mut v3handler: BmpV3Handler<_> = handler.into();
                //v3handler.process_stream_batched(|msgs|
                //    queue.write().unwrap().push_back(msgs)
                //);
                v3handler.process(|_rm, _sc| {
                    //queue.write().unwrap().push_back((rm.as_bytes().to_vec(), sc));
                });

            }

            BmpVersion(4) => { }
            _ => panic!()
        }

        while !queue.read().unwrap().is_empty() {
            //std::hint::spin_loop();
            thread::sleep(Duration::from_millis(10));
        }

        eprintln!("{:.1}GiB in {:.2}s -> {:.2}GiB/s or {:.2}Gbps",
            total_size as f64 / 2_f64.powf(30.0),
            Instant::now().duration_since(t0).as_secs_f64(),
            total_size as f64 / 2_f64.powf(30.0) / Instant::now().duration_since(t0).as_secs_f64(),
            total_size as f64 / 2_f64.powf(27.0) / Instant::now().duration_since(t0).as_secs_f64(),
        );

    }
}
