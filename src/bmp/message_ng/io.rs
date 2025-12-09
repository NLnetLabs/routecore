use std::{borrow::Cow, collections::VecDeque, io::Read, sync::{atomic::{AtomicUsize, Ordering}, Arc, RwLock}, thread, time::Duration};

use zerocopy::TryFromBytes;

use crate::{bgp::message_ng::common::SessionConfig, bmp::message_ng::{common::{CommonHeader, MessageType}, initiation::InitiationMessage, peer_down_notification::PeerDownNotification, peer_up_notification::PeerUpNotification, route_monitoring::RouteMonitoring, statistics_report::StatisticsReport}};


pub const MIN_MSG_SIZE: usize = std::mem::size_of::<CommonHeader>();

struct MessageIter<R: Read, const B: usize> {
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

    fn get_many(&mut self)  -> Result<Vec<u8>, Cow<'static, str>> {
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
}



pub struct Pool {
    queue: Arc<RwLock<VecDeque<Vec<u8>>>>,
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
    pub fn start_processing(self) -> Arc<RwLock<VecDeque<Vec<u8>>>> {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(6).build().unwrap();
        let queue = self.queue.clone();
        let sc = Arc::new(SessionConfig::default());
        for _ in 0..dbg!(pool.current_num_threads()) {
            let queue = queue.clone();
            let sc = sc.clone();
            pool.spawn(move || {
                eprintln!("[{:?}] spawned", thread::current().id());
                loop {
                    let Some(buf) = queue.write().unwrap().pop_front() else {
                        thread::park_timeout(Duration::from_millis(1));
                        //hint::spin_loop();
                        continue;
                    };
                    // buf is a Vec<u8> with many unchecked BGP PDUs
                    let mut buf_cursor = 0;
                    while buf_cursor < buf.len() {
                        let (header, _) = CommonHeader::try_ref_from_prefix(&buf[buf_cursor..]).unwrap();
                        let len: usize = header.length();
                        let msg = &buf[buf_cursor..buf_cursor+len];
                        match header.msg_type {
                            MessageType::ROUTE_MONITORING => {
                                UPDATES_TOTAL.fetch_add(1, Ordering::Relaxed);
                                //let rm = RouteMonitoring::try_v4_from_full_pdu(msg).unwrap();
                                let rm = RouteMonitoring::try_from_full_pdu(msg).unwrap();
                                let _pph = rm.per_peer_header();
                                let update = rm.bgp_update().unwrap();
                                let mut update = update.into_checked_parts(&sc).unwrap();

                                // conv stuff
                                if let Some(attributes) = update.take_conv_attributes() {
                                    // So we have path attributes for conventional NLRI
                                    
                                    let conv_iter = update.conv_reach_iter_raw();
                                    //routedb.insert_batch(attributes, conv_iter)

                                    let nlri_count = conv_iter.count();
                                    NLRI_TOTAL.fetch_add(nlri_count, Ordering::Relaxed);
                                    PA_BYTES_SUM.fetch_add(attributes.len(), Ordering::Relaxed);
                                    PA_BYTES_REDUNDANT_SUM.fetch_add(attributes.len() * (nlri_count - 1), Ordering::Relaxed);
                                }

                                // mp stuff
                                if let Some(attributes) = update.take_mp_attributes() {
                                    // So we have path attributes for mpentional NLRI
                                    
                                    let mp_iter = update.mp_reach_iter_raw();
                                    //routedb.insert_batch(attributes, mp_iter)

                                    let nlri_count = mp_iter.count();
                                    NLRI_TOTAL.fetch_add(nlri_count, Ordering::Relaxed);
                                    PA_BYTES_SUM.fetch_add(attributes.len(), Ordering::Relaxed);
                                    PA_BYTES_REDUNDANT_SUM.fetch_add(attributes.len() * (nlri_count - 1), Ordering::Relaxed);
                                }

                            }
                            MessageType::PEER_UP_NOTIFICATION => {
                                let peerup = PeerUpNotification::try_from_full_pdu(msg).unwrap();
                                let (bgp_open_sent, bgp_open_rcvd) = peerup.bgp_opens().unwrap();
                                bgp_open_sent.capabilities().count();
                                bgp_open_rcvd.capabilities().count();
                            }
                            MessageType::INITIATION => {
                                let _init = InitiationMessage::try_from_full_pdu(msg).unwrap();
                            }
                            MessageType::PEER_DOWN_NOTIFICATION => {
                                let _pd = PeerDownNotification::try_from_full_pdu(msg).unwrap();
                            }
                            MessageType::STATISTICS_REPORT => {
                                let _sr = StatisticsReport::try_from_full_pdu(msg).unwrap();
                            }
                            m => { todo!("implement msg type {m:?}"); }
                        }

                        buf_cursor += len;
                    }
                }
            });
        }
        queue
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::{fs::File, io::BufReader, time::Instant};


    #[test]
    fn read_from_file() {
        const FILENAME: &str = "/home/luuk/code/rotonda/test-data/rotonda_startup_500kpkts.bin.trimmed";
        //const FILENAME: &str = "/home/luuk/code/rotonda/reeds/pcaps/amsix_rs_tshoot.bmp";
        let f = File::open(FILENAME).unwrap();
        eprintln!("processing {FILENAME}");
        let total_size = f.metadata().unwrap().len();
        let reader = BufReader::new(f);
        let pool = Pool::default();
        let queue = pool.start_processing();

        let mut iter = MessageIter::<_, {2<<18}>::new(reader);
        let mut _last_capacity = queue.read().unwrap().capacity();
        let t0 = Instant::now();
        loop {
            if let Ok(Some(_)) = iter.read_into_buf() {
                if let Ok(msgs) = iter.get_many() {
                    queue.write().unwrap().push_back(msgs);
                    //let current_cap = queue.read().unwrap().capacity();
                    //if current_cap != last_capacity {
                    //    eprintln!("new cap {current_cap}");
                    //    last_capacity = current_cap;
                    //}
                }
            } else {
                break
            }

        }
        while !queue.read().unwrap().is_empty() {
            //std::hint::spin_loop();
            thread::sleep(Duration::from_millis(100));
        }
        eprintln!("Done, CNT: {UPDATES_TOTAL:?}, \
                NLRI: {NLRI_TOTAL:?}, \
                PA_BYTES_SUM: {PA_BYTES_SUM:?}, \
                PA_BYTES_REDUNDANT_SUM: {:.2}MiB, \
                % of raw: {:.2}%
                ",
                PA_BYTES_REDUNDANT_SUM.load(Ordering::Relaxed) as f64 / 2_f64.powf(20.0),
                (PA_BYTES_REDUNDANT_SUM.load(Ordering::Relaxed) as f64 / total_size as f64) * 100.0
                );
        eprintln!("{:.1}GiB in {:.2}s -> {:.2}GiB/s or {:.2}Gbps",
            total_size as f64 / 2_f64.powf(30.0),
            Instant::now().duration_since(t0).as_secs_f64(),
            total_size as f64 / 2_f64.powf(30.0) / Instant::now().duration_since(t0).as_secs_f64(),
            total_size as f64 / 2_f64.powf(27.0) / Instant::now().duration_since(t0).as_secs_f64(),
        );
    }
}
