use std::{borrow::Cow, collections::VecDeque, io::Read, sync::{atomic::{AtomicUsize, Ordering}, Arc, RwLock}, thread, time::Duration};

use zerocopy::TryFromBytes;

use crate::bgp::message_ng::{common::{Header, MessageType, SessionConfig, MIN_MSG_SIZE}, update::{CheckedParts, Update, HINT_SINGLE_SEQ}};


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
            let (header, _) = Header::try_ref_from_prefix(&self.buf[self.buf_cursor..]).unwrap();
            if header.marker != [0xff; 16] {
                return Err("invalid marker".into());
            }
            let len: usize = header.length.into();
            if self.buf_cursor + len <= self.buf_end {
                self.buf_cursor += len;
            } else {
                break
            }
        }
        Ok(self.buf[res_start..self.buf_cursor].into())
    }
}

//#[derive(Default)]
pub struct Pool {
    queue: Arc<RwLock<VecDeque<Vec<u8>>>>,
}
impl Default for Pool {
    fn default() -> Self {
        Self { queue: Arc::new(RwLock::new(Vec::with_capacity(1024).into()))  }
    }
}

static CNT_TOTAL: AtomicUsize = AtomicUsize::new(0);
static CNT_COMBINED: AtomicUsize = AtomicUsize::new(0);
static CNT_MP_R_U: AtomicUsize = AtomicUsize::new(0);
static CNT_NOT_SINGLE_SEQ: AtomicUsize = AtomicUsize::new(0);
static CNT_MALFORMED: AtomicUsize = AtomicUsize::new(0);

impl Pool {
    pub fn start_processing(self) -> Arc<RwLock<VecDeque<Vec<u8>>>> {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(6).build().unwrap();
        let queue = self.queue.clone();
        let sc = Arc::new(SessionConfig::default());
        for _ in 0..dbg!(pool.current_num_threads()) {
            //s.spawn(|_s2| {
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
                        let (header, _) = Header::try_ref_from_prefix(&buf[buf_cursor..]).unwrap();
                        let len: usize = header.length.into();
                        let msg = &buf[buf_cursor+19..buf_cursor+len];
                        match header.msg_type {
                            MessageType::UPDATE => {
                                let update = Update::try_from_raw(msg).unwrap();
                                //let (pa_hints, origin_as, mp_attr, mp_reach, mp_unreach, conv_attr, m) = update.into_checked_parts(&sc);
                                let CheckedParts{pa_hints, origin_as, mp_attributes, mp_reach, mp_unreach, conventional_attributes, malformed_attributes} = update.into_checked_parts(&sc);
                                CNT_TOTAL.fetch_add(1, Ordering::Relaxed);
                                if !mp_attributes.is_empty() && !conventional_attributes.is_empty() {
                                    CNT_COMBINED.fetch_add(1, Ordering::Relaxed);
                                }
                                if !mp_reach.is_empty() && !mp_unreach.is_empty() {
                                    CNT_MP_R_U.fetch_add(1, Ordering::Relaxed);
                                }
                                if !malformed_attributes.is_empty() {
                                    CNT_MALFORMED.fetch_add(1, Ordering::Relaxed);
                                }
                                if !conventional_attributes.is_empty() {
                                    assert!(!update.conventional_nlri().is_empty());
                                } else {
                                    assert!(update.conventional_nlri().is_empty());
                                }
                                if pa_hints & HINT_SINGLE_SEQ == HINT_SINGLE_SEQ {
                                    // then we should have a non-zero ASN:
                                    assert!(origin_as != 0);
                                } else {
                                    CNT_NOT_SINGLE_SEQ.fetch_add(1, Ordering::Relaxed);
                                    assert!(origin_as == 0);
                                }
                            },
                            MessageType::OPEN => { },
                            _ => { }
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
    use std::{fs::File, io::BufReader};

    use super::*;

    #[test]
    fn read_file_with_pool() {
        const FILENAME: &str = "/home/luuk/code/routecore.bak/examples/raw_bgp_updates";
        let f = File::open(FILENAME).unwrap();
        let reader = BufReader::new(f);
        let pool = Pool::default();
        let queue = pool.start_processing();

        let mut iter = MessageIter::<_, {2<<18}>::new(reader);
        let mut _last_capacity = queue.read().unwrap().capacity();
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
        eprintln!("Done, CNT: {CNT_TOTAL:?}, \
            COMBINED: {CNT_COMBINED:?}, \
            MP_R_U: {CNT_MP_R_U:?}, \
            NOT_SINGLE_SEQ: {CNT_NOT_SINGLE_SEQ:?}, \
            MALFORMED: {CNT_MALFORMED:?}, \
            ");
    }
}
