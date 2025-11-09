use std::{borrow::Cow, collections::VecDeque, io::Read, sync::{atomic::{AtomicUsize, Ordering}, Arc, RwLock}, thread, time::Duration};

use zerocopy::TryFromBytes;

use crate::bgp::message_ng::{common::{Header, MessageType, MIN_MSG_SIZE}, update::UncheckedUpdate};


struct MessageIter<R: Read, const B: usize> {
    reader: R,
    buf: [u8; B],
    buf_cursor: usize,
    buf_end: usize,
}

//impl<R: Read> MessageIter<R, {2<<20}> {
//    pub fn new(reader: R) -> Self {
//        Self {
//            reader,
//            buf: [0u8; 2<<20],
//            buf_cursor: 0,
//            buf_end: 0,
//        }
//    }
//}

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

#[derive(Default)]
pub struct Pool {
    queue: Arc<RwLock<VecDeque<Vec<u8>>>>,
}

static CNT: AtomicUsize = AtomicUsize::new(0);

impl Pool {
    pub fn start_processing(self) -> Arc<RwLock<VecDeque<Vec<u8>>>> {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(6).build().unwrap();
        let queue = self.queue.clone();
        for n in 0..dbg!(pool.current_num_threads()) {
            //s.spawn(|_s2| {
            let queue = queue.clone();
            pool.spawn(move || {
                eprintln!("[{:?}] spawned", thread::current().id());
                loop {
                    let Some(buf) = queue.write().unwrap().pop_front() else {
                        thread::park_timeout(Duration::from_millis(100));
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
                                let update = UncheckedUpdate::from_minimal_length(msg).unwrap();
                                let (c, mpr, mpu, c_c, m) = update.into_checked_parts();
                                CNT.fetch_add(1, Ordering::Relaxed);
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

        let mut iter = MessageIter::<_, {2<<16}>::new(reader);
        loop {
            if let Ok(Some(_)) = iter.read_into_buf() {
                if let Ok(msgs) = iter.get_many() {
                    queue.write().unwrap().push_back(msgs);
                }
            } else {
                break
            }

        }
        while !queue.read().unwrap().is_empty() {
            //std::hint::spin_loop();
            thread::sleep(Duration::from_millis(100));
        }
        thread::sleep(Duration::from_millis(1000));
        eprintln!("Done, CNT: {CNT:?}");
    }
}
