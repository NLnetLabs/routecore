extern crate routecore;
extern crate tokio;

use routecore::bgp::message::{Message as BgpMsg, UpdateMessage, SessionConfig};

use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::io::{AsyncReadExt, BufReader};
use std::io::Write;

async fn take_frame_async<'a, T: AsyncReadExt + Unpin>(bytes: &mut T, b: &'a mut [u8; 4096])
    //-> Result<Option<Vec<u8>>, &'a str>
    -> Result<Option<&'a [u8]>, &'a str>
{
    if let Err(e) = bytes.read_exact(&mut b[..18]).await {
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof => { return Ok(None) }
            _ => return Err("io error")
        }
    }

    let len = u16::from_be_bytes([b[16], b[17]]);
    if len > 4096 {
        println!("jumbo? {:x?}", &b[..18]);
    }

    let bytes_read = bytes.read_exact(&mut b[18..(len).into()]).await;
    //Ok(Some(b[..len as usize].to_vec())) // for Vec<u8>
    Ok(Some(&b[..len as usize]))
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("::1:9179").await.unwrap();


    let (socket, remote_ip) = listener.accept().await.unwrap();
    println!("{remote_ip} connected");
    let (mut tcp_rx, _tcp_tx) = socket.into_split();
    let mut buf = [0u8; 4096];
    let mut cnt = 0_u64;
    let mut bufreader = BufReader::new(tcp_rx);

    loop {
        tokio::select! {
            //match take_frame_async(&mut tcp_rx, &mut buf).await {
            // TODO:
            // - can we use a Bytes BytesMut instead of buf?
            // - can we utilize multiple cores if we dispatch tasks (e.g.
            // from_octets) via tokio spawn? using a shared BytesMut or w/e?
            res = take_frame_async(&mut bufreader, &mut buf) => {
                match res {
                    Ok(Some(res)) => {
                        cnt += 1;
                        if cnt % 100_000 == 0 {
                            print!("\rgot {:>10}", cnt);
                            std::io::stdout().flush();
                        }
                        tokio::spawn(async move {
                        let _ = BgpMsg::from_octets(&res[..], Some(SessionConfig::modern()));
                        });
                    },
                    Ok(None) => {
                        println!("\nend of stream");
                        break;
                    },
                    Err(e) => {
                        println!("error: {e}");
                    }
                }
            },
            _ = signal::ctrl_c() => { println!("ctrl+c, done"); break }
        }
    }
}
