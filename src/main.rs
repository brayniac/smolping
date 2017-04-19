#[macro_use]
extern crate log;
extern crate log_panics;
extern crate getopts;
extern crate smoltcp;

mod logging;

use getopts::Options;
use logging::set_log_level;
use smoltcp::Error;
use smoltcp::iface::{ArpCache, EthernetInterface, SliceArpCache};
use smoltcp::phy::{Device, RawSocket, TapInterface};
use smoltcp::socket::{AsSocket, SocketSet};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::wire::{EthernetAddress, IpAddress};
use smoltcp::wire::{EthernetFrame, EthernetProtocol, PrettyPrinter};
use std::env;
use std::str::{self, FromStr};
use std::time::Instant;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const PROGRAM: &'static str = env!("CARGO_PKG_NAME");

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn opts() -> Options {
    let mut opts = Options::new();
    opts.optopt("i", "interface", "name of ethernet interface", "[IFNAME]");
    opts.optopt("",
                "hwaddr",
                "MAC address of ethernet interface",
                "[HWADDR]");
    opts.optopt("", "srcip", "ip address", "[IPADDR]");
    opts.optopt("", "srcport", "tcp port", "[PORT]");
    opts.optopt("", "dstip", "ip address", "[IPADDR]");
    opts.optopt("", "dstport", "tcp port", "[PORT]");
    opts.optflag("", "version", "show version and exit");
    opts.optflagmulti("v", "verbose", "verbosity (stacking)");
    opts.optflag("h", "help", "print this help menu");

    opts
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    let opts = opts();

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("Failed to parse command line args: {}", f);
        }
    };

    if matches.opt_present("help") {
        print_usage(program, opts);
        return;
    }

    // initialize logging
    set_log_level(matches.opt_count("verbose"));
    log_panics::init();

    info!("{} {}", PROGRAM, VERSION);

    let ifname = matches.opt_str("interface").unwrap();
    let hwaddr = EthernetAddress::from_str(&matches.opt_str("hwaddr").unwrap()).unwrap();
    let srcip = IpAddress::from_str(&matches.opt_str("srcip").unwrap()).unwrap();
    let srcport = u16::from_str(&matches.opt_str("srcport").unwrap()).unwrap();
    let dstip = IpAddress::from_str(&matches.opt_str("dstip").unwrap()).unwrap();
    let dstport = u16::from_str(&matches.opt_str("dstport").unwrap()).unwrap();

    let device = RawSocket::new(ifname.as_ref()).unwrap();

    let startup_time = Instant::now();

    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut iface = EthernetInterface::new(Box::new(device),
                                           Box::new(arp_cache) as Box<ArpCache>,
                                           hwaddr,
                                           [srcip]);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    {
        let socket: &mut TcpSocket = sockets.get_mut(tcp_handle).as_socket();
        socket
            .connect((dstip, dstport), (srcip, srcport))
            .unwrap();
    }

    let mut tcp_active = false;
    let mut waiting = false;
    loop {
        {
            let socket: &mut TcpSocket = sockets.get_mut(tcp_handle).as_socket();
            if socket.is_active() && !tcp_active {
                debug!("connected");
            } else if !socket.is_active() && tcp_active {
                debug!("disconnected");
                break;
            }
            tcp_active = socket.is_active();

            if socket.may_recv() {
                if waiting {
                    let data = {
                        let mut data = socket.recv(128).unwrap().to_owned();
                        if data.len() > 0 {
                            debug!("recv data: {:?}",
                                   str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                            data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                            data.reverse();
                            data.extend(b"\n");
                        }
                        data
                    };
                    if data == "PONG\r\n".to_owned().as_bytes() {
                        waiting = false;
                    }
                } else {
                    let data = "PING\r\n".to_owned();
                    if socket.can_send() && data.len() > 0 {
                        debug!("send data: {:?}", data);
                        socket.send_slice(&data.as_bytes()).unwrap();
                    }
                }
            } else if socket.may_send() {
                debug!("close");
                socket.close();
            }
        }

        let timestamp = Instant::now().duration_since(startup_time);
        let timestamp_ms = (timestamp.as_secs() * 1000) +
                           (timestamp.subsec_nanos() / 1000000) as u64;
        match iface.poll(&mut sockets, timestamp_ms) {
            Ok(()) | Err(Error::Exhausted) => (),
            Err(e) => debug!("poll error: {}", e),
        }
    }
}
