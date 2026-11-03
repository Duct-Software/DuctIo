//! Minimal local I/O example. The production-facing sealed Noise path is
//! exercised by tests/loopback.rs and requires explicit peer-key admission.
use ductio::{Engine, Handler, Protocol, SessionToken};
use std::{net::SocketAddr, sync::Arc, time::Duration};

struct Echo;
impl Handler for Echo {
    fn frame(&self, _session: SessionToken, frame: &[u8]) -> Option<Vec<u8>> {
        Some(frame.to_vec())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Engine::start(1, 1)?;
    let protocol = engine.add_protocol(Protocol::plain("tcp-echo", Arc::new(Echo))?);
    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let port = engine.listen_tcp(protocol, addr)?;
    println!("echo listening at 127.0.0.1:{port} for 30 seconds");
    std::thread::sleep(Duration::from_secs(30));
    engine.stop()?;
    Ok(())
}
