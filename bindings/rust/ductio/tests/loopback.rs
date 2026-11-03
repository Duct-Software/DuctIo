use ductio::{
    CustomWire, DialId, Engine, Handler, InterHost, NoiseKeypair, ParseResult, Protocol,
    SessionToken,
};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    os::unix::net::{UnixDatagram, UnixStream},
    sync::{
        mpsc::{self, Sender},
        Arc, Mutex,
    },
    time::Duration,
};

#[cfg(feature = "tls-openssl")]
#[test]
fn tls_server_echoes_to_openssl_client() {
    use ductio::TlsWire;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        ssl::{SslConnector, SslContextBuilder, SslMethod, SslVerifyMode},
        x509::{X509NameBuilder, X509},
    };

    let _serial = TEST_ENGINE.lock().unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    certificate
        .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
        .unwrap();
    certificate.sign(&key, MessageDigest::sha256()).unwrap();
    let mut context = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
    context.set_certificate(&certificate.build()).unwrap();
    context.set_private_key(&key).unwrap();
    let mut engine = Engine::start(1, 1).unwrap();
    let (tx, rx) = mpsc::channel();
    let protocol = engine.add_protocol(
        Protocol::tls_server(
            "tls-echo",
            Arc::new(Echo(tx)),
            TlsWire::server(context.build()).unwrap(),
        )
        .unwrap(),
    );
    let mut listener = engine
        .bind_tcp(
            protocol,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    let stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, listener.port())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut stream = connector.build().connect("localhost", stream).unwrap();
    stream.write_all(b"tls-wire").unwrap();
    let mut received = [0_u8; 8];
    stream.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"tls-wire");
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Open(_)
    ));
    assert!(
        matches!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Frame(ref p) if p == b"tls-wire")
    );
    drop(stream);
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
}

static TEST_ENGINE: Mutex<()> = Mutex::new(());

#[derive(Debug)]
enum Event {
    Open(SessionToken),
    PeerKey,
    Frame(Vec<u8>),
    Close,
    Join(u32),
    Timer(u64),
}
struct Echo(Sender<Event>);
impl Handler for Echo {
    fn open(&self, tok: SessionToken) {
        let _ = self.0.send(Event::Open(tok));
    }
    fn frame(&self, _tok: SessionToken, frame: &[u8]) -> Option<Vec<u8>> {
        let _ = self.0.send(Event::Frame(frame.to_vec()));
        Some(frame.to_vec())
    }
    fn peer_key(&self, _tok: SessionToken, _key: &[u8]) -> bool {
        true
    }
    fn authenticated(&self, _tok: SessionToken, _key: &[u8]) {
        let _ = self.0.send(Event::PeerKey);
    }
    fn close(&self, _tok: SessionToken, _reason: u8) {
        let _ = self.0.send(Event::Close);
    }
    fn conn_join(&self, _tok: SessionToken, conn_id: u32) {
        let _ = self.0.send(Event::Join(conn_id));
    }
    fn timer(&self, _tok: SessionToken, tag: u64) -> Option<Vec<u8>> {
        let _ = self.0.send(Event::Timer(tag));
        None
    }
}
struct Client(Sender<Event>);
impl Handler for Client {
    fn open(&self, tok: SessionToken) {
        let _ = self.0.send(Event::Open(tok));
    }
    fn frame(&self, _tok: SessionToken, frame: &[u8]) -> Option<Vec<u8>> {
        let _ = self.0.send(Event::Frame(frame.to_vec()));
        None
    }
    fn peer_key(&self, _tok: SessionToken, _key: &[u8]) -> bool {
        true
    }
    fn authenticated(&self, _tok: SessionToken, _key: &[u8]) {
        let _ = self.0.send(Event::PeerKey);
    }
    fn close(&self, _tok: SessionToken, _reason: u8) {
        let _ = self.0.send(Event::Close);
    }
    fn conn_join(&self, _tok: SessionToken, conn_id: u32) {
        let _ = self.0.send(Event::Join(conn_id));
    }
}
struct DialFailure(Sender<(DialId, i32)>);
impl Handler for DialFailure {
    fn dial_error(&self, id: DialId, code: i32) {
        let _ = self.0.send((id, code));
    }
}

struct PacketSink(Sender<(SessionToken, u32, Vec<u8>)>);
impl InterHost for PacketSink {
    fn packet_out(&self, token: SessionToken, conn_id: u32, packet: Vec<u8>) {
        let _ = self.0.send((token, conn_id, packet));
    }
}

struct TwoByteLength;
impl CustomWire for TwoByteLength {
    fn header_size(&self) -> usize {
        2
    }
    fn max_frame(&self) -> usize {
        16 * 1024
    }
    fn parse(&self, input: &[u8]) -> ParseResult {
        if input.len() < 2 {
            return ParseResult::Need(2);
        }
        let len = u16::from_be_bytes([input[0], input[1]]) as usize;
        if len > self.max_frame() {
            return ParseResult::Invalid { discard: 2 };
        }
        let total = 2 + len;
        if input.len() < total {
            return ParseResult::Need(total);
        }
        ParseResult::Frame {
            consumed: total,
            payload_len: len,
            flags: 0,
            stream_id: 0,
        }
    }
    fn pack(&self, payload: &[u8], _flags: u8, _stream_id: u32) -> ductio::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(2 + payload.len());
        output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        output.extend_from_slice(payload);
        Ok(output)
    }
}

#[test]
fn sealed_tcp_echo_and_stop() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server_keys = NoiseKeypair::from_private([7u8; 32]).unwrap();
    let client_keys = NoiseKeypair::from_private([9u8; 32]).unwrap();
    let server_public = server_keys.public_key();
    let responder = server_keys
        .into_wire(None, [0; 32], false, false)
        .unwrap()
        .verify_with(|_| true);
    let initiator = client_keys
        .into_wire(Some(server_public), [0; 32], true, false)
        .unwrap();
    let server =
        engine.add_protocol(Protocol::sealed("server", Arc::new(Echo(stx)), responder).unwrap());
    let client =
        engine.add_protocol(Protocol::sealed("client", Arc::new(Client(ctx)), initiator).unwrap());
    let port = engine
        .listen_tcp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_tcp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )
        .unwrap();
    let token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(t) => t,
        _ => panic!("expected open"),
    };
    // Wait for both Noise peers to be identified before sending user data.
    for rx in [&crx, &srx] {
        let mut seen = false;
        for _ in 0..3 {
            if matches!(
                rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                Event::PeerKey
            ) {
                seen = true;
                break;
            }
        }
        assert!(seen);
    }
    engine.post(token, b"ductio-rust-sealed".to_vec()).unwrap();
    assert!(
        matches!(crx.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Frame(ref p) if p == b"ductio-rust-sealed")
    );
    // Queue enough owned responses to exercise the C send/retry ownership
    // paths, then close and stop without waiting for every echoed frame.
    let burst = vec![0x5a; 16 * 1024];
    for _ in 0..64 {
        engine.post(token, burst.clone()).unwrap();
    }
    engine.close(token).unwrap();
    engine.stop().unwrap();
}

fn sealed_tcp_bulk(window: u64, batches: u64) {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server_keys = NoiseKeypair::from_private([17u8; 32]).unwrap();
    let client_keys = NoiseKeypair::from_private([19u8; 32]).unwrap();
    let responder = server_keys
        .into_wire(None, [0; 32], false, false)
        .unwrap()
        .verify_with(|_| true);
    let initiator = client_keys
        .into_wire(
            Some(NoiseKeypair::from_private([17u8; 32]).unwrap().public_key()),
            [0; 32],
            true,
            false,
        )
        .unwrap();
    let server = engine
        .add_protocol(Protocol::sealed("bulk-server", Arc::new(Echo(stx)), responder).unwrap());
    let client = engine
        .add_protocol(Protocol::sealed("bulk-client", Arc::new(Client(ctx)), initiator).unwrap());
    let port = engine
        .listen_tcp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_tcp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )
        .unwrap();
    let token = loop {
        match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Open(token) => break token,
            Event::Close => panic!("bulk session closed before open"),
            _ => {}
        }
    };
    for rx in [&crx, &srx] {
        loop {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::PeerKey => break,
                Event::Close => panic!("bulk session closed before authentication"),
                _ => {}
            }
        }
    }
    for batch in 0..batches {
        let frame_size = if batch < batches / 2 { 4000 } else { 15000 };
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        for index in 0..window {
            let sequence = batch * window + index;
            let mut payload = vec![0x5a; frame_size];
            payload[..8].copy_from_slice(&sequence.to_be_bytes());
            loop {
                match engine.post(token, payload.clone()) {
                    Ok(()) => break,
                    Err(ductio::Error::Backpressure) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "host backlog did not drain: sequence={}, pending={:?}, echoes={}",
                            sequence,
                            engine.pending_post_stats(),
                            crx.try_iter()
                                .filter(|e| matches!(e, Event::Frame(_)))
                                .count()
                        );
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("bulk post {sequence}: {error}"),
                }
            }
        }
        for index in 0..window {
            let expected = batch * window + index;
            loop {
                match crx
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap_or_else(|error| {
                        panic!(
                            "echo timeout at {expected}: {error:?}, pending={:?}, server_frames={}",
                            engine.pending_post_stats(),
                            srx.try_iter()
                                .filter(|e| matches!(e, Event::Frame(_)))
                                .count()
                        )
                    }) {
                    Event::Frame(frame) => {
                        assert_eq!(frame.len(), frame_size);
                        assert_eq!(u64::from_be_bytes(frame[..8].try_into().unwrap()), expected);
                        break;
                    }
                    Event::Close => panic!("bulk session closed at frame {expected}"),
                    _ => {}
                }
            }
        }
    }
    engine.stop().unwrap();
}

#[test]
fn sealed_tcp_bulk_delivers_every_frame() {
    sealed_tcp_bulk(128, 32);
}

#[test]
fn sealed_tcp_large_window_drains_without_application_reads() {
    // 61 MB ahead of consuming the application queue: larger than Linux's
    // socket autotuning buffer. Worker RX must progress independently of TX.
    sealed_tcp_bulk(4096, 2);
}

#[test]
fn sealed_tcp_two_concurrent_sessions_deliver_bulk() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server_keys = NoiseKeypair::from_private([27u8; 32]).unwrap();
    let client_keys = NoiseKeypair::from_private([29u8; 32]).unwrap();
    let server_public = server_keys.public_key();
    let server = engine.add_protocol(
        Protocol::sealed(
            "multi-server",
            Arc::new(Echo(stx)),
            server_keys
                .into_wire(None, [0; 32], false, false)
                .unwrap()
                .verify_with(|_| true),
        )
        .unwrap(),
    );
    let client = engine.add_protocol(
        Protocol::sealed(
            "multi-client",
            Arc::new(Client(ctx)),
            client_keys
                .into_wire(Some(server_public), [0; 32], true, false)
                .unwrap(),
        )
        .unwrap(),
    );
    let port = engine
        .listen_tcp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    let mut tokens = Vec::new();
    for _ in 0..2 {
        engine
            .dial_tcp(
                client,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            )
            .unwrap();
        loop {
            match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Open(token) => {
                    tokens.push(token);
                    break;
                }
                Event::Close => panic!("multi-session closed before open"),
                _ => {}
            }
        }
        for rx in [&crx, &srx] {
            loop {
                match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                    Event::PeerKey => break,
                    Event::Close => panic!("multi-session closed before authentication"),
                    _ => {}
                }
            }
        }
    }
    for batch in 0..16u64 {
        let frame_size = if batch < 8 { 4000 } else { 15000 };
        for index in 0..64u64 {
            let sequence = batch * 64 + index;
            for (channel, token) in tokens.iter().enumerate() {
                let mut payload = vec![0x5a; frame_size];
                payload[0] = channel as u8;
                payload[1..9].copy_from_slice(&sequence.to_be_bytes());
                loop {
                    match engine.post(*token, payload.clone()) {
                        Ok(()) => break,
                        Err(ductio::Error::Backpressure) => {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        Err(error) => panic!("multi-session post {sequence}: {error}"),
                    }
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        while seen.len() < 128 {
            match crx.recv_timeout(Duration::from_secs(10)).unwrap() {
                Event::Frame(frame) => {
                    assert_eq!(frame.len(), frame_size);
                    let channel = frame[0];
                    let sequence = u64::from_be_bytes(frame[1..9].try_into().unwrap());
                    assert!(channel < 2);
                    assert!((batch * 64..(batch + 1) * 64).contains(&sequence));
                    assert!(seen.insert((channel, sequence)), "duplicate echo");
                }
                Event::Close => panic!("multi-session closed during bulk"),
                _ => {}
            }
        }
    }
    engine.stop().unwrap();
}

#[test]
fn engine_is_singleton_and_drop_releases_it() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let engine = Engine::start(1, 1).unwrap();
    assert!(Engine::start(1, 1).is_err());
    drop(engine);
    assert!(Engine::start(1, 1).is_ok());
}

#[test]
fn generated_noise_identity_has_a_public_key() {
    let pair = NoiseKeypair::generate().unwrap();
    assert_ne!(pair.public_key(), [0; 32]);
}

#[test]
fn failed_dial_is_correlated_without_session_state() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe); // no server remains at this localhost port
    let (tx, rx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let protocol =
        engine.add_protocol(Protocol::plain("failed-dial", Arc::new(DialFailure(tx))).unwrap());
    let id = engine.dial_tcp(protocol, addr).unwrap();
    let (reported, code) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(reported, id);
    assert_ne!(code, 0);
    engine.stop().unwrap();
}

#[test]
fn udp_datagram_echo_and_listener_revocation() {
    struct MetadataEcho {
        echo: Echo,
        info: Sender<ductio::FrameInfo>,
    }
    impl Handler for MetadataEcho {
        fn open(&self, token: SessionToken) {
            self.echo.open(token);
        }
        fn frame_with_info(
            &self,
            token: SessionToken,
            info: ductio::FrameInfo,
            bytes: &[u8],
        ) -> ductio::FrameAction {
            self.info.send(info).unwrap();
            ductio::FrameAction::Accept(self.echo.frame(token, bytes))
        }
    }
    let _serial = TEST_ENGINE.lock().unwrap();
    let (itx, irx) = mpsc::channel();
    let (stx, srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server = engine.add_protocol(
        Protocol::datagram(
            "udp-server",
            Arc::new(MetadataEcho {
                echo: Echo(stx),
                info: itx,
            }),
        )
        .unwrap(),
    );
    let client =
        engine.add_protocol(Protocol::datagram("udp-client", Arc::new(Client(ctx))).unwrap());
    let mut listener = engine
        .bind_udp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    assert_ne!(listener.port(), 0);
    engine
        .dial_udp_via(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
            0,
        )
        .unwrap();
    let token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(t) => t,
        _ => panic!("expected UDP client open"),
    };
    engine.post(token, b"packet-boundary".to_vec()).unwrap();
    assert!(matches!(
        srx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Open(_)
    ));
    assert!(
        matches!(srx.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Frame(ref p) if p == b"packet-boundary")
    );
    assert!(
        matches!(crx.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Frame(ref p) if p == b"packet-boundary")
    );
    let first = irx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.conn_id, 0);
    assert_eq!(first.counters.rx_frames, 0); // Snapshot precedes acceptance.
    engine.post(token, b"second".to_vec()).unwrap();
    assert!(matches!(crx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Frame(ref bytes) if bytes == b"second"));
    let second = irx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(second.counters.rx_frames, 1);
    assert_eq!(second.counters.rx_bytes, b"packet-boundary".len() as u64);
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
}

#[test]
fn sealed_udp_echo() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server_keys = NoiseKeypair::from_private([11; 32]).unwrap();
    let client_keys = NoiseKeypair::from_private([13; 32]).unwrap();
    let server_public = server_keys.public_key();
    let server_wire = server_keys
        .into_wire(None, [0; 32], false, true)
        .unwrap()
        .verify_with(|_| true);
    let client_wire = client_keys
        .into_wire(Some(server_public), [0; 32], true, true)
        .unwrap();
    let server = engine.add_protocol(
        Protocol::sealed("sealed-udp-server", Arc::new(Echo(stx)), server_wire).unwrap(),
    );
    let client = engine.add_protocol(
        Protocol::sealed("sealed-udp-client", Arc::new(Client(ctx)), client_wire).unwrap(),
    );
    let mut listener = engine
        .bind_udp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_udp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
        )
        .unwrap();
    let client_token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(token) => token,
        _ => panic!("expected client open"),
    };
    for rx in [&crx, &srx] {
        let mut authenticated = false;
        for _ in 0..3 {
            if matches!(
                rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                Event::PeerKey
            ) {
                authenticated = true;
                break;
            }
        }
        assert!(authenticated);
    }
    engine
        .post(client_token, b"sealed-datagram".to_vec())
        .unwrap();
    assert!(
        matches!(crx.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Frame(ref p) if p == b"sealed-datagram")
    );
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
}

#[test]
fn inter_leg_roundtrip_and_stop_revokes_ingress() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, _srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let (ptx, prx) = mpsc::channel();
    let mut engine = Engine::start_with_inter_host(1, 1, Arc::new(PacketSink(ptx))).unwrap();
    let server =
        engine.add_protocol(Protocol::datagram("inter-server", Arc::new(Echo(stx))).unwrap());
    let client =
        engine.add_protocol(Protocol::datagram("inter-client", Arc::new(Echo(ctx))).unwrap());
    let mut listener = engine
        .bind_udp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_udp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
        )
        .unwrap();
    let token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(token) => token,
        _ => panic!("expected client open"),
    };
    engine.attach_inter(token, 1).unwrap();
    assert!(matches!(
        crx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Join(1)
    ));
    let ingress = engine.inter_ingress().unwrap();
    ingress.batch(token, 1, &[b"first", b"second"]).unwrap();
    for expected in [b"first".as_slice(), b"second".as_slice()] {
        let (seen_token, conn_id, packet) = prx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(seen_token, token);
        assert_eq!(conn_id, 1);
        assert_eq!(packet, expected);
    }
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
    assert!(matches!(
        ingress.packet(token, 1, b"late"),
        Err(ductio::Error::Stopped)
    ));
}

#[test]
fn packet_fd_ownership_and_roundtrip() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, _srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server = engine.add_protocol(Protocol::datagram("fd-server", Arc::new(Echo(stx))).unwrap());
    let client = engine.add_protocol(Protocol::datagram("fd-client", Arc::new(Echo(ctx))).unwrap());
    let mut listener = engine
        .bind_udp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_udp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
        )
        .unwrap();
    let token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(token) => token,
        _ => panic!("expected open"),
    };
    let (peer, attached) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    engine
        .attach_packet_fd(token, 2, attached.into())
        .unwrap()
        .wait(Duration::from_secs(5))
        .unwrap();
    assert!(matches!(
        crx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Join(2)
    ));
    peer.send(b"packet-fd").unwrap();
    let mut buf = [0; 64];
    let n = peer.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"packet-fd");
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
}

#[test]
fn stream_fd_roundtrip() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, _srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server =
        engine.add_protocol(Protocol::plain("stream-fd-server", Arc::new(Echo(stx))).unwrap());
    let client =
        engine.add_protocol(Protocol::plain("stream-fd-client", Arc::new(Echo(ctx))).unwrap());
    let mut listener = engine
        .bind_tcp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_tcp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
        )
        .unwrap();
    let token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(token) => token,
        _ => panic!("expected open"),
    };
    let (mut peer, attached) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    engine
        .attach_stream_fd(token, 2, attached.into())
        .unwrap()
        .wait(Duration::from_secs(5))
        .unwrap();
    assert!(matches!(
        crx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Join(2)
    ));
    peer.write_all(&[0, 0, 0, 9]).unwrap();
    peer.write_all(b"stream-fd").unwrap();
    let mut output = [0; 13];
    peer.read_exact(&mut output).unwrap();
    assert_eq!(
        &output,
        &[0, 0, 0, 9, b's', b't', b'r', b'e', b'a', b'm', b'-', b'f', b'd']
    );
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
}

#[test]
fn worker_timers_fire_and_can_be_cancelled() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, _srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server =
        engine.add_protocol(Protocol::datagram("timer-server", Arc::new(Echo(stx))).unwrap());
    let client =
        engine.add_protocol(Protocol::datagram("timer-client", Arc::new(Echo(ctx))).unwrap());
    let mut listener = engine
        .bind_udp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_udp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
        )
        .unwrap();
    let token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(token) => token,
        _ => panic!("expected open"),
    };
    engine
        .schedule_timer(token, 7, Duration::from_millis(20), Duration::ZERO)
        .unwrap();
    assert!(matches!(
        crx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Timer(7)
    ));
    engine
        .schedule_timer(
            token,
            8,
            Duration::from_millis(20),
            Duration::from_millis(20),
        )
        .unwrap();
    assert!(matches!(
        crx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Timer(8)
    ));
    engine.cancel_timer(token, 8).unwrap();
    engine.cancel_timer(token, 7).unwrap();
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
}

#[test]
fn custom_wire_frames_tcp_without_ffi_in_application() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let (stx, _srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut engine = Engine::start(1, 1).unwrap();
    let server = engine.add_protocol(
        Protocol::custom(
            "custom-server",
            Arc::new(Echo(stx)),
            Arc::new(TwoByteLength),
        )
        .unwrap(),
    );
    let client = engine.add_protocol(
        Protocol::custom(
            "custom-client",
            Arc::new(Client(ctx)),
            Arc::new(TwoByteLength),
        )
        .unwrap(),
    );
    let mut listener = engine
        .bind_tcp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_tcp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
        )
        .unwrap();
    let token = match crx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Open(token) => token,
        _ => panic!("expected open"),
    };
    engine.post(token, b"custom-wire".to_vec()).unwrap();
    let result = crx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        matches!(result, Event::Frame(ref bytes) if bytes == b"custom-wire"),
        "{result:?}"
    );
    engine.close_listener(&mut listener).unwrap();
    engine.stop().unwrap();
}

#[test]
fn tcp_listener_can_be_revoked_and_stats_are_readable() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let mut engine = Engine::start(1, 1).unwrap();
    let (tx, _) = mpsc::channel();
    let protocol = engine.add_protocol(Protocol::plain("revocable", Arc::new(Echo(tx))).unwrap());
    let mut listener = engine
        .bind_tcp(
            protocol,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, listener.port())).is_err());
    let _ = engine.stats(); // present only in native builds with runtime stats
    engine.close_listener(&mut listener).unwrap();
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, listener.port())).is_ok());
    engine.stop().unwrap();
    assert!(engine.stats().is_none());
    assert!(matches!(
        engine.bind_tcp(
            protocol,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        ),
        Err(ductio::Error::Stopped)
    ));
}

#[test]
fn compact_udp_admits_owned_allow_list_peer_psk_and_hello() {
    let _serial = TEST_ENGINE.lock().unwrap();
    let mut engine = Engine::start(1, 1).unwrap();
    let (stx, srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let server_keys = NoiseKeypair::from_private([91; 32]).unwrap();
    let client_keys = NoiseKeypair::from_private([93; 32]).unwrap();
    let server_pub = server_keys.public_key();
    let client_pub = client_keys.public_key();
    let responder = server_keys
        .into_wire(None, [0; 32], false, true)
        .unwrap()
        .with_wire_key([95; 32])
        .with_hello(&[0; 5])
        .unwrap()
        .with_allowed_peers(vec![client_pub])
        .unwrap()
        .with_peer_psk(move |peer, hello| {
            if peer == &client_pub && hello == b"alice" {
                Some([97; 32])
            } else {
                None
            }
        })
        .with_join_lead([99; 16])
        .unwrap();
    let initiator = client_keys
        .into_wire(Some(server_pub), [97; 32], true, true)
        .unwrap()
        .with_wire_key([95; 32])
        .with_hello(b"alice")
        .unwrap()
        .with_join_lead([99; 16])
        .unwrap();
    let server = engine
        .add_protocol(Protocol::sealed("compact-server", Arc::new(Echo(stx)), responder).unwrap());
    let client = engine.add_protocol(
        Protocol::sealed("compact-client", Arc::new(Client(ctx)), initiator).unwrap(),
    );
    let listener = engine
        .bind_udp(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    engine
        .dial_udp(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port()),
        )
        .unwrap();
    let mut token = None;
    for receiver in [&crx, &srx] {
        loop {
            match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Open(t) => {
                    if token.is_none() {
                        token = Some(t);
                    }
                }
                Event::PeerKey => break,
                Event::Close => panic!("PSK/hello admission failed"),
                _ => {}
            }
        }
    }
    engine
        .post(token.unwrap(), b"compact-echo".to_vec())
        .unwrap();
    loop {
        if let Event::Frame(bytes) = crx.recv_timeout(Duration::from_secs(5)).unwrap() {
            assert_eq!(bytes, b"compact-echo");
            break;
        }
    }
    engine.stop().unwrap();
}

// Exercise the borrowed native config after both caller buffers have changed
// and gone away, and after NoiseWire -> Protocol -> Engine ownership transfers.
fn owned_hello_peer_psk_echo(datagram: bool) {
    let _serial = TEST_ENGINE.lock().unwrap();
    let mut engine = Engine::start(1, 1).unwrap();
    let (stx, srx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let server_keys = NoiseKeypair::from_private([101; 32]).unwrap();
    let client_keys = NoiseKeypair::from_private([103; 32]).unwrap();
    let server_pub = server_keys.public_key();
    let client_pub = client_keys.public_key();
    let expected = [0x5a; 32];
    let mut server_input = vec![0; expected.len()];
    let mut responder = server_keys.into_wire(None, [0; 32], false, datagram)
        .unwrap().with_wire_key([105; 32])
        .with_hello(&server_input).unwrap()
        .with_peer_psk(move |peer, hello| {
            (peer == &client_pub && hello == expected).then_some([107; 32])
        });
    server_input.fill(0xa5);
    drop(server_input);
    let mut client_input = expected.to_vec();
    let mut initiator = client_keys.into_wire(Some(server_pub), [107; 32], true, datagram)
        .unwrap().with_wire_key([105; 32])
        .with_hello(b"replace me").unwrap()
        .with_hello(&client_input).unwrap();
    client_input.fill(0xa5);
    drop(client_input);
    if datagram {
        responder = responder.with_join_lead([109; 16]).unwrap();
        initiator = initiator.with_join_lead([109; 16]).unwrap();
    }
    let server = engine.add_protocol(
        Protocol::sealed("owned-hello-server", Arc::new(Echo(stx)), responder).unwrap());
    let client = engine.add_protocol(
        Protocol::sealed("owned-hello-client", Arc::new(Client(ctx)), initiator).unwrap());
    let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = if datagram { engine.bind_udp(server, localhost) } else { engine.bind_tcp(server, localhost) }.unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port());
    if datagram { engine.dial_udp(client, addr) } else { engine.dial_tcp(client, addr) }.unwrap();
    let mut token = None;
    for receiver in [&crx, &srx] {
        loop {
            match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Open(t) => { if token.is_none() { token = Some(t); } }
                Event::PeerKey => break,
                Event::Close => panic!("owned hello/PSK admission failed"),
                _ => {}
            }
        }
    }
    engine.post(token.unwrap(), b"hello-after-caller-drop".to_vec()).unwrap();
    loop {
        if let Event::Frame(bytes) = crx.recv_timeout(Duration::from_secs(5)).unwrap() {
            assert_eq!(bytes, b"hello-after-caller-drop");
            break;
        }
    }
    engine.stop().unwrap();
}

#[test]
fn owned_hello_survives_caller_drop_and_engine_moves_over_tcp() {
    owned_hello_peer_psk_echo(false);
}

#[test]
fn owned_hello_survives_caller_drop_and_engine_moves_over_udp() {
    owned_hello_peer_psk_echo(true);
}

#[test]
fn engine_timer_stop_request_and_pool_readings() {
    struct Timer(Sender<u64>);
    impl Handler for Timer {
        fn engine_timer(&self, tag: u64) {
            self.0.send(tag).unwrap();
        }
    }
    let _serial = TEST_ENGINE.lock().unwrap();
    let mut engine = Engine::start(1, 1).unwrap();
    let (tx, rx) = mpsc::channel();
    let proto = engine.add_protocol(Protocol::plain("free-timer", Arc::new(Timer(tx))).unwrap());
    let before = engine.connection_pool().unwrap();
    assert!(before.free > 0);
    engine
        .schedule_engine_timer(proto, Duration::ZERO, 42)
        .unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 42);
    assert_eq!(engine.connection_pool().unwrap(), before);
    engine.request_stop().unwrap();
    engine.wait_for_stop().unwrap();
    assert!(matches!(
        engine.connection_pool(),
        Err(ductio::Error::Stopped)
    ));
}

#[test]
fn native_crypto_helpers_match_known_hmac_vector() {
    let mut random = [0; 64];
    ductio::random_bytes(&mut random).unwrap();
    assert!(random.iter().any(|b| *b != 0));
    let digest = ductio::hmac_sha256(&[0x0b; 20], b"Hi There").unwrap();
    assert_eq!(
        digest,
        [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7
        ]
    );
    assert!(ductio::constant_time_equal(&digest, &digest));
    assert!(!ductio::constant_time_equal(&digest, &random[..32]));
    assert!(!ductio::constant_time_equal(&digest, &[]));
}
