//! Safe, owner-thread Linux and macOS SDK for DuctIo v0.1.1.
//!
//! One engine per process. All methods on [`Engine`] run on its owner thread;
//! callbacks run on DuctIo workers and must return promptly. No borrowed C
//! buffer or session pointer escapes a callback. A Noise peer key authenticates
//! the *link key*, not an application's node identity.

use ductio_sys as ffi;
mod custom_wire;
pub use custom_wire::{CustomWire, ParseResult};
use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    fmt,
    marker::PhantomData,
    net::SocketAddr,
    os::fd::{IntoRawFd, OwnedFd},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr::{self, NonNull},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

/// OS randomness; zero-length buffers succeed without a system call.
pub fn random_bytes(out: &mut [u8]) -> Result<()> {
    if unsafe { ffi::duct_random_bytes(out.as_mut_ptr().cast(), out.len()) } {
        Ok(())
    } else {
        Err(Error::CreationFailed)
    }
}
/// HMAC-SHA256 through the native Noise crypto provider.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    if key.len() > i32::MAX as usize {
        return Err(Error::InvalidInput);
    }
    let mut out = [0; 32];
    if unsafe {
        ffi::duct_hmac_sha256(
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr(),
        )
    } {
        Ok(out)
    } else {
        Err(Error::CreationFailed)
    }
}
/// Compare equal-length byte strings without data-dependent early exits.
/// Length is public; different lengths return false immediately.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && unsafe { ffi::duct_ct_equal(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) }
}

static ENGINE_ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_DIAL_ID: AtomicU64 = AtomicU64::new(1);
const MAX_PENDING_COMMANDS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    AlreadyRunning,
    Stopped,
    InvalidInput,
    Backpressure,
    Native(i32),
    CreationFailed,
    Cancelled,
    Timeout,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => f.write_str("DuctIo engine is already running"),
            Self::Stopped => f.write_str("DuctIo engine has stopped"),
            Self::InvalidInput => f.write_str("invalid DuctIo argument or stale handle"),
            Self::Backpressure => f.write_str("DuctIo command queue is full"),
            Self::Native(code) => write!(f, "DuctIo returned native error {code}"),
            Self::CreationFailed => f.write_str("DuctIo resource creation failed"),
            Self::Cancelled => f.write_str("DuctIo command was cancelled"),
            Self::Timeout => f.write_str("DuctIo command result timed out"),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

fn checked(rc: i32) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Native(rc))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionToken {
    raw: u64,
    engine_id: u64,
}
impl SessionToken {
    pub fn raw_word(self) -> u64 {
        self.raw
    }
    pub fn post(self, engine: &Engine, payload: Vec<u8>) -> Result<()> {
        engine.post(self, payload)
    }
    pub fn close(self, engine: &Engine) -> Result<()> {
        engine.close(self)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DialId(u64);

/// Snapshot read on the native worker before accepting the current frame.
/// Counters count payload handling/staging, not remote delivery or ACKs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionCounters {
    pub rx_frames: u64,
    pub rx_bytes: u64,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub tx_refused: u64,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct FrameInfo {
    pub conn_id: u32,
    pub flags: u8,
    pub counters: ConnectionCounters,
}

/// Invoked on a DuctIo worker. Implementations must not block the worker.
/// Panics are caught; the affected session is closed. `send` requests a link
/// enqueue only; it does not prove remote delivery.
pub trait Handler: Send + Sync + 'static {
    fn open(&self, _session: SessionToken) {}
    fn engine_timer(&self, _tag: u64) {}
    fn frame_with_info(
        &self,
        session: SessionToken,
        _info: FrameInfo,
        frame: &[u8],
    ) -> FrameAction {
        self.frame_action(session, frame)
    }
    fn frame(&self, _session: SessionToken, _frame: &[u8]) -> Option<Vec<u8>> {
        None
    }
    /// Called on the native worker. `Defer` retains and replays a stream
    /// frame; it must not be used for shared UDP or inter legs, which have
    /// already consumed their input before this callback.
    fn frame_action(&self, session: SessionToken, frame: &[u8]) -> FrameAction {
        FrameAction::Accept(self.frame(session, frame))
    }
    fn close(&self, _session: SessionToken, _reason: u8) {}
    fn error(&self, _session: Option<SessionToken>, _code: i32) {}
    fn dial_open(&self, _dial: DialId, _session: SessionToken) {}
    fn dial_error(&self, _dial: DialId, _code: i32) {}
    fn peer_key(&self, _session: SessionToken, _key: &[u8]) -> bool {
        false
    }
    fn authenticated(&self, _session: SessionToken, _key: &[u8]) {}
    fn conn_join(&self, _session: SessionToken, _conn_id: u32) {}
    fn conn_lost(&self, _session: SessionToken, _conn_id: u32, _reason: u8) {}
    /// Native pack/enqueue outcome, not a remote acknowledgement.
    fn send_done(&self, _session: SessionToken, _send_token: u64, _result: i32) {}
    fn timer(&self, _session: SessionToken, _tag: u64) -> Option<Vec<u8>> {
        None
    }
}

pub enum FrameAction {
    Accept(Option<Vec<u8>>),
    /// Hold an unaccepted stream frame until `Engine::wake` is called.
    Defer,
    Drop,
}

/// Receives packets emitted by inter legs on a dedicated host thread.
/// Packets are owned and can be queued to another application thread.
pub trait InterHost: Send + Sync + 'static {
    fn packet_out(&self, session: SessionToken, conn_id: u32, packet: Vec<u8>);
    fn resume(&self) {}
}

struct HostWork {
    callback: unsafe extern "C" fn(*mut std::ffi::c_void),
    ctx: usize,
}
struct HostBridge {
    sender: mpsc::Sender<HostWork>,
    handler: Arc<dyn InterHost>,
    engine_id: u64,
}
struct HostRunner {
    bridge: Option<Box<HostBridge>>,
    thread: Option<JoinHandle<()>>,
}
impl HostRunner {
    fn new(handler: Arc<dyn InterHost>, engine_id: u64) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<HostWork>();
        let thread = thread::Builder::new()
            .name("ductio-inter-host".into())
            .spawn(move || {
                for work in receiver {
                    unsafe { (work.callback)(work.ctx as *mut _) };
                }
            })
            .map_err(|_| Error::CreationFailed)?;
        Ok(Self {
            bridge: Some(Box::new(HostBridge {
                sender,
                handler,
                engine_id,
            })),
            thread: Some(thread),
        })
    }
    fn config(&mut self) -> ffi::duct_host_cfg_t {
        let ctx = (&mut **self.bridge.as_mut().unwrap() as *mut HostBridge).cast();
        ffi::duct_host_cfg_t {
            run: Some(host_run),
            queue_ctx: ctx,
            on_packet_out: Some(host_packet_out),
            on_inter_resume: Some(host_resume),
            ctx,
        }
    }
    fn shutdown(&mut self) {
        // Native teardown can leave host work already queued. A late resume
        // callback still receives this bridge as its context, so keep its
        // allocation alive until the host thread has drained that work.
        let mut bridge = self.bridge.take();
        if let Some(bridge) = bridge.as_mut() {
            let (closed_sender, _) = mpsc::channel();
            drop(std::mem::replace(&mut bridge.sender, closed_sender));
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        drop(bridge);
    }
}
impl Drop for HostRunner {
    fn drop(&mut self) {
        self.shutdown();
    }
}
unsafe extern "C" fn host_run(
    callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    ctx: *mut std::ffi::c_void,
    queue_ctx: *mut std::ffi::c_void,
) {
    if let Some(callback) = callback {
        let bridge = &*(queue_ctx as *const HostBridge);
        let _ = bridge.sender.send(HostWork {
            callback,
            ctx: ctx as usize,
        });
    }
}
unsafe extern "C" fn host_packet_out(
    ctx: *mut std::ffi::c_void,
    token: u64,
    conn_id: u32,
    packet: ffi::duct_view_u8,
) {
    let bridge = &*(ctx as *const HostBridge);
    let bytes = if packet.size == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(packet.data.cast::<u8>(), packet.size).to_vec()
    };
    let session = SessionToken {
        raw: token,
        engine_id: bridge.engine_id,
    };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        bridge.handler.packet_out(session, conn_id, bytes)
    }));
}
unsafe extern "C" fn host_resume(ctx: *mut std::ffi::c_void) {
    let bridge = &*(ctx as *const HostBridge);
    let _ = catch_unwind(AssertUnwindSafe(|| bridge.handler.resume()));
}

/// Thread-safe ingress to an inter leg. Calls are serialized across this
/// engine, satisfying the native SPSC lane contract even across clones.
#[derive(Clone)]
pub struct InterIngress(Arc<InterIngressState>);
struct InterIngressState {
    raw: Mutex<Option<usize>>,
    engine_id: u64,
}
impl InterIngress {
    pub fn packet(&self, session: SessionToken, conn_id: u32, packet: &[u8]) -> Result<()> {
        self.batch(session, conn_id, &[packet])
    }
    pub fn batch(&self, session: SessionToken, conn_id: u32, packets: &[&[u8]]) -> Result<()> {
        if session.engine_id != self.0.engine_id
            || packets.is_empty()
            || packets.len() > 256
            || packets.iter().any(|p| p.is_empty() || p.len() > 16 * 1024)
        {
            return Err(Error::InvalidInput);
        }
        let views: Vec<ffi::duct_view_u8> = packets
            .iter()
            .map(|p| ffi::duct_view_u8 {
                data: p.as_ptr().cast_mut().cast(),
                size: p.len(),
            })
            .collect();
        let guard = self.0.raw.lock().unwrap_or_else(|e| e.into_inner());
        let raw = guard.ok_or(Error::Stopped)? as *mut ffi::duct_engine_t;
        checked(unsafe {
            ffi::ductio_rs_inter_batch(
                raw,
                session.raw,
                conn_id,
                views.as_ptr(),
                views.len() as u32,
            )
        })
    }
}

struct SessionState {
    handler: Arc<dyn Handler>,
    token: u64,
    engine_id: u64,
    pending: Arc<Mutex<HashMap<usize, Box<PostState>>>>,
    dials: Arc<Mutex<HashMap<usize, Box<DialState>>>>,
    dial_key: usize,
    accepted: AtomicBool,
    authenticated: Arc<Mutex<HashSet<u64>>>,
    fd_attaches: Arc<Mutex<HashMap<usize, Box<FdAttachState>>>>,
    timers: Arc<Mutex<HashMap<(u64, u64), Box<TimerSlot>>>>,
}
struct HandlerState {
    handler: Arc<dyn Handler>,
    engine_id: u64,
    pending: Arc<Mutex<HashMap<usize, Box<PostState>>>>,
    dials: Arc<Mutex<HashMap<usize, Box<DialState>>>>,
    sealed: bool,
    authenticated: Arc<Mutex<HashSet<u64>>>,
    fd_attaches: Arc<Mutex<HashMap<usize, Box<FdAttachState>>>>,
    timers: Arc<Mutex<HashMap<(u64, u64), Box<TimerSlot>>>>,
}
struct DialState {
    id: DialId,
    handler: Arc<dyn Handler>,
    registry: Arc<Mutex<HashMap<usize, Box<DialState>>>>,
}

unsafe extern "C" fn create_state(
    _s: *mut ffi::duct_session_t,
    ctx: *mut std::ffi::c_void,
    out: *mut *mut std::ffi::c_void,
) -> i32 {
    if ctx.is_null() || out.is_null() {
        return ffi::duct_result_rc_invalid_arg;
    }
    let h = &*(ctx as *const HandlerState);
    let state = Box::new(SessionState {
        handler: h.handler.clone(),
        token: 0,
        engine_id: h.engine_id,
        pending: h.pending.clone(),
        dials: h.dials.clone(),
        dial_key: 0,
        accepted: AtomicBool::new(!h.sealed),
        authenticated: h.authenticated.clone(),
        fd_attaches: h.fd_attaches.clone(),
        timers: h.timers.clone(),
    });
    *out = Box::into_raw(state).cast();
    0
}
unsafe extern "C" fn destroy_state(
    _s: *mut ffi::duct_session_t,
    _ctx: *mut std::ffi::c_void,
    state: *mut std::ffi::c_void,
) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut SessionState));
    }
}
fn token(state: &SessionState) -> SessionToken {
    SessionToken {
        raw: state.token,
        engine_id: state.engine_id,
    }
}
unsafe fn close_on_panic(out: *mut ffi::duct_response_t) {
    if !out.is_null() {
        (*out).control.close_target = ffi::duct_close_target_close_target_session;
        (*out).control.close_reason = ffi::duct_close_reason_close_internal_error;
    }
}

unsafe extern "C" fn on_open(
    _s: *mut ffi::duct_session_t,
    tok: u64,
    user: *mut std::ffi::c_void,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
) -> i32 {
    let state = &mut *(state as *mut SessionState);
    state.token = tok;
    state.dial_key = user as usize;
    if state.accepted.load(Ordering::Acquire) {
        state
            .authenticated
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(tok);
    }
    let open_panicked =
        catch_unwind(AssertUnwindSafe(|| state.handler.open(token(state)))).is_err();
    if open_panicked {
        close_on_panic(out);
    }
    if !user.is_null() {
        let dial = &*(user as *const DialState);
        if !open_panicked
            && catch_unwind(AssertUnwindSafe(|| {
                dial.handler.dial_open(dial.id, token(state))
            }))
            .is_err()
        {
            close_on_panic(out);
        }
        // C keeps user_ctx on the live session. Release at terminal close.
    }
    0
}
unsafe extern "C" fn on_close(
    _s: *mut ffi::duct_session_t,
    reason: u8,
    state: *mut std::ffi::c_void,
) {
    let state = &*(state as *const SessionState);
    // Serialize revocation with Engine::post. The owner thread holds this
    // guard through C's enqueue; after removal no new stale ctx can enter the
    // registry between the sweep below and the terminal close.
    let mut authenticated = state
        .authenticated
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    authenticated.remove(&state.token);
    // C fires this only in closing/quarantine after the final leg detached
    // (session_pool.c:s_session_maybe_fire_close). Later queued invokes use
    // attached_by_handle, which rejects that state without dereferencing ctx.
    // Worker callbacks for this session are serial; reclaim stale commands.
    let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
    // A response already accepted by send_post can be parked in C's retry
    // queue. Keep its bytes alive until C's release callback, even though
    // the session has closed. Only unrun invoke contexts are safe to reclaim.
    pending.retain(|_, cmd| cmd.token != state.token || cmd.started.load(Ordering::Acquire));
    drop(pending);
    state
        .fd_attaches
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, cmd| cmd.token != state.token);
    state
        .timers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(token, _), _| *token != state.token);
    drop(authenticated);
    let _ = catch_unwind(AssertUnwindSafe(|| {
        state.handler.close(token(state), reason)
    }));
    if state.dial_key != 0 {
        state
            .dials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&state.dial_key);
    }
}
unsafe extern "C" fn on_error(
    s: *mut ffi::duct_session_t,
    code: i32,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
) -> i32 {
    if s.is_null() {
        // Pre-session error carries this dial's own context, not SessionState.
        if !state.is_null() {
            let dial = &*(state as *const DialState);
            let registry = dial.registry.clone();
            let _ = catch_unwind(AssertUnwindSafe(|| dial.handler.error(None, code)));
            let _ = catch_unwind(AssertUnwindSafe(|| dial.handler.dial_error(dial.id, code)));
            registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&(state as usize));
        }
    } else {
        let st = &*(state as *const SessionState);
        if catch_unwind(AssertUnwindSafe(|| st.handler.error(Some(token(st)), code))).is_err() {
            close_on_panic(out);
        }
    }
    0
}
unsafe extern "C" fn on_conn_join(
    _s: *mut ffi::duct_session_t,
    conn_id: u32,
    _peer: *const ffi::duct_peer_t,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
) -> i32 {
    let state = &*(state as *const SessionState);
    if catch_unwind(AssertUnwindSafe(|| {
        state.handler.conn_join(token(state), conn_id)
    }))
    .is_err()
    {
        close_on_panic(out);
    }
    0
}
unsafe extern "C" fn on_conn_lost(
    _s: *mut ffi::duct_session_t,
    conn_id: u32,
    reason: u8,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
) {
    let state = &*(state as *const SessionState);
    if catch_unwind(AssertUnwindSafe(|| {
        state.handler.conn_lost(token(state), conn_id, reason)
    }))
    .is_err()
    {
        close_on_panic(out);
    }
}
unsafe extern "C" fn on_send_done(
    _s: *mut ffi::duct_session_t,
    info: *const ffi::duct_send_done_info_t,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
) -> i32 {
    let state = &*(state as *const SessionState);
    let info = &*info;
    if catch_unwind(AssertUnwindSafe(|| {
        state
            .handler
            .send_done(token(state), info.send_token as u64, info.result)
    }))
    .is_err()
    {
        close_on_panic(out);
    }
    0
}
unsafe extern "C" fn on_timer(
    session: *mut ffi::duct_session_t,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
    tag: u64,
) -> i32 {
    if session.is_null() {
        let state = &*(state as *const HandlerState);
        let _ = catch_unwind(AssertUnwindSafe(|| state.handler.engine_timer(tag)));
        return 0;
    }
    let state = &*(state as *const SessionState);
    match catch_unwind(AssertUnwindSafe(|| state.handler.timer(token(state), tag))) {
        Ok(Some(bytes)) if !bytes.is_empty() && bytes.len() <= 16 * 1024 => {
            let owned = Box::new(bytes);
            (*out).payload.data = owned.as_ptr() as *mut _;
            (*out).payload.size = owned.len();
            (*out).flags = ffi::duct_send_flags_fl_send_owned;
            (*out).conn_id = ffi::duct_conn_id_same;
            (*out).stream_id = ffi::duct_stream_id_same;
            (*out).release = Some(release_payload);
            (*out).release_arg = Box::into_raw(owned).cast();
        }
        Ok(Some(bytes)) if bytes.len() > 16 * 1024 => close_on_panic(out),
        Err(_) => close_on_panic(out),
        _ => {}
    }
    0
}
unsafe extern "C" fn on_peer_auth(
    _s: *mut ffi::duct_session_t,
    _conn: u32,
    identity: ffi::duct_view_u8,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
) {
    let state = &*(state as *const SessionState);
    let key = if identity.size == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(identity.data.cast::<u8>(), identity.size)
    };
    match catch_unwind(AssertUnwindSafe(|| {
        state.handler.peer_key(token(state), key)
    })) {
        Ok(true) => {
            state.accepted.store(true, Ordering::Release);
            state
                .authenticated
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(state.token);
            if catch_unwind(AssertUnwindSafe(|| {
                state.handler.authenticated(token(state), key)
            }))
            .is_err()
            {
                state.accepted.store(false, Ordering::Release);
                state
                    .authenticated
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&state.token);
                close_on_panic(out);
            }
        }
        _ => close_on_panic(out),
    }
}
unsafe extern "C" fn release_payload(p: *mut std::ffi::c_void) {
    if !p.is_null() {
        drop(Box::from_raw(p as *mut Vec<u8>));
    }
}
unsafe extern "C" fn on_frame(
    session: *mut ffi::duct_session_t,
    conn: u32,
    frame: *const ffi::duct_frame_t,
    out: *mut ffi::duct_response_t,
    state: *mut std::ffi::c_void,
) -> i32 {
    let state = &*(state as *const SessionState);
    if !state.accepted.load(Ordering::Acquire) {
        return ffi::duct_result_rc_drop;
    } // rc_drop
    let f = &*frame;
    let payload = if f.payload.size == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(f.payload.data.cast::<u8>(), f.payload.size)
    };
    match catch_unwind(AssertUnwindSafe(|| {
        let counters = if session.is_null() {
            ffi::duct_conn_counters_t::default()
        } else {
            ffi::duct_conn_counters(session, conn)
        };
        state.handler.frame_with_info(
            token(state),
            FrameInfo {
                conn_id: conn,
                flags: f.flags,
                counters: ConnectionCounters {
                    rx_frames: counters.rx_frames,
                    rx_bytes: counters.rx_bytes,
                    tx_frames: counters.tx_frames,
                    tx_bytes: counters.tx_bytes,
                    tx_refused: counters.tx_refused,
                },
            },
            payload,
        )
    })) {
        Ok(FrameAction::Accept(Some(bytes))) if !bytes.is_empty() => {
            if bytes.len() > 16 * 1024 {
                close_on_panic(out);
                return 0;
            }
            let owned = Box::new(bytes);
            (*out).payload.data = owned.as_ptr() as *mut _;
            (*out).payload.size = owned.len();
            (*out).flags = ffi::duct_send_flags_fl_send_owned;
            (*out).conn_id = ffi::duct_conn_id_same; // route to source leg
            (*out).stream_id = ffi::duct_stream_id_same;
            (*out).release = Some(release_payload);
            (*out).release_arg = Box::into_raw(owned).cast();
        }
        Ok(FrameAction::Defer) => return ffi::duct_result_rc_defer,
        Ok(FrameAction::Drop) => return ffi::duct_result_rc_drop,
        Ok(_) => {}
        Err(_) => close_on_panic(out),
    }
    0
}

/// X25519 identity for a Noise wire. The private bytes are wiped on drop.
pub struct NoiseKeypair {
    private: [u8; 32],
    public: [u8; 32],
}
impl NoiseKeypair {
    pub fn generate() -> Result<Self> {
        let mut raw = ffi::duct_noise_keypair_t::default();
        if !unsafe { ffi::duct_noise_keypair_generate(&mut raw) } {
            raw.priv_.zeroize();
            return Err(Error::CreationFailed);
        }
        let keypair = Self {
            private: raw.priv_,
            public: raw.pub_,
        };
        raw.priv_.zeroize();
        Ok(keypair)
    }
    pub fn from_private(mut private: [u8; 32]) -> Result<Self> {
        let mut raw = ffi::duct_noise_keypair_t::default();
        let ok = unsafe { ffi::duct_noise_keypair_from_priv(&mut raw, private.as_ptr()) };
        private.zeroize();
        if !ok {
            raw.priv_.zeroize();
            return Err(Error::InvalidInput);
        }
        let keypair = Self {
            private: raw.priv_,
            public: raw.pub_,
        };
        raw.priv_.zeroize();
        Ok(keypair)
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
    pub fn into_wire(
        self,
        remote_public: Option<[u8; 32]>,
        psk: [u8; 32],
        initiator: bool,
        datagram: bool,
    ) -> Result<NoiseWire> {
        NoiseWire::new(self.private, remote_public, psk, initiator, datagram)
    }
}
impl Drop for NoiseKeypair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

/// An owned Noise wire recipe. Its config and key bytes remain alive until
/// after the engine and all protocols using it are destroyed.
type PeerVerifier = dyn Fn(&[u8; 32]) -> bool + Send + Sync + 'static;
type PeerPsk = dyn Fn(&[u8; 32], &[u8]) -> Option<[u8; 32]> + Send + Sync + 'static;
type Opening = dyn Fn(u32, &mut [u8]) -> usize + Send + Sync + 'static;
#[derive(Default)]
struct NoiseCallbacks {
    verify: Option<Arc<PeerVerifier>>,
    allow_list: bool,
    psk: Option<Arc<PeerPsk>>,
    opening: Option<Arc<Opening>>,
}
unsafe extern "C" fn verify_noise_peer(ctx: *mut std::ffi::c_void, key: *const u8) -> bool {
    if ctx.is_null() || key.is_null() {
        return false;
    }
    let state = &*(ctx as *const NoiseCallbacks);
    let key = &*(key as *const [u8; 32]);
    catch_unwind(AssertUnwindSafe(|| {
        state
            .verify
            .as_ref()
            .map_or(state.allow_list || state.psk.is_some(), |f| f(key))
    }))
    .unwrap_or(false)
}
unsafe extern "C" fn noise_peer_psk(
    ctx: *mut std::ffi::c_void,
    key: *const u8,
    hello: ffi::duct_view_u8,
    out_psk: *mut u8,
) -> bool {
    let state = &*(ctx as *const NoiseCallbacks);
    let key = &*(key as *const [u8; 32]);
    let bytes = if hello.size == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(hello.data.cast::<u8>(), hello.size)
    };
    let answer = catch_unwind(AssertUnwindSafe(|| {
        state.psk.as_ref().and_then(|f| f(key, bytes))
    }))
    .ok()
    .flatten();
    match answer {
        Some(mut psk) => {
            ptr::copy_nonoverlapping(psk.as_ptr(), out_psk, 32);
            psk.zeroize();
            true
        }
        None => false,
    }
}
unsafe extern "C" fn noise_opening(
    ctx: *mut std::ffi::c_void,
    index: u32,
    out: *mut u8,
    cap: usize,
) -> usize {
    let state = &*(ctx as *const NoiseCallbacks);
    let bytes = std::slice::from_raw_parts_mut(out, cap);
    catch_unwind(AssertUnwindSafe(|| {
        state.opening.as_ref().map_or(0, |f| f(index, bytes))
    }))
    .unwrap_or(0)
}
pub struct NoiseWire {
    raw: NonNull<ffi::duct_wire_t>,
    cfg: Box<ffi::duct_noise_cfg_t>,
    callbacks: Box<NoiseCallbacks>,
    allowed: Vec<[u8; 32]>,
    // The native config borrows this allocation, not the caller's slice.
    // Boxed bytes stay at one address when the recipe/protocol is moved.
    hello: Zeroizing<Box<[u8]>>,
    spec: ffi::duct_sealed_wire_cfg_t,
}
impl NoiseWire {
    pub fn new(
        mut local_private: [u8; 32],
        remote_public: Option<[u8; 32]>,
        mut psk: [u8; 32],
        initiator: bool,
        datagram: bool,
    ) -> Result<Self> {
        unsafe {
            if initiator && remote_public.is_none() {
                local_private.zeroize();
                psk.zeroize();
                return Err(Error::InvalidInput);
            }
            let mut cfg = Box::new(ffi::duct_noise_cfg_t::default());
            if !ffi::duct_noise_keypair_from_priv(&mut cfg.local_static, local_private.as_ptr()) {
                local_private.zeroize();
                psk.zeroize();
                cfg.local_static.priv_.zeroize();
                cfg.psk.zeroize();
                return Err(Error::InvalidInput);
            }
            local_private.zeroize();
            cfg.remote_static_pub = remote_public.unwrap_or([0; 32]);
            cfg.psk = psk;
            psk.zeroize();
            let mut callbacks = Box::new(NoiseCallbacks::default());
            cfg.verify_peer = Some(verify_noise_peer);
            cfg.verify_ctx = (&mut *callbacks as *mut NoiseCallbacks).cast();
            let mut spec = ffi::duct_sealed_wire_cfg_t::default();
            spec.engine = if datagram {
                ffi::duct_noise_vtbl_dgram()
            } else {
                ffi::duct_noise_vtbl()
            };
            spec.engine_cfg = (&mut *cfg as *mut ffi::duct_noise_cfg_t).cast();
            spec.role = if initiator {
                ffi::duct_seal_role_seal_role_initiator
            } else {
                ffi::duct_seal_role_seal_role_responder
            };
            spec.framing = if datagram {
                ffi::duct_seal_framing_seal_framing_datagram
            } else {
                ffi::duct_seal_framing_seal_framing_stream
            };
            let raw = match NonNull::new(ffi::duct_wire_create_sealed(&spec)) {
                Some(raw) => raw,
                None => {
                    cfg.local_static.priv_.zeroize();
                    cfg.psk.zeroize();
                    return Err(Error::CreationFailed);
                }
            };
            Ok(Self {
                raw,
                cfg,
                callbacks,
                allowed: Vec::new(),
                hello: Zeroizing::new(Box::default()),
                spec,
            })
        }
    }
    /// Explicit early Noise admission on responders, before message 2.
    /// The callback runs on a DuctIo worker, may run concurrently, and must
    /// return promptly. Panics reject the peer.
    pub fn verify_with<F>(mut self, verifier: F) -> Self
    where
        F: Fn(&[u8; 32]) -> bool + Send + Sync + 'static,
    {
        self.callbacks.verify = Some(Arc::new(verifier));
        self
    }
    /// Configure the same hello length at both endpoints. A responder can
    /// configure zeros; its PSK callback receives the initiator's actual hello.
    /// Copies the bytes; the caller may change or drop its input immediately.
    /// The existing Rust API limit remains 32 bytes; this does not opt into
    /// the native API's newly unbounded configured hello length.
    pub fn with_hello(mut self, hello: &[u8]) -> Result<Self> {
        if hello.len() > 32 {
            return Err(Error::InvalidInput);
        }
        let owned = Zeroizing::new(hello.to_vec().into_boxed_slice());
        self.cfg.hello = if owned.is_empty() { ptr::null() } else { owned.as_ptr() };
        self.cfg.hello_len = owned.len();
        // Update the config before releasing/zeroizing the old allocation.
        self.hello = owned;
        Ok(self)
    }
    fn clear_hello(&mut self) {
        self.cfg.hello = ptr::null();
        self.cfg.hello_len = 0;
        self.hello.zeroize();
    }
    /// Deployment-wide handshake mask key, required with per-peer PSKs.
    /// Both endpoints must use the same key and DUCT_HANDSHAKE_MASK setting.
    pub fn with_wire_key(mut self, mut key: [u8; 32]) -> Self {
        self.cfg.wire_key = key;
        key.zeroize();
        self
    }
    /// Immutable responder allow-list, owned for the wire's whole lifetime.
    pub fn with_allowed_peers(mut self, peers: Vec<[u8; 32]>) -> Result<Self> {
        self.cfg.n_allowed = peers.len().try_into().map_err(|_| Error::InvalidInput)?;
        self.callbacks.allow_list = !peers.is_empty();
        self.allowed = peers;
        self.cfg.allowed = self.allowed.as_ptr().cast();
        Ok(self)
    }
    /// Select a responder PSK after peer-key authentication. None or a panic
    /// refuses the handshake. This callback may run concurrently on workers.
    pub fn with_peer_psk<F>(mut self, lookup: F) -> Self
    where
        F: Fn(&[u8; 32], &[u8]) -> Option<[u8; 32]> + Send + Sync + 'static,
    {
        self.callbacks.psk = Some(Arc::new(lookup));
        self.cfg.peer_psk = Some(noise_peer_psk);
        self
    }
    fn rebuild(&mut self) -> Result<()> {
        let raw = NonNull::new(unsafe { ffi::duct_wire_create_sealed(&self.spec) })
            .ok_or(Error::CreationFailed)?;
        unsafe {
            ffi::ductio_rs_wire_destroy(self.raw.as_ptr());
        }
        self.raw = raw;
        Ok(())
    }
    /// Protocol-defined opening packets sent before the first handshake flight.
    /// Return zero to finish. A panic finishes the opening; packets above the
    /// ceiling are not sent. The callback can run concurrently on workers.
    pub fn with_opening<F>(mut self, ceiling: u16, opening: F) -> Result<Self>
    where
        F: Fn(u32, &mut [u8]) -> usize + Send + Sync + 'static,
    {
        if ceiling == 0 {
            return Err(Error::InvalidInput);
        }
        self.callbacks.opening = Some(Arc::new(opening));
        self.cfg.opening_next = Some(noise_opening);
        self.cfg.opening_ctx = (&mut *self.callbacks as *mut NoiseCallbacks).cast();
        self.spec.opening_ceiling = ceiling;
        self.rebuild()?;
        Ok(self)
    }
    /// Enable authenticated UDP session leads for address changes. A stream
    /// wire refuses this option. Both endpoints must hold the same cover key.
    pub fn with_join_lead(mut self, mut cover_key: [u8; 16]) -> Result<Self> {
        if self.spec.framing != ffi::duct_seal_framing_seal_framing_datagram {
            cover_key.zeroize();
            return Err(Error::InvalidInput);
        }
        self.spec.join_lead = true;
        if self.spec.role == ffi::duct_seal_role_seal_role_initiator {
            self.spec.tx_prefix_len = 10;
        } else {
            self.spec.rx_prefix_len = 10;
        }
        self.spec.cover_key = cover_key;
        cover_key.zeroize();
        self.rebuild()?;
        Ok(self)
    }
}
impl Drop for NoiseWire {
    fn drop(&mut self) {
        unsafe {
            ffi::ductio_rs_wire_destroy(self.raw.as_ptr());
        }
        self.cfg.local_static.priv_.zeroize();
        self.cfg.psk.zeroize();
        self.cfg.wire_key.zeroize();
        self.clear_hello();
        self.spec.cover_key.zeroize();
    }
}

/// TLS 1.3 server wire backed by an owned, configured OpenSSL context.
#[cfg(feature = "tls-openssl")]
pub struct TlsWire {
    raw: NonNull<ffi::duct_wire_t>,
    _context: openssl::ssl::SslContext,
}
#[cfg(feature = "tls-openssl")]
impl TlsWire {
    pub fn server(context: openssl::ssl::SslContext) -> Result<Self> {
        use foreign_types::ForeignType;
        let mut spec = ffi::duct_sealed_wire_cfg_t::default();
        spec.engine = unsafe { ffi::duct_tls_openssl_vtbl() };
        spec.engine_cfg = context.as_ptr().cast();
        spec.role = ffi::duct_seal_role_seal_role_responder;
        spec.framing = ffi::duct_seal_framing_seal_framing_stream;
        let raw = NonNull::new(unsafe { ffi::duct_wire_create_sealed(&spec) })
            .ok_or(Error::CreationFailed)?;
        Ok(Self {
            raw,
            _context: context,
        })
    }
}
#[cfg(feature = "tls-openssl")]
impl Drop for TlsWire {
    fn drop(&mut self) {
        unsafe {
            ffi::ductio_rs_wire_destroy(self.raw.as_ptr());
        }
    }
}

enum Wire {
    Noise(NoiseWire),
    Plain(NonNull<ffi::duct_wire_t>),
    #[cfg(feature = "tls-openssl")]
    Tls(TlsWire),
}
impl Wire {
    fn ptr(&self) -> *mut ffi::duct_wire_t {
        match self {
            Self::Noise(n) => n.raw.as_ptr(),
            Self::Plain(p) => p.as_ptr(),
            #[cfg(feature = "tls-openssl")]
            Self::Tls(t) => t.raw.as_ptr(),
        }
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        if let Self::Plain(p) = self {
            unsafe {
                ffi::ductio_rs_wire_destroy(p.as_ptr());
            }
        }
    }
}

pub struct Protocol {
    raw: NonNull<ffi::duct_proto_t>,
    _name: CString,
    state: Box<HandlerState>,
    _wire: Wire,
}
impl Protocol {
    pub fn plain(name: &str, handler: Arc<dyn Handler>) -> Result<Self> {
        let ptr = unsafe { ffi::duct_wire_create_length_prefix(16 * 1024) };
        let wire = Wire::Plain(NonNull::new(ptr).ok_or(Error::CreationFailed)?);
        Self::build(name, handler, wire)
    }
    /// A packet-preserving datagram protocol. Each callback receives exactly
    /// one UDP payload; no application framing byte is added.
    pub fn datagram(name: &str, handler: Arc<dyn Handler>) -> Result<Self> {
        let ptr = unsafe { ffi::duct_wire_create_dgram_batch(16 * 1024, false) };
        let wire = Wire::Plain(NonNull::new(ptr).ok_or(Error::CreationFailed)?);
        Self::build(name, handler, wire)
    }
    pub fn custom(
        name: &str,
        handler: Arc<dyn Handler>,
        codec: Arc<dyn CustomWire>,
    ) -> Result<Self> {
        let raw = custom_wire::build(name, codec)?;
        Self::build(name, handler, Wire::Plain(raw))
    }
    #[cfg(feature = "tls-openssl")]
    pub fn tls_server(name: &str, handler: Arc<dyn Handler>, wire: TlsWire) -> Result<Self> {
        Self::build(name, handler, Wire::Tls(wire))
    }
    pub fn sealed(name: &str, handler: Arc<dyn Handler>, noise: NoiseWire) -> Result<Self> {
        Self::build(name, handler, Wire::Noise(noise))
    }
    /// Set inbound silence and sealed-leg handshake bounds before registration.
    /// Zero idle disables that bound; zero handshake keeps the native 10 s default.
    pub fn with_timeouts(mut self, idle: Duration, handshake: Duration) -> Result<Self> {
        let idle_ms: u32 = idle
            .as_millis()
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        let handshake_ms: u32 = handshake
            .as_millis()
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        if (!idle.is_zero() && idle_ms == 0) || (!handshake.is_zero() && handshake_ms == 0) {
            return Err(Error::InvalidInput);
        }
        unsafe {
            self.raw.as_mut().cfg.idle_timeout_ms = idle_ms;
            self.raw.as_mut().cfg.join_auth_timeout_ms = handshake_ms;
        }
        Ok(self)
    }
    fn build(name: &str, handler: Arc<dyn Handler>, wire: Wire) -> Result<Self> {
        let name = CString::new(name).map_err(|_| Error::InvalidInput)?;
        let mut state = Box::new(HandlerState {
            handler,
            engine_id: 0,
            pending: Arc::new(Mutex::new(HashMap::new())),
            dials: Arc::new(Mutex::new(HashMap::new())),
            sealed: matches!(wire, Wire::Noise(_)),
            authenticated: Arc::new(Mutex::new(HashSet::new())),
            fd_attaches: Arc::new(Mutex::new(HashMap::new())),
            timers: Arc::new(Mutex::new(HashMap::new())),
        });
        let mut cfg = ffi::duct_proto_cfg_t::default();
        cfg.name = name.as_ptr();
        cfg.wire = wire.ptr();
        cfg.on_frame = Some(on_frame);
        cfg.create_state_ctx = (&mut *state as *mut HandlerState).cast();
        cfg.user_ctx = ptr::null_mut(); // inbound open has no per-dial context
        cfg.create_state = Some(create_state);
        cfg.destroy_state = Some(destroy_state);
        cfg.on_session_open = Some(on_open);
        cfg.on_session_close = Some(on_close);
        cfg.on_error = Some(on_error);
        if state.sealed {
            cfg.on_peer_auth = Some(on_peer_auth);
        }
        cfg.on_conn_join = Some(on_conn_join);
        cfg.on_conn_lost = Some(on_conn_lost);
        cfg.on_send_done = Some(on_send_done);
        cfg.on_timer = Some(on_timer);
        cfg.max_response = 16 * 1024;
        let raw =
            NonNull::new(unsafe { ffi::duct_proto_create(&cfg) }).ok_or(Error::CreationFailed)?;
        Ok(Self {
            raw,
            _name: name,
            state,
            _wire: wire,
        })
    }
}
impl Drop for Protocol {
    fn drop(&mut self) {
        unsafe {
            ffi::duct_proto_destroy(self.raw.as_ptr());
        }
        // field order then drops state, name and wire, all after proto destruction.
    }
}

struct PostState {
    payload: Vec<u8>,
    token: u64,
    conn_id: u32,
    send_token: Option<u64>,
    started: AtomicBool,
    registry: Arc<Mutex<HashMap<usize, Box<PostState>>>>,
}

struct FdAttachState {
    fd: Option<OwnedFd>,
    token: u64,
    conn_id: u32,
    packet: bool,
    result: mpsc::Sender<Result<()>>,
    registry: Arc<Mutex<HashMap<usize, Box<FdAttachState>>>>,
}

struct TimerSlot {
    token: u64,
    tag: u64,
    delay_ms: u64,
    interval_ms: u64,
    id: u64,
    scheduled: AtomicBool,
    cancelling: AtomicBool,
    registry: Arc<Mutex<HashMap<(u64, u64), Box<TimerSlot>>>>,
}
unsafe extern "C" fn start_timer_post(
    _session: *mut ffi::duct_session_t,
    out: *mut ffi::duct_response_t,
    ctx: *mut std::ffi::c_void,
) -> i32 {
    let slot = &mut *(ctx as *mut TimerSlot);
    (*out).control.timer.delay_ms = slot.delay_ms;
    (*out).control.timer.interval_ms = slot.interval_ms;
    (*out).control.timer.arg = slot.tag as usize;
    (*out).control.timer.id_out = &mut slot.id;
    slot.scheduled.store(true, Ordering::Release);
    0
}
unsafe extern "C" fn cancel_timer_post(
    _session: *mut ffi::duct_session_t,
    out: *mut ffi::duct_response_t,
    ctx: *mut std::ffi::c_void,
) -> i32 {
    let slot = &*(ctx as *const TimerSlot);
    (*out).control.timer.cancel_id = slot.id;
    let registry = slot.registry.clone();
    registry
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(slot.token, slot.tag));
    0
}

/// Result of handing a descriptor to the native worker. Once the worker runs
/// the attach command, C owns the descriptor even when it rejects the leg.
pub struct FdAttachRequest(mpsc::Receiver<Result<()>>);
impl FdAttachRequest {
    pub fn wait(self, timeout: Duration) -> Result<()> {
        match self.0.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(Error::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(Error::Cancelled),
        }
    }
}

unsafe extern "C" fn attach_fd_post(
    session: *mut ffi::duct_session_t,
    _out: *mut ffi::duct_response_t,
    ctx: *mut std::ffi::c_void,
) -> i32 {
    let state = &mut *(ctx as *mut FdAttachState);
    let fd = state
        .fd
        .take()
        .expect("fd command invoked once")
        .into_raw_fd();
    let rc = if state.packet {
        ffi::duct_conn_attach_packet_fd(session, state.conn_id, fd, ptr::null())
    } else {
        ffi::duct_conn_attach_fd(session, state.conn_id, fd)
    };
    let _ = state.result.send(checked(rc));
    let registry = state.registry.clone();
    registry
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(ctx as usize));
    0 // An attach failure is reported on FdAttachRequest, not to C's invoke.
}
unsafe extern "C" fn release_post(p: *mut std::ffi::c_void) {
    let key = p as usize;
    // Copy the Arc before removing the Box that holds it.
    let reg = (*(p as *mut PostState)).registry.clone();
    reg.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
}
unsafe extern "C" fn send_post(
    _s: *mut ffi::duct_session_t,
    out: *mut ffi::duct_response_t,
    ctx: *mut std::ffi::c_void,
) -> i32 {
    let cmd = &*(ctx as *const PostState);
    cmd.started.store(true, Ordering::Release);
    (*out).payload.data = cmd.payload.as_ptr() as *mut _;
    (*out).payload.size = cmd.payload.len();
    (*out).flags = ffi::duct_send_flags_fl_send_owned;
    if let Some(send_token) = cmd.send_token {
        (*out).flags |= ffi::duct_send_flags_fl_send_done;
        (*out).send_token = send_token as usize;
    }
    (*out).conn_id = cmd.conn_id;
    (*out).stream_id = ffi::duct_stream_id_same;
    (*out).release = Some(release_post);
    (*out).release_arg = ctx;
    0
}
unsafe extern "C" fn attach_inter_post(
    _s: *mut ffi::duct_session_t,
    out: *mut ffi::duct_response_t,
    ctx: *mut std::ffi::c_void,
) -> i32 {
    (*out).control.open_leg.kind = ffi::duct_leg_kind_leg_kind_inter;
    (*out).control.open_leg.conn_id = (ctx as usize - 1) as u32;
    0
}

unsafe extern "C" fn wake_post(
    _session: *mut ffi::duct_session_t,
    _out: *mut ffi::duct_response_t,
    _ctx: *mut std::ffi::c_void,
) -> i32 {
    0
}

#[derive(Clone, Copy)]
pub struct ProtocolId {
    index: usize,
    engine_id: u64,
}

/// A bound TCP or UDP listener. Use [`Engine::close_listener`] to revoke it.
/// Dropping this value leaves the listener active until the engine stops.
#[derive(Debug)]
pub struct Listener {
    port: u16,
    fds: Vec<ffi::duct_sock_t>,
    engine_id: u64,
}
impl Listener {
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Process-wide conn pool readings, not reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionPoolStats {
    pub free: u32,
    pub refused: u64,
}

/// A snapshot of native runtime counters. `Engine::stats` returns `None` when
/// the C library was compiled without statistics support.
pub type RuntimeStats = ffi::duct_rt_stats_t;

/// Host-owned post contexts, separate from application send-token tracking.
/// Started contexts may still be held by native TX staging/retry/codec release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingPostStats {
    pub limit: usize,
    pub total: usize,
    pub started: usize,
    pub not_started: usize,
}

fn pending_post_stats(pending: &Mutex<HashMap<usize, Box<PostState>>>) -> Option<PendingPostStats> {
    // Diagnostics must not block the engine owner on a worker's registry lock.
    let pending = pending.try_lock().ok()?;
    let total = pending.len();
    let started = pending
        .values()
        .filter(|post| post.started.load(Ordering::Acquire))
        .count();
    Some(PendingPostStats {
        limit: MAX_PENDING_COMMANDS,
        total,
        started,
        not_started: total - started,
    })
}

/// Owner-thread facade. It is intentionally !Send and !Sync; worker callbacks
/// cannot call it. `Drop` stops/joins the engine before releasing any borrowed
/// protocol, Noise config, callback state, or pending post context.
pub struct Engine {
    raw: Option<NonNull<ffi::duct_engine_t>>,
    id: u64,
    protocols: Vec<Protocol>,
    pending: Arc<Mutex<HashMap<usize, Box<PostState>>>>,
    dials: Arc<Mutex<HashMap<usize, Box<DialState>>>>,
    authenticated: Arc<Mutex<HashSet<u64>>>,
    fd_attaches: Arc<Mutex<HashMap<usize, Box<FdAttachState>>>>,
    io_threads: u32,
    timers: Arc<Mutex<HashMap<(u64, u64), Box<TimerSlot>>>>,
    host: Option<HostRunner>,
    inter_ingress: Arc<InterIngressState>,
    _not_send_sync: PhantomData<Rc<()>>,
}
impl Engine {
    fn native(&self) -> Result<*mut ffi::duct_engine_t> {
        self.raw.map(NonNull::as_ptr).ok_or(Error::Stopped)
    }
    pub fn start(io_threads: u32, workers: u32) -> Result<Self> {
        Self::start_inner(io_threads, workers, None)
    }
    pub fn start_with_inter_host(
        io_threads: u32,
        workers: u32,
        handler: Arc<dyn InterHost>,
    ) -> Result<Self> {
        Self::start_inner(io_threads, workers, Some(handler))
    }
    fn start_inner(
        io_threads: u32,
        workers: u32,
        handler: Option<Arc<dyn InterHost>>,
    ) -> Result<Self> {
        if ENGINE_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::AlreadyRunning);
        }
        let mut cfg = ffi::duct_engine_cfg_t::default();
        cfg.io_threads = io_threads;
        cfg.workers = workers;
        let id = NEXT_ENGINE_ID.fetch_add(1, Ordering::Relaxed);
        let mut host = match handler {
            Some(handler) => match HostRunner::new(handler, id) {
                Ok(host) => Some(host),
                Err(err) => {
                    ENGINE_ACTIVE.store(false, Ordering::Release);
                    return Err(err);
                }
            },
            None => None,
        };
        if let Some(runner) = host.as_mut() {
            cfg.host = runner.config();
        }
        let raw = NonNull::new(unsafe { ffi::duct_engine_launch(&cfg) });
        match raw {
            Some(raw) => Ok(Self {
                raw: Some(raw),
                id,
                protocols: Vec::new(),
                pending: Arc::new(Mutex::new(HashMap::new())),
                dials: Arc::new(Mutex::new(HashMap::new())),
                authenticated: Arc::new(Mutex::new(HashSet::new())),
                fd_attaches: Arc::new(Mutex::new(HashMap::new())),
                io_threads,
                timers: Arc::new(Mutex::new(HashMap::new())),
                host,
                inter_ingress: Arc::new(InterIngressState {
                    raw: Mutex::new(Some(raw.as_ptr() as usize)),
                    engine_id: id,
                }),
                _not_send_sync: PhantomData,
            }),
            None => {
                drop(host);
                ENGINE_ACTIVE.store(false, Ordering::Release);
                Err(Error::CreationFailed)
            }
        }
    }
    pub fn inter_ingress(&self) -> Result<InterIngress> {
        if self.host.is_none() {
            return Err(Error::InvalidInput);
        }
        self.native()?;
        Ok(InterIngress(self.inter_ingress.clone()))
    }
    /// Declares an inter leg on an existing session. `Handler::conn_join`
    /// reports when the asynchronous attach has completed.
    pub fn attach_inter(&self, session: SessionToken, conn_id: u32) -> Result<()> {
        let native = self.native()?;
        if self.host.is_none()
            || session.engine_id != self.id
            || conn_id == 0
            || conn_id == u32::MAX
        {
            return Err(Error::InvalidInput);
        }
        checked(unsafe {
            ffi::duct_session_invoke(
                native,
                session.raw,
                Some(attach_inter_post),
                (conn_id as usize + 1) as *mut _,
            )
        })
    }
    pub fn attach_stream_fd(
        &self,
        session: SessionToken,
        conn_id: u32,
        fd: OwnedFd,
    ) -> Result<FdAttachRequest> {
        self.attach_fd(session, conn_id, fd, false)
    }
    pub fn attach_packet_fd(
        &self,
        session: SessionToken,
        conn_id: u32,
        fd: OwnedFd,
    ) -> Result<FdAttachRequest> {
        self.attach_fd(session, conn_id, fd, true)
    }
    fn attach_fd(
        &self,
        session: SessionToken,
        conn_id: u32,
        fd: OwnedFd,
        packet: bool,
    ) -> Result<FdAttachRequest> {
        let native = self.native()?;
        if session.engine_id != self.id || conn_id == 0 {
            return Err(Error::InvalidInput);
        }
        let (tx, rx) = mpsc::channel();
        let state = Box::new(FdAttachState {
            fd: Some(fd),
            token: session.raw,
            conn_id,
            packet,
            result: tx,
            registry: self.fd_attaches.clone(),
        });
        let key = (&*state as *const FdAttachState) as usize;
        {
            let mut registry = self.fd_attaches.lock().unwrap_or_else(|e| e.into_inner());
            if registry.len() >= MAX_PENDING_COMMANDS {
                return Err(Error::Backpressure);
            }
            registry.insert(key, state);
        }
        let rc = unsafe {
            ffi::duct_session_invoke(native, session.raw, Some(attach_fd_post), key as *mut _)
        };
        if rc != 0 {
            self.fd_attaches
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            checked(rc)?;
        }
        Ok(FdAttachRequest(rx))
    }
    /// Arm a timer identified by `tag` within this session. A zero interval
    /// makes it one-shot. Its callback runs on the session worker.
    pub fn schedule_timer(
        &self,
        session: SessionToken,
        tag: u64,
        delay: Duration,
        interval: Duration,
    ) -> Result<()> {
        let native = self.native()?;
        if session.engine_id != self.id || delay.is_zero() {
            return Err(Error::InvalidInput);
        }
        let delay_ms = u64::try_from(delay.as_millis()).map_err(|_| Error::InvalidInput)?;
        let interval_ms = u64::try_from(interval.as_millis()).map_err(|_| Error::InvalidInput)?;
        if delay_ms == 0 || (!interval.is_zero() && interval_ms == 0) {
            return Err(Error::InvalidInput);
        }
        let key = (session.raw, tag);
        let mut slots = self.timers.lock().unwrap_or_else(|e| e.into_inner());
        if slots.contains_key(&key) {
            return Err(Error::InvalidInput);
        }
        if slots.len() >= MAX_PENDING_COMMANDS {
            return Err(Error::Backpressure);
        }
        let mut slot = Box::new(TimerSlot {
            token: session.raw,
            tag,
            delay_ms,
            interval_ms,
            id: 0,
            scheduled: AtomicBool::new(false),
            cancelling: AtomicBool::new(false),
            registry: self.timers.clone(),
        });
        let ctx = (&mut *slot as *mut TimerSlot).cast();
        slots.insert(key, slot);
        let rc =
            unsafe { ffi::duct_session_invoke(native, session.raw, Some(start_timer_post), ctx) };
        if rc != 0 {
            slots.remove(&key);
        }
        checked(rc)
    }
    /// One-shot worker timer independent of any session. Zero delay schedules
    /// the next worker turn. Pending callbacks are discarded on engine stop.
    pub fn schedule_engine_timer(&self, id: ProtocolId, delay: Duration, tag: u64) -> Result<()> {
        self.proto(id)?;
        let millis: u64 = delay
            .as_millis()
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        if !delay.is_zero() && millis == 0 {
            return Err(Error::InvalidInput);
        }
        let proto = &self.protocols[id.index];
        checked(unsafe {
            ffi::duct_timer_start(
                self.native()?,
                proto.raw.as_ptr(),
                (&*proto.state as *const HandlerState).cast_mut().cast(),
                millis,
                tag as usize,
            )
        })
    }
    /// Cancel an armed timer. If the worker has not processed the start
    /// command yet, retry after it has had a chance to run.
    pub fn cancel_timer(&self, session: SessionToken, tag: u64) -> Result<()> {
        let native = self.native()?;
        if session.engine_id != self.id {
            return Err(Error::InvalidInput);
        }
        let slots = self.timers.lock().unwrap_or_else(|e| e.into_inner());
        let slot = slots.get(&(session.raw, tag)).ok_or(Error::InvalidInput)?;
        if !slot.scheduled.load(Ordering::Acquire) {
            return Err(Error::Backpressure);
        }
        if slot.cancelling.swap(true, Ordering::AcqRel) {
            return Err(Error::InvalidInput);
        }
        let ctx = (&**slot as *const TimerSlot).cast_mut().cast();
        let rc =
            unsafe { ffi::duct_session_invoke(native, session.raw, Some(cancel_timer_post), ctx) };
        if rc != 0 {
            slot.cancelling.store(false, Ordering::Release);
        }
        checked(rc)
    }
    pub fn add_protocol(&mut self, mut protocol: Protocol) -> ProtocolId {
        protocol.state.engine_id = self.id;
        protocol.state.pending = self.pending.clone();
        protocol.state.dials = self.dials.clone();
        protocol.state.authenticated = self.authenticated.clone();
        protocol.state.fd_attaches = self.fd_attaches.clone();
        protocol.state.timers = self.timers.clone();
        let id = ProtocolId {
            index: self.protocols.len(),
            engine_id: self.id,
        };
        self.protocols.push(protocol);
        id
    }
    fn proto(&self, id: ProtocolId) -> Result<*mut ffi::duct_proto_t> {
        if id.engine_id != self.id {
            return Err(Error::InvalidInput);
        }
        self.protocols
            .get(id.index)
            .map(|p| p.raw.as_ptr())
            .ok_or(Error::InvalidInput)
    }
    pub fn listen_tcp(&self, id: ProtocolId, addr: SocketAddr) -> Result<u16> {
        let host = CString::new(addr.ip().to_string()).unwrap();
        let mut port = addr.port();
        checked(unsafe {
            ffi::duct_io_listen(self.native()?, host.as_ptr(), &mut port, self.proto(id)?)
        })?;
        Ok(port)
    }
    /// Binds a revocable TCP listener.
    pub fn bind_tcp(&self, id: ProtocolId, addr: SocketAddr) -> Result<Listener> {
        self.bind(id, addr, ffi::duct_listener_kind_listener_stream)
    }
    /// Binds a revocable UDP listener. The protocol must use a datagram wire.
    pub fn bind_udp(&self, id: ProtocolId, addr: SocketAddr) -> Result<Listener> {
        self.bind(id, addr, ffi::duct_listener_kind_listener_dgram)
    }
    fn bind(
        &self,
        id: ProtocolId,
        addr: SocketAddr,
        kind: ffi::duct_listener_kind_t,
    ) -> Result<Listener> {
        let native = self.native()?;
        let host = CString::new(addr.ip().to_string()).map_err(|_| Error::InvalidInput)?;
        let proto = self.proto(id)? as *const ffi::duct_proto_t;
        let protos = [proto];
        let mut cfg = ffi::duct_listener_cfg_t::default();
        cfg.addr = host.as_ptr();
        cfg.n_protos = 1;
        cfg.protos = protos.as_ptr();
        cfg.kind = kind;
        let mut port = addr.port();
        let mut fds = vec![0 as ffi::duct_sock_t; self.io_threads as usize];
        let mut count = 0u32;
        checked(unsafe {
            ffi::duct_listener_bind(
                native,
                &cfg,
                &mut port,
                fds.as_mut_ptr(),
                fds.len() as u32,
                &mut count,
            )
        })?;
        // DuctIo opens at most one socket per I/O thread. Never expose a
        // partially reported set: it could not be completely revoked.
        if count as usize > fds.len() {
            return Err(Error::CreationFailed);
        }
        fds.truncate(count as usize);
        Ok(Listener {
            port,
            fds,
            engine_id: self.id,
        })
    }
    /// Revokes every socket in this listener. A native timeout means closure
    /// was requested but has not been confirmed. That socket is removed from
    /// the handle to avoid accidentally closing a reused file descriptor.
    pub fn close_listener(&self, listener: &mut Listener) -> Result<()> {
        if listener.engine_id != self.id {
            return Err(Error::InvalidInput);
        }
        while let Some(&fd) = listener.fds.last() {
            let rc = unsafe { ffi::duct_listener_close(self.native()?, fd) };
            if rc != 0 && rc != ffi::duct_result_rc_timeout {
                return Err(Error::Native(rc));
            }
            listener.fds.pop();
            checked(rc)?;
        }
        Ok(())
    }
    /// Nonblocking, read-only snapshot of the real post-context admission table.
    /// `None` means its lock was busy or poisoned; it does not mean zero pending.
    /// The started partition is a per-entry observation, not a global native
    /// queue snapshot, socket write completion or a remote acknowledgement.
    pub fn pending_post_stats(&self) -> Option<PendingPostStats> {
        pending_post_stats(&self.pending)
    }

    /// Request shutdown; stop() still owns the join and Rust resource cleanup.
    pub fn request_stop(&self) -> Result<()> {
        checked(unsafe { ffi::duct_engine_request_stop(self.native()?) })
    }
    /// Opt in to native process stop-signal handlers, restored during teardown.
    pub fn stop_on_signals(&self) -> Result<()> {
        checked(unsafe { ffi::duct_engine_stop_on_signals(self.native()?) })
    }
    pub fn wait_for_stop(&mut self) -> Result<()> {
        checked(unsafe { ffi::duct_engine_wait_request(self.native()?) })?;
        self.stop()
    }
    pub fn connection_pool(&self) -> Result<ConnectionPoolStats> {
        self.native()?;
        Ok(ConnectionPoolStats {
            free: unsafe { ffi::duct_conns_free() },
            refused: unsafe { ffi::duct_conns_refused() },
        })
    }
    pub fn stats(&self) -> Option<RuntimeStats> {
        let mut stats = RuntimeStats::default();
        unsafe { ffi::duct_engine_stats(self.native().ok()?, &mut stats) }.then_some(stats)
    }
    /// Starts a dial. Its session token arrives later in `Handler::open`;
    /// DNS/connect failure arrives in `Handler::error(None, code)`.
    pub fn dial_tcp(&self, id: ProtocolId, addr: SocketAddr) -> Result<DialId> {
        self.dial(id, addr, ffi::duct_xport_x_tcp, 0)
    }
    /// Dial through an interface index; zero leaves the choice to routing.
    pub fn dial_tcp_via(&self, id: ProtocolId, addr: SocketAddr, egress_if: u32) -> Result<DialId> {
        self.dial(id, addr, ffi::duct_xport_x_tcp, egress_if)
    }
    pub fn dial_udp_via(&self, id: ProtocolId, addr: SocketAddr, egress_if: u32) -> Result<DialId> {
        self.dial(id, addr, ffi::duct_xport_x_udp_peer, egress_if)
    }
    /// Starts a connected-UDP dial. Open and error events follow the same
    /// callback rules as [`Engine::dial_tcp`].
    pub fn dial_udp(&self, id: ProtocolId, addr: SocketAddr) -> Result<DialId> {
        self.dial(id, addr, ffi::duct_xport_x_udp_peer, 0)
    }
    fn dial(
        &self,
        id: ProtocolId,
        addr: SocketAddr,
        xport: ffi::duct_xport_t,
        egress_if: u32,
    ) -> Result<DialId> {
        let native = self.native()?;
        let target = CString::new(addr.to_string()).unwrap();
        if id.engine_id != self.id {
            return Err(Error::InvalidInput);
        }
        let proto = self.protocols.get(id.index).ok_or(Error::InvalidInput)?;
        let dial_id = DialId(NEXT_DIAL_ID.fetch_add(1, Ordering::Relaxed));
        let ctx = Box::new(DialState {
            id: dial_id,
            handler: proto.state.handler.clone(),
            registry: self.dials.clone(),
        });
        let key = (&*ctx as *const DialState) as usize;
        {
            let mut dials = self.dials.lock().unwrap_or_else(|e| e.into_inner());
            if dials.len() >= MAX_PENDING_COMMANDS {
                return Err(Error::Backpressure);
            }
            dials.insert(key, ctx);
        }
        let rc = unsafe {
            ffi::duct_io_connect_via(
                native,
                target.as_ptr(),
                proto.raw.as_ptr(),
                key as *mut _,
                xport,
                egress_if,
                ffi::duct_view_u8 {
                    data: ptr::null_mut(),
                    size: 0,
                },
            )
        };
        if rc != 0 {
            self.dials
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }
        checked(rc)?;
        Ok(dial_id)
    }
    pub fn close(&self, session: SessionToken) -> Result<()> {
        if session.engine_id != self.id {
            return Err(Error::InvalidInput);
        }
        checked(unsafe { ffi::duct_session_close(self.native()?, session.raw, 0) })
    }
    /// Schedule a worker turn so a stream frame held by `FrameAction::Defer`
    /// can be replayed after the application drains its queue.
    pub fn wake(&self, session: SessionToken) -> Result<()> {
        if session.engine_id != self.id {
            return Err(Error::InvalidInput);
        }
        checked(unsafe {
            ffi::duct_session_invoke(
                self.native()?,
                session.raw,
                Some(wake_post),
                ptr::null_mut(),
            )
        })
    }
    /// Queues an owned payload on a live session. A successful return means
    /// only that the worker command was posted, never that a peer received it.
    /// Unrun commands are reclaimed after `stop` joins the workers.
    pub fn post(&self, session: SessionToken, payload: Vec<u8>) -> Result<()> {
        self.post_to(session, ffi::duct_conn_id_same, payload, None)
    }
    /// Queue payload on a specific leg, optionally asking for the native
    /// pack/enqueue result through `Handler::send_done`.
    pub fn post_to(
        &self,
        session: SessionToken,
        conn_id: u32,
        payload: Vec<u8>,
        send_token: Option<u64>,
    ) -> Result<()> {
        let native = self.native()?;
        if session.engine_id != self.id || payload.is_empty() || payload.len() > 16 * 1024 {
            return Err(Error::InvalidInput);
        }
        let authenticated = self.authenticated.lock().unwrap_or_else(|e| e.into_inner());
        if !authenticated.contains(&session.raw) {
            return Err(Error::InvalidInput);
        }
        let boxed = Box::new(PostState {
            payload,
            token: session.raw,
            conn_id,
            send_token,
            started: AtomicBool::new(false),
            registry: self.pending.clone(),
        });
        let key = (&*boxed as *const PostState) as usize;
        {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if pending.len() >= MAX_PENDING_COMMANDS {
                return Err(Error::Backpressure);
            }
            pending.insert(key, boxed);
        }
        let rc = unsafe {
            ffi::duct_session_invoke(native, session.raw, Some(send_post), key as *mut _)
        };
        if rc != 0 {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }
        drop(authenticated);
        checked(rc)
    }
    pub fn stop(&mut self) -> Result<()> {
        if let Some(raw) = self.raw.take() {
            self.inter_ingress
                .raw
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            let rc = unsafe { ffi::duct_engine_stop(raw.as_ptr()) };
            unsafe {
                ffi::duct_engine_destroy(raw.as_ptr());
            }
            if let Some(mut host) = self.host.take() {
                host.shutdown();
            }
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.dials.lock().unwrap_or_else(|e| e.into_inner()).clear();
            self.fd_attaches
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.timers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.authenticated
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.protocols.clear();
            ENGINE_ACTIVE.store(false, Ordering::Release);
            checked(rc)
        } else {
            Ok(())
        }
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn noise_hello_owns_input_through_replacement_and_protocol_moves() {
        use super::*;
        let mut input = vec![0x5a; 32];
        let mut wire = NoiseWire::new([11; 32], None, [17; 32], false, false)
            .unwrap().with_hello(&input).unwrap();
        assert_ne!(wire.cfg.hello, input.as_ptr());
        input.fill(0xa5);
        drop(input);
        assert_eq!(unsafe { std::slice::from_raw_parts(wire.cfg.hello, wire.cfg.hello_len) }, &[0x5a; 32]);
        for bytes in [&b"x"[..], &[0x6b; 32][..], &b"short"[..], &[][..]] {
            wire = wire.with_hello(bytes).unwrap();
            assert_eq!(wire.cfg.hello_len, bytes.len());
            if bytes.is_empty() {
                assert!(wire.cfg.hello.is_null());
            } else {
                assert_eq!(wire.cfg.hello, wire.hello.as_ptr());
                assert_eq!(unsafe { std::slice::from_raw_parts(wire.cfg.hello, bytes.len()) }, bytes);
            }
        }
        let wire = wire.with_hello(b"stable allocation").unwrap();
        let ptr = wire.cfg.hello;
        let protocol = Protocol::sealed("owned-hello", Arc::new(Reject(AtomicUsize::new(0))), wire).unwrap();
        // Moving the recipe and reallocating its containing collection must not
        // move storage borrowed by C. Only inspect allocations still owned here.
        let mut protocols = vec![protocol];
        protocols.reserve(128);
        let Wire::Noise(wire) = &protocols[0]._wire else { panic!("Noise wire lost") };
        assert_eq!(wire.cfg.hello, ptr);
        assert_eq!(unsafe { std::slice::from_raw_parts(ptr, wire.cfg.hello_len) }, b"stable allocation");
    }

    #[test]
    fn noise_hello_cleanup_erases_live_storage_and_detaches_native_pointer() {
        let mut wire = super::NoiseWire::new([11; 32], None, [17; 32], false, false)
            .unwrap().with_hello(&[0x5a; 32]).unwrap();
        // The same cleanup is used by Drop AFTER native wire destruction.
        // Inspect live owned bytes, never read a freed allocation.
        wire.clear_hello();
        assert!(wire.cfg.hello.is_null());
        assert_eq!(wire.cfg.hello_len, 0);
        assert_eq!(&**wire.hello, &[0; 32]);
    }

    #[test]
    fn noise_hello_preserves_existing_rust_length_contract() {
        let wire = super::NoiseWire::new([11; 32], None, [17; 32], false, false).unwrap();
        assert!(wire.cfg.hello.is_null());
        assert_eq!(wire.cfg.hello_len, 0);
        assert!(matches!(wire.with_hello(&[0; 33]), Err(super::Error::InvalidInput)));
    }

    #[test]
    fn clearing_noise_allow_list_restores_default_denial() {
        let peer = [13; 32];
        let wire = super::NoiseWire::new([11; 32], None, [17; 32], false, false)
            .unwrap()
            .with_allowed_peers(vec![peer])
            .unwrap()
            .with_allowed_peers(Vec::new())
            .unwrap();
        let verify = wire.cfg.verify_peer.unwrap();
        assert!(!unsafe { verify(wire.cfg.verify_ctx, peer.as_ptr()) });
        let wire = wire.verify_with(|_| true);
        assert!(unsafe { verify(wire.cfg.verify_ctx, peer.as_ptr()) });
    }

    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct Reject(AtomicUsize);
    impl Handler for Reject {
        fn frame(&self, _: SessionToken, _: &[u8]) -> Option<Vec<u8>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    struct DeferOnce(AtomicUsize);
    impl Handler for DeferOnce {
        fn frame_action(&self, _: SessionToken, _: &[u8]) -> FrameAction {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                FrameAction::Defer
            } else {
                FrameAction::Accept(None)
            }
        }
    }

    #[test]
    fn pending_post_diagnostic_distinguishes_started_contexts_and_never_mutates_or_blocks() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        assert_eq!(
            pending_post_stats(&pending).unwrap(),
            PendingPostStats {
                limit: 1024,
                total: 0,
                started: 0,
                not_started: 0
            }
        );
        {
            let mut registry = pending.lock().unwrap();
            for key in 0..MAX_PENDING_COMMANDS {
                registry.insert(
                    key,
                    Box::new(PostState {
                        payload: vec![1],
                        token: 77,
                        conn_id: ffi::duct_conn_id_same,
                        send_token: None,
                        started: AtomicBool::new(key % 2 == 0),
                        registry: pending.clone(),
                    }),
                );
            }
            assert!(pending_post_stats(&pending).is_none()); // try_lock, not a wait
        }
        let snapshot = pending_post_stats(&pending).unwrap();
        assert_eq!(
            snapshot,
            PendingPostStats {
                limit: 1024,
                total: 1024,
                started: 512,
                not_started: 512
            }
        );
        assert_eq!(pending.lock().unwrap().len(), 1024);
        pending
            .lock()
            .unwrap()
            .get(&1)
            .unwrap()
            .started
            .store(true, Ordering::Release);
        assert_eq!(pending_post_stats(&pending).unwrap().started, 513);
        // Break the fake context registry ownership cycle; native release normally does this.
        pending.lock().unwrap().clear();
        assert_eq!(pending_post_stats(&pending).unwrap().total, 0);
    }

    #[test]
    fn pending_post_diagnostic_reports_poison_as_unavailable() {
        let pending = Mutex::new(HashMap::new());
        let _ = std::panic::catch_unwind(|| {
            let _guard = pending.lock().unwrap();
            panic!("poison diagnostic fixture");
        });
        assert!(pending_post_stats(&pending).is_none());
    }

    #[test]
    fn deferred_frame_is_not_accepted_until_replayed() {
        let handler = Arc::new(DeferOnce(AtomicUsize::new(0)));
        let state = Box::new(SessionState {
            handler: handler.clone(),
            token: 77,
            engine_id: 1,
            pending: Arc::new(Mutex::new(HashMap::new())),
            dials: Arc::new(Mutex::new(HashMap::new())),
            dial_key: 0,
            accepted: AtomicBool::new(true),
            authenticated: Arc::new(Mutex::new(HashSet::new())),
            fd_attaches: Arc::new(Mutex::new(HashMap::new())),
            timers: Arc::new(Mutex::new(HashMap::new())),
        });
        let mut bytes = [1u8];
        let mut frame = ffi::duct_frame_t::default();
        frame.payload.data = bytes.as_mut_ptr().cast();
        frame.payload.size = bytes.len();
        let state_ptr = (&*state as *const SessionState).cast_mut().cast();
        let mut out = ffi::duct_response_t::default();
        assert_eq!(
            unsafe { on_frame(ptr::null_mut(), 0, &frame, &mut out, state_ptr) },
            ffi::duct_result_rc_defer
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 1);
        let mut out = ffi::duct_response_t::default();
        assert_eq!(
            unsafe { on_frame(ptr::null_mut(), 0, &frame, &mut out, state_ptr) },
            ffi::duct_result_rc_ok
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 2);
    }

    struct PanicOnFrame;
    impl Handler for PanicOnFrame {
        fn frame(&self, _: SessionToken, _: &[u8]) -> Option<Vec<u8>> {
            panic!("test callback panic");
        }
    }

    #[test]
    fn rust_panic_is_contained_and_closes_session() {
        let state = Box::new(SessionState {
            handler: Arc::new(PanicOnFrame),
            token: 77,
            engine_id: 1,
            pending: Arc::new(Mutex::new(HashMap::new())),
            dials: Arc::new(Mutex::new(HashMap::new())),
            dial_key: 0,
            accepted: AtomicBool::new(true),
            authenticated: Arc::new(Mutex::new(HashSet::new())),
            fd_attaches: Arc::new(Mutex::new(HashMap::new())),
            timers: Arc::new(Mutex::new(HashMap::new())),
        });
        let mut out = ffi::duct_response_t::default();
        let mut bytes = [1u8];
        let mut frame = ffi::duct_frame_t::default();
        frame.payload.data = bytes.as_mut_ptr().cast();
        frame.payload.size = 1;
        let rc = unsafe {
            on_frame(
                ptr::null_mut(),
                0,
                &frame,
                &mut out,
                (&*state as *const SessionState).cast_mut().cast(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(out.control.close_target, 1);
    }

    #[test]
    fn rejected_noise_key_never_reaches_user_frame_even_in_same_pdu() {
        let h = Arc::new(Reject(AtomicUsize::new(0)));
        let state = Box::new(SessionState {
            handler: h.clone(),
            token: 42,
            engine_id: 1,
            pending: Arc::new(Mutex::new(HashMap::new())),
            dials: Arc::new(Mutex::new(HashMap::new())),
            dial_key: 0,
            accepted: AtomicBool::new(false),
            authenticated: Arc::new(Mutex::new(HashSet::new())),
            fd_attaches: Arc::new(Mutex::new(HashMap::new())),
            timers: Arc::new(Mutex::new(HashMap::new())),
        });
        let state_ptr = (&*state as *const SessionState).cast_mut().cast();
        let mut out = ffi::duct_response_t::default();
        let mut key = [3u8; 32];
        let identity = ffi::duct_view_u8 {
            data: key.as_mut_ptr().cast(),
            size: key.len(),
        };
        unsafe {
            on_peer_auth(ptr::null_mut(), 0, identity, &mut out, state_ptr);
        }
        let mut bytes = [7u8; 3];
        let mut frame = ffi::duct_frame_t::default();
        frame.payload.data = bytes.as_mut_ptr().cast();
        frame.payload.size = bytes.len();
        assert_eq!(
            unsafe { on_frame(ptr::null_mut(), 0, &frame, &mut out, state_ptr) },
            2
        );
        assert_eq!(h.0.load(Ordering::Relaxed), 0);
        assert_eq!(out.control.close_target, 1);
    }

    #[test]
    fn terminal_close_reclaims_unrun_post_context() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let cmd = Box::new(PostState {
            payload: vec![1, 2, 3],
            token: 42,
            conn_id: ffi::duct_conn_id_same,
            send_token: None,
            started: AtomicBool::new(false),
            registry: pending.clone(),
        });
        let key = (&*cmd as *const PostState) as usize;
        pending.lock().unwrap().insert(key, cmd);
        let state = Box::new(SessionState {
            handler: Arc::new(Reject(AtomicUsize::new(0))),
            token: 42,
            engine_id: 1,
            pending: pending.clone(),
            dials: Arc::new(Mutex::new(HashMap::new())),
            dial_key: 0,
            accepted: AtomicBool::new(true),
            authenticated: Arc::new(Mutex::new(HashSet::new())),
            fd_attaches: Arc::new(Mutex::new(HashMap::new())),
            timers: Arc::new(Mutex::new(HashMap::new())),
        });
        unsafe {
            on_close(
                ptr::null_mut(),
                0,
                (&*state as *const SessionState).cast_mut().cast(),
            );
        }
        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn close_preserves_parked_response_until_c_release() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let cmd = Box::new(PostState {
            payload: vec![9; 16 * 1024],
            token: 42,
            conn_id: ffi::duct_conn_id_same,
            send_token: None,
            started: AtomicBool::new(true),
            registry: pending.clone(),
        });
        let key = (&*cmd as *const PostState) as usize;
        pending.lock().unwrap().insert(key, cmd);
        let state = Box::new(SessionState {
            handler: Arc::new(Reject(AtomicUsize::new(0))),
            token: 42,
            engine_id: 1,
            pending: pending.clone(),
            dials: Arc::new(Mutex::new(HashMap::new())),
            dial_key: 0,
            accepted: AtomicBool::new(true),
            authenticated: Arc::new(Mutex::new(HashSet::new())),
            fd_attaches: Arc::new(Mutex::new(HashMap::new())),
            timers: Arc::new(Mutex::new(HashMap::new())),
        });
        unsafe {
            on_close(
                ptr::null_mut(),
                0,
                (&*state as *const SessionState).cast_mut().cast(),
            );
        }
        assert!(pending.lock().unwrap().contains_key(&key));
        unsafe {
            release_post(key as *mut _);
        }
        assert!(pending.lock().unwrap().is_empty());
    }
}
