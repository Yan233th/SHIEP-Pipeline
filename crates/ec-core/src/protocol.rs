use crate::endpoint::parse_server;
use crate::error::{EcError, EcResult};
use crate::output::{self, Scope};
use crate::protocol_wire::{
    COMMAND_REPLY_BODY_EXPECTED_LEN, HEARTBEAT_OPAQUE_TAIL_LEN, HEARTBEAT_SESSION_LEN,
    NATIVE_CONTROL_FRAME_LEN, NATIVE_CONTROL_MAGIC, NativeControlType, PROTOCOL_TOKEN_LEN,
    SendIpReply, build_command_message, build_initial_query_ip_message,
    build_stream_handshake_message, build_tx_heartbeat_packet, parse_command_control_reply,
    parse_native_control_frame, parse_protocol_token, parse_send_ip_reply,
};
use legacy_tls::TlsStream;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STREAM_RETRY_LIMIT: usize = 5;
const STREAM_RETRY_DELAY: Duration = Duration::from_secs(1);
const QUERY_IP_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TX_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(12);
const COMMAND_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const COMMAND_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_HEARTBEAT_RETRY_DELAY: Duration = Duration::from_secs(1);
const COMMAND_HEARTBEAT_FAILURE_LIMIT: u32 = 3;
const RUNTIME_ALREADY_STARTED: &str = "tunnel runtime already started in this process";

#[derive(Clone, Copy)]
enum StreamProfile {
    Rx,
    Tx,
}

#[derive(Clone, Copy)]
enum StreamOpenKind {
    First,
    Resume,
}

enum CommandHeartbeatFailure {
    Retryable(String),
    Fatal(String),
}

enum CommandHeartbeatOutcome {
    Ack,
    Fatal(String),
}

enum StreamOpenError {
    Retryable(EcError),
    Fatal(EcError),
}

enum StreamAckReply {
    Expected,
    UnexpectedControl(NativeControlType),
    NonControl,
}

#[derive(Clone, Copy)]
struct StreamOpenRetry {
    first_attempt: usize,
    delay_first_attempt: bool,
    phase: &'static str,
}

impl StreamProfile {
    fn first_op_code(self) -> u8 {
        match self {
            Self::Rx => 0x06,
            Self::Tx => 0x05,
        }
    }

    fn resume_op_code(self) -> u8 {
        match self {
            Self::Rx => 0x07,
            Self::Tx => 0x08,
        }
    }

    fn op_code(self, kind: StreamOpenKind) -> u8 {
        match kind {
            StreamOpenKind::First => self.first_op_code(),
            StreamOpenKind::Resume => self.resume_op_code(),
        }
    }

    fn expected_ack(self) -> NativeControlType {
        match self {
            Self::Rx => NativeControlType::RxAck,
            Self::Tx => NativeControlType::TxAck,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

#[cfg(debug_assertions)]
impl StreamOpenKind {
    fn label(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Resume => "resume",
        }
    }
}

impl StreamOpenKind {
    fn action_label(self) -> &'static str {
        match self {
            Self::First => "open",
            Self::Resume => "resume",
        }
    }
}

impl StreamOpenRetry {
    fn first_open() -> Self {
        Self {
            first_attempt: 0,
            delay_first_attempt: false,
            phase: "open",
        }
    }

    fn reconnect(first_attempt: usize) -> Self {
        Self {
            first_attempt,
            delay_first_attempt: true,
            phase: "reconnect",
        }
    }
}

impl StreamOpenError {
    fn retryable(err: EcError) -> Self {
        Self::Retryable(err)
    }

    fn error(&self) -> &EcError {
        match self {
            Self::Retryable(err) | Self::Fatal(err) => err,
        }
    }

    fn into_error(self) -> EcError {
        match self {
            Self::Retryable(err) | Self::Fatal(err) => err,
        }
    }

    fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal(_))
    }
}

#[derive(Clone)]
struct TunnelRuntimeParams {
    authority: String,
    token: [u8; PROTOCOL_TOKEN_LEN],
    assigned_ip: [u8; 4],
    ip_rev: [u8; 4],
    heartbeat_dst: [u8; 4],
    heartbeat_tail: [u8; HEARTBEAT_OPAQUE_TAIL_LEN],
}

impl TunnelRuntimeParams {
    fn new(authority: String, token: [u8; PROTOCOL_TOKEN_LEN], ips: TunnelIps) -> Self {
        let heartbeat_tail = new_heartbeat_tail(&token, ips.assigned_ip);
        Self {
            authority,
            token,
            assigned_ip: ips.assigned_ip,
            ip_rev: [
                ips.assigned_ip[3],
                ips.assigned_ip[2],
                ips.assigned_ip[1],
                ips.assigned_ip[0],
            ],
            heartbeat_dst: ips.lan_ip,
            heartbeat_tail,
        }
    }

    fn open_stream(&self, profile: StreamProfile) -> EcResult<TlsStream<TcpStream>> {
        open_data_stream_with_retries(
            &self.authority,
            &self.token,
            &self.ip_rev,
            profile,
            StreamOpenKind::First,
            StreamOpenRetry::first_open(),
        )
    }

    fn reopen_stream(
        &self,
        profile: StreamProfile,
        retries: usize,
    ) -> EcResult<TlsStream<TcpStream>> {
        open_data_stream_with_retries(
            &self.authority,
            &self.token,
            &self.ip_rev,
            profile,
            StreamOpenKind::Resume,
            StreamOpenRetry::reconnect(retries),
        )
    }

    fn tx_heartbeat_packet(&self) -> [u8; 0x4c] {
        build_tx_heartbeat_packet(
            self.assigned_ip,
            self.heartbeat_dst,
            self.heartbeat_session(),
            &self.heartbeat_tail,
        )
    }

    fn heartbeat_session(&self) -> &[u8; HEARTBEAT_SESSION_LEN] {
        self.token[32..48]
            .try_into()
            .expect("protocol token must contain a 16-byte session suffix")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelIps {
    pub assigned_ip: [u8; 4],
    pub lan_ip: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandStreamInit {
    pub ips: TunnelIps,
}

impl From<SendIpReply> for TunnelIps {
    fn from(reply: SendIpReply) -> Self {
        Self {
            assigned_ip: reply.assigned_ip,
            lan_ip: reply.lan_ip,
        }
    }
}

impl From<SendIpReply> for CommandStreamInit {
    fn from(reply: SendIpReply) -> Self {
        Self { ips: reply.into() }
    }
}

static TX_PACKET_SENDER: OnceLock<mpsc::Sender<Vec<u8>>> = OnceLock::new();
// L3IP op0/SEND_IP leaves a command/control stream open. Official op3
// heartbeat must stay on that same stream instead of the RX/TX data streams.
static COMMAND_STREAM_HOLDER: OnceLock<Mutex<Option<TlsStream<TcpStream>>>> = OnceLock::new();
static RX_PACKET_RECEIVER: OnceLock<Mutex<Option<mpsc::Receiver<Vec<u8>>>>> = OnceLock::new();
pub fn open_command_stream(server: &str, token: &str) -> EcResult<CommandStreamInit> {
    let (authority, _) = parse_server(server)?;
    let token_bytes = parse_protocol_token(token)?;

    open_command_stream_once(&authority, &token_bytes)
}

pub fn start_tunnel_runtime(server: &str, token: &str, ips: TunnelIps) -> EcResult<()> {
    crate::runtime_state::clear_fatal_reason();

    let (authority, _) = parse_server(server)?;
    let token_bytes = parse_protocol_token(token)?;
    let runtime = TunnelRuntimeParams::new(authority, token_bytes, ips);

    let rx_stream = runtime.open_stream(StreamProfile::Rx)?;
    output::success(Scope::Protocol, "RX handshake successful");
    let tx_stream = runtime.open_stream(StreamProfile::Tx)?;
    output::success(Scope::Protocol, "TX handshake successful");

    let (tx_sender, tx_receiver) = mpsc::channel::<Vec<u8>>();
    let (rx_sender, rx_receiver) = mpsc::channel::<Vec<u8>>();
    install_runtime_channels(tx_sender, rx_receiver)?;

    let rx_runtime = runtime.clone();
    thread::spawn(move || {
        let result = rx_worker_loop(rx_runtime, rx_stream, rx_sender);
        handle_worker_exit(StreamProfile::Rx, result);
    });

    thread::spawn(move || {
        let result = tx_worker_loop(runtime, tx_stream, tx_receiver);
        handle_worker_exit(StreamProfile::Tx, result);
    });

    output::info(
        Scope::Protocol,
        format_args!(
            "data heartbeat: TX every {}s",
            output::value(TX_HEARTBEAT_INTERVAL.as_secs())
        ),
    );
    output::info(
        Scope::Protocol,
        format_args!(
            "command heartbeat: every {}s; retry {}s x{}",
            output::value(COMMAND_HEARTBEAT_INTERVAL.as_secs()),
            output::value(COMMAND_HEARTBEAT_RETRY_DELAY.as_secs()),
            output::value(COMMAND_HEARTBEAT_FAILURE_LIMIT)
        ),
    );
    start_command_heartbeat(token_bytes);

    Ok(())
}

fn install_runtime_channels(
    tx_sender: mpsc::Sender<Vec<u8>>,
    rx_receiver: mpsc::Receiver<Vec<u8>>,
) -> EcResult<()> {
    let rx_holder = RX_PACKET_RECEIVER.get_or_init(|| Mutex::new(None));
    let mut guard = rx_holder
        .lock()
        .map_err(|_| EcError::Runtime("rx packet receiver mutex poisoned".to_string()))?;
    if guard.is_some() || TX_PACKET_SENDER.get().is_some() {
        return Err(runtime_already_started_err());
    }
    TX_PACKET_SENDER
        .set(tx_sender)
        .map_err(|_| runtime_already_started_err())?;
    *guard = Some(rx_receiver);
    Ok(())
}

fn runtime_already_started_err() -> EcError {
    EcError::Runtime(RUNTIME_ALREADY_STARTED.to_string())
}

pub fn send_tunnel_packet(packet: Vec<u8>) -> EcResult<()> {
    let sender = TX_PACKET_SENDER
        .get()
        .ok_or_else(|| EcError::Runtime("tunnel runtime is not started".to_string()))?;
    sender
        .send(packet)
        .map_err(|e| EcError::Runtime(format!("send tunnel packet failed: {e}")))
}

pub fn take_tunnel_packet_receiver() -> EcResult<mpsc::Receiver<Vec<u8>>> {
    let holder = RX_PACKET_RECEIVER
        .get()
        .ok_or_else(|| EcError::Runtime("tunnel runtime is not started".to_string()))?;
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("rx packet receiver mutex poisoned".to_string()))?;
    guard.take().ok_or_else(|| {
        EcError::Runtime("tunnel packet receiver was already taken or not initialized".to_string())
    })
}

fn worker_exit_detail(profile: StreamProfile, result: EcResult<()>) -> String {
    match result {
        Ok(()) => format!(
            "stream closed: {}; reason: exited unexpectedly",
            profile.label()
        ),
        Err(err) => format!(
            "stream closed: {}; reason: {}",
            profile.label(),
            crate::error::concise_error(err)
        ),
    }
}

fn handle_worker_exit(profile: StreamProfile, result: EcResult<()>) {
    let detail = worker_exit_detail(profile, result);
    output::warn(Scope::Protocol, &detail);
    crate::runtime_state::record_fatal(detail);
}

fn open_command_stream_once(
    authority: &str,
    token_bytes: &[u8; PROTOCOL_TOKEN_LEN],
) -> EcResult<CommandStreamInit> {
    let mut stream = connect_vpn_tls(authority)?;

    let message = build_initial_query_ip_message(token_bytes);
    stream
        .write_all(&message)
        .map_err(|e| EcError::Runtime(format!("SEND_IP write failed: {e}")))?;

    let mut reader = ControlReplyReader::default();
    let reply = reader
        .read(&mut stream, QUERY_IP_REPLY_TIMEOUT)
        .map_err(|e| {
            EcError::Runtime(format!(
                "SEND_IP read failed: {}",
                crate::error::concise_error(e)
            ))
        })?;

    let send_ip = parse_send_ip_reply(reply).inspect_err(|_| {
        debug_protocol_hex("debug: SEND_IP raw reply", reply);
    })?;
    hold_command_stream(stream)?;
    Ok(send_ip.into())
}

fn rx_worker_loop(
    runtime: TunnelRuntimeParams,
    mut stream: TlsStream<TcpStream>,
    tx: mpsc::Sender<Vec<u8>>,
) -> EcResult<()> {
    let mut retries = 0usize;
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                retries += 1;
                stream = runtime.reopen_stream(StreamProfile::Rx, retries)?;
                retries = 0;
            }
            Ok(n) => {
                retries = 0;
                if !should_forward_rx_payload(&buf[..n])? {
                    continue;
                }
                if tx.send(buf[..n].to_vec()).is_err() {
                    return Ok(());
                }
            }
            Err(e) if is_wouldblock_or_timeout(&e) => continue,
            Err(_) => {
                retries += 1;
                stream = runtime.reopen_stream(StreamProfile::Rx, retries)?;
                retries = 0;
            }
        }
    }
}

fn should_forward_rx_payload(data: &[u8]) -> EcResult<bool> {
    match parse_native_control_frame(data) {
        Some(NativeControlType::RxAck) => Ok(false),
        Some(control) => {
            debug_protocol_hex("debug: unexpected rx control frame raw", data);
            Err(EcError::Runtime(format!(
                "unexpected rx control frame: {}({})",
                control.label(),
                control.code()
            )))
        }
        None => Ok(true),
    }
}

fn tx_worker_loop(
    runtime: TunnelRuntimeParams,
    mut stream: TlsStream<TcpStream>,
    rx: mpsc::Receiver<Vec<u8>>,
) -> EcResult<()> {
    let mut retries = 0usize;
    let mut next_heartbeat = Instant::now() + TX_HEARTBEAT_INTERVAL;
    loop {
        let now = Instant::now();
        let packet = if now >= next_heartbeat {
            next_heartbeat = now + TX_HEARTBEAT_INTERVAL;
            runtime.tx_heartbeat_packet().to_vec()
        } else {
            match rx.recv_timeout(next_heartbeat - now) {
                Ok(packet) => packet,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        };

        if stream.write_all(&packet).is_ok() {
            retries = 0;
            continue;
        }

        retries += 1;
        stream = runtime.reopen_stream(StreamProfile::Tx, retries)?;
        stream.write_all(&packet).map_err(|e| {
            EcError::Runtime(format!("tx stream write failed after reconnect: {e}"))
        })?;
        retries = 0;
    }
}

fn open_data_stream_with_retries(
    authority: &str,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    ip_rev: &[u8; 4],
    profile: StreamProfile,
    kind: StreamOpenKind,
    retry: StreamOpenRetry,
) -> EcResult<TlsStream<TcpStream>> {
    let mut attempt = retry.first_attempt;
    let mut last_error = None;
    while attempt <= STREAM_RETRY_LIMIT {
        if retry.delay_first_attempt || attempt > retry.first_attempt {
            thread::sleep(STREAM_RETRY_DELAY);
        }
        debug_stream_open_attempt(profile, kind, retry.phase, attempt);
        match open_data_stream(authority, token, ip_rev, profile, kind) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                let concise = crate::error::concise_error(err.error());
                debug_stream_open_failure(profile, kind, retry.phase, attempt, concise.as_str());
                if err.is_fatal() {
                    return Err(err.into_error());
                }
                last_error = Some(concise);
                attempt += 1;
            }
        }
    }

    let detail = last_error
        .map(|err| format!("; last error: {err}"))
        .unwrap_or_default();
    Err(EcError::Runtime(format!(
        "{} stream reached retry limit during {}{}",
        profile.label(),
        retry.phase,
        detail
    )))
}

fn open_data_stream(
    authority: &str,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    ip_rev: &[u8; 4],
    profile: StreamProfile,
    kind: StreamOpenKind,
) -> Result<TlsStream<TcpStream>, StreamOpenError> {
    let mut stream = connect_vpn_tls(authority).map_err(StreamOpenError::retryable)?;
    let op_code = profile.op_code(kind);
    let expected_ack = profile.expected_ack();

    let message = build_stream_handshake_message(op_code, token, ip_rev);
    stream.write_all(&message).map_err(|e| {
        StreamOpenError::retryable(EcError::Runtime(format!(
            "stream handshake write failed: {e}"
        )))
    })?;

    let mut reader = ControlReplyReader::default();
    let reply = reader
        .read(&mut stream, STREAM_HANDSHAKE_TIMEOUT)
        .map_err(|e| {
            StreamOpenError::retryable(EcError::Runtime(format!(
                "{} stream handshake read failed: {e}; op: 0x{op_code:02x}",
                profile.label(),
            )))
        })?;
    validate_stream_ack(profile, kind, op_code, expected_ack, reply)?;

    clear_data_stream_read_timeout(&stream, profile).map_err(StreamOpenError::retryable)?;
    Ok(stream)
}

fn validate_stream_ack(
    profile: StreamProfile,
    kind: StreamOpenKind,
    op_code: u8,
    expected_ack: NativeControlType,
    reply: &[u8],
) -> Result<(), StreamOpenError> {
    match classify_stream_ack_reply(reply, expected_ack) {
        StreamAckReply::Expected => Ok(()),
        StreamAckReply::UnexpectedControl(control) => {
            debug_stream_ack_reply(profile, op_code, reply);
            let err = if is_terminal_stream_control(control) {
                StreamOpenError::Fatal(stream_control_rejected_err(profile, kind, op_code, control))
            } else {
                StreamOpenError::Retryable(unexpected_stream_ack_err(
                    profile,
                    op_code,
                    expected_ack,
                    format_args!("{}({})", control.label(), control.code()),
                ))
            };
            Err(err)
        }
        StreamAckReply::NonControl => {
            debug_stream_ack_reply(profile, op_code, reply);
            Err(StreamOpenError::Retryable(unexpected_stream_ack_err(
                profile,
                op_code,
                expected_ack,
                format_args!("non-control-frame len={}", reply.len()),
            )))
        }
    }
}

fn classify_stream_ack_reply(reply: &[u8], expected_ack: NativeControlType) -> StreamAckReply {
    if let Some(control) = parse_native_control_frame(reply) {
        return if control == expected_ack {
            StreamAckReply::Expected
        } else {
            StreamAckReply::UnexpectedControl(control)
        };
    }

    if reply.len() == COMMAND_REPLY_BODY_EXPECTED_LEN
        && let Ok(control) = parse_command_control_reply(reply)
    {
        return if control == expected_ack {
            StreamAckReply::Expected
        } else {
            StreamAckReply::UnexpectedControl(control)
        };
    }

    StreamAckReply::NonControl
}

fn is_terminal_stream_control(control: NativeControlType) -> bool {
    matches!(
        control,
        NativeControlType::Shutdown | NativeControlType::IpKick | NativeControlType::IpConflict
    )
}

fn stream_control_rejected_err(
    profile: StreamProfile,
    kind: StreamOpenKind,
    op_code: u8,
    control: NativeControlType,
) -> EcError {
    EcError::Runtime(format!(
        "{} stream {} rejected by server: {}({}); op: 0x{op_code:02x}",
        profile.label(),
        kind.action_label(),
        control.label(),
        control.code(),
    ))
}

fn unexpected_stream_ack_err(
    profile: StreamProfile,
    op_code: u8,
    expected_ack: NativeControlType,
    got: std::fmt::Arguments<'_>,
) -> EcError {
    EcError::Runtime(format!(
        "unexpected {} stream handshake ack; expected: {}({}); got: {}; op: 0x{op_code:02x}",
        profile.label(),
        expected_ack.label(),
        expected_ack.code(),
        got,
    ))
}

fn clear_data_stream_read_timeout(
    stream: &TlsStream<TcpStream>,
    profile: StreamProfile,
) -> EcResult<()> {
    stream.get_ref().set_read_timeout(None).map_err(|e| {
        EcError::Runtime(format!(
            "clear {} stream read timeout failed: {e}",
            profile.label()
        ))
    })
}

#[cfg(debug_assertions)]
fn debug_stream_ack_reply(profile: StreamProfile, op_code: u8, reply: &[u8]) {
    if !output::is_debug_enabled() {
        return;
    }

    debug_protocol_hex(
        format_args!(
            "debug: unexpected {} ack raw reply; op: 0x{op_code:02x}",
            profile.label()
        ),
        reply,
    );
}

#[cfg(not(debug_assertions))]
fn debug_stream_ack_reply(_: StreamProfile, _: u8, _: &[u8]) {}

#[cfg(debug_assertions)]
fn debug_stream_open_attempt(
    profile: StreamProfile,
    kind: StreamOpenKind,
    phase: &str,
    attempt: usize,
) {
    if !output::is_debug_enabled() {
        return;
    }
    output::debug(
        Scope::Protocol,
        format_args!(
            "debug: opening {} stream; phase: {}; kind: {}; op: 0x{:02x}; attempt: {}/{}",
            profile.label(),
            phase,
            kind.label(),
            profile.op_code(kind),
            attempt + 1,
            STREAM_RETRY_LIMIT + 1
        ),
    );
}

#[cfg(not(debug_assertions))]
fn debug_stream_open_attempt(_: StreamProfile, _: StreamOpenKind, _: &str, _: usize) {}

#[cfg(debug_assertions)]
fn debug_stream_open_failure(
    profile: StreamProfile,
    kind: StreamOpenKind,
    phase: &str,
    attempt: usize,
    reason: &str,
) {
    if !output::is_debug_enabled() {
        return;
    }
    output::debug(
        Scope::Protocol,
        format_args!(
            "debug: {} stream open failed; phase: {}; kind: {}; op: 0x{:02x}; attempt: {}/{}; reason: {}",
            profile.label(),
            phase,
            kind.label(),
            profile.op_code(kind),
            attempt + 1,
            STREAM_RETRY_LIMIT + 1,
            reason
        ),
    );
}

#[cfg(not(debug_assertions))]
fn debug_stream_open_failure(_: StreamProfile, _: StreamOpenKind, _: &str, _: usize, _: &str) {}

#[cfg(debug_assertions)]
fn debug_protocol_hex(label: impl std::fmt::Display, data: &[u8]) {
    output::debug_hex(Scope::Protocol, label, data);
}

#[cfg(not(debug_assertions))]
fn debug_protocol_hex(_: impl std::fmt::Display, _: &[u8]) {}

#[cfg(debug_assertions)]
fn debug_tls_summary(stream: &TlsStream<TcpStream>) {
    if !output::is_debug_enabled() {
        return;
    }

    let version = stream.version().name();
    let cipher = stream.cipher_suite().name();
    output::debug(
        Scope::Protocol,
        format_args!(
            "debug: vpn tls handshake; version: {}; cipher: {}; sni: disabled; legacy: enabled",
            version, cipher
        ),
    );
}

#[cfg(not(debug_assertions))]
fn debug_tls_summary(_: &TlsStream<TcpStream>) {}

fn connect_vpn_tls(authority: &str) -> EcResult<TlsStream<TcpStream>> {
    let tcp = crate::tls::connect_vpn_tcp(authority, Duration::from_secs(5))?;
    let stream = crate::tls::handshake(&crate::tls::vpn_config(), tcp, "vpn")?;
    debug_tls_summary(&stream);
    Ok(stream)
}

fn hold_command_stream(stream: TlsStream<TcpStream>) -> EcResult<()> {
    let holder = COMMAND_STREAM_HOLDER.get_or_init(|| Mutex::new(None));
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("command stream holder mutex poisoned".to_string()))?;
    *guard = Some(stream);
    Ok(())
}

fn start_command_heartbeat(token: [u8; PROTOCOL_TOKEN_LEN]) {
    thread::spawn(move || {
        if let Err(err) = command_heartbeat_loop(token) {
            let detail = format!(
                "stream closed: command; reason: {}",
                crate::error::concise_error(err)
            );
            output::warn(Scope::Protocol, &detail);
            crate::runtime_state::record_fatal(detail);
        }
    });
}

fn command_heartbeat_loop(token: [u8; PROTOCOL_TOKEN_LEN]) -> EcResult<()> {
    let mut failure_count = 0u32;
    let mut next_delay = COMMAND_HEARTBEAT_INTERVAL;
    let mut reader = ControlReplyReader::default();
    loop {
        thread::sleep(next_delay);
        let holder = COMMAND_STREAM_HOLDER
            .get()
            .ok_or_else(|| EcError::Runtime("command stream is not initialized".to_string()))?;
        let result = {
            let mut guard = holder.lock().map_err(|_| {
                EcError::Runtime("command stream holder mutex poisoned".to_string())
            })?;
            let stream = guard
                .as_mut()
                .ok_or_else(|| EcError::Runtime("command stream is not available".to_string()))?;
            send_command_heartbeat(stream, &token, &mut reader)
        };
        match result {
            Ok(()) => {
                failure_count = 0;
                next_delay = COMMAND_HEARTBEAT_INTERVAL;
            }
            Err(CommandHeartbeatFailure::Retryable(reason)) => {
                failure_count += 1;
                if failure_count >= COMMAND_HEARTBEAT_FAILURE_LIMIT {
                    return Err(EcError::Runtime(format!(
                        "command heartbeat reached failure limit ({}/{}): {reason}",
                        failure_count, COMMAND_HEARTBEAT_FAILURE_LIMIT
                    )));
                }
                output::warn(
                    Scope::Protocol,
                    format_args!(
                        "command heartbeat failed: {}; retrying in {}s ({}/{})",
                        reason,
                        COMMAND_HEARTBEAT_RETRY_DELAY.as_secs(),
                        output::value(failure_count),
                        output::value(COMMAND_HEARTBEAT_FAILURE_LIMIT)
                    ),
                );
                next_delay = COMMAND_HEARTBEAT_RETRY_DELAY;
            }
            Err(CommandHeartbeatFailure::Fatal(reason)) => {
                return Err(EcError::Runtime(reason));
            }
        }
    }
}

fn send_command_heartbeat(
    stream: &mut TlsStream<TcpStream>,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    reader: &mut ControlReplyReader,
) -> Result<(), CommandHeartbeatFailure> {
    let message = build_command_message(3, token);
    stream.write_all(&message).map_err(|e| {
        CommandHeartbeatFailure::Retryable(format!("command heartbeat write failed: {e}"))
    })?;

    let reply = reader
        .read(stream, COMMAND_HEARTBEAT_TIMEOUT)
        .map_err(|e| {
            CommandHeartbeatFailure::Retryable(format!(
                "command heartbeat read failed: {}",
                crate::error::concise_error(e)
            ))
        })?;
    classify_command_heartbeat_reply(reply, reply).into_result()
}

fn classify_command_heartbeat_reply(data: &[u8], raw: &[u8]) -> CommandHeartbeatOutcome {
    let control = match parse_command_control_reply(data) {
        Ok(control) => control,
        Err(err) => {
            debug_protocol_hex("debug: command heartbeat parse-failed raw reply", raw);
            return CommandHeartbeatOutcome::Fatal(format!(
                "command heartbeat parse failed: {}",
                crate::error::concise_error(err)
            ));
        }
    };

    match control {
        NativeControlType::Heartbeat => CommandHeartbeatOutcome::Ack,
        NativeControlType::Shutdown | NativeControlType::IpKick => {
            debug_protocol_hex("debug: command heartbeat shutdown raw reply", raw);
            CommandHeartbeatOutcome::Fatal(format!(
                "command control requested tunnel shutdown: {}",
                control.label()
            ))
        }
        control => {
            debug_protocol_hex("debug: unexpected command heartbeat raw reply", raw);
            CommandHeartbeatOutcome::Fatal(format!(
                "unexpected command heartbeat reply: {}({})",
                control.label(),
                control.code()
            ))
        }
    }
}

impl CommandHeartbeatOutcome {
    fn into_result(self) -> Result<(), CommandHeartbeatFailure> {
        match self {
            Self::Ack => Ok(()),
            Self::Fatal(reason) => Err(CommandHeartbeatFailure::Fatal(reason)),
        }
    }
}

struct ControlReplyReader {
    bytes: [u8; NATIVE_CONTROL_FRAME_LEN],
    filled: usize,
}

impl Default for ControlReplyReader {
    fn default() -> Self {
        Self {
            bytes: [0; NATIVE_CONTROL_FRAME_LEN],
            filled: 0,
        }
    }
}

impl ControlReplyReader {
    fn read(&mut self, stream: &mut impl Read, timeout: Duration) -> std::io::Result<&[u8]> {
        let deadline = Instant::now() + timeout;
        loop {
            // Read only this frame, even when TLS supplies several at once.
            let end = if self.filled < NATIVE_CONTROL_MAGIC.len() {
                NATIVE_CONTROL_MAGIC.len()
            } else if self.bytes.starts_with(NATIVE_CONTROL_MAGIC) {
                NATIVE_CONTROL_FRAME_LEN
            } else {
                COMMAND_REPLY_BODY_EXPECTED_LEN
            };
            if self.filled == end && end > NATIVE_CONTROL_MAGIC.len() {
                self.filled = 0;
                return Ok(&self.bytes[..end]);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "control reply timed out",
                ));
            }
            match stream.read(&mut self.bytes[self.filled..end]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "incomplete control reply",
                    ));
                }
                Ok(n) => self.filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted || is_wouldblock_or_timeout(&e) => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn is_wouldblock_or_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn new_heartbeat_tail(
    token: &[u8; PROTOCOL_TOKEN_LEN],
    assigned_ip: [u8; 4],
) -> [u8; HEARTBEAT_OPAQUE_TAIL_LEN] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_nanos() as u64)
        .unwrap_or_default();
    let mut seed =
        now ^ (u64::from(std::process::id()) << 32) ^ u64::from(u32::from_be_bytes(assigned_ip));
    for chunk in token.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        seed ^= u64::from_le_bytes(buf).rotate_left(13);
        seed = splitmix64(seed);
    }
    splitmix64(seed).to_le_bytes()
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::{
        CommandHeartbeatOutcome, NativeControlType, StreamOpenKind, StreamProfile, TunnelIps,
        TunnelRuntimeParams, classify_command_heartbeat_reply, should_forward_rx_payload,
        validate_stream_ack,
    };
    use std::io::{self, Cursor, Read};
    use std::time::Duration;

    struct SplitReply {
        input: Cursor<Vec<u8>>,
        split: usize,
        timeout_at_split: bool,
    }

    impl Read for SplitReply {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let position = self.input.position() as usize;
            if position == self.split && self.timeout_at_split {
                self.timeout_at_split = false;
                std::thread::sleep(Duration::from_millis(2));
                return Err(io::ErrorKind::TimedOut.into());
            }
            let count = if position < self.split {
                out.len().min(self.split - position)
            } else {
                out.len()
            };
            self.input.read(&mut out[..count])
        }
    }

    fn control_reply(native: bool, code: u32) -> Vec<u8> {
        let mut reply = vec![0; if native { 40 } else { 36 }];
        let offset = if native {
            reply[..4].copy_from_slice(b"AABB");
            4
        } else {
            0
        };
        reply[offset..offset + 4].copy_from_slice(&code.to_le_bytes());
        reply
    }

    #[test]
    fn control_replies_reassemble_at_every_boundary_without_consuming_next_frame() {
        for native in [false, true] {
            for code in [1, 2, 8, 15] {
                let frame = control_reply(native, code);
                for split in 1..=frame.len() {
                    let following = control_reply(!native, 8);
                    let mut stream = SplitReply {
                        input: Cursor::new([frame.clone(), following.clone()].concat()),
                        split,
                        timeout_at_split: false,
                    };
                    let mut reader = super::ControlReplyReader::default();
                    let reply = reader.read(&mut stream, Duration::from_secs(1)).unwrap();
                    assert_eq!(reply, frame);
                    assert_eq!(
                        super::parse_command_control_reply(reply).unwrap().code(),
                        code
                    );
                    if code == 1 || code == 2 {
                        let profile = if code == 1 {
                            StreamProfile::Rx
                        } else {
                            StreamProfile::Tx
                        };
                        assert!(
                            validate_stream_ack(
                                profile,
                                StreamOpenKind::First,
                                profile.first_op_code(),
                                profile.expected_ack(),
                                reply
                            )
                            .is_ok()
                        );
                    } else if code == 15 {
                        assert!(matches!(
                            classify_command_heartbeat_reply(reply, reply),
                            CommandHeartbeatOutcome::Ack
                        ));
                    }
                    assert_eq!(
                        reader.read(&mut stream, Duration::from_secs(1)).unwrap(),
                        following
                    );
                }
            }
        }
    }

    #[test]
    fn control_reply_timeouts_preserve_partial_header_and_body() {
        for native in [false, true] {
            let frame = control_reply(native, 15);
            for split in [1, 3, 4, 16, frame.len() - 1] {
                let mut stream = SplitReply {
                    input: Cursor::new(frame.clone()),
                    split,
                    timeout_at_split: true,
                };
                let mut reader = super::ControlReplyReader::default();
                assert_eq!(
                    reader
                        .read(&mut stream, Duration::from_millis(1))
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::TimedOut
                );
                assert_eq!(
                    reader.read(&mut stream, Duration::from_secs(1)).unwrap(),
                    frame
                );
            }
        }
    }

    #[test]
    fn truncated_control_replies_are_never_accepted() {
        for native in [false, true] {
            let frame = control_reply(native, 15);
            for end in 0..frame.len() {
                let mut reader = super::ControlReplyReader::default();
                let error = reader
                    .read(&mut &frame[..end], Duration::from_secs(1))
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "end={end}");
            }
        }
    }

    #[test]
    fn code_style_ack_checks_the_whole_code() {
        let reply = control_reply(false, 0x101);
        assert!(
            validate_stream_ack(
                StreamProfile::Rx,
                StreamOpenKind::First,
                6,
                NativeControlType::RxAck,
                &reply
            )
            .is_err()
        );
    }

    #[test]
    fn stream_profiles_use_official_first_and_resume_ops() {
        assert_eq!(StreamProfile::Rx.op_code(StreamOpenKind::First), 0x06);
        assert_eq!(StreamProfile::Rx.op_code(StreamOpenKind::Resume), 0x07);
        assert_eq!(StreamProfile::Tx.op_code(StreamOpenKind::First), 0x05);
        assert_eq!(StreamProfile::Tx.op_code(StreamOpenKind::Resume), 0x08);
    }

    #[test]
    fn stream_ack_accepts_matching_aabb_control_frame() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            validate_stream_ack(
                StreamProfile::Rx,
                StreamOpenKind::First,
                0x06,
                NativeControlType::RxAck,
                &frame
            )
            .is_ok()
        );

        frame[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            validate_stream_ack(
                StreamProfile::Tx,
                StreamOpenKind::First,
                0x05,
                NativeControlType::TxAck,
                &frame
            )
            .is_ok()
        );
    }

    #[test]
    fn stream_ack_rejects_wrong_type_and_accepts_code_style_reply() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            validate_stream_ack(
                StreamProfile::Rx,
                StreamOpenKind::First,
                0x06,
                NativeControlType::RxAck,
                &frame
            )
            .is_err()
        );

        let mut legacy_marker_reply = [0u8; 36];
        legacy_marker_reply[0] = 1;
        assert!(
            validate_stream_ack(
                StreamProfile::Rx,
                StreamOpenKind::First,
                0x06,
                NativeControlType::RxAck,
                &legacy_marker_reply
            )
            .is_ok()
        );
    }

    #[test]
    fn stream_ack_classifies_code_style_shutdown_as_fatal() {
        let mut reply = [0u8; 36];
        reply[0..4].copy_from_slice(&8u32.to_le_bytes());
        let err = validate_stream_ack(
            StreamProfile::Rx,
            StreamOpenKind::Resume,
            0x07,
            NativeControlType::RxAck,
            &reply,
        )
        .unwrap_err();

        assert!(err.is_fatal());
        assert!(
            err.error()
                .to_string()
                .contains("rx stream resume rejected by server: shutdown(8)")
        );
    }

    #[test]
    fn rx_payload_filter_consumes_rx_ack_only() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(!should_forward_rx_payload(&frame).unwrap());

        frame[4..8].copy_from_slice(&15u32.to_le_bytes());
        assert!(should_forward_rx_payload(&frame).is_err());

        let ipv4_packet = [0x45u8, 0, 0, 20, 0, 0, 0, 0];
        assert!(should_forward_rx_payload(&ipv4_packet).unwrap());
    }

    #[test]
    fn tunnel_runtime_builds_tx_heartbeat_from_assigned_ip_and_session_suffix() {
        let mut token = [b'a'; 48];
        token[32..48].copy_from_slice(b"eab27cdf7c24a40f");
        let runtime = TunnelRuntimeParams::new(
            "vpn.example:443".to_string(),
            token,
            TunnelIps {
                assigned_ip: [10, 166, 80, 12],
                lan_ip: [10, 166, 64, 7],
            },
        );

        let packet = runtime.tx_heartbeat_packet();
        assert_eq!(&packet[12..16], &[10, 166, 80, 12]);
        assert_eq!(&packet[16..20], &[10, 166, 64, 7]);
        assert_eq!(&packet[46..62], b"eab27cdf7c24a40f");
        assert_eq!(&packet[70..76], b"L3VPN\0");
    }

    #[test]
    fn command_heartbeat_reply_classifies_ack_and_shutdown() {
        let mut ack = [0u8; 36];
        ack[0..4].copy_from_slice(&15u32.to_le_bytes());
        assert!(matches!(
            classify_command_heartbeat_reply(&ack, &ack),
            CommandHeartbeatOutcome::Ack
        ));

        ack[0..4].copy_from_slice(&8u32.to_le_bytes());
        assert!(matches!(
            classify_command_heartbeat_reply(&ack, &ack),
            CommandHeartbeatOutcome::Fatal(reason) if reason.contains("shutdown")
        ));
    }

    #[test]
    fn command_heartbeat_reply_classifies_parse_failure_as_fatal() {
        assert!(matches!(
            classify_command_heartbeat_reply(&[], &[]),
            CommandHeartbeatOutcome::Fatal(reason) if reason.contains("parse failed")
        ));
    }
}
