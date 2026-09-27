use anstyle::{Ansi256Color, Color, Style};
use chrono::Local;
use std::fmt::{Display, Formatter, Result as FmtResult};
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};

const COLOR_VALUE: u8 = 183;
const COLOR_WEAK: u8 = 95;
const COLOR_ROUTE_REMOTE: u8 = 81;
const COLOR_ROUTE_FALLBACK: u8 = 215;
const COLOR_ROUTE_DIRECT: u8 = 150;
const COLOR_SCOPE_CLI: u8 = 117;
const COLOR_SCOPE_APP: u8 = 81;
const COLOR_SCOPE_LOGIN: u8 = 118;
const COLOR_SCOPE_AGENT: u8 = 222;
const COLOR_SCOPE_REQ: u8 = 213;
const COLOR_SCOPE_UPSTREAM: u8 = 141;
const COLOR_SCOPE_VPN: u8 = 214;
const COLOR_SCOPE_NETSTACK: u8 = 33;
const COLOR_TS_YEAR: u8 = 240;
const COLOR_TS_DATE: u8 = 244;
const COLOR_TS_CLOCK: u8 = 247;
const COLOR_SUCCESS: u8 = 34;
const COLOR_WARN: u8 = 220;
const COLOR_ERROR: u8 = 196;

#[cfg(debug_assertions)]
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
pub enum Scope {
    Cli,
    App,
    Login,
    Agent,
    Req,
    Upstream,
    Protocol,
    Netstack,
}

#[derive(Clone, Copy)]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

#[derive(Clone, Copy)]
pub enum RouteKind {
    Remote,
    Fallback,
    Direct,
}

pub struct Styled<T> {
    style: Style,
    value: T,
}

impl<T: Display> Display for Styled<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}{}{:#}", self.style, self.value, self.style)
    }
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::Cli => "CLI",
            Scope::App => "APP",
            Scope::Login => "LOGIN",
            Scope::Agent => "AGENT",
            Scope::Req => "REQ",
            Scope::Upstream => "UPSTREAM",
            Scope::Protocol => "VPN",
            Scope::Netstack => "NETSTACK",
        }
    }

    fn style(self) -> Style {
        match self {
            // High-saturation bright mapping for quick visual separation.
            Scope::Cli => style_ansi256(COLOR_SCOPE_CLI),
            Scope::App => style_ansi256(COLOR_SCOPE_APP),
            Scope::Login => style_ansi256(COLOR_SCOPE_LOGIN),
            Scope::Agent => style_ansi256(COLOR_SCOPE_AGENT),
            Scope::Req => style_ansi256(COLOR_SCOPE_REQ),
            Scope::Upstream => style_ansi256(COLOR_SCOPE_UPSTREAM),
            Scope::Protocol => style_ansi256(COLOR_SCOPE_VPN),
            Scope::Netstack => style_ansi256(COLOR_SCOPE_NETSTACK),
        }
    }
}

pub fn info(scope: Scope, message: impl Display) {
    log(Level::Info, scope, message);
}

pub fn warn(scope: Scope, message: impl Display) {
    log(Level::Warn, scope, message);
}

pub fn error(scope: Scope, message: impl Display) {
    log(Level::Error, scope, message);
}

pub fn success(scope: Scope, message: impl Display) {
    log(Level::Success, scope, message);
}

#[cfg(debug_assertions)]
pub fn set_debug_enabled(enabled: bool) {
    DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
}

#[cfg(debug_assertions)]
pub fn is_debug_enabled() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

#[cfg(debug_assertions)]
pub fn debug(scope: Scope, message: impl Display) {
    if is_debug_enabled() {
        log(Level::Info, scope, message);
    }
}

#[cfg(debug_assertions)]
pub fn debug_hex(scope: Scope, label: impl Display, data: &[u8]) {
    if !is_debug_enabled() {
        return;
    }

    let hex = data
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    debug(
        scope,
        format_args!("{label}; len: {}; hex: {hex}", data.len()),
    );
}

pub fn value<T: Display>(value: T) -> Styled<T> {
    styled(style_ansi256(COLOR_VALUE), value)
}

pub fn weak<T: Display>(value: T) -> Styled<T> {
    styled(style_ansi256(COLOR_WEAK), value)
}

pub fn route_label(kind: RouteKind) -> Styled<&'static str> {
    match kind {
        RouteKind::Remote => styled(style_ansi256(COLOR_ROUTE_REMOTE), "remote"),
        RouteKind::Fallback => styled(style_ansi256(COLOR_ROUTE_FALLBACK), "fallback"),
        RouteKind::Direct => styled(style_ansi256(COLOR_ROUTE_DIRECT), "direct"),
    }
}

fn styled<T>(style: Style, value: T) -> Styled<T> {
    Styled { style, value }
}

fn log(level: Level, scope: Scope, message: impl Display) {
    emit(level, scope, message);
}

fn emit(level: Level, scope: Scope, message: impl Display) {
    let (year, short_date, clock) = timestamp_parts();
    let year_style = style_ansi256(COLOR_TS_YEAR);
    let short_date_style = style_ansi256(COLOR_TS_DATE);
    let clock_style = style_ansi256(COLOR_TS_CLOCK);
    let scope_style = scope.style();
    match level {
        Level::Info => {
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {message}",
                scope.label()
            );
        }
        Level::Success => {
            let ok_style = style_ansi256(COLOR_SUCCESS);
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {ok_style}✓ {message}{ok_style:#}",
                scope.label()
            );
        }
        Level::Warn => {
            let warn_style = style_ansi256(COLOR_WARN);
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {warn_style}WARN:{warn_style:#} {message}",
                scope.label(),
            );
        }
        Level::Error => {
            let err_style = style_ansi256(COLOR_ERROR);
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {err_style}ERROR:{err_style:#} {message}",
                scope.label(),
            );
        }
    }
}

fn style_ansi256(code: u8) -> Style {
    Style::new().fg_color(Some(Color::Ansi256(Ansi256Color(code))))
}

fn timestamp_parts() -> (String, String, String) {
    let now = Local::now().naive_local();
    (
        now.format("%Y/").to_string(),
        now.format("%m/%d").to_string(),
        now.format(" %H:%M:%S%.3f").to_string(),
    )
}
