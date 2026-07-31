use crate::output::{self, Scope};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

static CLOSED_TUNNEL_WARNED: AtomicBool = AtomicBool::new(false);

pub(crate) struct TunnelDevice {
    rx_queue: VecDeque<Vec<u8>>,
}

impl TunnelDevice {
    pub(crate) fn new() -> Self {
        CLOSED_TUNNEL_WARNED.store(false, Ordering::Relaxed);
        Self {
            rx_queue: VecDeque::new(),
        }
    }

    pub(crate) fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }
}

pub(crate) struct TunnelRxToken {
    frame: Vec<u8>,
}

impl RxToken for TunnelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

#[derive(Default)]
pub(crate) struct TunnelTxToken;

impl TxToken for TunnelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let out = f(&mut frame);
        if let Err(err) = crate::protocol::send_tunnel_packet(frame) {
            let detail = crate::error::concise_error(err);
            if detail.contains("sending on a closed channel") {
                if !CLOSED_TUNNEL_WARNED.swap(true, Ordering::Relaxed) {
                    if let Some(reason) = crate::runtime_state::fatal_reason() {
                        output::warn(
                            Scope::Netstack,
                            format_args!(
                                "dropping outbound packet; tunnel already closed: {reason}"
                            ),
                        );
                    } else {
                        output::warn(
                            Scope::Netstack,
                            "dropping outbound packet; tunnel channel is closed",
                        );
                    }
                }
            } else {
                output::warn(
                    Scope::Netstack,
                    format_args!("send tunnel packet failed: {detail}"),
                );
            }
        }
        out
    }
}

impl Device for TunnelDevice {
    type RxToken<'a>
        = TunnelRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunnelTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx_queue.pop_front()?;
        Some((TunnelRxToken { frame }, TunnelTxToken))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}
