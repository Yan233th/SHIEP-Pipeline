use crate::output::{self, Scope};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;
use std::collections::VecDeque;
use std::sync::mpsc;

pub(crate) struct TunnelDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    closed_tunnel_warned: bool,
}

impl TunnelDevice {
    pub(crate) fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx,
            closed_tunnel_warned: false,
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

pub(crate) struct TunnelTxToken<'a> {
    tx: &'a mpsc::Sender<Vec<u8>>,
    closed_tunnel_warned: &'a mut bool,
}

impl TxToken for TunnelTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let out = f(&mut frame);
        if self.tx.send(frame).is_err() && !*self.closed_tunnel_warned {
            *self.closed_tunnel_warned = true;
            if let Some(reason) = crate::runtime_state::fatal_reason() {
                output::warn(
                    Scope::Netstack,
                    format_args!("dropping outbound packet; tunnel already closed: {reason}"),
                );
            } else {
                output::warn(
                    Scope::Netstack,
                    "dropping outbound packet; tunnel channel is closed",
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
        = TunnelTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx_queue.pop_front()?;
        Some((
            TunnelRxToken { frame },
            TunnelTxToken {
                tx: &self.tx,
                closed_tunnel_warned: &mut self.closed_tunnel_warned,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTxToken {
            tx: &self.tx,
            closed_tunnel_warned: &mut self.closed_tunnel_warned,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_and_transmit_tokens_use_the_owned_channel() {
        let (tx, rx) = mpsc::channel();
        let mut device = TunnelDevice::new(tx);
        let now = SmolInstant::from_millis(0);
        device.push_rx(vec![1, 2, 3]);
        let (input, reply) = device.receive(now).unwrap();
        input.consume(|packet| assert_eq!(packet, [1, 2, 3]));
        reply.consume(2, |packet| packet.copy_from_slice(&[4, 5]));
        assert_eq!(rx.try_recv().unwrap(), [4, 5]);
        assert!(device.receive(now).is_none());

        device
            .transmit(now)
            .unwrap()
            .consume(1, |packet| packet[0] = 6);
        assert_eq!(rx.try_recv().unwrap(), [6]);
        drop(rx);
        device.transmit(now).unwrap().consume(0, |_| ());
        assert!(device.closed_tunnel_warned);

        let (other_tx, other_rx) = mpsc::channel();
        let mut other = TunnelDevice::new(other_tx);
        assert!(!other.closed_tunnel_warned);
        other
            .transmit(now)
            .unwrap()
            .consume(1, |packet| packet[0] = 7);
        assert_eq!(other_rx.try_recv().unwrap(), [7]);
        assert!(device.closed_tunnel_warned);
    }
}
