//! The kernel's socket buffers, pinned per connection role (RFC-0181, "Memory is charged once, for
//! its life", model point 4).
//!
//! A TCP socket the relay leaves alone is autotuned: the kernel grows its receive buffer up to
//! `net.ipv4.tcp_rmem`'s third field (6 MiB by default) and its send buffer up to `tcp_wmem`'s
//! (4 MiB), charged to the relay's cgroup and counted by no store. At 24,000 sockets that came to
//! about 3 GB against a 64 MiB headroom. So every socket the relay accepts or dials is given fixed
//! buffers here (`SO_RCVBUF`, `SO_SNDBUF`), sized for what its role carries, and the plan counts
//! each connection's buffers at what the kernel charges for them ([`Role::kernel_bytes`]), not at
//! what an idle socket happens to hold.
//!
//! What the kernel charges. Linux doubles the value asked for (the other half is its own
//! bookkeeping: each `sk_buff`'s header and the slack of its pages, `socket(7)`), so a socket asked
//! for `n` bytes may hold `2n`. It admits a packet while what it holds is under that, so it can pass
//! it by one packet: a socket's charge here is twice each buffer asked for and one largest packet
//! a direction ([`SKB_OVERSHOOT_BYTES`]). The kernel also caps what is asked for at
//! `net.core.rmem_max` and `net.core.wmem_max` (208 KiB by default; the relay holds no capability
//! to pass them), so a host that leaves them alone grants less and holds less: the charge here is
//! the most, whatever the host. Less granted is less throughput, not less safety, for the two
//! roles asking more than 208 KiB (a subscriber's sends and a member link's both ways); a host
//! that serves a raw subscriber across a continent raises them.
//!
//! Setting a buffer turns the kernel's autotuning off for that socket and for that direction, so
//! the buffer stays what was asked for the socket's life. A receive buffer set after the
//! connection is open does not by itself widen the window the kernel advertises (the window's
//! ceiling, `window_clamp`, is fixed from the buffer as the connection opens, `tcp(7)`), so the
//! clamp is set with it (`TCP_WINDOW_CLAMP`), to the bytes asked for.
//!
//! An accepted connection holds a feeder's buffers until it holds a place the plan counts for a
//! larger role: a subscriber once it has a place among the subscribers, a member's link once it
//! is admitted as a member, an engine once it has one of the engines' places
//! ([`Tuner::set`]). A connection under the connection cap that holds none of them (one still in
//! its handshake, a directory link, a relay not yet admitted, an engine past the engines' places)
//! pins no more than a feeder may, so the plan counts every connection at a feeder's and only the
//! counted places at more (`budget::Plan::connection_sockets`).

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

/// What a connection carries, which sizes its kernel buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A receiver publishing its batches: about 8 KB a second in, a few records out (`Welcome`,
    /// delivery tags). Also a probe, a stats reader and any connection before its handshake.
    Feeder,
    /// A client reading the relay's streams: a raw one up to about 170 MB a second out, its
    /// `Subscribe` and acknowledgements in. Also a plain BEAST reader.
    Subscriber,
    /// Another relay's MLAT taking its areas' raw one hop (RFC-0174 §2.3), while it holds one of
    /// the engines' places (`Hub::engine_place`): an area's raw out, a border band's worth.
    Engine,
    /// Another relay's link once it is a sharing member (admitted, or dialled as one): raw both
    /// ways. A directory link or a relay not yet admitted holds a feeder's.
    Member,
}

/// The receive buffer asked for a feeder: 32 KiB. A feeder sends about 8 KB a second, so the
/// window it allows (32 KiB) carries that at any round trip under four seconds, and a backlog
/// after a reconnect (up to 64 batches, about 1 MB) drains in about 7 s at 200 ms. It is the most
/// a connection that has not finished its handshake can pin on the way in.
pub const FEEDER_RCVBUF_BYTES: usize = 32 << 10;
/// The send buffer asked for a feeder: 16 KiB. What the relay sends a feeder is a few small records
/// a second; a larger message (a relay list) waits on the feeder's acknowledgements, bounded by the
/// writer's deadline (`noise::WRITE_TIMEOUT`), as any send to a slow reader does.
pub const FEEDER_SNDBUF_BYTES: usize = 16 << 10;
/// The receive buffer asked for a subscriber: 16 KiB. It sends its `Subscribe` and acknowledgements,
/// nothing at a rate.
pub const SUBSCRIBER_RCVBUF_BYTES: usize = 16 << 10;
/// The send buffer asked for a subscriber: 512 KiB. A raw subscriber reads up to about 170 MB a
/// second; 512 KiB in flight carries that at a 3 ms round trip (a client in the relay's own
/// datacentre or LAN, where the world's raw is read) and 40 MB a second at 12 ms; a deduplicated
/// one, a few MB a second, at any round trip. Further away a raw client reads slower, and falls
/// behind the stream as any slow reader does (`fanout::BEHIND_MS`). Each subscriber place pins it,
/// so it is what the subscriber cap times this costs in the kernel, planned.
pub const SUBSCRIBER_SNDBUF_BYTES: usize = 512 << 10;
/// The receive buffer asked for another relay's link: 64 KiB. Members bring in together at most
/// the members' shared rate (`--max-member-bytes-per-sec`, about a megabyte a second at the
/// default), and what this relay sends a member is its groups' share, spread over every member of
/// the stripe trees; 64 KiB carries 1.3 MB a second a link at a 50 ms round trip, more than either
/// asks of one link. The relay plans one per member session and one per link it dials, so each
/// kibibyte here is two thousand in the plan of a relay holding a thousand members.
pub const MEMBER_RCVBUF_BYTES: usize = 64 << 10;
/// The send buffer asked for another relay's link: 64 KiB, as its receive.
pub const MEMBER_SNDBUF_BYTES: usize = 64 << 10;
/// The receive buffer asked for an engine: 16 KiB. It sends its `Subscribe`, nothing at a rate.
pub const ENGINE_RCVBUF_BYTES: usize = 16 << 10;
/// The send buffer asked for an engine: 128 KiB. An engine takes the raw of the areas it solves
/// along their border band, a few hundred kilobytes a second for a busy area; 128 KiB carries 2.6
/// MB a second at a 50 ms round trip.
pub const ENGINE_SNDBUF_BYTES: usize = 128 << 10;

/// The most one packet takes past a full buffer, a direction: the kernel admits a packet while
/// what a socket holds is under its buffer, and a coalesced receive or a segmentation-offload send
/// is at most 64 KiB of payload in its pages, counted here with its header at 64 KiB and a page.
pub const SKB_OVERSHOOT_BYTES: usize = (64 << 10) + 4096;

/// What the kernel charges a feeder's socket at most: 112 KiB asked for, doubled, and a packet
/// past each buffer ([`Role::kernel_bytes`]).
pub const FEEDER_KERNEL_BYTES: usize = Role::Feeder.kernel_bytes();
/// What the kernel charges a subscriber's socket at most.
pub const SUBSCRIBER_KERNEL_BYTES: usize = Role::Subscriber.kernel_bytes();
/// What the kernel charges another relay's link at most.
pub const MEMBER_KERNEL_BYTES: usize = Role::Member.kernel_bytes();
/// What the kernel charges an engine's socket at most.
pub const ENGINE_KERNEL_BYTES: usize = Role::Engine.kernel_bytes();

impl Role {
    /// The receive and send buffers asked for, in bytes.
    pub const fn buffers(self) -> (usize, usize) {
        match self {
            Self::Feeder => (FEEDER_RCVBUF_BYTES, FEEDER_SNDBUF_BYTES),
            Self::Subscriber => (SUBSCRIBER_RCVBUF_BYTES, SUBSCRIBER_SNDBUF_BYTES),
            Self::Member => (MEMBER_RCVBUF_BYTES, MEMBER_SNDBUF_BYTES),
            Self::Engine => (ENGINE_RCVBUF_BYTES, ENGINE_SNDBUF_BYTES),
        }
    }

    /// The most the kernel charges one socket of this role: each buffer asked for doubled (Linux
    /// doubles what `SO_RCVBUF` and `SO_SNDBUF` ask), and one packet past each
    /// ([`SKB_OVERSHOOT_BYTES`]). What one hostile connection of the role can pin in the kernel
    /// for as long as it is open, which the connection's floor counts.
    pub const fn kernel_bytes(self) -> usize {
        let (receive, send) = self.buffers();
        2 * receive + 2 * send + 2 * SKB_OVERSHOOT_BYTES
    }
}

/// Gives `stream`'s socket the buffers of `role`. Setting these on an open TCP socket fails only
/// for a descriptor that is not one, which an open stream's is not, so nothing is returned: a
/// connection is served the same either way.
#[cfg(unix)]
pub fn configure(stream: &impl AsRawFd, role: Role) {
    set(stream.as_raw_fd(), role);
}

/// As [`configure`]; elsewhere than Unix, nothing.
#[cfg(not(unix))]
pub fn configure<S>(_stream: &S, _role: Role) {}

#[cfg(unix)]
fn set(fd: RawFd, role: Role) {
    let (receive, send) = role.buffers();
    let option = |level: libc::c_int, name: libc::c_int, bytes: usize| {
        let value = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX);
        // SAFETY: `setsockopt` reads one `c_int` from a live local for the length given, and
        // changes only the socket's own options.
        unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                std::ptr::from_ref(&value).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    };
    option(libc::SOL_SOCKET, libc::SO_RCVBUF, receive);
    option(libc::SOL_SOCKET, libc::SO_SNDBUF, send);
    // The window's ceiling follows the buffer, raised or lowered, on a connection already open.
    #[cfg(target_os = "linux")]
    option(libc::IPPROTO_TCP, libc::TCP_WINDOW_CLAMP, receive);
}

/// A handle on a socket's buffers taken before the stream is handed to the session that consumes
/// it, so the buffers can be set once the connection holds a place of its role ([`Tuner::set`]). It holds the
/// descriptor's number, not the socket: it is set only while the session that owns the stream is
/// in hand, so the number is still that socket's.
#[derive(Clone, Copy, Debug)]
pub struct Tuner {
    #[cfg(unix)]
    fd: Option<RawFd>,
}

impl Tuner {
    /// A stream with no kernel socket (an in-process pipe): setting does nothing.
    pub const fn none() -> Self {
        Self {
            #[cfg(unix)]
            fd: None,
        }
    }

    /// Gives the socket the buffers of `role`, if there is a socket.
    pub fn set(self, role: Role) {
        #[cfg(unix)]
        if let Some(fd) = self.fd {
            set(fd, role);
        }
        #[cfg(not(unix))]
        let _ = role;
    }
}

/// A stream whose kernel buffers can be set once its role is known ([`Tuner`]). A stream with no
/// kernel socket of its own (an in-process pipe, a test's wrapper of one) takes the default: none.
pub trait Tunable {
    fn tuner(&self) -> Tuner {
        Tuner::none()
    }
}

impl Tunable for tokio::net::TcpStream {
    fn tuner(&self) -> Tuner {
        Tuner {
            #[cfg(unix)]
            fd: Some(self.as_raw_fd()),
        }
    }
}

/// An in-process pipe (the tests' connections) has no kernel buffers.
impl Tunable for tokio::io::DuplexStream {}

impl<S: Tunable> Tunable for crate::egress::Socket<S> {
    fn tuner(&self) -> Tuner {
        self.get_ref().tuner()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// What a socket was given, read back: the kernel reports the doubled value it charges.
    fn granted(stream: &tokio::net::TcpStream, name: libc::c_int) -> usize {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `getsockopt` writes one `c_int` and its length into live locals.
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            );
        }
        usize::try_from(value).unwrap_or(0)
    }

    #[tokio::test]
    async fn each_role_is_given_its_buffers_and_charged_no_less_than_the_kernel_holds()
    -> Result<(), String> {
        let text = |error: std::io::Error| error.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        let dial = tokio::spawn(tokio::net::TcpStream::connect(address));
        let (accepted, _) = listener.accept().await.map_err(text)?;
        let _dialled = dial
            .await
            .map_err(|error| error.to_string())?
            .map_err(text)?;
        for role in [
            Role::Feeder,
            Role::Subscriber,
            Role::Member,
            Role::Engine,
            Role::Feeder,
        ] {
            accepted.tuner().set(role);
            let (receive, send) = role.buffers();
            let (got_receive, got_send) = (
                granted(&accepted, libc::SO_RCVBUF),
                granted(&accepted, libc::SO_SNDBUF),
            );
            // Linux doubles what is asked, past `rmem_max` and `wmem_max` capped first: never more
            // than twice what was asked, which the charge counts.
            assert!(got_receive <= 2 * receive, "{role:?}: {got_receive}");
            assert!(got_send <= 2 * send, "{role:?}: {got_send}");
            assert!(got_receive + got_send <= role.kernel_bytes());
            // And it took: a feeder's, asked under the default caps, is exactly doubled.
            if role == Role::Feeder {
                assert_eq!((got_receive, got_send), (2 * receive, 2 * send));
            }
        }
        Ok(())
    }
}
