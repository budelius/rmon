//! Best-effort "which TCP/UDP endpoints are open, and by which process"
//! lookup, via `GetExtendedTcpTable`/`GetExtendedUdpTable` (iphlpapi).
//!
//! Unlike the open-files scan in `handles.rs`, this is a handful of cheap
//! syscalls (one per protocol/address-family) that already cover every
//! process on the system at once — no per-process elevation dance, no
//! kernel handle-table walking — so it's safe to poll every sampling tick.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE, MIB_TCP_STATE_CLOSE_WAIT,
    MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB,
    MIB_TCP_STATE_FIN_WAIT1, MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN,
    MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Transport-layer protocol of a `PortEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        }
    }
}

/// TCP connection state (`MIB_TCP_STATE`). UDP is connectionless, so
/// `PortEntry::state` is always `None` for UDP rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl TcpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRcvd => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::DeleteTcb => "DELETE_TCB",
            TcpState::Unknown => "UNKNOWN",
        }
    }

    fn from_raw(state: u32) -> Self {
        match MIB_TCP_STATE(state as i32) {
            MIB_TCP_STATE_CLOSED => TcpState::Closed,
            MIB_TCP_STATE_LISTEN => TcpState::Listen,
            MIB_TCP_STATE_SYN_SENT => TcpState::SynSent,
            MIB_TCP_STATE_SYN_RCVD => TcpState::SynRcvd,
            MIB_TCP_STATE_ESTAB => TcpState::Established,
            MIB_TCP_STATE_FIN_WAIT1 => TcpState::FinWait1,
            MIB_TCP_STATE_FIN_WAIT2 => TcpState::FinWait2,
            MIB_TCP_STATE_CLOSE_WAIT => TcpState::CloseWait,
            MIB_TCP_STATE_CLOSING => TcpState::Closing,
            MIB_TCP_STATE_LAST_ACK => TcpState::LastAck,
            MIB_TCP_STATE_TIME_WAIT => TcpState::TimeWait,
            MIB_TCP_STATE_DELETE_TCB => TcpState::DeleteTcb,
            _ => TcpState::Unknown,
        }
    }
}

/// One TCP or UDP endpoint from the system-wide table `GetExtendedTcpTable`/
/// `GetExtendedUdpTable` returns, already annotated with the owning PID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortEntry {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    /// `None` for UDP (connectionless) or a TCP row that isn't actively
    /// connected (e.g. still `LISTEN`).
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    /// `None` for UDP.
    pub state: Option<TcpState>,
    pub pid: u32,
}

impl PortEntry {
    /// True for TCP rows in `LISTEN` state and all UDP rows — a bound UDP
    /// socket has no "listen" state of its own, but is the closest
    /// equivalent, and the convention tools like `netstat -a` use.
    pub fn is_listening(&self) -> bool {
        match self.protocol {
            Protocol::Udp => true,
            Protocol::Tcp => self.state == Some(TcpState::Listen),
        }
    }
}

/// All TCP (v4+v6) and UDP (v4+v6) endpoints on the system, each tagged with
/// its owning PID. A handful of syscalls total; cheap enough to poll every
/// sampling tick and reuse for both a single process's detail view and a
/// system-wide search.
pub fn list_all_ports() -> Result<Vec<PortEntry>> {
    let mut out = Vec::new();
    out.extend(list_tcp4()?);
    out.extend(list_tcp6()?);
    out.extend(list_udp4()?);
    out.extend(list_udp6()?);
    Ok(out)
}

/// Only the listening/bound endpoints owned by `pid`, out of a previously
/// collected `list_all_ports()` result — the subset most relevant to a
/// process detail view.
pub fn listening_ports_for(ports: &[PortEntry], pid: u32) -> Vec<PortEntry> {
    ports
        .iter()
        .filter(|p| p.pid == pid && p.is_listening())
        .cloned()
        .collect()
}

fn list_tcp4() -> Result<Vec<PortEntry>> {
    let buf = unsafe {
        query_growing_buffer(|ptr, size| {
            GetExtendedTcpTable(
                Some(ptr),
                size,
                true,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        })
    }?;
    let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let num = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), num) };
    Ok(rows
        .iter()
        .map(|r| {
            let state = TcpState::from_raw(r.dwState);
            let connected = state != TcpState::Listen;
            PortEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
                local_port: u16::from_be(r.dwLocalPort as u16),
                remote_addr: connected
                    .then(|| IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)))),
                remote_port: connected.then(|| u16::from_be(r.dwRemotePort as u16)),
                state: Some(state),
                pid: r.dwOwningPid,
            }
        })
        .collect())
}

fn list_tcp6() -> Result<Vec<PortEntry>> {
    let buf = unsafe {
        query_growing_buffer(|ptr, size| {
            GetExtendedTcpTable(
                Some(ptr),
                size,
                true,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        })
    }?;
    let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let num = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), num) };
    Ok(rows
        .iter()
        .map(|r| {
            let state = TcpState::from_raw(r.dwState);
            let connected = state != TcpState::Listen;
            PortEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                local_port: u16::from_be(r.dwLocalPort as u16),
                remote_addr: connected.then(|| IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr))),
                remote_port: connected.then(|| u16::from_be(r.dwRemotePort as u16)),
                state: Some(state),
                pid: r.dwOwningPid,
            }
        })
        .collect())
}

fn list_udp4() -> Result<Vec<PortEntry>> {
    let buf = unsafe {
        query_growing_buffer(|ptr, size| {
            GetExtendedUdpTable(
                Some(ptr),
                size,
                true,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        })
    }?;
    let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let num = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), num) };
    Ok(rows
        .iter()
        .map(|r| PortEntry {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
            local_port: u16::from_be(r.dwLocalPort as u16),
            remote_addr: None,
            remote_port: None,
            state: None,
            pid: r.dwOwningPid,
        })
        .collect())
}

fn list_udp6() -> Result<Vec<PortEntry>> {
    let buf = unsafe {
        query_growing_buffer(|ptr, size| {
            GetExtendedUdpTable(
                Some(ptr),
                size,
                true,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        })
    }?;
    let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    let num = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), num) };
    Ok(rows
        .iter()
        .map(|r| PortEntry {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
            local_port: u16::from_be(r.dwLocalPort as u16),
            remote_addr: None,
            remote_port: None,
            state: None,
            pid: r.dwOwningPid,
        })
        .collect())
}

/// Calls `f(buffer_ptr, &mut size)` — a `GetExtended{Tcp,Udp}Table`-shaped
/// FFI call — growing `size` and retrying whenever it reports
/// `ERROR_INSUFFICIENT_BUFFER`, which can legitimately happen more than once
/// if the table grows between the sizing call and the real one.
unsafe fn query_growing_buffer(mut f: impl FnMut(*mut c_void, &mut u32) -> u32) -> Result<Vec<u8>> {
    let mut size: u32 = 1 << 15;
    loop {
        let mut buf = vec![0u8; size as usize];
        let mut out_size = size;
        let result = f(buf.as_mut_ptr() as *mut c_void, &mut out_size);
        if result == 0 {
            return Ok(buf);
        }
        if result == ERROR_INSUFFICIENT_BUFFER.0 {
            size = out_size.max(size * 2);
            continue;
        }
        bail!("iphlpapi query failed: win32 error {result}");
    }
}
