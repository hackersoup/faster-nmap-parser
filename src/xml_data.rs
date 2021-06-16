use serde::Deserialize;

// Written for Nmap XML version 1.03

// This is the root element!
#[derive(Debug, Deserialize)]
pub struct NmapRun {
    pub scanner: String,
    pub args: String,
    pub start: u64,
    pub startstr: String,
    pub version: String,
    pub xmloutputversion: String,
    #[serde(rename = "host", default)]
    pub hosts: Vec<Host>,
    pub runstats: RunStats,
}

impl<'a> NmapRun {
    pub fn alive_hosts_for_reason(&'a self, reason: Reason) -> Vec<&'a Host> {
        self.hosts.iter()
            .filter(|host| host.status.state == State::Up
                && host.status.reason == reason)
            .collect()
    }

    pub fn alive_hosts_with_open_ports(&'a self) -> Vec<&'a Host> {
        self.hosts.iter()
            .filter(|host| host.ports.ports.len() > 0)
            .collect()
    }

    pub fn all_ports_for_protocol(&'a self, protocol: Protocol) -> Vec<u16> {
        self.hosts.iter()
            .map(|host| host.ports.ports.iter()
                .filter(|port| port.protocol == protocol)
                .map(|port| port.port))
            .flatten()
            .collect()
    }

    pub fn hosts_with_this_port_open(&'a self, protocol: Protocol, port: u16) -> Vec<&'a Host> {
        self.hosts.iter()
            .filter(|host| host.ports.ports.iter()
                .any(|host_port| host_port.protocol == protocol
                    && host_port.port == port))
            .collect()
    }
}


#[derive(Debug, Deserialize)]
pub struct Host {
    pub starttime: u64,
    pub endtime: u64,
    pub status: Status,
    pub address: Address,
    pub ports: Ports,
}

#[derive(Debug, Deserialize, PartialEq)]
pub enum State {
    #[serde(rename = "up")]
    Up,
    #[serde(rename = "down")]
    Down,
}

#[derive(Debug, Deserialize, PartialEq)]
pub enum Reason {
    #[serde(rename = "echo-reply")]
    EchoReply,
    #[serde(rename = "forced")]
    Forced,
}

#[derive(Debug, Deserialize)]
pub struct Status {
    pub state: State,
    pub reason: Reason,
}

#[derive(Debug, Deserialize)]
pub enum AddrType {
    #[serde(rename = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    IPv6,
}

#[derive(Debug, Deserialize)]
pub struct Address {
    pub addr: String,
    pub addrtype: AddrType
}

#[derive(Debug, Deserialize)]
pub struct Ports {
    #[serde(rename = "port", default)]
    pub ports: Vec<Port>
}

#[derive(Debug, Deserialize)]
pub struct Port {
    pub protocol: Protocol,
    #[serde(rename = "portid")]
    pub port: u16
}

#[derive(Debug, Deserialize, PartialEq)]
pub enum Protocol {
    #[serde(rename = "tcp")]
    TCP,
    #[serde(rename = "udp")]
    UDP,
}

#[derive(Debug, Deserialize)]
pub struct RunStats {
    pub finished: Finished
}

#[derive(Debug, Deserialize)]
pub struct Finished {
    pub time: u64,
    pub timestr: String,
    pub elapsed: f64,
    pub summary: String,
    pub exit: ExitCode
}

#[derive(Debug, Deserialize)]
pub enum ExitCode {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    Failure,
}