use std::{fmt::format, fs::{File, create_dir}, io::{Read, Write}, path::{MAIN_SEPARATOR, PathBuf}, time::Duration};

extern crate serde;
extern crate quick_xml;

mod xml_data;

use xml_data::NmapRun;
use std::fs;

use crate::xml_data::{Protocol, Reason};

struct Config {
    out_dir: PathBuf,
    tcp_port_files_dir: PathBuf,
    udp_port_files_dir: PathBuf,
    metadata_file: PathBuf,
    alive_hosts_icmp: PathBuf,
    alive_hosts_ports: PathBuf,
    alive_hosts_forced: PathBuf,
}
fn main() {
    let xml_file_name = "test.xml";
    let out_dir_name = "Parsed-Results/";

    // Configure paths for the various output files
    let config = Config {
        out_dir: PathBuf::from(out_dir_name),
        tcp_port_files_dir: [out_dir_name, "port-files-tcp/"].iter().collect(),
        udp_port_files_dir: [out_dir_name, "port-files-udp/"].iter().collect(),
        metadata_file: [out_dir_name, "scan-metadata.txt"].iter().collect(),
        alive_hosts_icmp: [out_dir_name, "alive-hosts-icmp.txt"].iter().collect(),
        alive_hosts_ports: [out_dir_name, "alive-hosts-with-open-ports.txt"].iter().collect(),
        alive_hosts_forced: [out_dir_name, "alive-hosts-forced.txt"].iter().collect(),

    };

    // Read and parse the XML file into an easy to work with struct
    let mut xml_file = File::open(xml_file_name).unwrap();
    let mut xml = String::new();
    xml_file.read_to_string(&mut xml).unwrap();
    let xml = xml;
    let nmap_run: NmapRun = quick_xml::de::from_str(&xml).unwrap();

    // Step 1: Create results directory if it does not exist
    fs::create_dir_all(&out_dir_name)
        .expect("Failed to create results directory. Check your permissions and try again");

    // Step 2: Metadata file
    let mut f = File::create(config.metadata_file).unwrap();
    f.write(format!(
        "Scan Start:\t{}\nScan End:\t{}\nElapsed Time:\t{}s\nNmap Version:\t{}\nNmap Command:\t{}\n",
        nmap_run.startstr,
        nmap_run.runstats.finished.timestr,
        nmap_run.runstats.finished.elapsed,
        nmap_run.version,
        nmap_run.args).as_bytes()).unwrap();
    
    // Step 3: Alive Hosts via ICMP
    let mut f = File::create(config.alive_hosts_icmp).unwrap();
    for host in nmap_run.alive_hosts_for_reason(Reason::EchoReply) {
        f.write(format!("{}\n", host.address.addr).as_bytes()).unwrap();
    }

    // Step 4: Alive Hosts via -Pn flag
    let mut f = File::create(config.alive_hosts_forced).unwrap();
    for host in nmap_run.alive_hosts_for_reason(Reason::Forced) {
        f.write(format!("{}\n", host.address.addr).as_bytes()).unwrap();
    }

    // Step 5: Alive Hosts with Open Ports
    let mut f = File::create(config.alive_hosts_ports).unwrap();
    for host in nmap_run.alive_hosts_with_open_ports() {
        f.write(format!("{}\n", host.address.addr).as_bytes()).unwrap();
    }

    // Step 6: Create Port Files
    // Step 6.1: TCP
    let ports = nmap_run.all_ports_for_protocol(Protocol::TCP);
    if ports.len() > 0 {
        fs::create_dir(&config.tcp_port_files_dir).unwrap();
        
        for port in ports {
            let filename = format!("{}{}{}.txt",
                (&config.tcp_port_files_dir).to_str().unwrap(),
                MAIN_SEPARATOR,
                port.to_string());
            let mut f = File::create(filename).unwrap();
            for host in nmap_run.hosts_with_this_port_open(Protocol::TCP, port) {
                f.write(format!("{}\n", host.address.addr).as_bytes()).unwrap();
            }
        }
    }

    // Step 6.2: UDP
    let ports  = nmap_run.all_ports_for_protocol(Protocol::UDP);
    if ports.len() > 0 {
        fs::create_dir(&config.tcp_port_files_dir).unwrap();

        for port in ports {
            let filename = format!("{}{}{}.txt",
                (&config.tcp_port_files_dir).to_str().unwrap(),
                MAIN_SEPARATOR,
                port.to_string());
            let mut f = File::create(filename).unwrap();
            for host in nmap_run.hosts_with_this_port_open(Protocol::UDP, port) {
                f.write(format!("{}\n", host.address.addr).as_bytes()).unwrap();
            }
        }
    }
}