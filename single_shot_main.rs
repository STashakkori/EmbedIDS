// $t@$h
// For now use arpspoofing to route traffic through the board to sniff
// Thank you Firewalla Red for some ideas on that :]
// Currently only checks egress for uploads and reports it
// Aka its only useful right now to check if someone is snooping on you
// or otherwise nominal case of uploading data. External MQTT broker used for test
// Tested on Raspberry Pi 3B. Goal is to keep everything board agnostic and low footprint
use pnet::datalink::{self, MacAddr, NetworkInterface, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols, IpPacket};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::transport::{self, TransportChannelType};
use std::net::{Ipv4Addr, IpAddr};
use std::time::Duration;
use std::thread;
use rumqttc::{MqttOptions, Client, QoS};
use tokio;

const MQTT_CLIENT_ID: &str = "rust_mqtt";
const MQTT_BROKER_ADDRESS: &str = "broker.hivemq.com";
const MQTT_BROKER_PORT: u16 = 1337;
const IDS_UPLOAD_TOPIC: &str = "ids/upload";
const IDS_INGRESS_TOPIC: &str = "ids/ingress";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (interface, source_mac, local_ip) = initialize_network()?;
    let target_mac = send_arp_request(&interface, &local_ip, &source_mac)?;
    let mut mqtt_client = initialize_mqtt_client();
    spawn_mqtt_notification_handler(&mut mqtt_client);
    spawn_arp_spoofing_thread(&interface, source_mac, target_mac, local_ip);
    packet_processing_loop(local_ip, &mut mqtt_client);
    Ok(())
}

fn initialize_network() -> Result<(NetworkInterface, MacAddr, Ipv4Addr), Box<dyn std::error::Error>> {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.is_up() && iface.is_broadcast() && !iface.is_loopback())
        .expect("!!!No suitable network interface found");
    let source_mac = interface.mac.ok_or("!!!No MAC address found for interface")?;
    let local_ip = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| ip.ip())
        .ok_or("!!!No IPv4 address found for interface")?;
    Ok((interface, source_mac, local_ip))
}

fn initialize_mqtt_client() -> Client {
    let mut mqtt_options = MqttOptions::new(MQTT_CLIENT_ID, MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT);
    mqtt_options.set_keep_alive(Duration::from_secs(60));
    let (mut mqtt_client, _) = Client::new(mqtt_options, 10);
    mqtt_client
}

fn spawn_mqtt_notification_handler(mqtt_client: &mut Client) {
    tokio::spawn(async move {
        for notification in mqtt_client.iter() {
            if let Ok(notification) = notification {
                println!("{:?}", notification);
            }
        }
    });
}

fn spawn_arp_spoofing_thread(interface: &NetworkInterface, source_mac: MacAddr, target_mac: MacAddr, local_ip: Ipv4Addr) {
    thread::spawn(move || {
        loop {
            send_arp_reply(interface, source_mac, target_mac, local_ip);
            thread::sleep(Duration::from_secs(2));
        }
    });
}

fn packet_processing_loop(local_ip: Ipv4Addr, mqtt_client: &mut Client) {
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("!!!Datalink channel blank error"),
        Err(e) => panic!("!!!Datalink channel error: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                if let Some(ip) = IpPacket::new(ethernet.payload()) {
                    if ip.get_source() == local_ip {
                        handle_ethernet_packet(&ethernet);
                    }
                }
            },
            Err(e) => { eprintln!("!!!Packet read error: {}", e); }
        }
    }
}

fn send_arp_request(interface: &NetworkInterface, local_ip: &Ipv4Addr, source_mac: &MacAddr) -> Result<MacAddr, Box<dyn std::error::Error>> {
    let target_mac = send_arp_request_to_target(interface, local_ip, source_mac);
    Ok(target_mac)
}

fn send_arp_request_to_target(interface: &NetworkInterface, local_ip: &Ipv4Addr, source_mac: &MacAddr) -> MacAddr {
    let target_ip = Ipv4Addr::new(192, 168, 0, 1);
    send_arp_request(&interface, local_ip, source_mac, &target_ip)
}

fn send_arp_reply(interface: &NetworkInterface, source_mac: MacAddr, target_mac: MacAddr, local_ip: Ipv4Addr) {
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(local_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(local_ip);

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    // Send packet
    let mut tx = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, _)) => tx,
        Ok(_) => panic!("!!!Datalink channel blank error"),
        Err(e) => panic!("!!!Datalink channel error: {}", e),
    };
    tx.send_to(ethernet_packet.packet(), None).unwrap();
}

fn handle_ethernet_packet(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(packet) = IpPacket::new(ethernet.payload()) {
                match packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(packet.payload()) {
                            analyze_tcp_packet(&tcp);
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(packet.payload()) {
                            analyze_udp_packet(&udp);
                        }
                    },
                    _ => {} // Ignore other protocols
                }
            }
        },
        _ => {} // Ignore non-IPv4
    }
}

fn analyze_tcp_packet(tcp: &TcpPacket) {
    // Test to make sure code getting in here
    let data_length = tcp.payload().len();
    if data_length > 0 {
        let message = format!("Upload detected- {} bytes TCP", data_length);
        println!("{}", message);
    }
}

fn analyze_udp_packet(udp: &UdpPacket) {
    // Ingress rules are TODO. Need to write the isolated machine learning algorithms first
}
