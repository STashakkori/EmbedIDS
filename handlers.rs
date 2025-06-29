// $t@$h
use crate::types::*;
use anyhow::Result;
use log::info;
use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface, MacAddr},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ipv4::Ipv4Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        ip::IpNextHeaderProtocols,
        Packet,
    },
};
use rumqttc::{AsyncClient, QoS};
use std::net::Ipv4Addr;

pub async fn packet_processing_loop(
    interface: &NetworkInterface,
    local_ip: Ipv4Addr,
    _source_mac: MacAddr,
    mqtt_client: AsyncClient,
) -> Result<()> {
    let (_, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => return Err(anyhow::anyhow!("Unhandled channel type")),
        Err(e) => return Err(e.into()),
    };

    loop {
        let packet = match rx.next() {
            Ok(pkt) => pkt,
            Err(_) => continue,
        };

        let ethernet = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => continue,
        };

        if ethernet.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }

        let ip = match Ipv4Packet::new(ethernet.payload()) {
            Some(p) => p,
            None => continue,
        };

        if ip.get_source() != local_ip {
            continue;
        }

        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ip.payload()) {
                    handle_tcp_packet(tcp, &mqtt_client).await?;
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ip.payload()) {
                    handle_udp_packet(udp, &mqtt_client).await?;
                }
            }
            _ => {}
        }
    }
}

async fn handle_tcp_packet(pkt: TcpPacket, mqtt: &AsyncClient) -> Result<()> {
    let len = pkt.payload().len();
    if len > 0 {
        let msg = format!("TCP payload detected: {} bytes", len);
        mqtt.publish(IDS_UPLOAD_TOPIC, QoS::AtLeastOnce, false, msg.clone()).await?;
        info!("✓ TCP alert published: {}", msg);
    }
    Ok(())
}

async fn handle_udp_packet(pkt: UdpPacket, mqtt: &AsyncClient) -> Result<()> {
    let len = pkt.payload().len();
    if len > 0 {
        let msg = format!("UDP payload detected: {} bytes", len);
        mqtt.publish(IDS_INGRESS_TOPIC, QoS::AtLeastOnce, false, msg.clone()).await?;
        info!("✓ UDP alert published: {}", msg);
    }
    Ok(())
}
