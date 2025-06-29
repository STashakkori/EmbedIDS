// $t@$h
use rumqttc::{AsyncClient, EventLoop, MqttOptions};
use std::time::Duration;
use crate::types::*;

pub async fn initialize_mqtt_client() -> Result<(AsyncClient, EventLoop), Box<dyn std::error::Error>> {
    let mut opts = MqttOptions::new(MQTT_CLIENT_ID, MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT);
    opts.set_keep_alive(Duration::from_secs(60));
    Ok(rumqttc::AsyncClient::new(opts, 10))
}
