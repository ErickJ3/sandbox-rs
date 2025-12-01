use super::{NetworkConfig, NetworkInterface, NetworkMode, NetworkStats, PortMapping};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn network_config_supports_multiple_interfaces() {
    let mut config = NetworkConfig::isolated();
    let iface1 = NetworkInterface::new("eth0", Ipv4Addr::new(10, 10, 0, 1));
    let iface2 = NetworkInterface::new("eth1", Ipv4Addr::new(10, 10, 0, 2));
    config.add_interface(iface1).expect("interface valid");
    config.add_interface(iface2).expect("interface valid");

    assert_eq!(config.interfaces.len(), 2);
    assert!(config.validate().is_ok());
}

#[test]
fn network_config_accepts_port_mappings_with_protocols() {
    let mut config = NetworkConfig::isolated();
    let mut mapping = PortMapping::new(8080, 18080);
    mapping.protocol = "udp".to_string();
    config.add_port_mapping(mapping).expect("mapping valid");

    assert_eq!(config.port_mappings.len(), 1);
    assert_eq!(config.port_mappings[0].protocol, "udp");
}

#[test]
fn network_config_validation_catches_invalid_interface() {
    let mut iface = NetworkInterface::default();
    iface.name.clear();
    assert!(iface.validate().is_err());
}

#[test]
fn port_mapping_validation_rejects_bad_protocol() {
    let mut mapping = PortMapping::new(80, 8080);
    mapping.protocol = "icmp".to_string();
    assert!(mapping.validate().is_err());
}

#[test]
fn port_mapping_addresses_match_host_and_container() {
    let mapping = PortMapping::new(8080, 18080);
    let host_addr = mapping.get_host_addr();
    let container_addr = mapping.get_container_addr(Ipv4Addr::new(172, 18, 0, 2));

    assert_eq!(host_addr.port(), 18080);
    assert_eq!(container_addr.port(), 8080);
}

#[test]
fn network_config_serialization_roundtrip() {
    let mut config = NetworkConfig::isolated();
    config.dns_servers = vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))];

    let json = serde_json::to_string(&config).expect("serialize network config");
    let restored: NetworkConfig = serde_json::from_str(&json).expect("deserialize config");

    assert_eq!(restored.mode, NetworkMode::Isolated);
    assert_eq!(
        restored.dns_servers[0],
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))
    );
}

#[test]
fn network_stats_accumulates_values() {
    let stats = NetworkStats {
        bytes_recv: 1024,
        bytes_sent: 2048,
        packets_recv: 10,
        packets_sent: 20,
        ..Default::default()
    };

    assert_eq!(stats.bytes_recv, 1024);
    assert_eq!(stats.bytes_sent, 2048);
    assert_eq!(stats.packets_recv + stats.packets_sent, 30);
}
