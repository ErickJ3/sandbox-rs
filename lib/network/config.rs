//! Network configuration for sandbox isolation

use crate::errors::{Result, SandboxError};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,
    /// IPv4 address
    pub ipv4: Ipv4Addr,
    /// Netmask
    pub netmask: Ipv4Addr,
    /// Gateway
    pub gateway: Option<Ipv4Addr>,
    /// Whether to enable
    pub enabled: bool,
}

impl Default for NetworkInterface {
    fn default() -> Self {
        Self {
            name: "eth0".to_string(),
            ipv4: Ipv4Addr::new(172, 17, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(Ipv4Addr::new(172, 17, 0, 1)),
            enabled: true,
        }
    }
}

impl NetworkInterface {
    /// Create new network interface
    pub fn new(name: &str, ipv4: Ipv4Addr) -> Self {
        Self {
            name: name.to_string(),
            ipv4,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(Ipv4Addr::new(172, 17, 0, 1)),
            enabled: true,
        }
    }

    /// Validate interface configuration
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "Interface name cannot be empty".to_string(),
            ));
        }

        // Check if IP is valid container range (not 0.0.0.0 or broadcast)
        if self.ipv4.is_unspecified() || self.ipv4.is_broadcast() {
            return Err(SandboxError::InvalidConfig(
                "Invalid IP address for interface".to_string(),
            ));
        }

        Ok(())
    }

    /// Get CIDR notation
    pub fn get_cidr(&self) -> String {
        format!("{}/{}", self.ipv4, self.netmask_bits())
    }

    /// Get netmask bits (/24, /16, etc.)
    pub fn netmask_bits(&self) -> u8 {
        let octets = self.netmask.octets();
        let mut bits = 0u8;

        for octet in octets {
            bits += octet.count_ones() as u8;
        }

        bits
    }
}

/// Network mode for sandbox
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NetworkMode {
    /// Isolated network namespace
    #[default]
    Isolated,
    /// Bridge mode (connected via virtual bridge)
    Bridge,
    /// Host network namespace
    Host,
    /// Custom configuration
    Custom,
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkMode::Isolated => write!(f, "isolated"),
            NetworkMode::Bridge => write!(f, "bridge"),
            NetworkMode::Host => write!(f, "host"),
            NetworkMode::Custom => write!(f, "custom"),
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network mode
    pub mode: NetworkMode,
    /// Network interfaces
    pub interfaces: Vec<NetworkInterface>,
    /// DNS servers
    pub dns_servers: Vec<IpAddr>,
    /// Exposed ports (container:host)
    pub port_mappings: Vec<PortMapping>,
    /// Enable IP forwarding
    pub ip_forward: bool,
    /// Maximum bandwidth (bytes/sec, 0 = unlimited)
    pub bandwidth_limit: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Isolated,
            interfaces: vec![NetworkInterface::default()],
            dns_servers: vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ],
            port_mappings: Vec::new(),
            ip_forward: false,
            bandwidth_limit: 0,
        }
    }
}

impl NetworkConfig {
    /// Create isolated network config
    pub fn isolated() -> Self {
        Self {
            mode: NetworkMode::Isolated,
            interfaces: vec![NetworkInterface::default()],
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            port_mappings: Vec::new(),
            ip_forward: false,
            bandwidth_limit: 0,
        }
    }

    /// Create host network config
    pub fn host() -> Self {
        Self {
            mode: NetworkMode::Host,
            interfaces: Vec::new(),
            dns_servers: Vec::new(),
            port_mappings: Vec::new(),
            ip_forward: true,
            bandwidth_limit: 0,
        }
    }

    /// Add interface
    pub fn add_interface(&mut self, iface: NetworkInterface) -> Result<()> {
        iface.validate()?;
        self.interfaces.push(iface);
        Ok(())
    }

    /// Add port mapping
    pub fn add_port_mapping(&mut self, mapping: PortMapping) -> Result<()> {
        mapping.validate()?;
        self.port_mappings.push(mapping);
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        for iface in &self.interfaces {
            iface.validate()?;
        }

        for mapping in &self.port_mappings {
            mapping.validate()?;
        }

        Ok(())
    }
}

/// Port mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Container port
    pub container_port: u16,
    /// Host port
    pub host_port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
}

impl PortMapping {
    /// Create new port mapping
    pub fn new(container_port: u16, host_port: u16) -> Self {
        Self {
            container_port,
            host_port,
            protocol: "tcp".to_string(),
        }
    }

    /// Validate port mapping
    pub fn validate(&self) -> Result<()> {
        if self.container_port == 0 || self.host_port == 0 {
            return Err(SandboxError::InvalidConfig(
                "Port numbers must be > 0".to_string(),
            ));
        }

        if !["tcp", "udp"].contains(&self.protocol.as_str()) {
            return Err(SandboxError::InvalidConfig(
                "Protocol must be tcp or udp".to_string(),
            ));
        }

        Ok(())
    }

    /// Get socket address for host
    pub fn get_host_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.host_port))
    }

    /// Get socket address for container
    pub fn get_container_addr(&self, ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::from((ip, self.container_port))
    }
}

/// Network statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Bytes received
    pub bytes_recv: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Packets received
    pub packets_recv: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Errors
    pub errors: u64,
    /// Dropped packets
    pub dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_interface_creation() {
        let iface = NetworkInterface::new("eth0", Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.ipv4, Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn test_network_interface_validation() {
        let mut iface = NetworkInterface::default();
        assert!(iface.validate().is_ok());

        iface.ipv4 = Ipv4Addr::UNSPECIFIED;
        assert!(iface.validate().is_err());
    }

    #[test]
    fn test_network_interface_cidr() {
        let iface = NetworkInterface::default();
        let cidr = iface.get_cidr();
        assert!(cidr.contains("/"));
    }

    #[test]
    fn test_netmask_bits() {
        let iface = NetworkInterface {
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            ..Default::default()
        };
        assert_eq!(iface.netmask_bits(), 24);
    }

    #[test]
    fn test_network_mode_display() {
        assert_eq!(NetworkMode::Isolated.to_string(), "isolated");
        assert_eq!(NetworkMode::Bridge.to_string(), "bridge");
        assert_eq!(NetworkMode::Host.to_string(), "host");
    }

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.mode, NetworkMode::Isolated);
        assert!(!config.interfaces.is_empty());
    }

    #[test]
    fn test_network_config_isolated() {
        let config = NetworkConfig::isolated();
        assert_eq!(config.mode, NetworkMode::Isolated);
    }

    #[test]
    fn test_network_config_host() {
        let config = NetworkConfig::host();
        assert_eq!(config.mode, NetworkMode::Host);
        assert!(config.ip_forward);
    }

    #[test]
    fn test_port_mapping_creation() {
        let mapping = PortMapping::new(8080, 8080);
        assert_eq!(mapping.container_port, 8080);
        assert_eq!(mapping.host_port, 8080);
    }

    #[test]
    fn test_port_mapping_validation() {
        let mapping = PortMapping::new(8080, 8080);
        assert!(mapping.validate().is_ok());

        let bad_mapping = PortMapping {
            container_port: 0,
            host_port: 8080,
            protocol: "tcp".to_string(),
        };
        assert!(bad_mapping.validate().is_err());
    }

    #[test]
    fn test_port_mapping_addresses() {
        let mapping = PortMapping::new(8080, 8080);
        let host_addr = mapping.get_host_addr();
        assert_eq!(host_addr.port(), 8080);
    }

    #[test]
    fn test_network_stats_default() {
        let stats = NetworkStats::default();
        assert_eq!(stats.bytes_recv, 0);
        assert_eq!(stats.bytes_sent, 0);
    }
}
