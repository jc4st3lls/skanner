use native_tls::{TlsConnector, Protocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};

use crate::netscan_win;

struct ScanOptions {
    proto: String,
    protocol: Option<Protocol>,
}

impl ScanOptions {
    pub fn new(proto: String, protocol: Option<Protocol>) -> Self {
        ScanOptions { proto, protocol }
    }
}

pub fn sslscan(domain: String, port: u16) -> Result<String, String> {
    // Resolver el nombre de dominio a direcciones IP
    let dom = domain.as_str();
    let hostname = dom.to_string();
    let ips: Vec<SocketAddr> = match (hostname, port).to_socket_addrs() {
        Ok(ips) => ips.collect(),
        Err(_error) => {
            return Err("No se pudo resolver el dominio".to_string());
        }
    };

    // Verificar si el puerto está abierto (solo IPv4)
    for ip in ips {
        if ip.is_ipv4() {
            let ipv4 = convert_to_ipv4(ip.ip()).unwrap();
            if netscan_win::is_port_open(ipv4, port, None).unwrap() == false {
                return Err(format!("El puerto {} está cerrado.", port));
            } else {
                break;
            }
        }
    }

    let domain = dom.to_string();
    let sslversions: Vec<ScanOptions> = vec![
        ScanOptions::new("ssl3".to_string(), Some(Protocol::Sslv3)),
        ScanOptions::new("tls1".to_string(), Some(Protocol::Tlsv10)),
        ScanOptions::new("tls1.1".to_string(), Some(Protocol::Tlsv11)),
        ScanOptions::new("tls1.2".to_string(), Some(Protocol::Tlsv12)),
        //ScanOptions::new("tls1.3".to_string(),Some(Protocol::Tlsv13))
    ];

    let mut results: Vec<String> = Vec::new();

    for sslversion in sslversions {
        let mut builder = TlsConnector::builder();

        // Configurar versión específica
        if let Some(proto) = sslversion.protocol {
            builder.min_protocol_version(Some(proto));
            builder.max_protocol_version(Some(proto));
        }

        match builder.build() {
            Ok(connector) => {
                let addr = format!("{}:{}", domain, port);
                match TcpStream::connect(&addr) {
                    Ok(stream) => {
                        match connector.connect(&domain, stream) {
                            Ok(_tls_stream) => {
                                results.push(sslversion.proto.clone());
                            }
                            Err(_error) => {
                                results.push("".to_string());
                            }
                        }
                    }
                    Err(_) => {
                        results.push("".to_string());
                    }
                }
            }
            Err(_) => {
                results.push("".to_string());
            }
        }
    }

    Ok(results.join(","))
}

fn convert_to_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    if let IpAddr::V4(ipv4) = ip {
        Some(ipv4)
    } else {
        None
    }
}