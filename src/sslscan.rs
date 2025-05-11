use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};


use crate::netscan;

struct ScanOptions {
    proto: String,
    sslversion: Option<SslVersion>,
}
impl ScanOptions {
    pub fn new(proto: String, sslversion: Option<SslVersion>) -> Self {
        ScanOptions { proto, sslversion }
    }
}
pub fn sslscan(domain: String, port: u16) -> Result<String, String> {
    // Resolve hostname to IP addresses
    let dom = domain.as_str();
    let hostname = dom.to_string();
    let ips: Vec<SocketAddr> = match (hostname, port).to_socket_addrs() {
        Ok(ips) => ips.collect(),
        Err(_error) => {
            return Err("Not Resolved".to_string());
        }
    };

    
    for ip in ips {
        
        if ip.is_ipv4() {
            let ipv4 = convert_to_ipv4(ip.ip()).unwrap();
            if netscan::is_port_open(ipv4, port,None).unwrap() == false {
                return Err(format!("Port {} is closed.", port));
            } else {
                break;
            }
        }
    }

    let domain = dom.to_string();
    let sslversions: Vec<ScanOptions> = vec![
        ScanOptions::new("ssl3".to_string(), Some(SslVersion::SSL3)),
        ScanOptions::new("tls1".to_string(), Some(SslVersion::TLS1)),
        ScanOptions::new("tls1.1".to_string(), Some(SslVersion::TLS1_1)),
        ScanOptions::new("tls1.2".to_string(), Some(SslVersion::TLS1_2)),
        ScanOptions::new("tls1.3".to_string(), Some(SslVersion::TLS1_3)),
    ];

    let mut results: Vec<String> = Vec::new();

    for sslversion in sslversions {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.clear_options(SslOptions::NO_SSLV3);
        connector.clear_options(SslOptions::NO_TLSV1);
        connector.clear_options(SslOptions::NO_TLSV1_1);
        connector
            .set_max_proto_version(sslversion.sslversion)
            .unwrap();
        connector
            .set_min_proto_version(sslversion.sslversion)
            .unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        
        let connector = connector.build();
         

        let addr = format!("{}:{}", domain, port);
        match TcpStream::connect(&addr) {
            Ok(stream) => match connector.connect(&domain, stream) {
                Ok(_ssl_stream) => {
                    results.push(sslversion.proto.clone());
                    
                    

                }
                Err(_error) => {
                    results.push("".to_string());
                }
            },
            Err(_) => {}
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
