
use std::{ffi::CStr, net::Ipv4Addr};


use std::{io, os::raw::c_char};
use std::str;
use windows_sys::Win32::Networking::WinSock::{getnameinfo, WSACleanup, WSAGetLastError, WSAStartup, AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN, WSADATA, WSAHOST_NOT_FOUND, WSANO_DATA, WSANO_RECOVERY, WSATRY_AGAIN};

#[allow(non_camel_case_types)]
type libc_c_char = u8;



pub fn resolvenames(ips: Vec<String>, _ports: Option<Vec<u16>>) -> Option<Vec<String>> {
    let mut results: Vec<String> = Vec::new();
    
    for destip in ips.iter() {
        match resolvenameinfo(destip.as_str()) {
            Ok(hostname) => {
                let tmp = format!("{},{}", destip, hostname);
                results.push(tmp);
            },
            Err(_) => {}
        }
    }

    if !results.is_empty() {
        return Some(results);
    }

    None
}



pub fn resolvenameinfo(ip_address: &str) -> Result<String, String> {
    let destination_ip= ip_address.parse::<Ipv4Addr>();
    if destination_ip.is_err(){
        return Err("Error parsing IP".to_string());
    }

    // Parsear la dirección IP
    let octets = destination_ip.unwrap().octets();
    let addr=u32::from_le_bytes(octets);
    // Creem un adreça
    let in_addr = IN_ADDR{
        S_un: IN_ADDR_0{
            S_addr: addr,
        }
    };
    // creem un socket

    let sockaddr_in = SOCKADDR_IN {
        sin_family: AF_INET as u16,
        sin_port: 0, // ICMP no usa puertos

        sin_zero: [0; 8],
        sin_addr: in_addr,
    };
 
    // Configurar la estructura SOCKADDR según el tipo de IP


    let sockaddr_ptr=&sockaddr_in as *const _ as *const _;
    let sockaddr_len= std::mem::size_of::<SOCKADDR>() as i32;
    // Buffers para los resultados
   // Allocate buffers for name and service strings.
    let mut c_host = [0_u8; 1024];
    // No NI_MAXSERV, so use suggested value.
    let mut c_service = [0_u8; 32];

    unsafe {
        let mut wsa_data: WSADATA = std::mem::zeroed();
            if WSAStartup(0x202, &mut wsa_data) != 0 {
            panic!("WSAStartup failed");
        }

        let result =  getnameinfo(
            sockaddr_ptr,
            sockaddr_len,
            c_host.as_mut_ptr() as *mut libc_c_char,
            c_host.len() as _,
            c_service.as_mut_ptr() as *mut libc_c_char,
            c_service.len() as _,
            0,
        );

        WSACleanup();

        if result == 0 {
            let host =  CStr::from_ptr(c_host.as_ptr() as *const c_char) ;
            //let service = unsafe { CStr::from_ptr(c_service.as_ptr() as *const c_char) };

    let host = match str::from_utf8(host.to_bytes()) {
        Ok(name) => Ok(name.to_owned()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::Other,
            "Host UTF8 parsing failed",
        )),
    }.unwrap();
    Ok(host)
        } else {
            let error_code = WSAGetLastError();
            let error_msg = match error_code {
                WSAHOST_NOT_FOUND => "Host not found",
                WSATRY_AGAIN => "Temporary failure in name resolution",
                WSANO_RECOVERY => "Non-recoverable error in name resolution",
                WSANO_DATA => "Valid name, no data record of requested type",
                _ => "Unknown error",
            };
            Err(format!("Error {:?}: {:?}", error_code, error_msg))
        }
    }
}
