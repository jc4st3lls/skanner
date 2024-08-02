use std::{ffi::CStr, net::IpAddr};

use libc::{getnameinfo, sockaddr, sockaddr_in, AF_INET, EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NONAME, EAI_OVERFLOW, EAI_SYSTEM, NI_NAMEREQD, NI_NUMERICSERV};



pub fn resolvenames(ips:Vec<String>,_ports:Option<Vec<u16>>)->Option<Vec<String>>{
    let mut results:Vec<String>=Vec::new();
    
    for destip in ips.iter(){
        match resolvenameinfo(destip.as_str()) {
            Ok(hostname) => {

                let tmp=format!("{},{}",destip,hostname);
                results.push(tmp);
            },

            Err(_)=>{}
        }


      
    }

    if !results.is_empty(){
        return Some(results);
    }

    None

}
pub fn resolvenameinfo(ip_address: &str) -> Result<String, String> {
    let ip: IpAddr = ip_address.parse().map_err(|_| "Dirección IP no válida")?;
    
    let (sockaddr_storage, sockaddr_len): (Box<sockaddr>, u32) = match ip {
        IpAddr::V4(ipv4) => {
            let sockaddr_in = sockaddr_in {
                sin_family: AF_INET as u8,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(ipv4).to_be(),
                },
                sin_zero: [0; 8],sin_len:0
            };
            (Box::new(unsafe { std::mem::transmute(sockaddr_in) }), std::mem::size_of::<sockaddr_in>() as u32)
        },
        IpAddr::V6(_ipv6) => todo!()
        
    };

    let mut host_buf = vec![0u8; 1024];
    let mut service_buf = vec![0u8; 32];

    let result = unsafe {
        getnameinfo(
            &*sockaddr_storage as *const _,
            sockaddr_len,
            host_buf.as_mut_ptr() as *mut _,
            host_buf.len() as u32,
            service_buf.as_mut_ptr() as *mut _,
            service_buf.len() as u32,
            NI_NAMEREQD | NI_NUMERICSERV,
        )
    };

    if result == 0 {
        let hostname = unsafe { CStr::from_ptr(host_buf.as_ptr() as *const _) }
            .to_string_lossy()
            .into_owned();
        Ok(hostname)
    } else {
        let errmsg:&str;
        match result{
            EAI_AGAIN=>errmsg="The name could not be resolved at this time. Try again later.",
            EAI_BADFLAGS=>errmsg="The flags argument has an invalid value.",
            EAI_FAIL=>errmsg="A nonrecoverable error occurred.",
            EAI_FAMILY=>errmsg="The address family was not recognized, or the address length was invalid for the specified family.",
            EAI_MEMORY=>errmsg="Out of memory.",
            EAI_NONAME=> errmsg="The name does not resolve for the supplied arguments. NI_NAMEREQD is set and the host's name cannot be located, or neither hostname nor service name were requested.",
            EAI_OVERFLOW=>errmsg="The buffer pointed to by host or serv was too small.",
            EAI_SYSTEM=>errmsg="A system error occurred.  The error code can be found in errno. The gai_strerror(3) function translates these error codes to a human readable string, suitable for error reporting.",
            _ => errmsg="NO CODE",
            
        };
        Err(format!("{}",errmsg.to_string()))
    }
}
