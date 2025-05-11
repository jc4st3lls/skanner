
use std::{io::Write, mem::{self}, time::Duration};
use std::net::Ipv4Addr;
use libc::{
    c_int, c_void, connect, fcntl, in_addr, nfds_t, poll, pollfd, recv, send, setsockopt, sockaddr, sockaddr_in, socket, suseconds_t, time_t, timeval, AF_INET, EINPROGRESS, F_GETFL, F_SETFL, IPPROTO_IP, IP_TTL, O_NONBLOCK, POLLIN, POLLOUT, SOCK_RAW, SOCK_STREAM, SOL_SOCKET, SO_RCVTIMEO
};



use rand::random;
const ICMP_ECHO_REQUEST: u8 = 8;
const TIMEOUT_MILI_SECS_PING: i32 = 100;
const TIMEOUT_MILI_SECS_SCAN: i32 = 150;
pub fn ping(destination_ip: Ipv4Addr,on_processed: Option<Box<dyn Fn(String)>>) -> Result<String, String> {
    // Create a raw socket
    let sock = unsafe { socket(AF_INET, SOCK_RAW, 1) };
    if sock < 0 {
        return Err("Failed to create socket".to_string());
    }

    // Set TTL value
    let ttl: c_int = 64; 
    let result = unsafe {
        setsockopt(
            sock,
            IPPROTO_IP,
            IP_TTL,
            &ttl as *const c_int as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    if result < 0 {
        return Err("Failed to set TTL value".to_string());
    }

    let timeout = gettimeout(0, TIMEOUT_MILI_SECS_PING as u64);

    let result = unsafe {
        setsockopt(
            sock,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout as *const timeval as *const libc::c_void,
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };

    if result == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    // Prepare destination address structure
    let mut dest_addr = sockaddr_in {
        #[cfg(target_os = "macos")]
        sin_family: AF_INET as u8,
        #[cfg(target_os = "linux")]
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: ipv4_to_in_addr(destination_ip),
        sin_zero: [0; 8],
        #[cfg(target_os = "macos")]
        sin_len: 0,
    };

    // Send ICMP echo request
    let ident: u16 = random();
    let seq: u16 = 1;
    let payload: &[u8; 24] = &random();

    let icmp_packet = prepare_icmp_packet(ident, seq, payload);
    let result = unsafe {
        connect(
            sock,
            &mut dest_addr as *mut sockaddr_in as *mut libc::sockaddr,
            mem::size_of::<sockaddr_in>() as u32,
        );
        send(
            sock,
            icmp_packet.as_ptr() as *const c_void,
            icmp_packet.len().try_into().unwrap(),
            0,
        )
    };

    if result < 0 {
        return Err("Failed to send ICMP packet".to_string());
    }

    // Receive response
    let mut recv_buf = [0u8; 1024];
    let recv_result = unsafe {
        recv(
            sock,
            recv_buf.as_mut_ptr() as *mut c_void,
            recv_buf.len().try_into().unwrap(),
            0,
        )
    };

    // Close the socket
    unsafe { libc::close(sock) };

    if recv_result < 0 {
        let err = format!(
            "Failed to receive ICMP response: {}",
            std::io::Error::last_os_error()
        );
        return Err(err);
    }
    if let Some(callback) = on_processed {
        callback(destination_ip.to_string());
    }
    Ok(destination_ip.to_string())
}

pub fn is_port_open(destination_ip: Ipv4Addr, port: u16,on_processed: Option<Box<dyn Fn(String)>>) -> Result<bool, String> {
    //println!("{}:{}",destination_ip.to_string().red(),port.to_string().red());
    // Create a TCP socket
    let sock = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
    if sock < 0 {
        return Err("Failed to create socket".to_string());
    }

    let optvalue = 1;
    unsafe {
        setsockopt(
            sock,
            libc::SOL_SOCKET,
            #[cfg(target_os = "macos")]
            libc::SO_NOSIGPIPE,
            #[cfg(target_os = "linux")]
            libc::MSG_NOSIGNAL,
            optvalue as *const i32 as *const libc::c_void,
            std::mem::size_of_val(&optvalue) as libc::socklen_t,
        );
    }

    //Set no blocking
    // Get the current file descriptor flags
    let flags = unsafe { fcntl(sock, F_GETFL) };
    if flags == -1 {
        return Ok(false);
    }

    // Set the file descriptor flags to non-blocking
    let result = unsafe { fcntl(sock, F_SETFL, flags | O_NONBLOCK) };
    if result == -1 {
        return Ok(false);
    }


    // Set up the server address structure
    let dest_addr: sockaddr_in = sockaddr_in {
        #[cfg(target_os = "macos")]
        sin_family: AF_INET as u8,
        #[cfg(target_os = "linux")]
        sin_family: AF_INET as u16,
        sin_port: port.to_be(), // Convert to big-endian
        sin_addr: ipv4_to_in_addr(destination_ip),
        sin_zero: [0; 8],
        #[cfg(target_os = "macos")]
        sin_len: 0,
    };
    unsafe {
        let result: i32 = connect(
            sock,
            &dest_addr as *const sockaddr_in as *const _ as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        );

        
        if result == -1 {
            // Seguim
            #[cfg(target_os = "macos")]
            let err = *libc::__error() ;
            #[cfg(target_os = "linux")]

            let err = *libc::__errno_location() ;
            if err == EINPROGRESS {
                //Continuem
                
                match wait_for_connection(sock, TIMEOUT_MILI_SECS_SCAN) {
                    Ok(_) => {
                        if let Some(callback) = on_processed {
                            let msg = format!("{}:{}", destination_ip.to_string(), port.to_string());
                            callback(msg);
                        }
                        return Ok(true);
                    }
                    Err(_err) => {
                        return Ok(false);
                    }
                }
            } else {
                return Ok(false);
            }
        } else {
            return Ok(true);
        }
    }
}
fn wait_for_connection(fd: i32, millisecons: i32) -> Result<bool, String> {
    // Set up the pollfd structure
    let mut fds = [pollfd {
        fd,
        events: POLLIN | POLLOUT,
        revents: 0,
    }];

    // Poll for events
    let timeout = millisecons;
    let ret = unsafe { poll(fds.as_mut_ptr(), fds.len() as nfds_t, timeout) };
    if ret == -1 {
        #[cfg(target_os = "macos")]
        return Err(unsafe { *libc::__error() }.to_string());
        #[cfg(target_os = "linux")]
        return Err(unsafe { *libc::__errno_location() }.to_string());
    } else if ret == 0 {
        return Err("Connection timed out".to_string());
    }

    // Check the revents field to determine if the connection was successful
    if fds[0].revents & POLLOUT != 0 {
        // Check if there was an error with the connection
        let mut error: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut error as *mut _ as *mut _,
                &mut len,
            )
        };
        if ret == -1 {
            #[cfg(target_os = "macos")]
            return Err(unsafe { *libc::__error() }.to_string());
            #[cfg(target_os = "linux")]
            return Err(unsafe { *libc::__errno_location()}.to_string());
        }
        if error != 0 {
            #[cfg(target_os = "macos")]
            return Err(unsafe { *libc::__error() }.to_string());
            #[cfg(target_os = "linux")]
            return Err(unsafe { *libc::__errno_location() }.to_string());
        }
    } else {
        return Err("Poll indicated an unexpected event".to_string());
    }

    Ok(true)
}


fn gettimeout(seconds: u64, milliseconds: u64) -> timeval {
    let milli = (seconds * 1_000) + milliseconds;
    let duration = Duration::from_millis(milli);
    let sec = duration.as_secs() as time_t;
    let microsec = (duration.subsec_micros() % 1_000_000) as suseconds_t;
    timeval {
        tv_sec: sec,       //seconds
        tv_usec: microsec, //microseconds
    }
}

fn prepare_icmp_packet(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 64];
    packet[0] = ICMP_ECHO_REQUEST; // Type
    packet[1] = 0; // Code
    packet[4] = (ident >> 8) as u8;
    packet[5] = ident as u8;
    packet[6] = (seq >> 8) as u8;
    packet[7] = seq as u8;

    if let Err(_) = (&mut packet[8..]).write(payload) {
        panic!("Error prepapring packet");
    }
    // Calculate checksum
    let sum = write_checksum(&mut packet);
    packet[2] = (sum >> 8) as u8;
    packet[3] = (sum & 0xff) as u8;

    packet
}
fn write_checksum(buffer: &mut [u8]) -> u16 {
    let mut sum = 0u32;
    for word in buffer.chunks(2) {
        let mut part = u16::from(word[0]) << 8;
        if word.len() > 1 {
            part += u16::from(word[1]);
        }
        sum = sum.wrapping_add(u32::from(part));
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let sum = !sum as u16;

    sum
}
fn ipv4_to_in_addr(ipv4_addr: Ipv4Addr) -> in_addr {
    let ip_u32 = u32::from(ipv4_addr);
    let in_addr = in_addr {
        s_addr: ip_u32.to_be(), // Convert to big-endian byte order
    };

    in_addr
}

