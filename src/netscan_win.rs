


use windows_sys::Win32::Networking::WinSock::{closesocket, connect, getsockopt, htons, ioctlsocket, recvfrom, select, sendto, setsockopt, socket, WSACleanup, WSAStartup, AF_INET, FIONBIO, INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO_ICMP, IPPROTO_TCP, SOCKADDR, SOCKADDR_IN, SOCKET_ERROR, SOCK_RAW, SOCK_STREAM, SOL_SOCKET, SO_ERROR, SO_RCVTIMEO, TIMEVAL, WSADATA};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};



const TIMEOUT_MILI_SECS_PING: u32 = 100;
const TIMEOUT_MILI_SECS_PORTSCAN: u32 = 100;




pub fn wsastartup() -> Result<(),String>{

        let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
        if unsafe { WSAStartup(0x202, &mut wsa_data) } != 0 {
            return Err("WSAStartup failed".to_string());
        }else{
            Ok(())
        }
}

pub fn wsacleanup(){
    
      unsafe { WSACleanup() };
}

fn create_icmp_echo_request(identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + data.len());

    // ICMP Header
    packet.push(8); // Type: Echo Request
    packet.push(0); // Code: 0
    packet.extend_from_slice(&[0, 0]); // Placeholder for checksum
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());

    // Payload
    packet.extend_from_slice(data);

    // Calculate checksum
    let checksum = compute_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    packet
}

fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }

    if let Some(&last_byte) = chunks.remainder().first() {
        sum = sum.wrapping_add((last_byte as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}


pub fn ping(destination_ip: Ipv4Addr, on_processed: Option<Arc<Box<dyn Fn(String) + Send + Sync>>>, echo_replies:Arc<Mutex<HashMap<String,bool>>>) -> Result<String, String> {
    let octets = destination_ip.octets();
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
    
     let payload = create_icmp_echo_request(0x1234, 1, b"ping test");
   
        // Crear socket RAW
        
        let sock = unsafe { socket(AF_INET as i32, SOCK_RAW as i32, IPPROTO_ICMP as i32) };
        //println!("socket {:?}",sock);
        if sock == INVALID_SOCKET {
            return Err("Can't create RAW socket".to_string());
        }
        
        //println!("Fil {:?} amb socket {:?}", std::thread::current().id(), sock);

        let timeout: u32= TIMEOUT_MILI_SECS_PING;
        unsafe { setsockopt(
                 sock,
                 SOL_SOCKET,
                 SO_RCVTIMEO,
                 &timeout as *const _ as *const u8,
                 std::mem::size_of_val(&timeout) as i32,
                  ) };

       

             // Enviar paquete
        let result = unsafe { sendto(
            sock,
            payload.as_ptr() as *const u8,
            payload.len() as i32,
            0,
            &sockaddr_in as *const _ as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        ) };
        // println!("result {:?}",result);
        if result == SOCKET_ERROR {
            
            unsafe { closesocket(sock) };
            return Err("Error when send".to_string());
        }

     
        let mut from: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<SOCKADDR_IN>() as i32;
        let mut recv_buf=[0u8; 1024];
        
        let start = Instant::now();
        let duration = Duration::from_millis(TIMEOUT_MILI_SECS_PING.into());
        

        loop {
            let callback=on_processed.clone();
            let received = unsafe { recvfrom(
            sock,
            recv_buf.as_mut_ptr() as *mut u8,
            recv_buf.len() as i32,
            0,
            &mut from as *mut _ as *mut SOCKADDR,
            &mut from_len,
            ) };
            unsafe { closesocket(sock) };

            if received!=SOCKET_ERROR {
                let from_ip = Ipv4Addr::from(u32::from_be(unsafe { from.sin_addr.S_un.S_addr }));
                let icmp_offset = 20; // IP header size (sin opciones)
                let icmp_type = recv_buf[icmp_offset];
                let icmp_code = recv_buf[icmp_offset + 1];

                if icmp_type == 0 && icmp_code == 0 {
                  match echo_replies.lock() {
                     Ok(mut echosr)=>{
                         if let Some(value)=echosr.get_mut(from_ip.to_string().as_str()){
                              *value = true;
                         }else{
                              echosr.insert(from_ip.to_string(), true);
                         }
                     }
                     Err(_) =>{}
                  }
            
                  
                  if callback.is_some() {
                    callback.unwrap()(destination_ip.to_string());
                  }
                }
            }

            if start.elapsed() >= duration {
                break;
            }

        }
        Ok(destination_ip.to_string())
       
}

pub fn is_port_open(
    destination_ip: Ipv4Addr,
    port: u16,
    on_processed: Option<Box<dyn Fn(String)>>,
) -> Result<bool, String> {

    let octets = destination_ip.octets();
    let addr=u32::from_le_bytes(octets);
        // Creem un adreça
    let in_addr = IN_ADDR{
           S_un: IN_ADDR_0{
                 S_addr: addr,
            }
    };

    unsafe{
 // creem un socket
    
    let sockaddr_in = SOCKADDR_IN {
        sin_family: AF_INET as u16,
        sin_port: htons(port), // ICMP no usa puertos

        sin_zero: [0; 8],
        sin_addr: in_addr,
    };
        // Inicializar Winsock
        let mut wsa_data: WSADATA = std::mem::zeroed();
        if WSAStartup(0x202, &mut wsa_data) != 0 {
            return Err("WSAStartup failed".to_string());
        }

        // Crear socket TCP
        let sock = socket(AF_INET as i32, SOCK_STREAM as i32, IPPROTO_TCP as i32);
        if sock == INVALID_SOCKET {
            WSACleanup();
            return Err("Can't create STREAM socket".to_string());
        }
    // Poner el socket en modo no bloqueante
    let mut non_blocking: u32 = 1;
    ioctlsocket(sock, FIONBIO, &mut non_blocking);

    // Intentar conectar
    connect(
        sock,
        &sockaddr_in as *const SOCKADDR_IN as *const SOCKADDR,
        size_of::<SOCKADDR_IN>() as i32,
    );

    // Preparar para select()

    let mut timeout = TIMEVAL {
        tv_sec: 0, // segundos
        tv_usec: (TIMEOUT_MILI_SECS_PORTSCAN * 1000) as i32, // microsegundos
    };
    
    let mut writefds = FdSet::new();
    writefds.set(sock as usize);

    let result = select(0, null_mut(), &mut writefds as *mut _ as *mut _, null_mut(), &mut timeout);

    if result > 0 {
  // Verificar si la conexión fue exitosa
        let mut optval: i32 = 0;
        let mut optlen = size_of::<i32>() as i32;
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &mut optval as *mut _ as *mut _, &mut optlen);
        if optval == 0 {
           //println!("Puerto {} abierto", port);
           if let Some(callback) = on_processed {
                callback(format!("{}:{}",destination_ip.to_string(),port));
           }
        }

        non_blocking = 0;
        ioctlsocket(sock, FIONBIO, &mut non_blocking);

        return Ok(optval==0);
    }else{
        Ok(false)
    }

    
    }//unsafe
   
}


#[repr(C)]
pub struct FdSet {
    pub fd_count: u32,
    pub fd_array: [usize; 64], // SOCKET es usize en Windows
}

impl FdSet {
    pub fn new() -> Self {
        FdSet {
            fd_count: 0,
            fd_array: [0; 64],
        }
    }

    pub fn set(&mut self, socket: usize) {
        if self.fd_count < 64 {
            self.fd_array[self.fd_count as usize] = socket;
            self.fd_count += 1;
        }
    }
}
