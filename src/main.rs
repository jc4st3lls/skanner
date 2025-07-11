#[cfg(target_os = "windows")]
mod netscan_win; 
#[cfg(target_os = "windows")]
mod resolv_win;
#[cfg(target_os = "windows")]
mod sslscan_win;
#[cfg(not(target_os = "windows"))]
mod netscan; 
#[cfg(not(target_os = "windows"))]
mod resolv;
#[cfg(not(target_os = "windows"))]
mod sslscan;



#[cfg(not(target_os = "windows"))]
use netscan::{is_port_open, ping};
#[cfg(not(target_os = "windows"))]
use resolv::resolvenames;
#[cfg(not(target_os = "windows"))]
use sslscan::sslscan;

#[cfg(target_os = "windows")]
use netscan_win::{is_port_open,ping};
#[cfg(target_os = "windows")]
use resolv_win::resolvenames;
#[cfg(target_os = "windows")]
use sslscan_win::sslscan;


use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::HashMap;
use std::env;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let argslen = args.len();

    let mut function: fn(ips: Vec<String>, ports: Option<Vec<u16>>) -> Option<Vec<String>> = online_par;

    let mut ports: Vec<u16> = Vec::new();

    match argslen {
        1 => {
            function = online_par;
        }
        2 | 3 => {
            let arg1 = &args[1];
            if arg1 == "resolv" {
                function = resolvenames;
            } else {
                let tmp = arg1.split(',');
                for t in tmp.into_iter() {
                    match t.parse::<u16>() {
                        Ok(parsed_num) => {
                            ports.push(parsed_num);
                        }
                        Err(_) => {
                            println!("Failed to parse the string {} as a u32", t);
                        }
                    }
                }

                if ports.is_empty() {
                    println!("Failed to parse ports {}", arg1);

                    return Ok(());
                }

                function = portsstatus_par;
            }

            if argslen == 3 {
                let arg2 = &args[2];
                if arg2 == "ssl" {
                    function = sslprotocols_par;
                } else {
                    println!("Bad argument {}", arg2);
                    return Ok(());
                }
            }
        }

        _ => {}
    }
    /*let name = resolv_win::resolvenameinfo("192.168.10.30").unwrap();
    println!("{name}");
    let mut ips: Vec<String> = Vec::new();
    ips.push("192.168.10.12".to_string());
    ips.push("192.168.10.13".to_string());
    ports.push(443);
    function = online_par;
    if let Some(results) = function(ips.clone(), Some(ports)) {
         // I escriure resultats a final stdout
        let mut stdout = io::stdout();
        let _=stdout.flush().unwrap();
        let mut handle = stdout.lock();
        let results = results;
        for ip in results {
            let iip = ip + "\n";
            let _ = handle.write_all(iip.as_bytes());
        }

        let _ = handle.write_all(b"\n");
     }
    

    return Ok(()); */

    let mut buffer: Vec<u8> = Vec::new();

    match io::stdin().read_to_end(&mut buffer) {
        Ok(numbytes) => {
    
            if numbytes > 0 {
                let alltext = String::from_utf8(buffer);
                if alltext.is_ok() {
                    let alltext = alltext.unwrap();
                    #[cfg(not(target_os = "windows"))]
                    let lines: Vec<&str> = alltext.split("\n").collect();
                    #[cfg(target_os = "windows")]
                    let lines: Vec<&str> = alltext.split("\r\n").collect();
                    let mut ips: Vec<String> = Vec::new();

                    for line in lines.iter() {
                        let li = *line;
                        let li = String::from(li);
                        if li != "" {
                            if li.contains("-") {
                                match expand_ip_range(&li.clone()) {
                                    Ok(vip) => {
                                        let _ = vip.iter().for_each(|f| ips.push(f.clone()));
                                    }
                                    Err(_) => {}
                                }
                            } else {
                                ips.push(li.clone());
                            }
                        }
                    }
                   
                    if !ips.is_empty() {
                        if let Some(results) = function(ips.clone(), Some(ports)) {
                            // I escriure resultats a final stdout
                            let mut stdout = io::stdout();
                            let _=stdout.flush().unwrap();
                            let mut handle = stdout.lock();
                            let results = results;
                            for ip in results {
                                let iip = ip + "\n";
                                let _ = handle.write_all(iip.as_bytes());
                            }

                            let _ = handle.write_all(b"\n");
                        }
                    }
                } else {
                    println!("Error parsing text!!!");
                }
            } else {
                println!("No content to parse!!!");
            }
        }
        Err(_) => {
            println!("Error!!!");
        }
    }

    Ok(())
}

fn expand_ip_range(ip_range: &str) -> Result<Vec<String>, String> {
    // Dividir la cadena en partes
    let parts: Vec<&str> = ip_range.split('.').collect();
    if parts.len() != 4 {
        return Err("Formato de IP inválido".to_string());
    }

    // Procesar el último octeto que contiene el rango
    let last_part = parts[3];
    let range_parts: Vec<&str> = last_part.split('-').collect();
    if range_parts.len() != 2 {
        return Err("Formato de rango inválido".to_string());
    }

    // Parsear los números
    let start: u8 = range_parts[0].parse().map_err(|_| "Inicio de rango inválido")?;
    let end: u8 = range_parts[1].parse().map_err(|_| "Fin de rango inválido")?;

    // Validar el rango
    if start > end || end > 254 {
        return Err("Rango de IP inválido (debe ser 1-254)".to_string());
    }

    // Construir la base de la IP (primeros 3 octetos)
    let base = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

    // Generar todas las IPs en el rango
    Ok((start..=end)
        .map(|i| format!("{}.{}", base, i))
        .collect())
}

fn online_par(ips: Vec<String>, _ports: Option<Vec<u16>>) -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        if netscan_win::wsastartup().is_err(){
            println!("Error inicializing Winsock");
            return Some(Vec::new());
        }
        let echoresponses:Arc<Mutex<HashMap<String,bool>>> = Arc::new(Mutex::new(HashMap::new()));
    }
    
    let on_processed:Option<Arc<Box<dyn Fn(String) + Send + Sync>>>=Some(Arc::new(Box::new(move |msg : String| {
        let mut stdout = io::stdout();
        let _=stdout.flush().unwrap();
        let mut handle = stdout.lock();
        let _ =handle.write_all("\x1b[32m".as_bytes());
        let _= handle.write_all(msg.as_bytes());
        let _= handle.write("\x1b[0m\n".as_bytes());
        })));

    
 


    let results:Vec<String> = ips
        .par_iter() // Iterador paralelo
        .filter_map(|destip| {
            // Parsear IP y hacer ping (en paralelo)
             //destip.parse::<Ipv4Addr>().ok().and_then(|ip| ping(ip,None).ok())
            let ip=destip.parse::<Ipv4Addr>().unwrap();
            
            #[cfg(windows)]{
                match ping(ip, on_processed.clone(),echoresponses.clone()) {
                Ok(_) => Some(ip.to_string()),
                Err(_) => None,
                }
            }
            
           #[cfg(unix)]{
                match ping(ip, on_processed.clone()) {
                Ok(_) => Some(ip.to_string()),
                Err(_) => None,
                }
            }

        })
        .collect();
         #[cfg(windows)]{
           let echors=echoresponses.lock().unwrap();
           let mut results: Vec<String> = echors.keys().map(|k| k.to_string()).collect();
           results.sort();
         }
        
    
    
    #[cfg(windows)]
    {
       netscan_win::wsacleanup();
    }


    if !results.is_empty() {
        return Some(results);
    }

    None
}

fn portsstatus_par(ips: Vec<String>, ports: Option<Vec<u16>>) -> Option<Vec<String>> {
    let on_processed=Box::new(move |msg : String| {
        let mut stdout = io::stdout();
        let _=stdout.flush().unwrap();
        let mut handle = stdout.lock();
        let _ =handle.write_all("\x1b[32m".as_bytes());
        let _= handle.write_all(msg.as_bytes());
        let _= handle.write("\x1b[0m\n".as_bytes());

    });

    let results: Vec<String> = ips
        .par_iter() // Procesar IPs en paralelo
        .filter_map(|destip| {
            // Parsear IP (ignorar inválidas)
            destip.parse::<Ipv4Addr>().ok().map(|ip| (ip, &ports))
        })
        .map(|(ip, ports)| {
            // Escanear TODOS los puertos de esta IP (en paralelo)
            let open_ports: Vec<u16> = ports.clone().unwrap()
                .par_iter() // Procesar puertos en paralelo
                .filter_map(|&port| match is_port_open(ip, port,Some(on_processed.clone())) {
                    Ok(true) => Some(port), // Solo puertos abiertos
                    Ok(false) | Err(_) => None, // Ignorar puertos cerrados o errores
                }) // Verificar cada puerto
                .collect();

            // Formatear resultado si hay puertos abiertos
            if !open_ports.is_empty() {
                let ports_str = open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                Some(format!("{},{}", ip, ports_str))
            } else {
                None
            }
        })
        .filter_map(|x| x) // Filtrar IPs sin puertos abiertos
        .collect();

    //println!("Resultados: {:?}", results);
    if !results.is_empty() {
        return Some(results);
    }

    return None;
}



fn sslprotocols_par(ips: Vec<String>, ports: Option<Vec<u16>>) -> Option<Vec<String>> {

    let results: Vec<String> = match ports {
        Some(ports) => {
            ips.par_iter() // Procesar IPs en paralelo
                .filter_map(|destip| {
                    let open_ports: Vec<String> = ports
                        .par_iter() // Procesar puertos en paralelo
                        .filter_map(|&port| {
                            sslscan(destip.clone(), port)
                                .ok()
                                .filter(|protocols| !protocols.is_empty())
                                .map(|protocols| format!("{},{}", port, protocols))
                        })
                        .collect();
    
                    if !open_ports.is_empty() {
                        Some(format!("{},{}", destip, open_ports.join(",")))
                    } else {
                        None
                    }
                })
                .collect()
        }
        None => Vec::new(),
    };
    
    if !results.is_empty() {
        Some(results)
    } else {
        None
    }


}