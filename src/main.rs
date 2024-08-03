
mod netscan;
mod sslscan;
mod resolv;

use std::io::{self, Read, Write};
use std::env;
use std::net::Ipv4Addr;
use netscan::{is_port_open, ping,splitrange};
use resolv::resolvenames;
use sslscan::sslscan;



fn main() -> io::Result<()> {
    
    let args: Vec<String> = env::args().collect();
    let argslen=args.len();
    
    let mut function:fn(ips:Vec<String>,ports:Option<Vec<u16>>)->Option<Vec<String>>=online;

    let mut ports:Vec<u16>=Vec::new();

    match argslen {
       1 => {
              function=online ;
            },
       2 | 3 => {
             let arg1=&args[1];
             if arg1=="resolv"{
                function=resolvenames;
             }else{
                let tmp=arg1.split(',');
                for t in tmp.into_iter(){
                   match t.parse::<u16>() {
                       Ok(parsed_num) => {
                               ports.push(parsed_num);
                       }
                       Err(_) => {
                           println!("Failed to parse the string {} as a u32",t);
                               
                       }
                   }
               }
   
               if ports.is_empty(){
                   println!("Failed to parse ports {}",arg1);
   
                   return Ok(());
               }
   
               function=portsstatus;
             }

             if argslen==3 {
                let arg2 = &args[2];
                if arg2=="ssl"{
                   function=sslprotocols;
                }else{
                    println!("Bad argument {}",arg2);
                    return Ok(());
                }                
            }
       },

       _ => {}
    } 
    /*let mut ips:Vec<String>=Vec::new();
    ips.push("192.168.1.1".to_string());
    let mut ports:Vec<u16>=Vec::new();
    ports.push(443);
    portsstatus(ips.clone(), Some(ports.clone()));*/

    let mut buffer:Vec<u8> = Vec::new();
    match io::stdin().read_to_end(&mut buffer){
        Ok(numbytes)=>{
            if numbytes>0 {
                let alltext = String::from_utf8(buffer);
                if alltext.is_ok(){
                   let alltext=alltext.unwrap();
                   let lines:Vec<&str>=alltext.split("\n").collect();
                   let mut ips:Vec<String>=Vec::new();

                   for line in lines.iter(){
                       let li=*line;
                       let li = String::from(li) ;
                       if li != "" {
                          if li.contains("-"){
                            match splitrange(&li.clone()){
                                 Ok(vip)=>{
                                    let _=vip.iter().for_each(|f| ips.push(f.clone()));
                                 }
                                 Err(_)=>{


                                 }

                            }

                          }else{
                            ips.push(li.clone());
                          }
                          
 
                       }
                   }
                   if !ips.is_empty(){
                    
                      if let Some(results)=function(ips.clone(),Some(ports)){
                          // I escriure resultats a final stdout
                          let stdout = io::stdout();
                          let mut handle = stdout.lock();
                          let results=results;
                          for ip in results {
                              let iip= ip + "\n";
                              let _ = handle.write_all(iip.as_bytes());
                          }

                          let _ = handle.write_all(b"\n");   
                      }

                      
                   }
                }else{
                    println!("Error parsing text!!!");
                }
            }
            else
            {
                println!("No content to parse!!!");
            }

        }
        Err(_)=>{

           println!("Error!!!");
        }

    }

    Ok(())
}



fn online(ips:Vec<String>,_ports:Option<Vec<u16>>)->Option<Vec<String>>{

    let mut results:Vec<String>=Vec::new();
    
    for destip in ips.iter(){
        match destip.parse::<Ipv4Addr>(){
            Ok(destination_ip)=>{
                match ping(destination_ip){
                    Ok(ip)=>{
                        results.push(ip);
                    }
                    Err(_)=>{

                    }
                }
            }Err(_)=>{
               
            }

        }
    }

    if !results.is_empty(){
        return Some(results);
    }

    None

}
fn portsstatus(ips:Vec<String>,ports:Option<Vec<u16>>)->Option<Vec<String>>{
    let mut results:Vec<String>=Vec::new();
    //println!("portstatus");
    match ports{
        Some(ports)=>{
             for destip in ips.iter(){
                match destip.parse::<Ipv4Addr>(){
                    Ok(destination_ip)=>{

                        let mut openports:Vec<u16>=Vec::new();
                        for port in ports.clone() {
                            
                            match is_port_open(destination_ip,port){
                                Ok(isopen)=>{
                                    if isopen { openports.push(port); }
                                }
                                Err(_)=>{
            
                                }
                            }
                        }
                        if !openports.is_empty(){
                            let mut ipports=destination_ip.to_string();
                            
                            let joined_ports: String =openports.iter()
                            .map(|&x| x.to_string())
                            .collect::<Vec<String>>()
                            .join(",");

                            ipports=format!("{},{}",ipports,joined_ports);

                            results.push(ipports.to_string());
                        }
                        

                    }Err(_)=>{
                       
                    }
        
                }
            }
        
            if !results.is_empty(){
                return Some(results);
            }
        
            return None;
        }
        None => return None
    };
    
}
fn sslprotocols(ips:Vec<String>,ports:Option<Vec<u16>>)->Option<Vec<String>>{
    let mut results:Vec<String>=Vec::new();

    match ports{
        Some(ports)=>{
             for destip in ips.iter(){
                let mut endpprotos:Vec<String>=Vec::new();
                for port in ports.clone() {
                    match sslscan(destip.clone(),port){
                        Ok(protocols)=>{
                            if !protocols.is_empty() { 
                                let tmp = format!("{},{}",port,protocols);
                                endpprotos.push(tmp); 
                            }
                        }
                        Err(_)=>{
    
                        }
                    }
                }
                if !endpprotos.is_empty(){
                    let mut ipprotos=destip.clone().to_string();                   
                    let joined_protos: String =endpprotos.join(",");
                    ipprotos=format!("{},{}",ipprotos,joined_protos);
                    results.push(ipprotos.to_string());
                }

            }
        
            if !results.is_empty(){
                return Some(results);
            }
        
            return None;
        }
        None => return None
    };
}
