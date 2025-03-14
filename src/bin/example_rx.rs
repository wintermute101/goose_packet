extern crate goose_packet;

use pnet::datalink::{self,interfaces,Channel, NetworkInterface};
use goose_packet::pdu::decodeGoosePacket;

use std::env;

fn display_network_interfaces(){
    let interfaces = interfaces();
    for interface in interfaces.iter() {
        println!("interface  {}", interface.index);
        println!("\t name {}", interface.name);
        println!("\t ips {:?}", interface.ips);
        println!("\t description {}", interface.description);

    }
}

fn main(){
    let interface_name = match env::args().nth(1){
        Some (name)=>name,
        None=>{
            println!("please add an interface name as argument. the available interface in the system:");
            display_network_interfaces();
            panic!();
        }
    };

    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = interfaces();
    // Find the network interface with the provided name
    let interface = match interfaces.into_iter()
                              .filter(interface_names_match)
                              .next() {
        Some(val)=>val,
        _=>{
            println!("unknown interface name. the available interface in the system:");
            display_network_interfaces();
            panic!();
        }

    };

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    println!("start listening goose messages");

    loop {
        match rx.next() {
            Ok(packet) => {
                println!("something received");
                //display_buffer(packet, packet.len())
                if let Some(result) = decodeGoosePacket(&packet,0)
                {
                    match result {
                        Ok(pkt) =>{
                            println!("Goose packet {:?}",pkt);
                        },
                        Err(e) =>{
                            eprintln!("Error parsing goose fraame {} at posistion {}", e.message, e.pos);
                        }

                    }
                }

            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }

}