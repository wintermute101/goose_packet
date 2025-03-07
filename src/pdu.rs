#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::error::GooseError;
pub use crate::types::{*};

use crate::pdu_encoder::{*};
use crate::pdu_decoder::{*};

use std::time::{SystemTime, UNIX_EPOCH};

pub fn encodeGoosePacket(pkt: &IECGoosePacket, buffer: &mut[u8], pos:usize) -> usize{
    encodeGooseFrame(&pkt.hdr, &pkt.pdu, buffer, pos)
}

pub fn encodeGooseFrame(header: & EthernetHeader, pdu: & IECGoosePdu, buffer: &mut[u8], pos:usize) ->usize{
    let hdr_len= if header.VLANID.is_some(){
        pos + 26
    }
    else {
        pos + 22
    };

    let mut new_pos = hdr_len;

    let goose_length=encodeIECGoosePdu(pdu,buffer,new_pos) - hdr_len;
    encodeEthernetHeader(header,buffer,pos, goose_length as u16);

    new_pos += goose_length;
    if let Some(end) = pdu.frameEnd{
        buffer[new_pos..new_pos+6].copy_from_slice(&end);
        new_pos += 6;
    }
    new_pos
}

pub fn encodeEthernetHeader(header: & EthernetHeader, buffer: &mut[u8], pos:usize, ether_len: u16) ->usize{

    let mut new_pos=pos;

    buffer[new_pos..new_pos+6].copy_from_slice(&header.dstAddr);
    new_pos=new_pos+6;

    buffer[new_pos..new_pos+6].copy_from_slice(&header.srcAddr);
    new_pos=new_pos+6;

    if let Some(vlanid) = header.VLANID{
        buffer[new_pos..new_pos+2].copy_from_slice(&[0x81,0x00]);
        new_pos=new_pos+2;

        buffer[new_pos..new_pos+2].copy_from_slice(&vlanid.to_be_bytes());
        new_pos=new_pos+2;
    }

    buffer[new_pos..new_pos+2].copy_from_slice(&[0x88, 0xb8]);
    new_pos=new_pos+2;

    // Start of GOOSE length
    buffer[new_pos..new_pos+2].copy_from_slice(&header.APPID);
    new_pos=new_pos+2;

    buffer[new_pos..new_pos+2].copy_from_slice(&ether_len.to_be_bytes());
    new_pos=new_pos+2;

    buffer[new_pos..new_pos+2].copy_from_slice(&[0 ;2]); // reserved 1
    new_pos=new_pos+2;

    buffer[new_pos..new_pos+2].copy_from_slice(&[0 ;2]); // reserved 2
    new_pos=new_pos+2;

    new_pos

}

pub fn getTimeMs()->[u8;8]{
    let mut time_array=[0 as u8;8];
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    //println!("{:?}", since_the_epoch);
    let seconds= since_the_epoch.as_secs() as u32;
    let sec_array=seconds.to_be_bytes();
    let subsec_nano=(since_the_epoch.subsec_micros() as f32 * 4294.967296) as u32;
    let nano_array=subsec_nano.to_be_bytes();
    time_array[0..4].copy_from_slice(&sec_array);
    time_array[4..7].copy_from_slice(&nano_array[..3]);
    time_array[7]=0x18;
    time_array
}

pub fn display_buffer( buffer: &[u8], size:usize){
    for i in 0..std::cmp::min(buffer.len(),size){
        if (i)%8==0 {
            print!("{:06x} ",i);
        }
        print!("{:02x} ",buffer[i]);
        if (i+1)%8==0 {
            print!("\n");
        }
    }
    print!("\n");
}

pub fn decodeGoosePacket(buffer: &[u8], pos:usize) -> Option<Result<IECGoosePacket,GooseError>>{
    match decodeGooseFrame(buffer, pos){
        Some(Ok((hdr, pdu))) =>{
            Some(Ok(IECGoosePacket {hdr: hdr, pdu: pdu}))
        },
        None => None,
        Some(Err(e)) => Some(Err(e))
    }
}

pub fn decodeGooseFrame(buffer: &[u8], pos:usize) -> Option<Result<(EthernetHeader, IECGoosePdu),GooseError>>{
    let mut new_pos=pos;
    let mut header =  EthernetHeader::default();

    new_pos = match decodeEthernetHeader(&mut header,buffer,new_pos){
        Some(Ok(v)) => {v},
        Some(Err(e)) => {
            return Some(Err(e));
        }
        None => {return None;}
    };

    let mut pdu = IECGoosePdu::default();

    new_pos=match decodeIECGoosePdu(&mut pdu,buffer,new_pos){
        Err(e) => {
            return Some(Err(e));
        }
        Ok(v) => {v}
    };
    if buffer.len() - new_pos == 6{
        let mut end = [0;6];
        end.copy_from_slice(&buffer[new_pos..new_pos+6]);
        pdu.frameEnd = Some(end);
    }
    Some(Ok((header, pdu)))
}

pub fn decodeEthernetHeader(header: & mut EthernetHeader, buffer: &[u8], pos:usize) -> Option<Result<usize,GooseError>>{

    let mut new_pos=pos;

    header.dstAddr.copy_from_slice(&buffer[new_pos..new_pos+6]);
    new_pos=new_pos+6;

    header.srcAddr.copy_from_slice(&buffer[new_pos..new_pos+6]);
    new_pos=new_pos+6;

    let mut ether_type = [0;2];

    ether_type.copy_from_slice(&buffer[new_pos..new_pos+2]);
    new_pos += 2;

    if ether_type ==[0x81,0x00]{ //if vlan
        let vlanid = u16::from_be_bytes(buffer[new_pos..new_pos+2].try_into().unwrap());
        header.VLANID = Some(vlanid);
        new_pos=new_pos+2;

        //https://github.com/libpnet/libpnet/issues/460
        //println!("vlan stripped");

        ether_type.copy_from_slice(&buffer[new_pos..new_pos+2]);
        new_pos += 2;
    }

    if ether_type !=[0x88,0xb8]
    {
        return None;
    }

    header.APPID.copy_from_slice(&buffer[new_pos..new_pos+2]);
    new_pos=new_pos+2;

    header.length= u16::from_be_bytes(buffer[new_pos..new_pos+2].try_into().unwrap());
    new_pos=new_pos+2;

    new_pos=new_pos+2;  // reserved 1

    new_pos=new_pos+2; // reserved 2

    Some(Ok(new_pos))

}