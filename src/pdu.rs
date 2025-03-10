#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::error::GooseError;
pub use crate::types::{*};

use crate::pdu_encoder::{*};
use crate::pdu_decoder::{*};

use std::time::{SystemTime, UNIX_EPOCH};

pub fn encodeGoosePacket(pkt: &IECGoosePacket, buffer: &mut[u8], pos:usize) -> usize{
    encodeGooseFrame(&pkt.eth_hdr, &pkt.goose_hdr, &pkt.pdu, &pkt.prp, buffer, pos)
}

fn encodeGooseFrame(header: & EthernetHeader, goose_header: &IECGooseHeader, pdu: & IECGoosePdu, prp: &Option<IECPRP1>, buffer: &mut[u8], pos:usize) ->usize{
    let mut new_pos;

    let hdr_pos = encodeEthernetHeader(header,buffer,pos);
    new_pos = hdr_pos;
    new_pos = encodeIECGoosePdu(pdu,buffer,new_pos + IECGooseHeader::getSize());
    let goose_length = new_pos - hdr_pos - IECGooseHeader::getSize();
    encodeGooseHeader(goose_header, buffer, hdr_pos, goose_length as u16);

    if let Some(prp) = prp{
        let frame_size = if header.VLANID.is_some(){
            new_pos - hdr_pos + 4
        }
        else{
            new_pos - hdr_pos
        };
        new_pos = encodeIECPRP1(&prp, buffer, frame_size as u16, new_pos);
    }
    new_pos
}

fn encodeEthernetHeader(header: & EthernetHeader, buffer: &mut[u8], pos:usize) ->usize{

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

    new_pos
}

fn encodeGooseHeader(header: &IECGooseHeader, buffer: &mut[u8], pos:usize, goose_len: u16) ->usize{
    let mut new_pos=pos;

    buffer[new_pos..new_pos+2].copy_from_slice(&[0x88, 0xb8]);
    new_pos+=2;
    // Start of GOOSE length
    buffer[new_pos..new_pos+2].copy_from_slice(&header.APPID);
    new_pos=new_pos+2;

    buffer[new_pos..new_pos+2].copy_from_slice(&(goose_len+8).to_be_bytes()); //+8 to include this data from appid
    new_pos=new_pos+2;

    buffer[new_pos..new_pos+2].copy_from_slice(&[0 ;2]); // reserved 1
    new_pos=new_pos+2;

    buffer[new_pos..new_pos+2].copy_from_slice(&[0 ;2]); // reserved 2
    new_pos=new_pos+2;

    new_pos
}

fn encodeIECPRP1(prp: &IECPRP1, buffer: &mut[u8], frame_size: u16, mut pos:usize) -> usize{
    buffer[pos..pos+2].copy_from_slice(&prp.sequence.to_be_bytes());
    pos += 2;

    let lan = match prp.lan{
        IECPRPLAN::LAN_A => 0b1010 << 12 as u16,
        IECPRPLAN::LAN_B => 0b1011 << 12 as u16,
    };

    let fsize = lan | frame_size & 0x0fff;

    buffer[pos..pos+2].copy_from_slice(&fsize.to_be_bytes());
    pos += 2;

    buffer[pos..pos+2].copy_from_slice(&[0x88, 0xfb]);
    pos + 2
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

fn decodeIECPRP1(buffer: &[u8], pos: &mut usize) -> Result<Option<IECPRP1>, GooseError>{
    println!("Decode PRP {} {}", *pos, buffer.len());
    if (buffer.len() - *pos == 6) && buffer[*pos+4] == 0x88 && buffer[*pos+5] == 0xfb {
        let seq = u16::from_be_bytes(buffer[*pos..*pos+2].try_into().unwrap());
        *pos += 2;
        let fsize = u16::from_be_bytes(buffer[*pos..*pos+2].try_into().unwrap());
        match fsize >> 12{
            0b1010 => Ok(Some(IECPRP1{ sequence: seq, lan: IECPRPLAN::LAN_A, frame_size: fsize & 0x0fff })),
            0b1011 => Ok(Some(IECPRP1{ sequence: seq, lan: IECPRPLAN::LAN_B, frame_size: fsize & 0x0fff })),
            _=> Err(GooseError{message: "IEC PRP LAN undefined".into(), pos: *pos})
        }
    }
    else{
        Ok(None)
    }
}

pub fn decodeGoosePacket(buffer: &[u8], mut pos:usize) -> Option<Result<IECGoosePacket,GooseError>>{

    let header = match decodeEthernetHeader(buffer,&mut pos){
        Ok(e) => e,
        Err(e) => {return Some(Err(e));}
    };

    let goose_hedaer = match decodeGooseHeader(buffer, &mut pos) {
        Some(Ok(h)) => h,
        Some(Err(e)) => {return Some(Err(e));},
        None => {return  None;},
    };

    let pdu =match decodeIECGoosePdu(buffer, &mut pos){
        Err(e) => {
            return Some(Err(e));
        }
        Ok(v) => {v}
    };

    let prp = match decodeIECPRP1(buffer, &mut pos){
        Ok(v) => v,
        Err(e) => {return Some(Err(e));}
    };

    Some(Ok(IECGoosePacket{eth_hdr: header, goose_hdr: goose_hedaer, pdu: pdu, prp: prp}))

}

fn decodeEthernetHeader(buffer: &[u8], pos: &mut usize) -> Result<EthernetHeader,GooseError>{
    if *pos + 18 > buffer.len(){
        return Err(GooseError{ message: "Buffer too short".into(), pos: *pos});
    }
    let mut header = EthernetHeader::default();
    header.dstAddr.copy_from_slice(&buffer[*pos..*pos+6]);
    *pos+=6;

    header.srcAddr.copy_from_slice(&buffer[*pos..*pos+6]);
    *pos+=6;

    let mut ether_type = [0;2];
    ether_type.copy_from_slice(&buffer[*pos..*pos+2]);

    if ether_type ==[0x81,0x00]{ //if vlan
        *pos += 2;
        let vlanid = u16::from_be_bytes(buffer[*pos..*pos+2].try_into().unwrap());
        header.VLANID = Some(vlanid);
        *pos+=2;
    }
    Ok(header)
}

fn decodeGooseHeader(buffer: &[u8], pos: &mut usize) -> Option<Result<IECGooseHeader, GooseError>>{
    if *pos + 10 > buffer.len(){
        return Some(Err(GooseError{ message: "Buffer too short".into(), pos: *pos}));
    }
    let mut header =IECGooseHeader::default();
    let mut ether_type = [0;2];
    ether_type.copy_from_slice(&buffer[*pos..*pos+2]);
    *pos += 2;
    if ether_type !=[0x88,0xb8]
    {
        return None;
    }

    header.APPID.copy_from_slice(&buffer[*pos..*pos+2]);
    *pos+=2;

    header.length= u16::from_be_bytes(buffer[*pos..*pos+2].try_into().unwrap());
    *pos+=2;

    *pos+=2;  // reserved 1
    *pos+=2;  // reserved 2

    Some(Ok(header))
}
