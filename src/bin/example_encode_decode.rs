extern crate goose_packet;

use goose_packet::types::{IECGoosePacket,IECGoosePdu,IECGooseHeader,EthernetHeader,IECData};
use goose_packet::pdu::{encodeGoosePacket,getTimeMs,display_buffer,decodeGoosePacket};

const GOOSE_BUFFER_SIZE:usize = 512;

fn main(){

    let ether_header= EthernetHeader{
        srcAddr:[00 as u8;6],
        dstAddr:[0x01,0x0C,0xCD,0x01,0x00,0x01],
        VLANID: Some(0x8001),
    };
    let goose_header = IECGooseHeader{
        APPID:[0x01,0x01],
        length:0,
    };
    let current_time=getTimeMs();
    let goose_data=vec![
        IECData::int8(2),
        IECData::int32(234),
        IECData::int64(234567890),
        IECData::array(
            vec![
                IECData::int8(-2),
                IECData::int32(-234),
                IECData::int64(-234567890),
                ]),
        IECData::structure(
            vec![
                IECData::int32u(4294967295),
                IECData::float32(0.123),
                IECData::octet_string(vec![0x22,0x33,0x66]),
                IECData::utc_time(current_time)
                ]),
        IECData::boolean(true),
        IECData::boolean(false),
        IECData::visible_string("abc234".to_string()),
        IECData::mms_string("hÃllo".to_string()),
        IECData::bit_string{padding:3,val:vec![0x00,0x01]}
        ];
    let goose_pdu= IECGoosePdu{
        gocbRef:"testGoose".to_string(),
        timeAllowedtoLive:6400,
        datSet:"test_datSet".to_string(),
        goID:"test_ID".to_string(),
        t:current_time,
        stNum:12,
        sqNum:23,
        simulation:false,
        confRev:5,
        ndsCom:false,
        numDatSetEntries:goose_data.len() as u32,
        allData:goose_data,
        };

    let mut buffer=[0 as u8;GOOSE_BUFFER_SIZE];

        let goose_packet = IECGoosePacket{
        eth_hdr: ether_header,
        goose_hdr: goose_header,
        pdu: goose_pdu,
        prp: None
    };

    let goose_frame_size=encodeGoosePacket(&goose_packet,&mut buffer,0);

    println!("goose frame:");
    display_buffer(&buffer,goose_frame_size);

    println!("decode as:");
    if let Some(result) = decodeGoosePacket(& buffer,0)
    {
        match result {
            Ok(pkt) =>{
                println!("Packet {:?}",pkt);
            },
            Err(e) =>{
                eprintln!("Error parsing goose fraame {} at posistion {}", e.message, e.pos);
            }
        }
    }

}