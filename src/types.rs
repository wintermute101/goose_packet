#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use serde::{Serialize, Deserialize};

#[derive(Debug,Serialize, Deserialize, Clone)]
pub enum IECData{
    array(Vec<IECData>),
    structure(Vec<IECData>),
    boolean(bool),

    int8(i8),
    int16(i16),
    int32(i32),
    int64(i64),

    int8u(u8),
    int16u(u16),
    int32u(u32),

    float32(f32),
    float64(f64),

    visible_string(String),
    mms_string(String),
    bit_string{ padding: u8, val: Vec<u8> },
    octet_string(Vec<u8>),
    utc_time([u8;8])
}
#[derive(Serialize,Deserialize,Debug,Default,Clone)]
pub struct EthernetHeader {
    pub srcAddr:[u8;6],
    pub dstAddr:[u8;6],
    pub VLANID:Option<u16>,
}

#[derive(Serialize,Deserialize,Debug,Default,Clone)]
pub struct IECGooseHeader {
    pub APPID:[u8;2],
    pub length: u16
}

impl IECGooseHeader {
    pub fn getSize() -> usize{
        10
    }
}

#[derive(Serialize,Deserialize,Debug,Default,Clone)]
pub struct IECGoosePdu {
    pub gocbRef: String,
    pub timeAllowedtoLive: u32,
    pub datSet: String,
    pub goID: String,
    pub t: [u8;8],
    pub stNum: u32,
    pub sqNum: u32,
    pub simulation: bool,
    pub confRev: u32,
    pub ndsCom: bool,
    pub numDatSetEntries: u32,
    pub allData: Vec<IECData>,
}

impl IECGoosePdu {
    pub fn report(&mut self) {
        println!("gocbRef:{},data:{:?}",self.gocbRef,self.allData);
    }
}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub enum IECPRPLAN{
    LAN_A,
    LAN_B,
}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct IECPRP1 { //IEC 62439-3 Parallel Redundancy Protocol (PRP)
    pub sequence: u16,
    pub lan: IECPRPLAN,
    pub frame_size: u16,
}

#[derive(Serialize,Deserialize,Debug,Default,Clone)]
pub struct IECGoosePacket{
    pub eth_hdr: EthernetHeader,
    pub goose_hdr: IECGooseHeader,
    pub pdu: IECGoosePdu,
    pub prp: Option<IECPRP1>,
}
