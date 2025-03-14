#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::error::GooseError;
use crate::types::{*};
use crate::basic_decoder::{*};

pub fn decodeIECDataElement(buffer: &[u8], pos:usize) ->Result<(usize,IECData),GooseError>{

    let mut new_pos=pos;

    let mut tag:u8=0;
    let mut length:usize=0;
    new_pos=decode_tag_length(&mut tag,&mut length,buffer,new_pos)?;

    match  tag{
        0x83=> {
            let mut val:bool=false;
            new_pos=decode_boolean(& mut val, buffer, new_pos);
            return Ok((new_pos,IECData::boolean(val)));
        },
        0x85=>{
            match length{
                1=>{
                    let mut val:i8=0;
                    new_pos=decode_interger_8(& mut val, buffer, new_pos,length);
                    return Ok((new_pos,IECData::int8 (val)));
                },
                2=>{
                    let mut val:i16=0;
                    new_pos=decode_interger_16(& mut val, buffer, new_pos,length);
                    return Ok((new_pos,IECData::int16 (val)));
                },
                3..=4=>{
                    let mut val:i32=0;
                    new_pos=decode_interger(& mut val, buffer, new_pos,length);
                    return Ok((new_pos,IECData::int32 (val)));
                }
                5..=8=>{
                    let mut val:i64=0;
                    new_pos=decode_interger_64(& mut val, buffer, new_pos,length);
                    return Ok((new_pos,IECData::int64 (val)));                },
                _=>{
                    return Err(GooseError{
                        message:"oversize signed interger".to_string(),
                        pos:new_pos
                    });
                }
            }
        },
        0x86=>{
            match length{
                1=>{
                    let mut val:u8=0;
                    new_pos=decode_unsigned_8(& mut val, buffer, new_pos,length);
                    return Ok((new_pos,IECData::int8u (val)));
                },
                2=>{
                    let mut val:u16=0;
                    new_pos=decode_unsigned_16(& mut val, buffer, new_pos,length);
                    return Ok((new_pos,IECData::int16u (val)));
                },
                3..=4=>{
                    let mut val:u32=0;
                    new_pos=decode_unsigned(& mut val, buffer, new_pos,length);
                    return Ok((new_pos,IECData::int32u (val)));
                },
                5=>{
                    // only occur when 32bit unsigned prepend with zero
                    if buffer[new_pos]!=0x00
                    {
                        return Err(GooseError{
                            message:"oversize unsigned interger".to_string(),
                            pos:new_pos
                        });
                    }
                    let mut val:u32=0;
                    new_pos=decode_unsigned(& mut val, buffer, new_pos+1,length-1);
                    return Ok((new_pos,IECData::int32u (val)));
                },
                6..=8=>{
                    // no support for u64
                    return Err(GooseError{
                        message:"oversize unsigned interger".to_string(),
                        pos:new_pos
                    });
                },
                _=>{
                    return Err(GooseError{
                        message:"oversize unsigned interger".to_string(),
                        pos:new_pos
                    });
                }
            }
        },
        0x87=>{
            match length{
                5=>{
                    let mut val:f32=0.0;
                    new_pos=decode_float(&mut val,buffer, new_pos, length);
                    return Ok((new_pos,IECData::float32(val)));
                },
                9=>{
                    let mut val:f64=0.0;
                    new_pos=decode_float_64(&mut val,buffer, new_pos, length);
                    return Ok((new_pos,IECData::float64(val)));
                },
                _=>{
                    return Err(GooseError{
                        message:"unexpexted size float".to_string(),
                        pos:new_pos
                    });
                }

            }
        },
        0x8a=>{
            let mut val:String="".to_string();
            new_pos=decode_string(&mut val,buffer,new_pos,length);
            return Ok((new_pos,IECData::visible_string (val)));
        },
        0x90=>{
            let mut val:String="".to_string();
            new_pos=decode_string(&mut val,buffer,new_pos,length);
            return Ok((new_pos,IECData::mms_string (val)));
        },
        0x84=>{
            let mut padding:u8=0;
            let mut val:Vec<u8>=vec![0;length-1];
            new_pos=decode_bit_string(&mut val,&mut padding,buffer,new_pos,length);
            return Ok((new_pos,IECData::bit_string {val,padding}));
        },
        0xa1=>{
            let mut val:Vec<IECData>=vec![];
            new_pos=decodeIECData(&mut val,buffer,new_pos,new_pos+length)?;
            return Ok((new_pos,IECData::array (val)));
        },
        0xa2=>{
            let mut val:Vec<IECData>=vec![];
            new_pos=decodeIECData(&mut val,buffer,new_pos,new_pos+length)?;
            return Ok((new_pos,IECData::structure (val)));
        },
        0x89=>{
            let mut val:Vec<u8>=vec![0;length];
            new_pos=decode_octet_string(&mut val,buffer,new_pos,length);
            return Ok((new_pos,IECData::octet_string (val)));
        },
        0x91=>{
            let mut val=[0 as u8;8];
            new_pos=decode_octet_string(&mut val,buffer,new_pos,length);
            return Ok((new_pos,IECData::utc_time (val)));
        },
        _=>{
            return Err(GooseError{
                message:"unknown data type".to_string(),
                pos:new_pos
            });
        }
    };

}

pub fn decodeIECData(data: &mut Vec<IECData>, buffer: &[u8], pos:usize, end:usize) ->Result<usize,GooseError>{

    let mut new_pos=pos;

    loop {
        let (next_pos, new_data)=decodeIECDataElement(buffer, new_pos)?;
        data.push(new_data);
        new_pos=next_pos;
        if new_pos>= end {
            break;
        }
    }

    Ok(new_pos)
}

pub fn decodeIECGoosePdu(buffer: &[u8], pos: &mut usize) -> Result<IECGoosePdu,GooseError>{
    let mut tag:u8=0;
    let mut length:usize=0;

    let mut pdu = IECGoosePdu::default();

    //goosePduLength
    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    if tag != 0x61{
        return Err(GooseError{ message: "first tag != 61".into(), pos: *pos});
    }
    if length+*pos > buffer.len(){
        return Err(GooseError{ message: "buffer too short".into(), pos: *pos});
    }

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_string(&mut pdu.gocbRef,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_unsigned(&mut pdu.timeAllowedtoLive,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_string(&mut pdu.datSet,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_string(&mut pdu.goID,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_octet_string(&mut pdu.t,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_unsigned(&mut pdu.stNum,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_unsigned(&mut pdu.sqNum,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_boolean(&mut pdu.simulation,buffer,*pos);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_unsigned(&mut pdu.confRev,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_boolean(&mut pdu.ndsCom,buffer,*pos);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    *pos=decode_unsigned(&mut pdu.numDatSetEntries,buffer,*pos,length);

    *pos=decode_tag_length(&mut tag,&mut length,buffer,*pos)?;
    if tag != 0xab{
        return Err(GooseError{ message: "allData tag != ab".into(), pos: *pos});
    }
    *pos=decodeIECData(&mut pdu.allData,buffer,*pos,*pos+length)?;

    if pdu.numDatSetEntries as usize != pdu.allData.len(){
        eprintln!("all data len {} pdu {}", pdu.allData.len(), pdu.numDatSetEntries);
        return Err(GooseError{ message: "allData size does not match data entries".into(), pos: *pos});
    }

    //print!("decode pdu: {:?}",pdu);
    Ok(pdu)
}