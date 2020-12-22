// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SVCB and HTTPSSVC records
use crate::error::*;
use crate::rr::domain::Name;
use crate::serialize::binary::*;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fmt;

lazy_static! {
    static ref SVCB_MAP: HashMap<u16, SVCBKey> = {
        let mut m = HashMap::new();
        m.insert(0, SVCBKey::Mandatory);
        m.insert(1, SVCBKey::Alpn);
        m.insert(2, SVCBKey::NoDefaultAlpn);
        m.insert(3, SVCBKey::Port);
        m.insert(4, SVCBKey::IPv4Hint);
        m.insert(5, SVCBKey::ECHConfig);
        m.insert(6, SVCBKey::IPv6Hint);
        m.insert(32769, SVCBKey::ODoHConfig);
        m.insert(65535, SVCBKey::Reserved);
        m
    };
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[repr(u16)]
pub enum SVCBKey {
    Mandatory = 0,
    Alpn = 1,
    NoDefaultAlpn = 2,
    Port = 3,
    IPv4Hint = 4,
    ECHConfig = 5,
    IPv6Hint = 6,
    ODoHConfig = 32769,
    Reserved = 65535,
}

impl fmt::Display for SVCBKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let key = match self {
            SVCBKey::Mandatory => "mandatory",
            SVCBKey::Alpn => "alpn",
            SVCBKey::NoDefaultAlpn => "no-default-alpn",
            SVCBKey::Port => "port",
            SVCBKey::IPv4Hint => "ipv4hint",
            SVCBKey::ECHConfig => "echconfig",
            SVCBKey::IPv6Hint => "ipv6hint",
            SVCBKey::ODoHConfig => "odohconfig",
            _ => "",
        };
        write!(f, "{}", key)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct KeyValue {
    pub key: SVCBKey,
    pub value: String,
}

impl fmt::Display for KeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{key}={value}", key = self.key, value = self.value)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SVCB {
    priority: u16,
    target: Name,
    values: Vec<KeyValue>,
}

pub type HTTPS = SVCB;

impl SVCB {
    pub fn new(priority: u16, target: Name, values: Vec<KeyValue>) -> Self {
        Self {
            priority,
            target,
            values,
        }
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn target(&self) -> &Name {
        &self.target
    }

    pub fn value(&self) -> Vec<u8> {
        vec![1, 2]
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<SVCB> {
    let priority = decoder.read_u16()?.unverified(/*any u16 is valid*/);
    let target = Name::read(decoder)?;
    let mut values = Vec::new();
    while decoder.len() > 4 {
        let key = SVCB_MAP
            .get(&decoder.read_u16()?.unverified(/*any u16 is valid*/))
            .unwrap();
        let val_len = decoder.read_u16()?.unverified(/*any u16 is valid*/);
        let buf = decoder.read_vec(val_len as usize)?.unverified();
        let kv = KeyValue {
            key: key.clone(),
            value: String::from_utf8(buf).unwrap(),
        };
        values.push(kv.clone());
    }
    Ok(SVCB::new(priority, target, values))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, svcb: &SVCB) -> ProtoResult<()> {
    let is_canonical_names = encoder.is_canonical_names();

    encoder.emit_u16(svcb.priority())?;
    svcb.target()
        .emit_with_lowercase(encoder, is_canonical_names)?;
    for kv in svcb.values.iter() {
        encoder.emit_u16(kv.key.clone() as u16)?;
        encoder.emit_u16((kv.value.len()) as u16)?;
        encoder.emit_vec(kv.value.clone().as_bytes())?;
    }
    Ok(())
}

impl fmt::Display for SVCB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let mut values = String::new();
        for value in self.values.iter() {
            values.push_str(&value.to_string());
        }
        write!(
            f,
            "{priority} {target} {values}",
            priority = self.priority,
            target = self.target,
            values = values,
        )
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test_parse_from_rdata() {
        use std::str::FromStr;

        let kv = KeyValue {
            key: SVCBKey::Alpn,
            value: "rip".to_string(),
        };

        let rdata = SVCB::new(
            1,
            Name::from_str("_dns._tcp.example.com").unwrap(),
            vec![kv],
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);

        let read_rdata = read(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_parse_from_str() {}

    #[test]
    fn test_bad_svcb() {}

    #[test]
    fn test_https() {}
}
