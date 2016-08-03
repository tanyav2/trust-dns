/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! service records for identify port mapping for specific services on a host

use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;
use ::rr::domain::Name;

/// [RFC 2782, DNS SRV RR, February 2000](https://tools.ietf.org/html/rfc2782)
///
/// Introductory example
///
///  If a SRV-cognizant LDAP client wants to discover a LDAP server that
///  supports TCP protocol and provides LDAP service for the domain
///  example.com., it does a lookup of
///
/// _ldap._tcp.example.com
///
///  as described in [ARM].  The example zone file near the end of this
///  memo contains answering RRs for an SRV query.
///
///  Note: LDAP is chosen as an example for illustrative purposes only,
///  and the LDAP examples used in this document should not be considered
///  a definitive statement on the recommended way for LDAP to use SRV
///  records. As described in the earlier applicability section, consult
///  the appropriate LDAP documents for the recommended procedures.
///
/// The format of the SRV RR
///
///  Here is the format of the SRV RR, whose DNS type code is 33:
///
/// _Service._Proto.Name TTL Class SRV Priority Weight Port Target
///
/// (There is an example near the end of this document.)
///
///  Service
/// The symbolic name of the desired service, as defined in Assigned
/// Numbers [STD 2] or locally.  An underscore (_) is prepended to
/// the service identifier to avoid collisions with DNS labels that
/// occur in nature.
///
/// Some widely used services, notably POP, don't have a single
/// universal name.  If Assigned Numbers names the service
/// indicated, that name is the only name which is legal for SRV
/// lookups.  The Service is case insensitive.
///
///  Proto
/// The symbolic name of the desired protocol, with an underscore
/// (_) prepended to prevent collisions with DNS labels that occur
/// in nature.  _TCP and _UDP are at present the most useful values
/// for this field, though any name defined by Assigned Numbers or
/// locally may be used (as for Service).  The Proto is case
/// insensitive.
///
///  Name
/// The domain this RR refers to.  The SRV RR is unique in that the
/// name one searches for is not this name; the example near the end
/// shows this clearly.
///
///  TTL
/// Standard DNS meaning [RFC 1035].
///
///  Class
/// Standard DNS meaning [RFC 1035].   SRV records occur in the IN
/// Class.
///
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SRV { priority: u16, weight: u16, port: u16, target: Name }

impl SRV {
  /// Creates a new SRV record data.
  ///
  /// # Arguments
  ///
  /// * `priority` - lower values have a higher priority and clients will attempt to use these
  ///                first.
  /// * `weight` - for servers with the same priority, higher weights will be chosen more often.
  /// * `port` - the socket port number on which the service is listening.
  /// * `target` - like CNAME, this is the target domain name to which the service is associated.
  ///
  /// # Return value
  ///
  /// The newly constructed SRV record data.
  pub fn new(priority: u16, weight: u16, port: u16, target: Name) -> SRV {
    SRV { priority: priority, weight: weight, port: port, target: target }
  }

  /// ```text
  ///  Priority
  /// The priority of this target host.  A client MUST attempt to
  /// contact the target host with the lowest-numbered priority it can
  /// reach; target hosts with the same priority SHOULD be tried in an
  /// order defined by the weight field.  The range is 0-65535.  This
  /// is a 16 bit unsigned integer in network byte order.
  /// ```
  pub fn get_priority(&self) -> u16 { self.priority }

  /// ```text
  ///  Weight
  /// A server selection mechanism.  The weight field specifies a
  /// relative weight for entries with the same priority. Larger
  /// weights SHOULD be given a proportionately higher probability of
  /// being selected. The range of this number is 0-65535.  This is a
  /// 16 bit unsigned integer in network byte order.  Domain
  /// administrators SHOULD use Weight 0 when there isn't any server
  /// selection to do, to make the RR easier to read for humans (less
  /// noisy).  In the presence of records containing weights greater
  /// than 0, records with weight 0 should have a very small chance of
  /// being selected.
  ///
  /// In the absence of a protocol whose specification calls for the
  /// use of other weighting information, a client arranges the SRV
  /// RRs of the same Priority in the order in which target hosts,
  /// specified by the SRV RRs, will be contacted. The following
  /// algorithm SHOULD be used to order the SRV RRs of the same
  /// priority:
  ///
  /// To select a target to be contacted next, arrange all SRV RRs
  /// (that have not been ordered yet) in any order, except that all
  /// those with weight 0 are placed at the beginning of the list.
  ///
  /// Compute the sum of the weights of those RRs, and with each RR
  /// associate the running sum in the selected order. Then choose a
  /// uniform random number between 0 and the sum computed
  /// (inclusive), and select the RR whose running sum value is the
  /// first in the selected order which is greater than or equal to
  /// the random number selected. The target host specified in the
  /// selected SRV RR is the next one to be contacted by the client.
  /// Remove this SRV RR from the set of the unordered SRV RRs and
  /// apply the described algorithm to the unordered SRV RRs to select
  /// the next target host.  Continue the ordering process until there
  /// are no unordered SRV RRs.  This process is repeated for each
  /// Priority.
  /// ```
  pub fn get_weight(&self) -> u16 { self.weight }

  /// ```text
  ///  Port
  /// The port on this target host of this service.  The range is 0-
  /// 65535.  This is a 16 bit unsigned integer in network byte order.
  /// This is often as specified in Assigned Numbers but need not be.
  ///
  /// ```
  pub fn get_port(&self) -> u16 { self.port }

  /// ```text
  ///  Target
  /// The domain name of the target host.  There MUST be one or more
  /// address records for this name, the name MUST NOT be an alias (in
  /// the sense of RFC 1034 or RFC 2181).  Implementors are urged, but
  /// not required, to return the address record(s) in the Additional
  /// Data section.  Unless and until permitted by future standards
  /// action, name compression is not to be used for this field.
  ///
  /// A Target of "." means that the service is decidedly not
  /// available at this domain.
  /// ```
  pub fn get_target(&self) -> &Name { &self.target }
}

pub fn read(decoder: &mut BinDecoder) -> DecodeResult<SRV> {
  // SRV { priority: u16, weight: u16, port: u16, target: Name, },
  Ok(SRV::new(try!(decoder.read_u16()),
              try!(decoder.read_u16()),
              try!(decoder.read_u16()),
              try!(Name::read(decoder)),
  ))
}

pub fn emit(encoder: &mut BinEncoder, srv: &SRV) -> EncodeResult {
  try!(encoder.emit_u16(srv.get_priority()));
  try!(encoder.emit_u16(srv.get_weight()));
  try!(encoder.emit_u16(srv.get_port()));
  try!(srv.get_target().emit(encoder));
  Ok(())
}

// _foobar._tcp    SRV 0 1 9 old-slow-box.example.com.
pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<SRV> {
  let mut token = tokens.iter();

  let priority: u16 = try!(token.next().ok_or(ParseError::from(ParseErrorKind::MissingToken("priority".to_string()))).and_then(|t| if let &Token::CharData(ref s) = t { Ok(try!(s.parse())) } else {Err(ParseErrorKind::UnexpectedToken(t.clone()).into())} ));
  let weight: u16 = try!(token.next().ok_or(ParseError::from(ParseErrorKind::MissingToken("weight".to_string()))).and_then(|t| if let &Token::CharData(ref s) = t { Ok(try!(s.parse())) } else {Err(ParseErrorKind::UnexpectedToken(t.clone()).into())} ));
  let port: u16 = try!(token.next().ok_or(ParseError::from(ParseErrorKind::MissingToken("port".to_string()))).and_then(|t| if let &Token::CharData(ref s) = t { Ok(try!(s.parse())) } else {Err(ParseErrorKind::UnexpectedToken(t.clone()).into())} ));
  let target: Name = try!(token.next().ok_or(ParseError::from(ParseErrorKind::MissingToken("target".to_string()))).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseErrorKind::UnexpectedToken(t.clone()).into())} ));

  Ok(SRV::new(priority, weight, port, target))
}

#[test]
fn test() {
  let rdata = SRV::new(1, 2, 3, Name::new().label("_dns_tcp").label("example").label("com"));

  let mut bytes = Vec::new();
  let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
  assert!(emit(&mut encoder, &rdata).is_ok());
  let bytes = encoder.as_bytes();

  println!("bytes: {:?}", bytes);

  let mut decoder: BinDecoder = BinDecoder::new(bytes);
  let read_rdata = read(&mut decoder);
  assert!(read_rdata.is_ok(), format!("error decoding: {:?}", read_rdata.unwrap_err()));
  assert_eq!(rdata, read_rdata.unwrap());
}