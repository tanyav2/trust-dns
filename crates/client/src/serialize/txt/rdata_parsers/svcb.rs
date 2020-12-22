use std::str::FromStr;

use crate::error::*;
use crate::rr::domain::Name;
use crate::rr::rdata::SVCB;
use crate::rr::rdata::svcb::SVCBKeyValues;

/// Parse the RData from a set of Tokens
pub fn parse<'i, I: Iterator<Item = &'i str>>(
    mut tokens: I,
    origin: Option<&Name>,
) -> ParseResult<SVCB> {
    let priority: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("priority".to_string())))
        .and_then(|s| u16::from_str(s).map_err(Into::into))?;

    let target: Name = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("target".to_string())))
        .and_then(|s| Name::parse(s, origin).map_err(ParseError::from))?;

    let values: SVCBKeyValues = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("values".to_string())))
        .and_then(|s| SVCBKeyValues::parse(s).map_err(ParseError::from))?;

    Ok(SVCB::new(priority, target, values.0))
}
