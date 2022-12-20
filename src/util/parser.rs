// This file contains additional types to be used in conjuction with the
// Parser struct from the octseq crate, mainly related to error handling for
// now.

use core::fmt;
use octseq::ShortInput;
use octseq::{Octets, Parser};
use std::net::{Ipv4Addr, Ipv6Addr};


//--------- IpAddr parse functions -------------------------------------------

/// Takes a [`Ipv4Addr`] from the beginning of the parser.
///
/// The value is created using a constructor from [`Ipv4Addr`]. The parser
/// is advanced by four octets. If there aren't enough octets left, leaves
/// the parser untouched and returns an error instead.
pub fn parse_ipv4addr<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<Ipv4Addr, ShortInput>
{
    parser.check_len(4)?;
    Ok(Ipv4Addr::new(
            parser.parse_u8()?,
            parser.parse_u8()?,
            parser.parse_u8()?,
            parser.parse_u8()?,
    ))
}

/// Takes a [`Ipv6Addr`] from the beginning of the parser.
///
/// The value is created using a constructor from [`Ipv6Addr`]. The parser
/// is advanced by sixteen octets. If there aren't enough octets left,
/// leaves the parser untouched and returns an error instead.
pub fn parse_ipv6addr<R: Octets>(parser: &mut Parser<'_, R>)
    -> Result<Ipv6Addr, ShortInput>
{
    let mut buf = [0u8; 16];
    parser.parse_buf(&mut buf)?;
    Ok(buf.into())
}

//--------- ParseError -------------------------------------------------------

/// An error happened while parsing data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// An attempt was made to go beyond the end of the parser.
    ShortInput,

    /// A formatting error occurred.
    Form(FormError),

    /// Required stateful information was not provided.
    StateRequired,
}

impl ParseError {
    /// Creates a new parse error as a form error with the given message.
    pub fn form_error(msg: &'static str) -> Self {
        FormError::new(msg).into()
    }
}

//--- From

impl From<ShortInput> for ParseError {
    fn from(_: ShortInput) -> Self {
        ParseError::ShortInput
    }
}

impl From<FormError> for ParseError {
    fn from(err: FormError) -> Self {
        ParseError::Form(err)
    }
}

//--- Display and Error

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::ShortInput => f.write_str("unexpected end of input"),
            ParseError::Form(ref err) => err.fmt(f),
            ParseError::StateRequired => f.write_str("required stateful parsing info missing")
        }
    }
}

//------------ FormError -----------------------------------------------------

/// A formatting error occured.
///
/// This is a generic error for all kinds of error cases that result in data
/// not being accepted. For diagnostics, the error is being given a static
/// string describing the error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormError(&'static str);

impl FormError {
    /// Creates a new form error value with the given diagnostics string.
    pub fn new(msg: &'static str) -> Self {
        FormError(msg)
    }
}

//--- Display and Error

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}
