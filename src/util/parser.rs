// this file contains verbatim copies from code in domain/base/octets.rs,
// mainly to find out which parts of Parse(r) we need.

use core::{fmt};
use crate::bgp::message::SessionConfig;
use std::net::{Ipv6Addr, Ipv4Addr};

#[derive(Clone, Copy, Debug)]
pub struct Parser<Ref> {
    /// The underlying octets reference.
    octets: Ref,

    /// The current position of the parser from the beginning of `octets`.
    pos: usize,

    /// The length of the octets sequence.
    ///
    /// This starts out as the length of the underlying sequence and is kept
    /// here to be able to temporarily limit the allowed length for
    /// `parse_blocks`.
    len: usize,

    config: SessionConfig,
}

impl<Ref> Parser<Ref> {
    /// Creates a new parser atop a reference to an octet sequence.
    pub fn from_ref(octets: Ref, config: SessionConfig) -> Self
    where
        Ref: AsRef<[u8]>,
    {
        Parser {
            pos: 0,
            len: octets.as_ref().len(),
            octets,
            config,
        }
    }

    /// Returns the current parse position as an index into the octets.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the number of remaining octets to parse.
    pub fn remaining(&self) -> usize {
        self.len - self.pos
    }

    /// Returns the length of the underlying octet sequence.
    ///
    /// This is _not_ the number of octets left for parsing. Use
    /// [`remaining`] for that.
    ///
    /// [`remaining`]: #method.remaining
    pub fn len(&self) -> usize {
        self.len
    }

    /// Advances the parser‘s position by `len` octets.
    ///
    /// If this would take the parser beyond its end, an error is returned.
    pub fn advance(&mut self, len: usize) -> Result<(), ParseError> {
        if len > self.remaining() {
            Err(ParseError::ShortInput)
        } else {
            self.pos += len;
            Ok(())
        }
    }

    /// Repositions the parser to the given index.
    ///
    /// It is okay to reposition anywhere within the sequence. However,
    /// if `pos` is larger than the length of the sequence, an error is
    /// returned.
    pub fn seek(&mut self, pos: usize) -> Result<(), ParseError> {
        if pos > self.len {
            Err(ParseError::ShortInput)
        } else {
            self.pos = pos;
            Ok(())
        }
    }

    /// Returns the wrapped reference to the underlying octets sequence.
    pub fn octets_ref(&self) -> Ref
    where
        Ref: Copy,
    {
        self.octets
    }

    pub fn config(&self) -> SessionConfig {
        self.config
    }

    pub fn config_mut(&mut self) -> &mut SessionConfig {
        &mut self.config
    }

}

impl<Ref: AsRef<[u8]>> Parser<Ref> {
    /// Returns an octets slice of the underlying sequence.
    ///
    /// The slice covers the entire sequence, not just the remaining data. You
    /// can use [`peek`] for that.
    ///
    /// [`peek`]: #method.peek
    pub fn as_slice(&self) -> &[u8] {
        &self.octets.as_ref()[..self.len]
    }

    /// Fills the provided buffer by taking octets from the parser.
    ///
    /// Copies as many octets as the buffer is long from the parser into the
    /// buffer and advances the parser by that many octets.
    ///
    /// If there aren’t enough octets left in the parser to fill the buffer
    /// completely, returns an error and leaves the parser untouched.
    pub fn parse_buf(&mut self, buf: &mut [u8]) -> Result<(), ParseError> {
        let pos = self.pos;
        self.advance(buf.len())?;
        buf.copy_from_slice(&self.octets.as_ref()[pos..self.pos]);
        Ok(())
    }

    /// Takes and returns the next `len` octets.
    ///
    /// Advances the parser by `len` octets. If there aren’t enough octats
    /// left, leaves the parser untouched and returns an error instead.
    pub fn parse_octets(
        &mut self,
        len: usize,
    ) -> Result<Ref::Range, ParseError>
    where
        Ref: OctetsRef,
    {
        let end = self.pos + len;
        if end > self.len {
            return Err(ParseError::ShortInput);
        }
        let res = self.octets.range(self.pos, end);
        self.pos = end;
        Ok(res)
    }

    /// Returns a slice for the next `len` octets.
    ///
    /// If less than `len` octets are left, returns an error.
    pub fn peek(&self, len: usize) -> Result<&[u8], ParseError> {
        self.check_len(len)?;
        Ok(&self.peek_all()[..len])
    }

    /// Returns a slice of the data left to parse.
    pub fn peek_all(&self) -> &[u8] {
        &self.octets.as_ref()[self.pos..]
    }

    /// Checks that there are `len` octets left to parse.
    ///
    /// If there aren’t, returns an error.
    pub fn check_len(&self, len: usize) -> Result<(), ParseError> {
        if self.remaining() < len {
            Err(ParseError::ShortInput)
        } else {
            Ok(())
        }
    }

    /// Takes a `u8` from the beginning of the parser.
    ///
    /// Advances the parser by one octet. If there aren’t enough octets left,
    /// leaves the parser untouched and returns an error instead.
    pub fn parse_u8(&mut self) -> Result<u8, ParseError> {
        let res = self.peek(1)?[0];
        self.pos += 1;
        Ok(res)
    }

    /// Takes a `u16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two ocetets. If
    /// there aren’t enough octets left, leaves the parser untouched and
    /// returns an error instead.
    pub fn parse_u16(&mut self) -> Result<u16, ParseError> {
        let mut res = [0; 2];
        self.parse_buf(&mut res)?;
        Ok(u16::from_be_bytes(res))
    }

    /// Takes a `u32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four octets. If
    /// there aren’t enough octets left, leaves the parser untouched and
    /// returns an error instead.
    pub fn parse_u32(&mut self) -> Result<u32, ParseError> {
        let mut res = [0; 4];
        self.parse_buf(&mut res)?;
        Ok(u32::from_be_bytes(res))
    }

    /// Takes a `u64` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four octets. If
    /// there aren’t enough octets left, leaves the parser untouched and
    /// returns an error instead.
    pub fn parse_u64(&mut self) -> Result<u64, ParseError> {
        let mut res = [0; 8];
        self.parse_buf(&mut res)?;
        Ok(u64::from_be_bytes(res))
    }
}

impl<T: AsRef<[u8]>> Parse<T> for Ipv6Addr {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 16];
        parser.parse_buf(&mut buf)?;
        Ok(buf.into())
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(16).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for Ipv4Addr {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        Ok(Self::new(
                parser.parse_u8()?,
                parser.parse_u8()?,
                parser.parse_u8()?,
                parser.parse_u8()?,
        ))
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(4).map_err(Into::into)
    }
}


pub trait Parse<Ref>: Sized {
    /// Extracts a value from the beginning of `parser`.
    ///
    /// If parsing fails and an error is returned, the parser’s position
    /// should be considered to be undefined. If it is supposed to be reused
    /// in this case, you should store the position before attempting to parse
    /// and seek to that position again before continuing.
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError>;

    /// Skips over a value of this type at the beginning of `parser`.
    ///
    /// This function is the same as `parse` but doesn’t return the result.
    /// It can be used to check if the content of `parser` is correct or to
    /// skip over unneeded parts of the parser.
    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError>;
}

//------------ OctetsRef -----------------------------------------------------

/// A reference to an octets sequence.
///
/// This trait is to be implemented for a (imutable) reference to a type of
/// an octets sequence. I.e., it `T` is an octets sequence, `OctetsRef` needs
/// to be implemented for `&T`.
///
/// The primary purpose of the trait is to allow access to a sub-sequence,
/// called a ‘range.’ The type of this range is given via the `Range`
/// associated type. For most types it will be a `&[u8]` with a lifetime equal
/// to that of the reference itself. Only if an owned range can be created
/// cheaply, it should be that type.
///
/// There is two basic ways of using the trait for a trait bound. You can
/// either limit the octets sequence type itself by bounding references to it
/// via a where clause. I.e., for an  octets sequence type argument `Octets`
/// you can specify `where &'a Octets: OctetsRef` or, if you don’t have a
/// lifetime argument available `where for<'a> &'a Octets: OctetsRef`. For
/// this option, you’d typically refer to values as references to the
/// octets type, i.e., `&Octets`.
///
/// Alternatively, you can refer to the reference itself as a owned value.
/// This works out fine since all octets references are required to be
/// `Copy`. For instance, a function can take a value of generic type `Oref`
/// and that type can then be directly bounded via `Oref: OctetsRef`.
pub trait OctetsRef: AsRef<[u8]> + Copy + Sized {
    /// The type of a range of the sequence.
    type Range: AsRef<[u8]>;

    /// Returns a sub-sequence or ‘range’ of the sequence.
    fn range(self, start: usize, end: usize) -> Self::Range;

    /// Returns a range starting at index `start` and going to the end.
    fn range_from(self, start: usize) -> Self::Range {
        self.range(start, self.as_ref().len())
    }

    /// Returns a range from the start to before index `end`.
    fn range_to(self, end: usize) -> Self::Range {
        self.range(0, end)
    }

    /// Returns a range that covers the entire sequence.
    fn range_all(self) -> Self::Range {
        self.range(0, self.as_ref().len())
    }
}

impl<'a, T: OctetsRef> OctetsRef for &'a T {
    type Range = T::Range;

    fn range(self, start: usize, end: usize) -> Self::Range {
        (*self).range(start, end)
    }
}

impl<'a> OctetsRef for &'a [u8] {
    type Range = &'a [u8];

    fn range(self, start: usize, end: usize) -> Self::Range {
        &self[start..end]
    }
}

impl<'a> OctetsRef for &'a Vec<u8> {
    type Range = &'a [u8];

    fn range(self, start: usize, end: usize) -> Self::Range {
        &self[start..end]
    }
}

//------------ ShortBuf ------------------------------------------------------

/// An attempt was made to write beyond the end of a buffer.
///
/// This type is returned as an error by all functions and methods that append
/// data to an [octets builder] when the buffer size of the builder is not
/// sufficient to append the data.
///
/// [octets builder]: trait.OctetsBuilder.html
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortBuf;

//--- Display and Error

impl fmt::Display for ShortBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("buffer size exceeded")
    }
}


//--------- ParseError -------------------------------------------------------

/// An error happened while parsing data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// An attempt was made to go beyond the end of the parser.
    ShortInput,

    /// A formatting error occurred.
    Form(FormError),
}

impl ParseError {
    /// Creates a new parse error as a form error with the given message.
    pub fn form_error(msg: &'static str) -> Self {
        FormError::new(msg).into()
    }
}

//--- From

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
