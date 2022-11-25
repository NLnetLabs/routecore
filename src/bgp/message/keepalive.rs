use crate::bgp::message::{Header, MsgType};
use crate::util::parser::ParseError;
use octseq::{OctetsBuilder, OctetsRef, Parser, ShortBuf, Truncate};

/// BGP KeepAlive message, variant of the [`Message`] enum.
#[derive(Clone, Debug)]
pub struct KeepAliveMessage<Octets> {
    octets: Octets
}

impl<Octets: AsRef<[u8]>> KeepAliveMessage<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    pub fn from_octets(octets: Octets) -> Result<Self, ParseError> {
        Self::check(&octets)?;
        Ok(KeepAliveMessage { octets })
    }

    pub fn check(octets: &Octets) -> Result<(), ParseError>
    {
        let mut parser = Parser::from_ref(octets);
        Header::<Octets>::check(&mut parser)?;
        if parser.remaining() > 0 {
            return Err(ParseError::form_error("KEEPALIVE of >19 bytes"));
        }
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> KeepAliveMessage<Octets> {
    pub fn octets(&self) -> &Octets {
            &self.octets
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for KeepAliveMessage<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}


//--- Builder ----------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct KeepAliveBuilder<Target> {
    target: Target,
}

use core::convert::Infallible;
impl<Target: OctetsBuilder + Truncate> KeepAliveBuilder<Target>
where Infallible: From<<Target as OctetsBuilder>::AppendError>
{
    pub fn from_target(mut target: Target) -> Result<Self, ShortBuf> {
        target.truncate(0);
        let mut h = Header::<Target::Octets>::new();
        h.set_type(MsgType::KeepAlive);
        target.append_slice(h.as_ref());
        Ok(KeepAliveBuilder { target })
    }
}

impl<Target: OctetsBuilder> KeepAliveBuilder<Target> {
    pub fn finish(self) -> Target {
        self.target
    }
    pub fn into_message(self) -> KeepAliveMessage<Target::Octets> {
        KeepAliveMessage{ octets: self.finish().freeze() }
    }
}
impl KeepAliveBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::from_target(Vec::new()).unwrap()
    }
}

//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    // TODO

    mod builder {
        use super::*;

        #[test]
        fn builder() {
            let kap = KeepAliveBuilder::new_vec();
            let res = kap.into_message();
            println!("{:?}", res);
        }
    }

    
}
