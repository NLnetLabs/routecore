use crate::bgp::message::{Header, MsgType};
use crate::util::parser::ParseError;
use octseq::{OctetsBuilder, OctetsRef, Parser, ShortBuf, Truncate};

/// BGP Keepalive message, variant of the [`Message`] enum.
#[derive(Clone, Debug)]
pub struct KeepaliveMessage<Octets> {
    octets: Octets
}

impl<Octets: AsRef<[u8]>> KeepaliveMessage<Octets>
where
    for <'a> &'a Octets: OctetsRef
{
    pub fn from_octets(octets: Octets) -> Result<Self, ParseError> {
        Self::check(&octets)?;
        Ok(KeepaliveMessage { octets })
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

impl<Octets: AsRef<[u8]>> KeepaliveMessage<Octets> {
    pub fn octets(&self) -> &Octets {
            &self.octets
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for KeepaliveMessage<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}


//--- Builder ----------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct KeepaliveBuilder<Target> {
    target: Target,
}

use core::convert::Infallible;
impl<Target: OctetsBuilder + Truncate> KeepaliveBuilder<Target>
where Infallible: From<<Target as OctetsBuilder>::AppendError>
{
    pub fn from_target(mut target: Target) -> Result<Self, ShortBuf> {
        target.truncate(0);
        let mut h = Header::<Target::Octets>::new();
        h.set_type(MsgType::Keepalive);
        target.append_slice(h.as_ref());
        Ok(KeepaliveBuilder { target })
    }
}

impl<Target: OctetsBuilder> KeepaliveBuilder<Target> {
    pub fn finish(self) -> Target {
        self.target
    }
    pub fn into_message(self) -> KeepaliveMessage<Target::Octets> {
        KeepaliveMessage{ octets: self.finish().freeze() }
    }
}
impl KeepaliveBuilder<Vec<u8>> {
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
            let kap = KeepaliveBuilder::new_vec();
            let res = kap.into_message();
            println!("{:?}", res);
        }
    }

    
}
