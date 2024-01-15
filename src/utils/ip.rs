use std::net::Ipv6Addr;

pub trait Ipv6Ext {
    fn is_link_local(&self) -> bool;
}

impl Ipv6Ext for Ipv6Addr {
    #[inline]
    fn is_link_local(&self) -> bool {
        self.segments()[0] == 0xfe80
    }
}
