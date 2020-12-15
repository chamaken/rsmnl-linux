extern crate libc;
extern crate errno;
extern crate rsmnl as mnl;

#[macro_use]
extern crate rsmnl_linux_derive;
    
// based on linux-stable tag: v5.9
pub mod netlink;
pub mod rtnetlink;
pub mod if_addr;
pub mod if_link;
pub mod ifh;
pub mod netfilter;
pub mod ipv6;
pub mod genetlink;
