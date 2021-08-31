extern crate errno;
extern crate libc;
extern crate rsmnl as mnl;

#[macro_use]
extern crate rsmnl_linux_derive;

// based on linux-stable tag: v5.9
pub mod genetlink;
pub mod if_addr;
pub mod if_link;
pub mod ifh;
pub mod ipv6;
pub mod neighbour;
pub mod netfilter;
pub mod netlink;
pub mod rtnetlink;
