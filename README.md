rsmnl-linux
===========

I just want to write [rsmnl](https://crates.io/crates/rsmnl)-core examples
shorter and more compact, and to try using Rust procedual macro.


what is, by example
===================

see examples/netfilter/nfct-daemon.rs and src/netfilter/nfnetlink_conntrack.rs.

define:

    use { Msghdr, Attr, AttrTbl, Result };

    #[repr(u16)]
    #[derive(..., NlaType)
    pub enum Parent {
        None = 0,
        One,
        Two,
        Three,
        _MAX
    }

will implements std::convert::TryFrom<u16> and a few for Parent.


simple type
-----------

Then define nla_type by macro attribute:

    [#nla_type(u32, one)]
    One,

putting value to nlh: Msghdr (e.g. Nlmsghdr) can be done by:

    use mnl:: { AttrTbl, Msghdr };
    Parent::put_one(&mut nlv, 1234u32)

create tb data from read Msghdr, specify its table name:

    #[tbname="ParentTbl"]
    pub enum Parent {

Then, value can be accessed via:

    let tb = ParentTbl::from_nlmsg(header_offset, nlh)?;
    let one: Option<u32> = tb.one()?;
    let attr: Option<&Attr> = tb[Parent::One]?;


nested type
-----------

Two is nested which is defined:

    #[repr(u16)]
    #[derive(..., NlaType)
    #[tbname="ChildTbl"]
    pub enum Child {
        None = 0,
        [#nla_type(str, one)]
        Ichi,
        Ni,
        San,
        _MAX
    }

In enum Parent, define:

    [#nla_nest(ChildTbl, two)]
    Two,

Then Two can be acquire and access:

    let two = tb.two()?;
    let ichi = two.ichi()?;
