kernel version
--------------

5.12


struct, enum naming
-------------------

remove trairing _t
1. struct: snake to camel
2. enum:
   variant: remove prefix then snake to camel
   1. anonymouse: use its prefix as enum name
   2. nlattr type: snake to camel
   3. not nlattr type variant
      define as const, by original (uppercase snake) name
3. macro with args: delete if getting ret val via rsmnl functions


struct, enum derive
-------------------
derive
- struct
#[repr(C)]
#[derive(Debug, Clone, Copy)]

- enum not NlaType
#[repr(...)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]

- NlaType enum
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
