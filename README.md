# Multicid

A Rust implementation of a
[multiformats](https://github.com/multiformats/multiformats) content identifier
(CID).

## Current Status

This crate supports the full CIDv0 and CIDv1
[specification](https://github.com/multiformats/cid) as used in IPFS. It also
defines a new content identifier called a Vlad (i.e. Very Long-lived ADdress)
that is documented below. A Vlad is intended to replace public keys as
identifiers in distributed systems by combinind a random nonce (i.e. number
used once) and a CID for a WASM verification script designed to run in a
[WACC](https://github.com/cryptidtech/wacc.git) compliant virtual machine. The 
nonce in the Vlad can be random but in some use cases the bytes inside the 
nonce are a [multisig](https://github.com/multisig/multisig) digital signature
over the CID part of the Vlad. Digital signatures are random enough to serve 
the purposes of making the vlad unique while also cryptographically linking the
Vlad to the person who controls the key pair used to create the Vlad.

## Vlad Format

```
vlad 
sigil       cid value
|              |
v              v
0x07 <nonce> <cid>
        ^
        |
    nonce value

<nonce> ::= 0x3b <varbytes>
             ^
            / 
 nonce sigil

<varbytes> ::= <varuint> N(OCTET)
                   ^        ^
                  /          \
          count of            variable number
            octets            of octets
```

The multicodec varuint sigil for a vlad is `0x07`. Immediately following the 
sigil is the nonce followed by the cid. The multicodec varuint sigil for a 
nonce is 0x3b followed by a varbytes. In the cases where the nonce is a digital
signature, the bytes in the varbytes starts with the multisig varuint sigil of 
`0x39`.
