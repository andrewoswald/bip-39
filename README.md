# BIP-39

A BIP-39 library to create a deterministic wallet seed by way of randomly generated words and an optional salt.

## Overview
This code was written as an exercise to get familiar with the Rust programming language.  It became demo code
for a presentation I gave in 2019 at Chariot Solutions' annual internal conference: Chariot Day.  As such,
you'll find comments in the code pointing out various features of the language.

There *is* arguably some novelty in the code thoough!  If you're familiar with BIP-39, you derive the mnemonic
terms from a list of 2,048 words; term indexes are *11* bits of entropy.  There may be a handy crate
to do that sort of chunking, but I chose to do it by way of modulus, division, bitshifting, and Rust's *half-open*
ranges.

## Features

The various wordlists get brought in via *feature* during compilation.  For example:

```terminal
cargo build -F chinese_traditional
```

## Example

To run the code, you can simply
```terminal
cargo run
```
and you'll be prompted for required inputs.