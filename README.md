# vcrypt [![GoDoc](https://godoc.org/github.com/vcrypt/vcrypt?status.svg)](http://godoc.org/github.com/vcrypt/vcrypt) [![Build Status](https://travis-ci.org/vcrypt/vcrypt.svg)](https://travis-ci.org/vcrypt/vcrypt)

A toolkit for multi-factor, multi-role encryption.

## Overview

vcrypt is a toolkit for building & executing multi-factor encryption schemes.
It supports a mulit-role encryption workflow: an expert user crafts an
encryption plan distributed to a novice user for safe, reliable encryption.

## Install

        $ go get github.com/vcrypt/vcrypt/cmd/vcrypt

## Commands

        $ vcrypt help
        > usage: vcrypt <command> [<args>]
        >
        > The vcrypt commands are:
        >   build   Build plan file from plan config
        >   export  Export material data
        >   import  Import material data
        >   inspect Inspect vault, plan, or material data
        >   lock    Encrypt data to a vault
        >   unlock  Decrypt data from a vault

## Artifacts

* *plan*: encodes each step (node) in a multi-factor encryption scheme. Steps are
  arranged into a directed acyclic graph with a single root step. Each node is
  either a cryptex, secret, or material. Plans may be sealed. They contain no
  secret information and are safe to distribute publicly.

* *vault*: holds a plan, the ciphertext for the protected data, and
  intermediate (non-secret) material required for decryption. There is no
  unencrypted secret data in the vault artifact. The `lock` command creates a
  vault which can be decrypted with the `unlock` command.

* *material*: the serialized input/output of a node for a vault. Secret
  material data is stored in the database, non-secret data may be stored as
  part of the vault. Allows sharing of solutions to nodes (secret data) between
  users with the `import` & `export` command.

## Reference

* *cryptex*: the combination of an encryption construct (like Shamir's Secret
  Sharing,  NaCl's secretbox, or OpenPGP public key encryption) along with any
  required configuration (public keys, m-of-n values). A cryptex node is a
  single factor in a multi-factor encryption scheme.

* *seal*: a digital signature combined with the cryptographic material needed
  to verify the signature (e.g. a public key).

* *secret*: the sensitive input data required to lock and/or unlock a single
  cryptex.

## Examples

* [twoman: simple plan for a two-man rule control mechanism with passwords](examples/01-twoman/README.md)
* [diamond: requires three secrets; the second has two possible solutions](examples/02-diamond/README.md)
* [dnssec: inspired by DNSSEC root key; m-of-n, multi-party OpenPGP encryption](examples/03-dnssec/README.md)
