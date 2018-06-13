// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![crate_name = "filesampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_types;
#[macro_use]
extern crate sgx_rand_derive;
extern crate sgx_serialize;
#[macro_use]
extern crate sgx_serialize_derive;
extern crate secp256k1;
extern crate bigint;
extern crate sha3;
extern crate block;

use bigint::{Address, H256};
use block::{FromKey};
use sha3::{Digest, Keccak256};
use secp256k1::*;

use std::sgxfs::SgxFile;
use std::io::{Read, Write};
use sgx_types::*;

use sgx_serialize::{SerializeHelper, DeSerializeHelper};

#[derive(Copy, Clone, Default, Debug, Serializable, DeSerializable, Rand)]
struct EthereumSecretWallet {
    signing_key: [u8; 32],
}


#[no_mangle]
pub extern "C" fn write_file() -> sgx_status_t {
    let wallet = sgx_rand::random::<EthereumSecretWallet>();

    let helper = SerializeHelper::new();
    let data = match helper.encode(wallet) {
        Some(d) => d,
        None => {
            println!("encode data failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let mut file = match SgxFile::create("sgx_file") {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::create failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let write_size = match file.write(data.as_slice()) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::write failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    println!("write file success, write size: {}.", write_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn read_file() -> sgx_status_t {
    let mut data = [0_u8; 100];

    let mut file = match SgxFile::open("sgx_file") {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::open failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::read failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let helper = DeSerializeHelper::<EthereumSecretWallet>::new(data.to_vec());
    let wallet = match helper.decode() {
        Some(d) => d,
        None => {
            println!("decode data failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let secret_key = SecretKey::parse(&wallet.signing_key).unwrap();
    let address = Address::from_secret_key(&secret_key).unwrap();

    println!("read file success, read size: {}.", read_size);
    println!("Your SGX ethereum wallet is: 0x{:02x?}", address);
    sgx_status_t::SGX_SUCCESS
}



#[no_mangle]
pub extern "C" fn sign() -> sgx_status_t {
    let mut data = [0_u8; 100];

    let mut file = match SgxFile::open("sgx_file") {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::open failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::read failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let helper = DeSerializeHelper::<EthereumSecretWallet>::new(data.to_vec());
    let wallet = match helper.decode() {
        Some(d) => d,
        None => {
            println!("decode data failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let secret_key = SecretKey::parse(&wallet.signing_key).unwrap();
    let address = Address::from_secret_key(&secret_key).unwrap();

    println!("read file success, read size: {}.", read_size);
    println!("Your SGX ethereum wallet is: 0x{:02x?}", address);

    // TODO: signing.
    sgx_status_t::SGX_SUCCESS
}
