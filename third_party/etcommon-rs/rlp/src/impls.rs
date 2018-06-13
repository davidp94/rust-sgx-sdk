// Copyright 2015-2017 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(not(feature = "std"))]
use alloc::{String, Vec};

#[cfg(feature = "std")] use std::{cmp, mem, str};
#[cfg(not(feature = "std"))] use core::{cmp, mem, str};
use byteorder::{ByteOrder, BigEndian};
use traits::{Encodable, Decodable};
use stream::RlpStream;
use {UntrustedRlp, DecoderError};

pub fn decode_usize(bytes: &[u8]) -> Result<usize, DecoderError> {
	match bytes.len() {
		l if l <= mem::size_of::<usize>() => {
			if bytes[0] == 0 {
				return Err(DecoderError::RlpInvalidIndirection);
			}
			let mut res = 0usize;
			for i in 0..l {
				let shift = (l - 1 - i) * 8;
				res = res + ((bytes[i] as usize) << shift);
			}
			Ok(res)
		}
		_ => Err(DecoderError::RlpIsTooBig),
	}
}

impl Encodable for bool {
	fn rlp_append(&self, s: &mut RlpStream) {
		if *self {
			s.encoder().encode_value(&[1]);
		} else {
			s.encoder().encode_value(&[0]);
		}
	}
}

impl Decodable for bool {
	fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
		rlp.decoder().decode_value(|bytes| {
			match bytes.len() {
				0 => Ok(false),
				1 => Ok(bytes[0] != 0),
				_ => Err(DecoderError::RlpIsTooBig),
			}
		})
	}
}

impl<'a> Encodable for &'a [u8] {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.encoder().encode_value(self);
	}
}

impl Encodable for Vec<u8> {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.encoder().encode_value(self);
	}
}

impl Decodable for Vec<u8> {
	fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
		rlp.decoder().decode_value(|bytes| {
			Ok(bytes.to_vec())
		})
	}
}

impl<T> Encodable for Option<T> where T: Encodable {
	fn rlp_append(&self, s: &mut RlpStream) {
		match *self {
			None => {
				s.begin_list(0);
			},
			Some(ref value) => {
				s.begin_list(1);
				s.append(value);
			}
		}
	}
}

impl<T> Decodable for Option<T> where T: Decodable {
	fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
		let items = rlp.item_count()?;
		match items {
			1 => rlp.val_at(0).map(Some),
			0 => Ok(None),
			_ => Err(DecoderError::RlpIncorrectListLen),
		}
	}
}

impl Encodable for u8 {
	fn rlp_append(&self, s: &mut RlpStream) {
		if *self != 0 {
			s.encoder().encode_value(&[*self]);
		} else {
			s.encoder().encode_value(&[]);
		}
	}
}

impl Decodable for u8 {
	fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
		rlp.decoder().decode_value(|bytes| {
			match bytes.len() {
				1 if bytes[0] != 0 => Ok(bytes[0]),
				0 => Ok(0),
				1 => Err(DecoderError::RlpInvalidIndirection),
				_ => Err(DecoderError::RlpIsTooBig),
			}
		})
	}
}

macro_rules! impl_encodable_for_u {
	($name: ident, $func: ident, $size: expr) => {
		impl Encodable for $name {
			fn rlp_append(&self, s: &mut RlpStream) {
				let leading_empty_bytes = self.leading_zeros() as usize / 8;
				let mut buffer = [0u8; $size];
				BigEndian::$func(&mut buffer, *self);
				s.encoder().encode_value(&buffer[leading_empty_bytes..]);
			}
		}
	}
}

macro_rules! impl_decodable_for_u {
	($name: ident) => {
		impl Decodable for $name {
			fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
				rlp.decoder().decode_value(|bytes| {
					match bytes.len() {
						0 | 1 => u8::decode(rlp).map(|v| v as $name),
						l if l <= mem::size_of::<$name>() => {
							if bytes[0] == 0 {
								return Err(DecoderError::RlpInvalidIndirection);
							}
							let mut res = 0 as $name;
							for i in 0..l {
								let shift = (l - 1 - i) * 8;
								res = res + ((bytes[i] as $name) << shift);
							}
							Ok(res)
						}
						_ => Err(DecoderError::RlpIsTooBig),
					}
				})
			}
		}
	}
}

impl_encodable_for_u!(u16, write_u16, 2);
impl_encodable_for_u!(u32, write_u32, 4);
impl_encodable_for_u!(u64, write_u64, 8);

impl_decodable_for_u!(u16);
impl_decodable_for_u!(u32);
impl_decodable_for_u!(u64);

impl Encodable for usize {
	fn rlp_append(&self, s: &mut RlpStream) {
		(*self as u64).rlp_append(s);
	}
}

impl Decodable for usize {
	fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
		u64::decode(rlp).map(|value| value as usize)
	}
}

macro_rules! impl_encodable_for_hash {
	($name: ident) => {
		impl Encodable for $name {
			fn rlp_append(&self, s: &mut RlpStream) {
				s.encoder().encode_value(self);
			}
		}
	}
}

macro_rules! impl_decodable_for_hash {
	($name: ident, $size: expr) => {
		impl Decodable for $name {
			fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
				rlp.decoder().decode_value(|bytes| match bytes.len().cmp(&$size) {
					cmp::Ordering::Less => Err(DecoderError::RlpIsTooShort),
					cmp::Ordering::Greater => Err(DecoderError::RlpIsTooBig),
					cmp::Ordering::Equal => {
						let mut t = [0u8; $size];
						t.copy_from_slice(bytes);
						Ok($name(t))
					}
				})
			}
		}
	}
}

impl<'a> Encodable for &'a str {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.encoder().encode_value(self.as_bytes());
	}
}

impl Encodable for String {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.encoder().encode_value(self.as_bytes());
	}
}

impl Decodable for String {
	fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        #[cfg(not(feature = "std"))]
        use alloc::borrow::ToOwned;

		rlp.decoder().decode_value(|bytes| {
			match str::from_utf8(bytes) {
				Ok(s) => Ok(s.to_owned()),
				// consider better error type here
				Err(_err) => Err(DecoderError::RlpExpectedToBeData),
			}
		})
	}
}
