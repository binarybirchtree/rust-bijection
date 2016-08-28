// This file is part of Rust-Bijection.
// Copyright 2016 Binary Birch Tree
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Bijection
//! A library for producing bijective functions in Rust.

#[macro_use] extern crate arrayref;
             extern crate byteorder;
             extern crate crypto;
#[macro_use] extern crate matches;

use byteorder::{ByteOrder, NetworkEndian};
use crypto::{aes, symmetriccipher};
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::sha3::Sha3;
use crypto::symmetriccipher::{Decryptor, Encryptor};

pub struct Bijection {
  key: [u8; 32],
  initialization_vector: [u8; 16],
}

impl Bijection {
  pub fn new (seed: &str) -> Bijection {
    let mut bijection = Bijection {
      key: [0; 32],
      initialization_vector: [0; 16],
    };

    let mut sha256 = Sha256::new();
    sha256.input_str(seed);
    sha256.result(&mut bijection.key);

    let mut shake128 = Sha3::shake_128();
    shake128.input_str(seed);
    shake128.result(&mut bijection.initialization_vector);

    bijection
  }
}

macro_rules! convert_integer {
  ($bijection: expr, $input: expr, $value_size: expr, $writer: ident) => {
    {
      let mut buffer = [0; $value_size];
      NetworkEndian::$writer(&mut buffer, $input);
      $bijection.convert_bytes(&buffer)
    }
  }
}

impl Bijection {
  /// Converts a string.
  ///
  /// ## Example
  ///
  /// ```
  /// # extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  /// let result = Bijection::new("example").convert_string("Example string");
  /// # }
  /// ```
  pub fn convert_string (&mut self, input: &str) -> Result<Vec<u8>, Error> {
    self.convert_bytes(input.as_bytes())
  }

  /// Converts an unsigned 8-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  /// let result = Bijection::new("example").convert_u8(u8::max_value());
  /// # }
  /// ```
  pub fn convert_u8 (&mut self, input: u8) -> Result<Vec<u8>, Error> {
    self.convert_bytes(&[input])
  }

  /// Converts an unsigned 16-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  /// let result = Bijection::new("example").convert_u16(u16::max_value());
  /// # }
  /// ```
  pub fn convert_u16 (&mut self, input: u16) -> Result<Vec<u8>, Error> {
    convert_integer!(self, input, 2, write_u16)
  }

  /// Converts an unsigned 32-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  /// let result = Bijection::new("example").convert_u32(u32::max_value());
  /// # }
  /// ```
  pub fn convert_u32 (&mut self, input: u32) -> Result<Vec<u8>, Error> {
    convert_integer!(self, input, 4, write_u32)
  }

  /// Converts an unsigned 64-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  /// let result = Bijection::new("example").convert_u64(u64::max_value());
  /// # }
  /// ```
  pub fn convert_u64 (&mut self, input: u64) -> Result<Vec<u8>, Error> {
    convert_integer!(self, input, 8, write_u64)
  }
}

macro_rules! revert_integer {
  ($bijection: expr, $input: expr, $reader: ident) => {
    Ok(NetworkEndian::$reader(&try!($bijection.revert_bytes($input))))
  }
}

impl Bijection {
  /// Reverts a string.
  ///
  /// ## Example
  ///
  /// ```
  /// # #[macro_use] extern crate arrayref;
  /// #              extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  ///   let mut bijection = Bijection::new("example");
  ///   let converted_value = bijection.convert_string("Example string").unwrap();
  ///   let result = bijection.revert_string(&converted_value);
  /// # }
  /// ```
  pub fn revert_string (&mut self, input: &[u8]) -> Result<String, Error> {
    String::from_utf8(try!(self.revert_bytes(input))).map_err(Error::FromUtf8)
  }

  /// Reverts an unsigned 8-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # #[macro_use] extern crate arrayref;
  /// #              extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  ///   let mut bijection = Bijection::new("example");
  ///   let converted_value = bijection.convert_u8(u8::max_value()).unwrap();
  ///   let result = Bijection::new("example").revert_u8(array_ref!(converted_value, 0, 1));
  /// # }
  /// ```
  pub fn revert_u8 (&mut self, input: &[u8; 1]) -> Result<u8, Error> {
    Ok(try!(self.revert_bytes(input))[0])
  }

  /// Reverts an unsigned 16-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # #[macro_use] extern crate arrayref;
  /// #              extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  ///   let mut bijection = Bijection::new("example");
  ///   let converted_value = bijection.convert_u16(u16::max_value()).unwrap();
  ///   let result = Bijection::new("example").revert_u16(array_ref!(converted_value, 0, 2));
  /// # }
  /// ```
  pub fn revert_u16 (&mut self, input: &[u8; 2]) -> Result<u16, Error> {
    revert_integer!(self, input, read_u16)
  }

  /// Reverts an unsigned 8-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # #[macro_use] extern crate arrayref;
  /// #              extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  ///   let mut bijection = Bijection::new("example");
  ///   let converted_value = bijection.convert_u32(u32::max_value()).unwrap();
  ///   let result = Bijection::new("example").revert_u32(array_ref!(converted_value, 0, 4));
  /// # }
  /// ```
  pub fn revert_u32 (&mut self, input: &[u8; 4]) -> Result<u32, Error> {
    revert_integer!(self, input, read_u32)
  }

  /// Reverts an unsigned 8-bit integer.
  ///
  /// ## Example
  ///
  /// ```
  /// # #[macro_use] extern crate arrayref;
  /// #              extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  ///   let mut bijection = Bijection::new("example");
  ///   let converted_value = bijection.convert_u64(u64::max_value()).unwrap();
  ///   let result = Bijection::new("example").revert_u64(array_ref!(converted_value, 0, 8));
  /// # }
  /// ```
  pub fn revert_u64 (&mut self, input: &[u8; 8]) -> Result<u64, Error> {
    revert_integer!(self, input, read_u64)
  }
}

macro_rules! process_buffer {
  ($bijection: expr, $input: expr, $cipher_method: ident) => {
    {
      let mut output = Vec::<u8>::new();

      let mut cipher = aes::ctr(aes::KeySize::KeySize256, &$bijection.key, &$bijection.initialization_vector);
      let mut read_buffer = RefReadBuffer::new($input);
      let mut raw_write_buffer = [0; 32];
      let mut write_buffer = RefWriteBuffer::new(&mut raw_write_buffer);

      loop {
        let result = try!(cipher.$cipher_method(&mut read_buffer, &mut write_buffer, true).map_err(Error::SymmetricCipher));
        output.extend_from_slice(write_buffer.take_read_buffer().take_remaining());

        match result {
          BufferResult::BufferOverflow => continue,
          BufferResult::BufferUnderflow => break,
        }
      }

      Ok(output)
    }
  }
}

impl Bijection {
  /// Converts a byte array.
  ///
  /// ## Example
  ///
  /// ```
  /// # extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  /// let result = Bijection::new("example").convert_bytes("Example string".as_bytes());
  /// # }
  /// ```
  pub fn convert_bytes (&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
    process_buffer!(self, input, encrypt)
  }

  /// Reverts a byte array.
  ///
  /// ## Example
  ///
  /// ```
  /// # #[macro_use] extern crate arrayref;
  /// #              extern crate bijection;
  /// # use bijection::Bijection;
  /// # fn main () {
  ///   let mut bijection = Bijection::new("example");
  ///   let converted_value = bijection.convert_bytes("Example string".as_bytes()).unwrap();
  ///   let result = bijection.revert_bytes(&converted_value);
  /// # }
  /// ```
  pub fn revert_bytes (&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
    process_buffer!(self, input, decrypt)
  }
}

#[derive(Debug)]
pub enum Error {
  FromUtf8(std::string::FromUtf8Error),
  SymmetricCipher(symmetriccipher::SymmetricCipherError),
}

#[cfg(test)]
mod tests {
  macro_rules! test_roundtrip_conversion {
    ($($test_name: ident($input: expr, $converter: ident, $reverter: ident),)+) => {
      $(
        #[test]
        fn $test_name () {
          let mut bijection = super::Bijection::new("Test seed");
          let converted = bijection.$converter($input).unwrap();
          let reverted = bijection.$reverter(&converted).unwrap();
          assert_eq!(&reverted[..], $input);
        }
      )+
    }
  }

  test_roundtrip_conversion! {
    roundtrip_conversion_for_empty_byte_array(&[], convert_bytes, revert_bytes),
    roundtrip_conversion_for_non_empty_byte_array("Test input".as_bytes(), convert_bytes, revert_bytes),
    roundtrip_conversion_for_empty_string("", convert_string, revert_string),
    roundtrip_conversion_for_non_empty_string("Test input", convert_string, revert_string),
  }

  macro_rules! test_roundtrip_conversion_for_integers {
    ($($test_name: ident($value_type: ty, $value_size: expr, $converter: ident, $reverter: ident, $initial_value: expr),)+) => {
      $(
        #[test]
        fn $test_name () {
          let mut bijection = super::Bijection::new("Test seed");

          for i in $initial_value..(<$value_type>::max_value()) {
            let converted = bijection.$converter(i).unwrap();
            let reverted = bijection.$reverter(array_ref!(converted, 0, $value_size)).unwrap();
            assert_eq!(reverted, i);
          }
        }
      )+
    }
  }

  test_roundtrip_conversion_for_integers! {
    roundtrip_conversion_for_unsigned_8_bit_integers(u8, 1, convert_u8, revert_u8, 0),
    roundtrip_conversion_for_unsigned_16_bit_integers(u16, 2, convert_u16, revert_u16, u16::max_value() - 1),
    roundtrip_conversion_for_unsigned_32_bit_integers(u32, 4, convert_u32, revert_u32, u32::max_value() - 1),
    roundtrip_conversion_for_unsigned_64_bit_integers(u64, 8, convert_u64, revert_u64, u64::max_value() - 1),
  }

  #[test]
  fn roundtrip_conversion_with_different_seeds () {
    let input = "Test input";

    let mut bijection1 = super::Bijection::new("Test seed 1");
    let converted = bijection1.convert_bytes(input.as_bytes()).unwrap();

    let mut bijection2 = super::Bijection::new("Test seed 2");
    let reverted = bijection2.revert_bytes(&converted).unwrap();

    assert!(&reverted[..] != input.as_bytes());
  }

  #[test]
  fn roundtrip_conversion_with_identical_seeds () {
    let input = "Test input";
    let seed = "Test seed";

    let mut bijection1 = super::Bijection::new(seed);
    let converted = bijection1.convert_bytes(input.as_bytes()).unwrap();

    let mut bijection2 = super::Bijection::new(seed);
    let reverted = bijection2.revert_bytes(&converted).unwrap();

    assert_eq!(&reverted[..], input.as_bytes());
  }

  #[test]
  fn converted_output_has_same_length_as_input () {
    let input = "Test input";

    let mut bijection = super::Bijection::new("Test seed");
    let converted = bijection.convert_bytes(input.as_bytes()).unwrap();

    assert_eq!(converted.len(), input.as_bytes().len());
  }
}
