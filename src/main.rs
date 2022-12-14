/*
 * Vaulty - Encrypt/Decrypt with ChaCha20-Poly1305
 * Copyright (c) 2021-2023 Chris Mason <chris@netnix.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

use std::str;
use std::io::{Read, Write};
use rand_core::{RngCore, OsRng};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};

fn main() {
  const VAULTY_VERSION: u8 = 0x01;
  const VAULTY_PREFIX: &str = "$VAULTY;";

  let mut input = Vec::new();
  let mut h = std::io::stdin().lock();
  h.read_to_end(&mut input).unwrap();

  if String::from_utf8_lossy(&input).trim().starts_with(VAULTY_PREFIX) {
    let s: &String = &String::from_utf8(input).unwrap().split_whitespace().collect();
    let x = base64::decode(&s[VAULTY_PREFIX.len()..]).unwrap();

    if x[0] == VAULTY_VERSION && x.len() > 29 {
      let password = rpassword::prompt_password("Vaulty Password: ").unwrap();

      let mut key = [0_u8; 32];
      let mut salt = [0_u8; 16];
      salt.copy_from_slice(&x[1..17]);

      derive_key(&password, &mut salt, &mut key, false).unwrap();

      let mut nonce = [0_u8; 12];
      nonce.copy_from_slice(&x[17..29]);

      let cipher = ChaCha20Poly1305::new(key[..].as_ref().into());
      match cipher.decrypt(nonce[..].as_ref().into(), &x[29..]) {
        Ok(v) => {
          std::io::stdout().write(&v).unwrap();
          std::io::stdout().flush().unwrap();
        },
        Err(_e) => {
          eprintln!("Error: Unable to Decrypt Ciphertext");
        }
      };
    }
    else {
      eprintln!("Error: Invalid Vaulty Ciphertext");
    }
  }
  else {
    let password = rpassword::prompt_password("Vaulty Password: ").unwrap();
    if password == rpassword::prompt_password("Password Verification: ").unwrap() {
      let mut key = [0_u8; 32];
      let mut salt = [0_u8; 16];

      derive_key(&password, &mut salt, &mut key, true).unwrap();

      let mut nonce = [0_u8; 12];
      OsRng.fill_bytes(&mut nonce);
  
      let cipher = ChaCha20Poly1305::new(key[..].as_ref().into());
      let ciphertext = cipher.encrypt(nonce[..].as_ref().into(), &input[..]).unwrap();
  
      let x = [&VAULTY_VERSION.to_be_bytes(), &salt[..], &nonce[..], &ciphertext[..]].concat();
  
      let mut s = VAULTY_PREFIX.to_owned();
      s.push_str(&base64::encode(x));

      for r in s.as_bytes().chunks(80).map(str::from_utf8).collect::<Result<Vec<&str>, _>>().unwrap() {
        println!("{}", r);
      }
  
    }
    else {
      eprintln!("Error: Password Verification Failed");
    }
  }
}

fn derive_key(password: &str, salt: &mut [u8; 16], key: &mut [u8; 32], gsalt: bool) -> Result<(), scrypt::errors::InvalidOutputLen> {
  if gsalt == true {
    OsRng.fill_bytes(salt);
  }
  let params = scrypt::Params::new(16, 8, 1).unwrap();
  scrypt::scrypt(&password.as_bytes(), salt, &params, key)
}

