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
use std::io::Read;
use rand_core::{RngCore, OsRng};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};
use zeroize::Zeroize;

fn main() {
  const VAULTY_VERSION: u8 = 0x01;
  const VAULTY_PREFIX: &str = "$VAULTY;";

  let mut input = Vec::new();
  let mut h = std::io::stdin().lock();
  h.read_to_end(&mut input).unwrap();

  if str::from_utf8(&input).unwrap().starts_with(VAULTY_PREFIX) { // DECRYPT
    let x = base64::decode(&s[VAULTY_PREFIX.len()..]).unwrap();

    if x[0] == VAULTY_VERSION && x.len() > 29 {
      let mut password = rpassword::prompt_password("Vaulty Password: ").unwrap();

      let mut salt = [0_u8; 16];
      salt.copy_from_slice(&x[1..17]);

      let mut key = [0_u8; 32];
      let params = scrypt::Params::new(4, 8, 1).unwrap();
      scrypt::scrypt(&password.as_bytes(), &salt, &params, &mut key).unwrap();

      let mut nonce = [0_u8; 12];
      nonce.copy_from_slice(&x[17..29]);

      let cipher = ChaCha20Poly1305::new(key[..].as_ref().into());
      match cipher.decrypt(nonce[..].as_ref().into(), &x[29..]) {
        Ok(v) => {
          print!("{}", str::from_utf8(&v).unwrap());
        },
        Err(_e) => {
          eprintln!("error: unable to decrypt ciphertext");
        }
      };

      password.zeroize();
      key.zeroize();
    }
    else {
      eprintln!("error: invalid vaulty ciphertext");
    }
  }
  else { // ENCRYPT
    let mut password = rpassword::prompt_password("Vaulty Password: ").unwrap();


  }




  let mut salt = [0_u8; 16];
  OsRng.fill_bytes(&mut salt);

  let mut key = [0_u8; 32];
  let params = scrypt::Params::new(4, 8, 1).unwrap();
  scrypt::scrypt(&password.as_bytes(), &salt, &params, &mut key).unwrap();

  let mut nonce = [0_u8; 12];
  OsRng.fill_bytes(&mut nonce);

  let cipher = ChaCha20Poly1305::new(key[..].as_ref().into());
  let ciphertext = cipher.encrypt(nonce[..].as_ref().into(), &input[..]).unwrap();

  let x = [&VAULTY_VERSION.to_be_bytes(), &salt[..], &nonce[..], &ciphertext[..]].concat();

  let mut s = VAULTY_PREFIX.to_owned();
  s.push_str(&base64::encode(x));

  println!("{}", s);

  password.zeroize();
  key.zeroize();

  // - DECRYPT

  if s.starts_with(VAULTY_PREFIX) {
  }
  else {
    eprintln!("error: invalid ciphertext - missing prefix");
  }
}

