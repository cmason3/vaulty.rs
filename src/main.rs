// Vaulty - Encrypt/Decrypt with ChaCha20-Poly1305
// Copyright (c) 2021-2023 Chris Mason <chris@netnix.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use rand_core::{RngCore, OsRng};
use chacha20poly1305::{aead::{Aead,KeyInit}, ChaCha20Poly1305};
use zeroize::Zeroize;

fn main() {
  let mut salt = [0u8; 16];
  OsRng.fill_bytes(&mut salt);

  println!("Random Salt is {:x?}", salt);

  let mut password = rpassword::prompt_password("Vaulty Password: ").unwrap();

  let mut key = [0u8; 32];
  let params = scrypt::Params::new(16, 8, 1).unwrap();
  scrypt::scrypt(&password.as_bytes(), &salt, &params, &mut key).unwrap();

  println!("Key is {:x?}", key);

  let mut nonce = [0u8; 12];
  OsRng.fill_bytes(&mut nonce);

  println!("Nonce is {:x?}", nonce);

  let cipher = ChaCha20Poly1305::new(key[..].as_ref().into());
  let ciphertext = cipher.encrypt(nonce[..].as_ref().into(), b"Hello World".as_ref()).unwrap();

  println!("Ciphertext is {:x?}", ciphertext);

  let version = "\u{1}".as_bytes();

  let x = [&version[..], &salt[..], &nonce[..], &ciphertext[..]].concat();

  println!("All is {:x?}", x);

  let s = base64::encode(x);

  println!("$VAULTY;{}", s);

  password.zeroize();
  key.zeroize();
}

