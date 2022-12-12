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

fn main() {
  let mut salt = [0u8; 16];
  OsRng.fill_bytes(&mut salt);

  println!("Random Salt is {:x?}", salt);

  let password = rpassword::prompt_password("Vaulty Password: ").unwrap();

  let mut key = [0u8; 32];
  let params = scrypt::Params::new(16, 8, 1).unwrap();
  scrypt::scrypt(&password.as_bytes(), &salt, &params, &mut key).unwrap();

  println!("Key is {:x?}", key);
}

