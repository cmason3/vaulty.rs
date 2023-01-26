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

use std::{io::{self, Read, Write}, fs::{File, symlink_metadata}, str, cmp, mem, env};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};
use rand_core::{RngCore, OsRng};
use sha2::{Digest, Sha256};

const VAULTY_VERSION: u8 = 0x01;
const VAULTY_PREFIX: &[u8; 8] = b"$VAULTY;";

enum PolyIO {
  Stdin(io::Stdin),
  File(File)
}

impl io::Read for PolyIO {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    match self {
      PolyIO::Stdin(s) => s.read(buf),
      PolyIO::File(f) => f.read(buf)
    }
  }
}

fn main() {
  let mut mo = 0;
  let mut recurse = false;
  let mut args: Vec<String> = env::args().collect();

  if args.len() > 1 {
    if args[1] == "encrypt"[..cmp::min(args[1].len(), 7)] {
      mo = 1;
    }
    else if args[1] == "decrypt"[..cmp::min(args[1].len(), 7)] {
      mo = 2;
    }
    else if args[1] == "chpass"[..cmp::min(args[1].len(), 6)] {
      mo = 3;
    }
    else if args[1] == "sha256"[..cmp::min(args[1].len(), 6)] {
      if args.contains(&"-r".to_string()) {
        args.retain(|x| *x != "-r");
        recurse = true;
      }
      mo = 4;
    }
  }

  if mo > 0 {
    if mo <= 3 {
      if mo == 1 {
        if args.len() == 2 {
          let input = read_stdin();
          let password = rpassword::prompt_password("Vaulty Password: ").unwrap();
          if password == rpassword::prompt_password("Password Verification: ").unwrap() {
            let ciphertext = encrypt(&input, &password, true, 80);
            println!("{}", std::str::from_utf8(&ciphertext).unwrap());
          }
          else {
            eprintln!("\x1b[1;31mError: Password Verification Failed\x1b[0m");
          }
        }
        else {
          let password = rpassword::prompt_password("Vaulty Password: ").unwrap();
          if password == rpassword::prompt_password("Password Verification: ").unwrap() {
            println!();

            let mut i = 2;
            while i < args.len() {
              let r = symlink_metadata(&args[i]);
  
              if r.is_ok() && r.unwrap().is_file() {
                print!("Encrypting {}... ", args[i]);
                io::stdout().flush().unwrap();
                match std::fs::read(&args[i]) {
                  Ok(buffer) => {
                    let ciphertext = encrypt(&buffer, &password, false, 0);
                    match std::fs::write(&args[i], ciphertext) {
                      Ok(()) => {
                        match std::fs::rename(&args[i], format!("{}.vlt", args[i])) {
                          Ok(()) => {
                            println!("\x1b[1;32mok\x1b[0m");
                          },
                          Err(..) => {
                            println!("\x1b[1;31munable to rename\x1b[0m");
                          }
                        }
                      },
                      Err(..) => {
                        println!("\x1b[1;31munable to write\x1b[0m");
                      }
                    }
                  },
                  Err(..) => {
                    println!("\x1b[1;31munable to read\x1b[0m");
                  }
                }
              }
              else {
                println!("Encrypting {}... \x1b[1;31minvalid file\x1b[0m", args[i]);
              }
              i += 1;
            }
          }
          else {
            eprintln!("\x1b[1;31mError: Password Verification Failed\x1b[0m");
          }
        }
      }
      else if mo == 2 {
        if args.len() == 2 {
          let mut input = read_stdin();
          let password = rpassword::prompt_password("Vaulty Password: ").unwrap();

          match decrypt(&mut input, &password) {
            Ok(v) => {
              std::io::stdout().write(&v).unwrap();
              std::io::stdout().flush().unwrap();
            },
            Err(e) => {
              eprintln!("\x1b[1;31m{}\x1b[0m", e)
            }
          }
        }
        else {
          let password = rpassword::prompt_password("Vaulty Password: ").unwrap();
          println!();

          let mut i = 2;
          while i < args.len() {
            let r = symlink_metadata(&args[i]);

            if r.is_ok() && r.unwrap().is_file() {
              print!("Decrypting {}... ", args[i]);
              io::stdout().flush().unwrap();
              match std::fs::read(&args[i]) {
                Ok(mut buffer) => {
                  match decrypt(&mut buffer, &password) {
                    Ok(v) => {
                      match std::fs::write(&args[i], v) {
                        Ok(()) => {
                          match std::fs::rename(&args[i], args[i].strip_suffix(".vlt").unwrap_or(&args[i])) {
                            Ok(()) => {
                              println!("\x1b[1;32mok\x1b[0m");
                            },
                            Err(..) => {
                              println!("\x1b[1;31munable to rename\x1b[0m");
                            }
                          }
                        },
                        Err(..) => {
                          println!("\x1b[1;31munable to write\x1b[0m");
                        }
                      }
                    },
                    Err(..) => {
                      println!("\x1b[1;31merror\x1b[0m");
                    }
                  }
                },
                Err(..) => {
                  println!("\x1b[1;31munable to read\x1b[0m");
                }
              }
            }
            else {
              println!("Decrypting {}... \x1b[1;31minvalid file\x1b[0m", args[i]);
            }
            i += 1;
          }
        }
      }
      else if mo == 3 {
        if args.len() == 2 {
          let mut input = read_stdin();
          let opassword = rpassword::prompt_password("Old Vaulty Password: ").unwrap();
          let password = rpassword::prompt_password("\nNew Vaulty Password: ").unwrap();
          if password == rpassword::prompt_password("Password Verification: ").unwrap() {
            match decrypt(&mut input, &opassword) {
              Ok(v) => {
                let ciphertext = encrypt(&v, &password, true, 80);
                println!("{}", std::str::from_utf8(&ciphertext).unwrap());
              },
              Err(e) => {
                eprintln!("\x1b[1;31m{}\x1b[0m", e)
              }
            }
          }
          else {
            eprintln!("\x1b[1;31mError: Password Verification Failed\x1b[0m");
          }
        }
        else {
          let opassword = rpassword::prompt_password("Old Vaulty Password: ").unwrap();
          let password = rpassword::prompt_password("\nNew Vaulty Password: ").unwrap();
          if password == rpassword::prompt_password("Password Verification: ").unwrap() {
            println!();

            let mut i = 2;
            while i < args.len() {
              let r = symlink_metadata(&args[i]);
  
              if r.is_ok() && r.unwrap().is_file() {
                print!("Updating {}... ", args[i]);
                io::stdout().flush().unwrap();
                match std::fs::read(&args[i]) {
                  Ok(mut buffer) => {
                    match decrypt(&mut buffer, &opassword) {
                      Ok(v) => {
                        mem::drop(buffer);
                        let ciphertext = encrypt(&v, &password, false, 0);
                        match std::fs::write(&args[i], ciphertext) {
                          Ok(()) => {
                            println!("\x1b[1;32mok\x1b[0m");
                          },
                          Err(..) => {
                            println!("\x1b[1;31munable to write\x1b[0m");
                          }
                        }
                      },
                      Err(..) => {
                        println!("\x1b[1;31merror\x1b[0m");
                      }
                    }
                  },
                  Err(..) => {
                    println!("\x1b[1;31munable to read\x1b[0m");
                  }
                }
              }
              else {
                println!("Updating {}... \x1b[1;31minvalid file\x1b[0m", args[i]);
              }
              i += 1;
            }
          }
          else {
            eprintln!("\x1b[1;31mError: Password Verification Failed\x1b[0m");
          }
        }
      }
    }
    else if mo == 4 {
      if args.len() == 2 {
        sha256(PolyIO::Stdin(std::io::stdin()), "-");
      }
      else {
        let mut i = 2;
        while i < args.len() {
          let r = symlink_metadata(&args[i]);

          if r.is_ok() && r.unwrap().is_dir() {
            if recurse == true {
              match std::fs::read_dir(&args[i]) {
                Ok(d) => {
                  for p in d {
                    args.push(p.unwrap().path().display().to_string());
                  }
                },
                Err(e) => {
                  eprintln!("\x1b[1;31m{:<64}  {}\x1b[0m", e.to_string(), args[i]);
                }
              }
            }
          }
          else {
            match File::open(&args[i]) {
              Ok(fh) => {
                sha256(PolyIO::File(fh), &args[i]);
              },
              Err(e) => {
                eprintln!("\x1b[1;31m{:<64}  {}\x1b[0m", e.to_string(), args[i]);
              }
            }
          }
          i += 1;
        }
      }
    }
  }
  else {
    eprintln!("Vaulty v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Usage: vaulty encrypt [file] [..]");
    eprintln!("              decrypt [file] [..]");
    eprintln!("              chpass [file] [..]");
    eprintln!("              sha256 [-r] [file|dir] [..]");
  }
}

fn read_stdin() -> Vec<u8> {
  let mut input = Vec::new();
  let mut h = std::io::stdin().lock();
  h.read_to_end(&mut input).unwrap();
  input
}

fn derive_key(password: &str, salt: &mut [u8; 16], gsalt: bool) -> [u8; 32] {
  if gsalt == true {
    OsRng.fill_bytes(salt);
  }

  let mut key = [0_u8; 32];
  let params = scrypt::Params::new(16, 8, 1).unwrap();
  scrypt::scrypt(&password.as_bytes(), salt, &params, &mut key).unwrap();
  key
}
  
fn encrypt(plaintext: &Vec<u8>, password: &str, armour: bool, cols: usize) -> Vec<u8> {
  let mut salt = [0_u8; 16];
  let key = derive_key(&password, &mut salt, true);
  
  let mut nonce = [0_u8; 12];
  OsRng.fill_bytes(&mut nonce);
    
  let cipher = ChaCha20Poly1305::new(&key.into());

  let ciphertext = [
    &VAULTY_VERSION.to_be_bytes(),
    salt.as_ref(),
    &nonce,
    &cipher.encrypt(&nonce.into(), plaintext.as_ref()).unwrap()
  ].concat();

  if armour == true {
    let mut s = str::from_utf8(VAULTY_PREFIX).unwrap().to_owned();
    s.push_str(&base64::encode(ciphertext));

    if cols > 0 {
      s = s.as_bytes().chunks(cols).map(str::from_utf8).collect::<Result<Vec<&str>, _>>().unwrap().join("\n");
    }
    s.into()
  }
  else {
    ciphertext
  }
}

fn decrypt(ciphertext: &mut Vec<u8>, password: &str) -> Result<Vec<u8>, String> {
  if ciphertext.windows(VAULTY_PREFIX.len()).position(|x| x == VAULTY_PREFIX) != None {
    let s: String = String::from_utf8(ciphertext.to_vec()).unwrap().split_whitespace().collect();
    ciphertext.clear();
    ciphertext.extend(&base64::decode(&s[VAULTY_PREFIX.len()..]).unwrap());
  }

  if ciphertext.len() > 29 && ciphertext[0] == VAULTY_VERSION {
    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&ciphertext[1..17]);

    let key = derive_key(&password, &mut salt, false);
      
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&ciphertext[17..29]);

    let cipher = ChaCha20Poly1305::new(&key.into());
    match cipher.decrypt(&nonce.into(), &ciphertext[29..]) {
      Ok(v) => {
        Ok(v) 
      },
      Err(..) => {
        Err("Error: Unable to Decrypt Ciphertext".to_string())
      }
    }
  }
  else {
    Err("Error: Invalid Vaulty Ciphertext".to_string())
  }
}

fn sha256(mut fh: PolyIO, f: &str) {
  let mut buffer = [0; 4096];
  let mut sha256 = Sha256::new();

  while let Ok(n) = fh.read(&mut buffer) {
    if n > 0 {
      sha256.update(&buffer[0..n]);
    }
    else {
      break;
    }
  }
  println!("{:x}  {}", sha256.finalize(), f);
}

/*
fn memory_usage(label: &str) {
  let x = std::fs::read("/proc/self/stat").unwrap();
  let vsz = str::from_utf8(&x).unwrap().split_whitespace().nth(22).unwrap();
  eprintln!("{} {}", label, vsz);
}
*/
