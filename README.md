## Vaulty
### Encrypt/Decrypt with ChaCha20-Poly1305

Vaulty is an extremely lightweight encryption/decryption tool which uses ChaCha20-Poly1305 to provide 256-bit authenticated symmetric encryption (AEAD) using Scrypt as the password based key derivation function.

It can be used to encrypt/decrypt files, or `stdin` if you don't specify any files. If encrypting `stdin` then the output will be Base64 encoded whereas if encrypting a file then it won't and it will have a `.vlt` extension added to indicate it has been encrypted.
