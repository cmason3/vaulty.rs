## Vaulty
### Encrypt/Decrypt with ChaCha20-Poly1305

Vaulty is an extremely lightweight encryption/decryption tool which uses ChaCha20-Poly1305 to provide 256-bit authenticated symmetric encryption (AEAD) using Scrypt as the password based key derivation function.

```
vaulty encrypt [file] [..]
       decrypt [file] [..]
       chpass [file] [..]
       sha256 [-r] [file|dir] [..]
```

#### Usage - Symmetric Encryption

Symmetric encryption is where encryption and decryption happens with the same password/key. If Alice is sharing an encrypted file with Bob then both [Alice and Bob](https://en.wikipedia.org/wiki/Alice_and_Bob) need to know the same password/key. With symmetric encryption both parties need a secure mechanism to exchange the password/key without anyone else (i.e. Eve) obtaining it.

```
echo "Hello World" | vaulty encrypt
$VAULTY;AY3eJ98NF6WFDMAP62lRdl58A2db5XJ2gNvKd0nmDs5ZrmNlJ8TSURpxc3bNF1iGw77dHA==

echo "$VAULTY;..." | vaulty decrypt
Hello World
```

#### Usage - SHA256

```
echo "Hello World" | vaulty sha256
d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26  -
```
