# c9ryptool
A collection of cryptographic related tools

## Entry points
| - | description |
| --- | --- |
| [`c9ryptool`](#c9ryptool) | A simple cryptographic tool |
| [`c9pubkey`](#c9pubkey) | Extract and export the public key from a private key |
| [`c9split`](#c9split) | Split a file into 2 by number of bytes |
| `test` | Test various functions from the command line |

## c9ryptool
``` bash
> ./c9ryptool [command] {options}
```

### 1. Miscellaneous
| command | description |
| --- | --- |
| `version` | display current version of `c9ryptool` |
| `help` | display the help message |

### 2. Encryption
| command | description |
| --- | --- |
| `encrypt` | encrypt input using the provided encryption key |
| `decrypt` | decrypt encrypted input back to the original form |
| `yamlenc` | encrypt values in the given YAML file while preserving the file structure |
| `yamldec` | decrypt values in the given YAML file |

| option | 2<sup>nd</sup> form | - | description |
| --- | --- | --- | --- |
| `-a ALGR` | `--algorithm=ALGR` | all | `ALGR` is the name of the encryption algorithm to use |
| `-k FILE` | `--key=FILE` | all | `FILE` is the path of the file containing the encryption (private) key |
| - | `--iv=IV` | sym | `IV` is the path of the file containing the initialization vector, if omitted:<br/>1. encryption - auto-generate and concat at the begining the<br/>ciphertext before base64 encoding<br/>2. decryption - read from the begining of the ciphertext after base64<br/>decoding |
| - | `--tag=TAG` | sym | `TAG` is the path of the file containing the message authentication tag |
| - | `--aad=AAD` | sym | `AAD` is the path of the file containing the additional authenticated data |
| `-g` | `--generate` | all | generate a new encrytpion key |
| `-p` | `--password` | sym | indicate a password is input interactively |
| - | `--salt=LEN` | sym | `LEN` is the length of salt to use for generating keys from password |
| `-l` | `--list` | all | list the supported algorithms or encoding schemes |
| `-i FILE` | `--in=FILE` | all | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out=FILE` | all | `FILE` is the path of the output file, omitting means output to stdout |
| `-n ENC` | `--encoding=ENC` | yaml | `ENC` is the name of the encoding scheme to use, only applies to yaml encryption/decryption |

> ### console input
> #### 1. password
> Specify the option `-p` or `--password` to use keys generated from password for the encryption. When
> these options are specified, a prompt will appear for the user to type in the password.

> #### 2. salt
> To enhance security of the keys used, a random value known as `salt` is needed when generating keys
> from passwords. A new, random `salt` is generated during encryption. This salt is written to the
> output at the end of the cipher text, separated with a dot (`.`). During decryption this `salt` is
> read from the input cipher text.

> #### 3. interactive input
> If the option `-i` or `--in=` is omitted, the input text to be encryption is read from stdin.
> Type a period (`.`) then press `<enter>` in a new line to finish inputting.

> #### 4. piped input
> If input content is piped, the stdin will be put to the EOF state. As a result a password can no
> longer be entered via the command line. In these cases password generated keys cannot be used.

### 3. Encoding
| command | description |
| --- | --- |
| `encode` | convert the given input into the specified encoding |
| `decode` | convert the given input back from the specified encoding |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-l` | `--list` | list the supported algorithms or encoding schemes |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out=FILE` | `FILE` is the path of the output file, omitting means output to stdout |
| `-n ENC` | `--encoding=ENC` | `ENC` is the name of the encoding scheme to use |

### 4. Hashing
| command | description |
| --- | --- |
| `hash` | hash input using the specified algorithm |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-l` | `--list` | list the supported algorithms or encoding schemes |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out=FILE` | `FILE` is the path of the output file, omitting means output to stdout |
| `-h ALGR` | `--hashing=ALGR` | `ALGR` is the name of the hashing algorithm to use |

### 5. Display
| command | description |
| --- | --- |
| `display` | display content of the given input as hex, and as characters if printable |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin |
| `-n ENC` | `--encoding=ENC` | `ENC` is the name of the encoding scheme to use |

### 6. Common options
| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-b SIZE` | `--buffer=SIZE` | `SIZE` is the size of the read buffer in # of bytes |
| `-v` | `--verbose` |  display detail operation messages during processing |

---

## c9pubkey
``` bash
> ./c9pubkey [options]
```

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-a ALGR` | `--algorithm=ALGR` | `ALGR` is the name of the encryption algorithm to use |
| `-k FILE` | `--key=FILE` | `FILE` is the path of the file containing the encryption (private) key |
| `-o FILE` | `--out=FILE` | `FILE` is the path of the output file, omitting means output to stdout |

---

## c9split
``` bash
> ./c9split [options]
```

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out0=FILE` | `FILE` is the path of the 1<sup>st</sup> output file, omitting means output to stdout |
| `-p FILE` | `--out1=FILE` | `FILE` is the path of the 2<sup>nd</sup> output file, omitting means output to stdout |
| `-l LEN` | `--len=LEN` | `LEN` is the ??? |

---

## TODO
### 2025-10-14
- Work on AES-CBC
- Check if the handling of `tag`/`aad` for `ChaCha20-Poly1305` is needed or not
- Let user to control encoding of input/output (in file, out file, key file) during encryption

---

## Changelog
### v1.2.0
- add `secp256k1` encryption/decryption
  - Use both `github.com/decred/dcrd/dcrec/secp256k1/v4` and `github.com/ecies/go/v2` as 2 algorithms
  - Import/Export `secp256k1` key pairs from/to `.pem` files

### v1.1.0
- add display file contents

### v1.0.0
- add hashing

### v0.9.0
- add YAML encryption/decryption

### v0.8.0
- add an entry point to split files
- move export public key to a separate entry point

### v0.7.5
- remove all auto encoding during encryption/decryption
- change input of `IV` to read from file
- add supplying of `tag` and `aad` for AES-GCM
- add `rawbase64url` encoding

### v0.7.4
- add command to export public key

### v0.7.3
- add `base64url` encoding

### v0.7.2
- add `hex` encoding

### v0.7.1
- add `base64` encoding

### v0.5.4
- add `RSA-PKCS1v15` algorithm

### v0.5.3
- revamp and refactor packages

### v0.5.2
- improve the handling of salt for generating keys from password

### v0.5.1
- add command to list supported algorithms

### v0.5.0
- add asymmetric encryption (RSA)

### v0.4.1
- fix issue causing populating keys to fail

### v0.4.0
- change `algorithm` to interface

### v0.3.0
- finish all initially planned features

### v0.2.0
- first usable version

### v0.1.0
- initial commit
