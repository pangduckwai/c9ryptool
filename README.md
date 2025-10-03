# c9ryptool
A simple cryptographic tool

## Usage
``` bash
> ./c9ryptool [command] {options}
```

### 1. Miscellaneous
| command | description |
| --- | --- |
| `version` | display current version of `c9ryptool` |
| `help` | display the help message |

---

### 2. Encryption
| command | description |
| --- | --- |
| `encrypt` | encrypt input using the provided encryption key |
| `decrypt` | decrypt encrypted input back to the original form |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-a ALGR` | `--algorithm=ALGR` | `ALGR` is the name of the encryption algorithm to use |
| `-k FILE` | `--key=FILE` | `FILE` is the path of the file containing the encryption key<br/>* key files are not decoded when read, nor encoded when written |
| - | `--iv=IV` | `IV` is the initialization vector (_in base256 encoding_), if omitted:<br/>1. encryption - auto-generate and concat at the begining the ciphertext before base64 encoding<br/>2. decryption - read from the begining of the ciphertext after base64 decoding |
| - | `--iv-b64=IV` | `IV` is the initialization vector in base64 encoding, if omitted:<br/>1. encryption - auto-generate and concat at the begining the ciphertext before base64 encoding<br/>2. decryption - read from the begining of the ciphertext after base64 decoding |
| - | `--iv-hex=IV` | `IV` is the initialization vector in hex endocing, if omitted:<br/>1. encryption - auto-generate and concat at the begining the ciphertext before base64 encoding<br/>2. decryption - read from the begining of the ciphertext after base64 decoding |
| `-g` | `--generate` | generate a new encrytpion key |
| `-p` | `--password` | indicate a password is input interactively |
| - | `--salt=LEN` | `LEN` is the length of salt to use for generating keys from password |

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

---

### 3. Encoding
| command | description |
| --- | --- |
| `encode` | convert the given input into the specified encoding |
| `decode` | convert the given input back from the specified encoding |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-n ENC` | `--encoding=ENC` | `ENC` is the name of the encoding scheme to use |

---

### 4. Common options
| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin<br/>1. for encryption, the input plaintext is not decoded<br/>2. for decryption, the input ciphertext is base64 decoded |
| `-o FILE` | `--out=FILE` | `FILE` is the path of the output file, omitting means output to stdout<br/>1. for encryption, the output ciphertext is base64 encoded<br/>2. for decryption, the output plaintext is not encoded |
| `-l` | `--list` | list the supported algorithms or encoding schemes |
| `-b SIZE` | `--buffer=SIZE` | `SIZE` is the size of the read buffer in # of bytes |
| `-v` | `--verbose` |  display detail operation messages during processing |

## Changelog
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
