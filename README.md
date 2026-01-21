# c9ryptool
A collection of cryptographic related tools

|  tool | description |
| --- | --- |
| [`c9ryptool`](#c9ryptool) | A simple cryptographic tool |
| [`c9utils`](#c9utils) | Misc. utilities accompany `c9ryptool` |

## c9ryptool
A simple cryptographic tool

```bash
> ./cmd/c9ryptool [command] {options}
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

| option | 2<sup>nd</sup> form | - | description |
| --- | --- | --- | --- |
| `-a ALGR` | `--algorithm=ALGR` | all | `ALGR` is the name of the encryption algorithm to use |
| `-k FILE` | `--key=FILE` | all | `FILE` is the path of the file containing the encryption (private) key |
| - | `--iv=IV` | symmetric | `IV` is the path of the file containing the initialization vector, if omitted:<br/>1. encryption - auto-generate and concat at the begining the<br/>ciphertext before base64 encoding<br/>2. decryption - read from the begining of the ciphertext after base64<br/>decoding |
| - | `--tag=TAG` | symmetric | `TAG` is the path of the file containing the message authentication tag |
| - | `--aad=AAD` | symmetric | `AAD` is the path of the file containing the additional authenticated data |
| `-g` | `--generate` | all | generate a new encrytpion key |
| `-p` | - | symmetric | iindicate a password, for encryption key generation, is input interactively |
| - | `--password=PASS` | symmetric | `PASS` is the key-generating password, input via the command line |
| - | `--salt=LEN` | symmetric | `LEN` is the length of salt to use for generating keys from password |
| `-l` | `--list` | all | list the supported encryption algorithms |
| `-i FILE` | `--in=FILE` | all | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out=FILE` | all | `FILE` is the path of the output file, omitting means output to stdout |
| `-f FORMAT` | `--format=FORMAT` | all | `FORMAT` format of the input file:<br/>1. `none` - no format, the entire input is treated as a stream of bytes<br/>2. `yaml` - encrypt/decrypt values in the given YAML file while preserving the file structure<br/>3. `json` - to be added |
| `-n ENC` | `--encoding=ENC` | all | `ENC` is the name of the overall encoding scheme to use for:<br/>1. output and symmetric key for encryption, and<br/>2. input and symmetric key for decryption<br/>NOTE: for the 4 encoding related options, those appear later overwrite the former ones, e.g. if `-n` appear last, it overwrites all the other 3 encoding options |
| - | `--encode-in=ENC` | all | `ENC` is the name of the encoding scheme to use for input:<br/>1. encoding scheme to decode field values before decryption when input format is 'yaml'/'json'<br/>2. encoding scheme to decode the entire input when input format is 'none'<br/>3. encoding scheme to decode AAD, IV and TAG values when given<br/>NOTE 1: normally encryption inputs do not need to be decoded (except e.g. JWE cases)<br/>NOTE 2: `none` is not allowed when input format is not `none` |
| - | `--encode-out=ENC` | all | `ENC` is the name of the encoding scheme to use for output:<br/>1. encoding scheme to encode field values after encryption when output format is 'yaml'/'json'<br/>2. encoding scheme to encode the entire output when input format is 'none'<br/>NOTE 1: normally decryption outputs do not need to be encoded<br/>NOTE 2: `none` is not allowed when input format is not `none` |
| - | `--encode-key=ENC` | symmetric | `ENC` is the name of the encoding scheme to use for encoding/decoding symmetric keys (when option -k / --key is specified) when writing/reading the key files<br/>NOTE: ignored for asymmetric encryption, as asymmetric keys are encoded in PEM format |

> ### console input
> #### 1. password
> Specify the option `-p` or `--password` to use keys generated from password for the encryption. When
> `-p` is specified, a prompt will appear for the user to type in the password.

> #### 2. salt
> To enhance security of the keys used, a random value known as `salt` is needed when generating keys
> from passwords. A new, random `salt` is generated during encryption. This salt is written to the
> output at the end of the cipher text, separated with a dot (`.`). During decryption this `salt` is
> read from the input cipher text.

> #### 3. piped input
> If input content is piped, the stdin will be put to the EOF state. As a result a password can no
> longer be entered via the command line. In these cases interactive password input cannot be used.

> #### 4. interactive input
> If the option `-i` or `--in=` is omitted, the input text to be encryption is read from stdin.
> Type a period (`.`) then press `<enter>` in a new line to finish inputting.

### 3. Encoding
| command | description |
| --- | --- |
| `encode` | convert the given input into the specified encoding |
| `decode` | convert the given input back from the specified encoding |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-l` | `--list` | list the supported encoding schemes |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out=FILE` | `FILE` is the path of the output file, omitting means output to stdout |
| `-n ENC` | `--encoding=ENC` | `ENC` is the name of the encoding scheme to use |

### 4. Hashing
| command | description |
| --- | --- |
| `hash` | hash input using the specified algorithm |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-l` | `--list` | list the supported hashing algorithms |
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

## c9utils
Miscellaneous utilities accompany `c9ryptool`

```bash
> ./cmd/c9utils [command] {options}
```

### 1. Miscellaneous
| command | description |
| --- | --- |
| `version` | display current version of `c9utils` |

### 2. Generate key
| command | description |
| --- | --- |
| `genkey` | generate and export the newly generated encryption key |

| option | 2<sup>nd</sup> form | - | description |
| --- | --- | --- | --- |
| `-a ALGR` | `--algorithm=ALGR` | all | `ALGR` is the name of the encryption algorithm to use |
| `-o FILE` | `--out0=FILE` | all | `FILE` is the path of the file to write the generated key to |
| `-p FILE` | `--out1=FILE` | asymmetric | `FILE` is the path of the file to write the public key of the generated key to, if the specified algorithm is asymmetric |
| `-n ENC` | `--encoding=ENC` | symmetric | `ENC` is the name of the encoding scheme to use to encode the generated symmetric key when writing to file. Asymmetric keys always use PEM encoding |
| `-l` | `--list` | all | list the supported encryption algorithms |

### 3. Export public key
| command | description |
| --- | --- |
| `pubkey` | extract and export the public key from the given private key |

| option | 2<sup>nd</sup> form | - | description |
| --- | --- | --- | --- |
| `-a ALGR` | `--algorithm=ALGR` | asymmetric | `ALGR` is the name of the asymmetric encryption algorithm to use |
| `-i FILE` | `--in=FILE` | asymmetric | `FILE` is the path of the file containing the private key |
| `-o FILE` | `--out=FILE` | asymmetric | `FILE` is the path of the file to write the extracted public key to |
| `-l` | `--list` | asymmetric | list the supported asymmetric encryption algorithms |

### 4. Split file
| command | description |
| --- | --- |
| `split` | split a file into 2 by number of bytes |

| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out0=FILE` | `FILE` is the path of the 1<sup>st</sup> output file |
| `-p FILE` | `--out1=FILE` | `FILE` is the path of the 2<sup>nd</sup> output file |
| `-l LEN` | `--len=LEN` | `LEN` is the number of bytes to split the input file |

### 5. Common options
| option | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-b SIZE` | `--buffer=SIZE` | `SIZE` is the size of the read buffer in # of bytes |
| `-v` | `--verbose` |  display detail operation messages during processing |

---

## TODO
### 2025-10-14
- Work on AES-CBC
- Check if the handling of `tag`/`aad` for `ChaCha20-Poly1305` is needed or not

---

## Changelog
### v1.5.1
- Combine functions under `/cmd` into `c9utils`
- Make yaml traversal function more generic

### v1.4.1
- Add control of encoding of encryption input, output and symmetric key file

### v1.3.0
- Add control for key file encoding for symmetric encryption

### v1.2.2
- preserve file order when doing `yaml` encryption/decryption

### v1.2.1
- change `yaml` encryption from separate commands to a switch

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
