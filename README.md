# cryptool
A simple encryption tool

## Usage

`> ./cryptool [command] {options}`

### commands
| full name | description |
| --- | --- |
| `encrypt` | encrypt input using the provided encryption key |
| `decrypt` | decrypt encrypted input back to the original form |
| `algorithms` | list names of the supported algorithms |
| `version` | display current version of `cryptool` |
| `help` | display the help message |

### options
| 1<sup>st</sup> form | 2<sup>nd</sup> form | description |
| --- | --- | --- |
| `-a ALGR` | `--algorithm=ALGR` | `ALGR` is the name of the encryption algorithm to use |
| `-i FILE` | `--in=FILE` | `FILE` is the path of the input file, omitting means input from stdin |
| `-o FILE` | `--out=FILE` | `FILE` is the path of the output file, omitting means output to stdout |
| `-k FILE` | `--key=FILE` | `FILE` is the path of the file containing the encryption key |
| `-b SIZE` | `--buffer=SIZE` | `SIZE` is the size of the read buffer in # of bytes |
| - | `--salt=LEN` | `LEN` is the length of salt to use for generating keys from password |
| `-g` | `--generate` | generate a new encrytpion key |
| `-p` | `--password` | indicate a password is input interactively |
| `-v` | `--verbose` |  display detail operation messages during processing |

## console input
### password
> Specify the option `-p` or `--password` to use keys generated from password for the encryption. When
> these options are specified, a prompt will appear for the user to type in the password.

### salt
> To enhance security of the keys used, a random value known as `salt` is needed when generating keys
> from passwords. A new, random `salt` is generated during encryption. This salt is written to the
> output at the end of the cipher text, separated with a dot (`.`). During decryption this `salt` is
> read from the input cipher text.

### interactive input
> If the option `-i` or `--in=` is omitted, the input text to be encryption is read from stdin.
> Type a period (`.`) then press `<enter>` in a new line to finish inputting.

## Changelog
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
