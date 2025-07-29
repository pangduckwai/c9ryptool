# cryptool
A simple encryption tool

## Usage

`> ./cryptool [command] {options}`

### commands
| full name | description |
| --- | --- |
| `encrypt` | encrypt input using the provided encryption key |
| `decrypt` | decrypt encrypted input back to the original form |
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
| - | `--salt=SALT` | `SALT` is the base64 encoded salt value to be used to generate encryption key from password |
| - | `--salt-file=FILE` | `FILE` is the path of the file containing the salt to be used to generate key from password |
| `-g` | `--generate` | generate a new encrytpion key |
| `-p` | `--password` | indicate a password is input interactively |
| `-v` | `--verbose` |  display detail operation messages during processing |

## console input
### password
> Specify the option `-p` or `--password` to use password generated key for the encryption. When
> these options are specified, a prompt will appear for the user to type in the password.

### interactive input
> If the option `-i` or `--in=` is omitted, the input text to be encryption is read from stdin.
> Type a period (`.`) then press `<enter>` in a new line to finish inputting.
