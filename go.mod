module sea9.org/go/c9ryptool

go 1.25.5

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/ecies/go/v2 v2.0.11
	github.com/pangduckwai/sea9go v0.3.0
	golang.org/x/crypto v0.46.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/pangduckwai/sea9go v0.3.0 => ../sea9go

require (
	github.com/ethereum/go-ethereum v1.16.7 // indirect
	golang.org/x/sys v0.39.0 // indirect
)
