// Package passhash
package passhash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"math/rand"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var (
	ErrBcryptNoHmacEnc      = errors.New("bcrypt hash output can not be encrypted")
	ErrUnknownHashFunc      = errors.New("unknown hash function")
	ErrGenRandSalt          = errors.New("can not generate random salt")
	ErrBcryptNotSupportCost = errors.New("bcrypt: unsupported cost value")
	ErrBcryptNotGenCost     = errors.New("bcrypt did not generate hash with user provided cost value")
	ErrUnknownKeyDerivation = errors.New("unknown key derivation")
)

// Opts
type Opts struct {
	Salt     string
	Iter     int
	HashName string
	KdName   string
	Cost     int
	HmacEnc  string
}

var str2hash = map[string](func() hash.Hash){
	"md4":    md4.New,
	"md5":    md5.New,
	"sha1":   sha1.New,
	"sha224": sha256.New224,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

// DefaultOpts default opts is used when opts is nil
var DefaultOpts = &Opts{
	Salt:     "Akagi201",
	Iter:     4096,
	HashName: "sha1",
	KdName:   "pbkdf2",
}

// Generate
func Generate(passwd string, opts *Opts) (string, error) {
	if opts == nil {
		opts = DefaultOpts
	}

	if opts.KdName == "bcrypt" && opts.HmacEnc != "" {
		return passwd, ErrBcryptNoHmacEnc
	}

	if opts.KdName == "scrypt" {
		opts.HashName = "sha256"
	}

	var hmacEncBin []byte
	var err error
	if opts.HmacEnc != "" {
		hmacEncBin, err = base64.URLEncoding.DecodeString(opts.HmacEnc)
		if err != nil {
			return passwd, err
		}
	}

	h, ok := str2hash[opts.HashName]
	if !ok {
		return passwd, ErrUnknownHashFunc
	}

	var dk []byte
	hashLen := h().Size()
	pw := []byte(passwd)
	var salt []byte
	if len(opts.Salt) != 0 {
		salt = []byte(opts.Salt)
	} else {
		salt = make([]byte, hashLen)
		if n, err := rand.Read(salt); n != len(salt) || err != nil {
			return passwd, ErrGenRandSalt
		}
	}

	switch opts.KdName {
	case "pbkdf2":
		dk = pbkdf2.Key(pw, salt, opts.Iter, hashLen, h)
	case "scrypt":
		dk, err = scrypt.Key(pw, salt, 1<<uint(opts.Cost), 8, 1, 32)
		if err != nil {
			return passwd, err
		}
	case "bcrypt":
		if opts.Cost < bcrypt.MinCost || opts.Cost > bcrypt.MaxCost {
			return passwd, ErrBcryptNotSupportCost
		}
		dk, err = bcrypt.GenerateFromPassword(pw, opts.Cost)
		if err != nil {
			return passwd, err
		}
		// safeguard against bcrypt working with wrong cost value
		if realCost, err := bcrypt.Cost(dk); err != nil {
			return passwd, err
		} else if opts.Cost != realCost {
			return passwd, ErrBcryptNotGenCost
		}
	default:
		return passwd, ErrUnknownKeyDerivation
	}

	if opts.HmacEnc != "" {
		hmacEnc := hmac.New(h, hmacEncBin)
		if _, err = hmacEnc.Write(dk); err != nil {
			return passwd, err
		}
		dk = hmacEnc.Sum(nil)
	}

	return string(dk), nil
}

// Verify
func Verify(passwd string, opts *Opts, hashedPasswd string) bool {
	hp, _ := Generate(passwd, opts)
	return hp == hashedPasswd
}
