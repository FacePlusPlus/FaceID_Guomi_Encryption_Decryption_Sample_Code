package main

import (
	"io/ioutil"
	"log"

	"github.com/tjfoc/gmsm/x509"
)

type Parser interface {
	// read public/private key from file
	ReadFromFile(filename string) ([]byte, error)

	// parse pemkey(pkcs8) to private/public key
	Parse(der []byte) (interface{}, error)
}

type PublicParser struct{}

func (parser *PublicParser) ReadFromFile(filename string) ([]byte, error) {
	content, ioErr := ioutil.ReadFile(filename)
	if ioErr != nil {
		log.Printf("ioutil read file failed, err: %v\n", ioErr)
		return []byte{}, ioErr
	}
	return content, nil
}

func (parser *PublicParser) Parse(der []byte) (interface{}, error) {
	sm2PublicKey, x509Err := x509.ReadPublicKeyFromPem(der)
	if x509Err != nil {
		log.Printf("ioutil read public key from pem failed, err: %v\n", x509Err)
		return nil, x509Err
	}
	return sm2PublicKey, nil
}

func NewPublicParser() *PublicParser {
	return &PublicParser{}
}

type PrivateParser struct{}

func (parser *PrivateParser) ReadFromFile(filename string) ([]byte, error) {
	content, ioErr := ioutil.ReadFile(filename)
	if ioErr != nil {
		log.Printf("ioutil read file failed, err: %v\n", ioErr)
		return []byte{}, ioErr
	}
	return content, nil
}

func (parser *PrivateParser) Parse(der []byte) (interface{}, error) {
	sm2PrivateKey, x509Err := x509.ReadPrivateKeyFromPem(der, nil)
	if x509Err != nil {
		log.Printf("x509 read private key from pem failed, err: %v\n", x509Err)
		return nil, x509Err
	}
	return sm2PrivateKey, nil
}

func NewPrivateParser() *PrivateParser {
	return &PrivateParser{}
}
