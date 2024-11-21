package modules

import (

    "crypto/rsa"

    "crypto/x509"

    "encoding/pem"

    "errors"

)



// ParsePrivateKey parses a PEM encoded RSA private key.

func ParsePrivateKey(pemEncodedKey string) (*rsa.PrivateKey, error) {

    block, _ := pem.Decode([]byte(pemEncodedKey))

    if block == nil || block.Type != "RSA PRIVATE KEY" {

        return nil, errors.New("failed to decode PEM block containing private key")

    }



    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)

    if err != nil {

        return nil, err

    }



    return privateKey, nil

}
