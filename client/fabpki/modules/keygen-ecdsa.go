/*
    The BlockMeter Experiment
    ~~~~~~~~~
    This module generates a pair of elliptic curve keys that can 
    be used together the other modules. We use the curve NIST 256p.
    Also, we save the keys in the files <meter_id>.pub and 
    <meter_id>.priv.
        
    :copyright: © 2020 by Wilson Melo Jr.
*/
package modules

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "path/filepath"
)

// Este código gera as duas chaves pub e priv

func main() {
    // test if the meter ID was informed as argument
    if len(os.Args) != 2 {
        fmt.Println("Usage:", os.Args[0], "<meter id>")
        os.Exit(1)
    }

    // get the meter ID
    meterID := os.Args[1]

    err := GenerateKeyPair(meterID)
    if err != nil {
        fmt.Println("Error:", err)
        os.Exit(1)
    }
}

func GenerateKeyPair(meterID string) error {
    // feedback to the user
    fmt.Println("Generating a key pair...")

    // instantiate a key pair, sk = private key, vk = public key
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return fmt.Errorf("error generating key: %v", err)
    }
    pubKey := &privKey.PublicKey

    // format the key names according to the meter ID
    pubKeyFile := filepath.Join("data", meterID+".pub")
    privKeyFile := filepath.Join("data", meterID+".priv")

    // write keys in their respective files using PEM format
    privKeyPEM, err := os.Create(privKeyFile)
    if err != nil {
        return fmt.Errorf("error creating private key file: %v", err)
    }
    defer privKeyPEM.Close()
    privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
    if err != nil {
        return fmt.Errorf("error marshaling private key: %v", err)
    }
    pem.Encode(privKeyPEM, &pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: privKeyBytes,
    })

    pubKeyPEM, err := os.Create(pubKeyFile)
    if err != nil {
        return fmt.Errorf("error creating public key file: %v", err)
    }
    defer pubKeyPEM.Close()
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
    if err != nil {
        return fmt.Errorf("error marshaling public key: %v", err)
    }
    pem.Encode(pubKeyPEM, &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pubKeyBytes,
    })

    // feedback is always good
    fmt.Println("The keys were saved into", pubKeyFile, "and", privKeyFile)
    return nil
}