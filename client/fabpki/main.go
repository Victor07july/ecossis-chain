package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"os"
	"time"

	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	//"fabpki/modules"
)

func main() {
	configFilePath := "connection-org.yaml"
	channelName := "demo"
	mspID := "INMETROMSP"
	chaincodeName := "fabpki"

	file, err := os.OpenFile("logs/log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)

	meterID := "ECOSSIS"
	// genra par de chaves e salva na pasta data
	// if err := modules.GenerateKeyPair(meterID); err != nil {
	// 	fmt.Println("Error generating key pair:", err)
	// 	os.Exit(1)
	// }

	// leitura da chave pública
	pubKeyFile := meterID + ".pub"
	pubKeyPath := fmt.Sprintf("data/%s", pubKeyFile)
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Println("Error reading public key file:", err)
		os.Exit(1)
	}
	pubKey := string(pubKeyBytes)

	fmt.Println("Public Key:", string(pubKey))

	enrollID := randomString(10)
	registerEnrollUser(configFilePath, enrollID, mspID)

	// create data directory if it doesn't exist
	// if err := os.MkdirAll("data", os.ModePerm); err != nil {
	//     fmt.Println("Error creating data directory:", err)
	//     os.Exit(1)
	// }

	// armazena medidor com a chave publica
	// invokeCCgw(configFilePath, channelName, enrollID, mspID, chaincodeName, "registerMeter", []string{meterID, pubKey})

	// // verifica assinatura
	message := "Hello, World!"
	b64sig, err := readPrivateKey(meterID, message)
	invokeCCgw(configFilePath, channelName, enrollID, mspID, chaincodeName, "checkSignature", []string{meterID, message, b64sig})

}

func registerEnrollUser(configFilePath, enrollID, mspID string) {
	log.Info("Registering User : ", enrollID)
	sdk, err := fabsdk.New(config.FromFile(configFilePath))
	if err != nil {
		log.Error("Failed to create SDK: %s\n", err)
		return
	}
	ctx := sdk.Context()
	caClient, err := mspclient.New(ctx, mspclient.WithCAInstance("inmetro-ca.default"), mspclient.WithOrg(mspID))
	if err != nil {
		log.Error("Failed to create msp client: %s\n", err)
		return
	}

	log.Info("ca client created")
	enrollmentSecret, err := caClient.Register(&mspclient.RegistrationRequest{
		Name:           enrollID,
		Type:           "client",
		MaxEnrollments: -1,
		Affiliation:    "",
		Secret:         enrollID,
	})
	if err != nil {
		log.Error(err)
		return
	}

	err = caClient.Enroll(enrollID, mspclient.WithSecret(enrollmentSecret), mspclient.WithProfile("tls"))
	if err != nil {
		log.Error(errors.WithMessage(err, "failed to register identity"))
		return
	}

	wallet, err := gateway.NewFileSystemWallet(fmt.Sprintf("wallet/%s", mspID))
	if err != nil {
		log.Error("Failed to create wallet: %s", err)
		return
	}

	signingIdentity, err := caClient.GetSigningIdentity(enrollID)
	if err != nil {
		log.Error("Failed to get signing identity: %s", err)
		return
	}

	key, err := signingIdentity.PrivateKey().Bytes()
	if err != nil {
		log.Error("Failed to get private key: %s", err)
		return
	}
	identity := gateway.NewX509Identity(mspID, string(signingIdentity.EnrollmentCertificate()), string(key))

	err = wallet.Put(enrollID, identity)
	if err != nil {
		log.Error(err)
	}
}

func invokeCCgw(configFilePath, channelName, userName, mspID, chaincodeName, fcn string, params []string) {
	configBackend := config.FromFile(configFilePath)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		log.Error(err)
		return
	}

	wallet, err := gateway.NewFileSystemWallet(fmt.Sprintf("wallet/%s", mspID))
	if err != nil {
		log.Error("Failed to create wallet: %s", err)
		return
	}

	gw, err := gateway.Connect(gateway.WithSDK(sdk), gateway.WithUser(userName), gateway.WithIdentity(wallet, userName))
	if err != nil {
		log.Error("Failed to create new Gateway: %s", err)
		return
	}
	defer gw.Close()

	nw, err := gw.GetNetwork(channelName)
	if err != nil {
		log.Error("Failed to get network: %s", err)
		return
	}

	contract := nw.GetContract(chaincodeName)
	resp, err := contract.SubmitTransaction(fcn, params...)
	if err != nil {
		log.Error("Failed submit transaction: %s", err)
		return
	}
	log.Info(resp)
}

func queryCCgw(configFilePath, channelName, userName, mspID, chaincodeName, fcn string, args []string) {
	configBackend := config.FromFile(configFilePath)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		log.Error(err)
		return
	}

	wallet, err := gateway.NewFileSystemWallet(fmt.Sprintf("wallet/%s", mspID))
	if err != nil {
		log.Error("Failed to create wallet: %s", err)
		return
	}

	gw, err := gateway.Connect(gateway.WithSDK(sdk), gateway.WithUser(userName), gateway.WithIdentity(wallet, userName))
	if err != nil {
		log.Error("Failed to create new Gateway: %s", err)
		return
	}
	defer gw.Close()

	nw, err := gw.GetNetwork(channelName)
	if err != nil {
		log.Error("Failed to get network: %s", err)
		return
	}

	contract := nw.GetContract(chaincodeName)
	resp, err := contract.EvaluateTransaction(fcn, args...)
	if err != nil {
		log.Error("Failed submit transaction: %s", err)
		return
	}
	log.Info(string(resp))
}

func randomString(length int) string {
	mathrand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:length]
}

func readPrivateKey(meterID string, message string) (string, error) {
	// leitura da chave privada
	privKeyFile := meterID + ".priv"
	privKeyPath := fmt.Sprintf("data/%s", privKeyFile)
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if (err != nil) {
		return "", err
	}
	block, _ := pem.Decode(privKeyBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse EC private key: %v", err)
	}

	hashed := sha256.Sum256([]byte(message))

	// Assinar a mensagem usando a chave privada
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed[:])
	if err != nil {
		return "", fmt.Errorf("Erro ao assinar a mensagem: %v", err)
	}

	// Codificar a assinatura em DER
	signature, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		return "", fmt.Errorf("Erro ao codificar a assinatura em DER: %v", err)
	}

	// Codificar a assinatura em Base64
	b64sig := base64.StdEncoding.EncodeToString(signature)

	return b64sig, nil
}
