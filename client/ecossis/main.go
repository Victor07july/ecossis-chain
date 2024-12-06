package main

import (
	"crypto/rand"
	"ecossis/microservices"
	"fmt"
	"os"
	"time"

	mathrand "math/rand"

	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Struct para armazenar os dados do arquivo JSON e o hash
type FileData struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	Geolocation string `json:"geolocation"`
	Hash        string `json:"hash"`
}

func main() {
	// Gerar dados mock aleatórios e escrever em um arquivo JSON
	mockData := microservices.GenerateMockData()
	err := microservices.WriteMockDataToFile("json/mock_data.json", mockData)
	if err != nil {
		fmt.Println("Error writing mock data to file:", err)
	} else {
		fmt.Println("Mock data written to mock_data.json")
	}

	// Processar o arquivo JSON localmente e gerar um hash
	hash, err := microservices.ProcessLocalJSON("json/mock_data.json")
	if err != nil {
		fmt.Println("Error processing local JSON file:", err)
		return
	}

	// Ler os dados do arquivo JSON
	var fileData FileData
	fileData.ID = mockData.ID
	fileData.Timestamp = mockData.Timestamp
	fileData.Geolocation = mockData.Geolocation
	fileData.Hash = hash

	fmt.Printf("File Data: %+v\n", fileData)

	/* ///// CONEXÃO COM A BLOCKCHAIN ///// */

	configFilePath := "connection-org.yaml"
	channelName := "demo"
	mspID := "INMETROMSP"
	chaincodeName := "fabpki"

	file, err := os.OpenFile("logs/log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)

	enrollID := randomString(10)
	registerEnrollUser(configFilePath, enrollID, mspID)

	invokeCCgw(configFilePath, channelName, enrollID, mspID, chaincodeName, "test", []string{"a"})
	invokeCCgw(configFilePath, channelName, enrollID, mspID, chaincodeName, "qtest", []string{"a"})
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
