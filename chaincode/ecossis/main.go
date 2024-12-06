package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type FileData struct { // id é a chave primária
	Timestamp   string `json:"timestamp"`
	Geolocation string `json:"geolocation"`
	Hash        string `json:"hash"`
}

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}

func (s *SmartContract) StoreFileData(ctx contractapi.TransactionContextInterface, id string, timestamp string, geolocation string, hash string) error {
	fileData := FileData{
		Timestamp:   timestamp,
		Geolocation: geolocation,
		Hash:        hash,
	}

	fileDataBytes, err := json.Marshal(fileData)
	if err != nil {
		return fmt.Errorf("failed to marshal file data: %v", err)
	}

	return ctx.GetStub().PutState(id, fileDataBytes)
}

func (s *SmartContract) QueryFileData(ctx contractapi.TransactionContextInterface, id string) (*FileData, error) {
	fileDataBytes, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if fileDataBytes == nil {
		return nil, fmt.Errorf("file data not found: %s", id)
	}

	var fileData FileData
	err = json.Unmarshal(fileDataBytes, &fileData)
