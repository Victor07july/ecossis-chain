/////////////////////////////////////////////
//    THE BLOCKCHAIN PKI EXPERIMENT     ////
///////////////////////////////////////////
/*
	This is the fabpki, a chaincode that implements a Public Key Infrastructure (PKI)
	for measuring instruments. It runs in Hyperledger Fabric 1.4.
	He was created as part of the PKI Experiment. You can invoke its methods
	to store measuring instruments public keys in the ledger, and also to verify
	digital signatures that are supposed to come from these instruments.

	@author: Wilson S. Melo Jr.
	@date: Oct/2019
*/
package main

import (
	//the majority of the imports are trivial...
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

/* All the following functions are used to implement fabpki chaincode. This chaincode
basically works with 2 main features:
	1) A Register Authority RA (e.g., Inmetro) verifies a new measuring instrument (MI) and attests
	the correspondence between the MI's private key and public key. After doing this, the RA
	inserts the public key into the ledger, associating it with the respective instrument ID.

	2) Any client can ask for a digital signature ckeck. The client informs the MI ID, an
	information piece (usually a legally relevant register) and its supposed digital signature.
	The chaincode retrieves the MI public key and validates de digital signature.
*/

// SmartContract defines the chaincode base structure. All the methods are implemented to
// return a SmartContrac type.
// SmartContract provides functions for managing a car
type SmartContract struct {
	contractapi.Contract
}

// ECDSASignature represents the two mathematical components of an ECDSA signature once
// decomposed.
type ECDSASignature struct {
	R, S *big.Int
}

// Meter constitutes our key|value struct (digital asset) and implements a single
// record to manage the
// meter public key and measures. All blockchain transactions operates with this type.
// IMPORTANT: all the field names must start with upper case
type Meter struct {
	//PubKey ecdsa.PublicKey `json:"pubkey"`
	PubKey string `json:"pubkey"`
}

// PublicKeyDecodePEM method decodes a PEM format public key. So the smart contract can lead
// with it, store in the blockchain, or even verify a signature.
// - pemEncodedPub - A PEM-format public key
func PublicKeyDecodePEM(pemEncodedPub string) ecdsa.PublicKey {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return *publicKey
}

// Init method is called when the fabpki is instantiated.
// Best practice is to have any Ledger initialization in separate function.
// Note that chaincode upgrade also calls this function to reset
// or to migrate data, so be careful to avoid a scenario where you
// inadvertently clobber your ledger's data!

/*
SmartContract::registerMeter(...)
Does the register of a new meter into the ledger.
The meter is the base of the key|value structure.
The key constitutes the meter ID.
- args[0] - meter ID
- args[1] - the public key associated with the meter
*/

func (s *SmartContract) RegisterMeter(ctx contractapi.TransactionContextInterface, meterid string, strpubkey string) error {

	//validate args vector lenght
	// if !(len(args) == 2 || len(args) == 3) {
	// 	return fmt.Errorf("it was expected the parameters: <meter id> <public key> [encrypted inital consumption]")
	// }

	//gets the parameters associated with the meter ID and the public key (in PEM format)
	// meterid := args[0]
	// strpubkey := args[1]

	//creates the meter record with the respective public key
	var meter = Meter{PubKey: strpubkey}

	//encapsulates meter in a JSON structure
	meterAsBytes, _ := json.Marshal(meter)

	//registers meter in the ledger
	fmt.Println("Registering meter: ", meter)
	return ctx.GetStub().PutState(meterid, meterAsBytes)
}

/*
This method implements the insertion of encrypted measurements in the blockchain.
The encryptation must uses the same public key configured to the meter.
Notice that the informed measurement will be added (accumulated) to the the previous
encrypted measurement consumption information.
The vector args[] must contain two parameters:
- args[0] - meter ID
- args[1] - the legally relevant information, in a string representing a big int number.
- args[2] - the signature digest, in base64 encode format.
*/
func (s *SmartContract) CheckSignature(ctx contractapi.TransactionContextInterface, meterid string, info string, sign string) error {

	//loging...
	fmt.Println("Testing args: ", meterid, info, sign)
	fmt.Println("Meter ID: ", meterid)
	fmt.Println("Information: ", info)

	// extrai o registro do medidor
	meterAsBytes, err := ctx.GetStub().GetState(meterid)

	//test if we receive a valid meter ID
	if err != nil || meterAsBytes == nil {
		return fmt.Errorf("error on retrieving meter ID register")
	}

	//cria estrutura para manipular os bytes do medidor
	MyMeter := Meter{}

	//loging...
	fmt.Println("Retrieving meter bytes: ", meterAsBytes)

	// decodifica os bytes do medidor para a estrutura e obtem a chave publica
	json.Unmarshal(meterAsBytes, &MyMeter)
	pubkey := PublicKeyDecodePEM(MyMeter.PubKey)

	//loging...
	fmt.Println("Retrieving meter after unmarshall: ", MyMeter)

	//calculates the information hash
	hash := sha256.Sum256([]byte(info))

	//decodifica a assinatura para extrair a string de bytes codificada em DER
	der, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("error on decode the digital signature: %v", err)
	}

	//cria uma estrutura de dados para armazenar a assinatura
	sig := &ECDSASignature{}

	//unmarshal the R and S components of the ASN.1-encoded signature
	//deserializa os componentes R e S da assinatura codificada em ASN.1
	_, err = asn1.Unmarshal(der, sig)
	if err != nil {
		return fmt.Errorf("error on get R and S terms from the digital signature: %v", err)
	}

	//valida a assinatura digital
	valid := ecdsa.Verify(&pubkey, hash[:], sig.R, sig.S)

	// buffer is a JSON array containing records
	var buffer bytes.Buffer
	buffer.WriteString("[")
	buffer.WriteString("\"Counter\":")
	buffer.WriteString(strconv.FormatBool(valid))
	buffer.WriteString("]")

	// notifica o resultado. caso seja true, a mensagem foi assinada corretamente e não foi adulterada
	log.Printf("Signature verified: %t\n", valid)
	// print buffer
	log.Print(buffer.String())

	// return success
	return nil
}

/*
This method is a dummy test that makes the endorser "sleep" for some seconds.
It is usefull to check either the sleeptime affects the performance of concurrent
transactions.
- args[0] - sleeptime (in seconds)
*/
func (s *SmartContract) SleepTest(ctx contractapi.TransactionContextInterface, sleeptimestr string) error {
	//validate args vector lenght
	// if len(args) != 1 {
	// 	return fmt.Errorf("it was expected 1 parameter: <sleeptime>")
	// }

	//gets the parameter associated with the meter ID and the incremental measurement
	sleeptime, err := strconv.Atoi(sleeptimestr)

	//test if we receive a valid meter ID
	if err != nil {
		return fmt.Errorf("error on retrieving sleep time")
	}

	//tests if sleeptime is a valid value
	if sleeptime > 0 {
		//stops during sleeptime seconds
		time.Sleep(time.Duration(sleeptime) * time.Second)
	}

	//return payload with bytes related to the meter state
	return nil
}

/*
This method brings the changing history of a specific meter asset. It can be useful to
query all the changes that happened with a meter value.
- args[0] - asset key (or meter ID)
*/
func (s *SmartContract) QueryHistory(ctx contractapi.TransactionContextInterface, key string) error {

	//validate args vector lenght
	// if len(args) != 1 {
	// 	return fmt.Errorf("it was expected 1 parameter: <key>")
	// }

	historyIer, err := ctx.GetStub().GetHistoryForKey(key)

	//verifies if the history exists
	if err != nil {
		//fmt.Println(errMsg)
		return fmt.Errorf("fail on getting ledger history")
	}

	// buffer is a JSON array containing records
	var buffer bytes.Buffer
	var counter = 0
	buffer.WriteString("[")
	bArrayMemberAlreadyWritten := false
	for historyIer.HasNext() {
		//increments iterator
		queryResponse, err := historyIer.Next()
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten {
			buffer.WriteString(",")
		}

		//generates a formated result
		buffer.WriteString("{\"Value\":")
		buffer.WriteString("\"")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("\"")
		buffer.WriteString(", \"Counter\":")
		buffer.WriteString(strconv.Itoa(counter))
		//buffer.WriteString(queryResponse.Timestamp)
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true

		//increases counter
		counter++
	}
	buffer.WriteString("]")
	historyIer.Close()

	//loging...
	log.Printf("Consulting ledger history, found %d\n records", counter)
	log.Print(buffer.String())

	//notify procedure success
	return nil
}

/*
This method brings the number of times that a meter asset was modified in the ledger.
It performs faster than queryHistory() method once it does not retrive any information,
it only counts the changes.
- args[0] - asset key (or meter ID)
*/
func (s *SmartContract) CountHistory(ctx contractapi.TransactionContextInterface, key string) error {

	//validate args vector lenght
	// if len(args) != 1 {
	// 	return fmt.Errorf("it was expected 1 parameter: <key>")
	// }

	historyIer, err := ctx.GetStub().GetHistoryForKey(key)

	//verifies if the history exists
	if err != nil {
		//fmt.Println(errMsg)
		return fmt.Errorf("fail on getting ledger history")
	}

	//creates a counter
	var counter int64 = 0

	for historyIer.HasNext() {
		//increments iterator
		_, err := historyIer.Next()
		if err != nil {
			return fmt.Errorf(err.Error())
		}

		//increases counter
		counter++

		fmt.Printf("Consulting ledger history, found %d\n records", counter)
	}
	// buffer is a JSON array containing records
	var buffer bytes.Buffer
	buffer.WriteString("[")
	buffer.WriteString("\"Counter\":")
	buffer.WriteString(strconv.FormatInt(counter, 10))
	buffer.WriteString("]")

	historyIer.Close()

	//loging...
	fmt.Printf("Consulting ledger history, found %d\n records", counter)
	log.Print(buffer.String())

	return nil
}

/*
This method counts the total of well succeeded transactions in the ledger.
*/
func (s *SmartContract) CountLedger(ctx contractapi.TransactionContextInterface) error {

	//use a range of keys, assuming that the max key value is 999999,
	resultsIterator, err := ctx.GetStub().GetStateByRange("0", "999999")
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	//defer iterator closes at the end of the function
	defer resultsIterator.Close()

	//creates a counter
	var counter int64
	var keys int64
	counter = 0
	keys = 0

	//the interator checks all the valid keys
	for resultsIterator.HasNext() {

		//increments iterator
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return fmt.Errorf(err.Error())
		}

		//busca historico da proxima key
		historyIer, err := ctx.GetStub().GetHistoryForKey(queryResponse.Key)

		//verifies if the history exists
		if err != nil {
			//fmt.Println(errMsg)
			return fmt.Errorf(err.Error())
		}

		defer historyIer.Close()

		for historyIer.HasNext() {
			//increments iterator
			_, err := historyIer.Next()
			if err != nil {
				return fmt.Errorf(err.Error())
			}

			//increases counter
			counter++
		}
		fmt.Printf("Consulting ledger history, found key %s\n", queryResponse.Key)

		keys++
	}
	// buffer is a JSON array containing records
	var buffer bytes.Buffer
	buffer.WriteString("[")
	buffer.WriteString("\"Counter\":")
	buffer.WriteString(strconv.FormatInt(counter, 10))
	buffer.WriteString("\"Keys\":")
	buffer.WriteString(strconv.FormatInt(keys, 10))
	buffer.WriteString("]")

	//loging...
	log.Printf("Consulting ledger history, found %d transactions in %d keys\n", counter, keys)
	log.Print(buffer.String())

	//notify procedure success
	return nil
}

/*
This method executes a free query on the ledger, returning a vector of meter assets.
The query string must be a query expression supported by CouchDB servers.
- args[0] - query string.
*/
func (s *SmartContract) QueryLedger(ctx contractapi.TransactionContextInterface, queryString string) error {

	//validate args vector lenght
	// if len(args) != 1 {
	// 	return fmt.Errorf("it was expected 1 parameter: <query string>")
	// }

	//using auxiliar variable
	// queryString := args[0]

	//loging...
	fmt.Printf("Executing the following query: %s\n", queryString)

	//try to execute query and obtain records iterator
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	//test if iterator is valid
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	//defer iterator closes at the end of the function
	defer resultsIterator.Close()

	// buffer is a JSON array containing QueryRecords
	var buffer bytes.Buffer
	buffer.WriteString("[")
	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		//increments iterator
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten {
			buffer.WriteString(",")
		}

		//generates a formated result
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")
		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	//loging...
	fmt.Printf("Obtained the following fill up records: %s\n", buffer.String())
	log.Print(buffer.String())

	//notify procedure success
	return nil
}

// Public method to meet the requirement
func (s *SmartContract) GetMeter(ctx contractapi.TransactionContextInterface, meterID string) (*Meter, error) {
	meterAsBytes, err := ctx.GetStub().GetState(meterID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if meterAsBytes == nil {
		return nil, fmt.Errorf("meter %s does not exist", meterID)
	}

	meter := new(Meter)
	err = json.Unmarshal(meterAsBytes, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal meter: %v", err)
	}

	return meter, nil
}

/*
 * The main function starts up the chaincode in the container during instantiate
 */
func main() {

	////////////////////////////////////////////////////////
	// USE THIS BLOCK TO COMPILE THE CHAINCODE
	chaincode, err := contractapi.NewChaincode(new(SmartContract))

	if err != nil {
		fmt.Printf("error create fabpki chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("error starting fabpki chaincode: %s", err.Error())
	}
	////////////////////////////////////////////////////////

	////////////////////////////////////////////////////////
	// USE THIS BLOCK TO PERFORM ANY TEST WITH THE CHAINCODE

	// //create pair of keys
	// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	panic(err)
	// }

	// //marshal the keys in a buffer
	// e, err := json.Marshal(privateKey)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// _ = ioutil.WriteFile("ecdsa-keys.json", e, 0644)

	// //read the saved key
	// file, _ := ioutil.ReadFile("ecdsa-keys.json")

	// myPrivKey := ecdsa.PrivateKey{}
	// //myPubKey := ecdsa.PublicKey{}

	// _ = json.Unmarshal([]byte(file), &myPrivKey)

	// fmt.Println("Essa é minha chave privada:")
	// fmt.Println(myPrivKey)

	// myPubKey := myPrivKey.PublicKey

	// //test digital signature verifying
	// msg := "message"
	// hash := sha256.Sum256([]byte(msg))
	// fmt.Println("hash: ", hash)

	// r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("signature: (0x%x, 0x%x)\n", r, s)

	// myPubKey.Curve = elliptic.P256()

	// fmt.Println("Essa é minha chave publica:")
	// fmt.Println(myPubKey)

	// valid := ecdsa.Verify(&myPubKey, hash[:], r, s)
	// fmt.Println("signature verified:", valid)

	// otherpk := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6NXETwtkAKGWBcIsI6/OYE0EwsVj\n3Fc4hHTaReNfq6Hz2UEzsJKCYN0stjPCXbpdUlYtETC1a3EcS3SUVYX6qA==\n-----END PUBLIC KEY-----\n"

	// newkey := PublicKeyDecodePEM(otherpk)
	// myPubKey.Curve = elliptic.P256()

	// //valid = ecdsa.Verify(newkey, hash[:], r, s)
	// //fmt.Println("signature verified:", valid)

	// mysign := "MEYCIQCY16jbdY222oEpFiSRwXPi1kS7c4wuwxYXeWJOoAjnVgIhAJQTM+itbm1mQyd40Ug0xr2/AvjZmFSdoc/iSSHA6nRI"

	// // first decode the signature to extract the DER-encoded byte string
	// der, err := base64.StdEncoding.DecodeString(mysign)
	// if err != nil {
	// 	panic(err)
	// }

	// // unmarshal the R and S components of the ASN.1-encoded signature into our
	// // signature data structure
	// sig := &ECDSASignature{}
	// _, err = asn1.Unmarshal(der, sig)
	// if err != nil {
	// 	panic(err)
	// }

	// valid = ecdsa.Verify(&newkey, hash[:], sig.R, sig.S)
	// fmt.Println("signature verified:", valid)

	// fmt.Println("Curve: ", newkey.Curve.Params())

	////////////////////////////////////////////////////////

}
