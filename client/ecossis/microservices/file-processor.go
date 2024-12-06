package microservices

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Estrutura do JSON
type Data struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	Geolocation string `json:"geolocation"`
}

// Função para obter segredo
func getSecret(secretID string) string {
	return os.Getenv(secretID)
}

// Função para publicar no Pub/Sub
func publishToPubSub(projectID, topicID, hashData string) error {
	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to create PubSub client: %v", err)
	}
	defer client.Close()

	topic := client.Topic(topicID)
	defer topic.Stop()

	message := &pubsub.Message{
		Data: []byte(hashData),
	}

	result := topic.Publish(ctx, message)
	_, err = result.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to publish message to Pub/Sub: %v", err)
	}

	fmt.Printf("Mensagem publicada com sucesso no Pub/Sub: %s\n", hashData)
	return nil
}

// Função para armazenar hash no Firestore
func storeHashInFirestore(hashValue, fileName string) (bool, error) {
	ctx := context.Background()

	client, err := firestore.NewClient(ctx, getSecret("FIRESTORE_PROJECT_ID"))
	if err != nil {
		return false, fmt.Errorf("failed to create Firestore client: %v", err)
	}
	defer client.Close()

	hashRef := client.Collection("ipfs_hashes").Doc(hashValue)
	doc, err := hashRef.Get(ctx)
	if err != nil && status.Code(err) == codes.NotFound {
		return false, fmt.Errorf("failed to get document: %v", err)
	}

	if doc.Exists() {
		fmt.Printf("Hash %s já existe no Firestore\n", hashValue)
		return false, nil
	}

	// Armazenar novo hash
	hashData := map[string]interface{}{
		"hash":      hashValue,
		"file_name": fileName,
		"timestamp": time.Now().UTC(),
		"status":    "pending_mint",
	}

	_, err = hashRef.Set(ctx, hashData)
	if err != nil {
		return false, fmt.Errorf("failed to store hash in Firestore: %v", err)
	}

	fmt.Printf("Hash %s armazenado com sucesso no Firestore\n", hashValue)
	return true, nil
}

// Função para gerar hash SHA-256 de uma string (nesse caso o nome do arquivo)
func generateHash(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	hashBytes := hash.Sum(nil)
	return fmt.Sprintf("%x", hashBytes)
}

// Função principal (processamento de arquivo)
func ProcessFile(event map[string]interface{}, ctx interface{}) error {
	fileName := "unknown"
	bucketName := ""

	// Recuperar o nome do bucket e do arquivo
	if bucketName, ok := event["bucket"].(string); !ok || bucketName == "" {
		return fmt.Errorf("bucket name not provided")
	}

	if fileName, ok := event["name"].(string); !ok || fileName == "" {
		return fmt.Errorf("file name not provided")
	}

	// Gerar o hash do nome do arquivo
	hashValue := generateHash(fileName)
	fmt.Printf("Hash gerado: %s\n", hashValue)

	// Publicar o hash no Pub/Sub
	projectID := getSecret("PUBSUB_PROJECT_ID")
	topicID := getSecret("PUBSUB_TOPIC_ID")
	err := publishToPubSub(projectID, topicID, hashValue)
	if err != nil {
		return fmt.Errorf("error publishing to Pub/Sub: %v", err)
	}

	// Armazenar o hash no Firestore
	_, err = storeHashInFirestore(hashValue, fileName)
	if err != nil {
		return fmt.Errorf("error storing hash in Firestore: %v", err)
	}

	// Obter o arquivo do Cloud Storage (caso necessário)
	client, err := storage.NewClient(context.Background())
	if err != nil {
		return fmt.Errorf("failed to create storage client: %v", err)
	}
	defer client.Close()

	bucket := client.Bucket(bucketName)
	object := bucket.Object(fileName)
	rc, err := object.NewReader(context.Background())
	if err != nil {
		return fmt.Errorf("failed to read file from storage: %v", err)
	}
	defer rc.Close()

	// Ler o arquivo
	content, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("failed to read file content: %v", err)
	}
	fmt.Printf("Conteúdo do arquivo lido: %s\n", string(content))

	return nil
}

// Função para ler o JSON localmente e gerar um hash
func ProcessLocalJSON(filePath string) (string, error) {
	// Ler o arquivo JSON
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	byteValue, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	// Deserializar o JSON
	var data Data
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	// Serializar o JSON de volta para string
	jsonString, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Gerar o hash do JSON
	hashValue := generateHash(string(jsonString))
	return hashValue, nil
}
