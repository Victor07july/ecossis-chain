package microservices

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"
)

type MockData struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	Geolocation string `json:"geolocation"`
}

func GenerateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func GenerateMockData() MockData {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return MockData{
		ID:          r.Intn(10) + 1,
		Timestamp:   time.Now().Format("02/01/2006 15:04:05"),
		Geolocation: fmt.Sprintf("%f, %f", r.Float64()*180-90, r.Float64()*360-180),
	}
}

func WriteMockDataToFile(filename string, data MockData) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(data)
}
