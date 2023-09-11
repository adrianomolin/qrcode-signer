package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/skip2/go-qrcode"
)

// Define the QRData structure
type QRData struct {
	Data string `json:"data"`
}

// Define the private and public keys
var privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var publicKey = &privateKey.PublicKey

func main() {
	// Setup router
	router := mux.NewRouter()
	router.HandleFunc("/generate", GenerateQR).Methods("GET")
	router.HandleFunc("/validate", ValidateQR).Methods("POST")

	// Start the server
	log.Fatal(http.ListenAndServe(":8332", router))
}

func GenerateQR(w http.ResponseWriter, r *http.Request) {
	// Create some QR code data
	qrData := QRData{Data: "Teste 2"}

	// Sign the data using RSA and SHA256
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"qr_data": qrData,
		"nbf":     time.Now().Unix(),
	})
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Error signing data", http.StatusInternalServerError)
		return
	}

	// Generate the QR code
	err = qrcode.WriteFile(tokenString, qrcode.Medium, 256, "qr.png")
	if err != nil {
		http.Error(w, "Error generating QR code", http.StatusInternalServerError)
		return
	}

	// Respond with the QR code
	fmt.Fprintf(w, "QR code generated: %v", tokenString)
}

func ValidateQR(w http.ResponseWriter, r *http.Request) {
	// Parse the JWT from the request body
	var qrData QRData

	err := json.NewDecoder(r.Body).Decode(&qrData)
	if err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	// Parse the token
	token, err := jwt.Parse(qrData.Data, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	// Check if the token is valid
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Fprintf(w, "The token is valid, data: %v", claims["qr_data"])
	} else {
		fmt.Fprintf(w, "The token is not valid")
	}
}
