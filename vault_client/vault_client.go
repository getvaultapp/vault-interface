package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/getvaultapp/storage-engine/vault-storage-engine/pkg/acl"
	"github.com/getvaultapp/storage-engine/vault-storage-engine/pkg/bucket"
	"github.com/getvaultapp/storage-engine/vault-storage-engine/pkg/database"
	"github.com/getvaultapp/storage-engine/vault-storage-engine/users/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

var clientTokenBalance float64 = 100.0 // Initial token balance for the client

var db, _ = database.InitDB()

const (
	tokensPerMBStorage   = 0.1 // Tokens required per MB for storage
	tokensPerMBRetrieval = 0.2 // Tokens required per MB for retrieval
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Extract the token from the "Bearer <token>" format
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Parse and validate the token
		secret := []byte(os.Getenv("JWT_SECRET"))
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure the signing method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username             string `json:"username" binding:"required"`
		Email                string `json:"email" binding:"required"`
		Password             string `json:"password" binding:"required"`
		PasswordConfirmation string `json:"password_confirmation" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request. Bad JSON", http.StatusBadRequest)
		return
	}

	if credentials.Password != credentials.PasswordConfirmation {
		fmt.Println("Passeword missmatch!")
		http.Error(w, "Invalid request. Password confirmation failed!", http.StatusBadRequest)
		return
	}

	user := &models.User{
		Username: credentials.Username,
		Email:    credentials.Email,
	}

	if err := user.HashPassword(credentials.Password); err != nil {
		http.Error(w, fmt.Sprintf("failed to hash password %v", err), http.StatusInternalServerError)
		return
	}

	if err := models.CreateUser(db, user); err != nil {
		http.Error(w, fmt.Sprintf("failed to create new user %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fmt.Sprintf("user created: %s", credentials.Username))

}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request. Bad JSON", http.StatusBadRequest)
		return
	}

	// This should get the username from the email
	user, err := models.GetUserByEmail(db, credentials.Email)
	if err != nil {
		log.Printf("User not found, %v", err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// This checks the username associated with the email
	if err := user.CheckPassword(credentials.Password); err != nil {
		http.Error(w, fmt.Sprintf("Invalid password: %v", err), http.StatusBadRequest)
		return
	}

	// Validate credentials (replace with your own logic)
	//if credentials.Username != "admin" || credentials.Password != "password" {
	//	http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	//	return
	//}

	// Generate JWT token
	secret := []byte(os.Getenv("JWT_SECRET"))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": credentials.Email,
		"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // Token expires in 24 hours
	})
	tokenString, err := token.SignedString(secret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Send the token to the client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

// --- ACL and RBAC ---
func handleAddPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
		UserID       string `json:"user_id"`
		Permission   string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ResourceID == "" || req.ResourceType == "" || req.UserID == "" || req.Permission == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Open database connection
	db, err := database.InitDB()
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Add permission
	err = acl.AddPermission(db, req.ResourceID, req.ResourceType, req.UserID, req.Permission)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add permission: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Permission added successfully"))
}

func handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID string `json:"group_id"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.GroupID == "" || req.Name == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Open database connection
	db, err := database.InitDB()
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Create group
	err = acl.CreateGroup(db, req.GroupID, req.Name)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create group: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Group created successfully"))
}

func handleAddUserToGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  string `json:"user_id"`
		GroupID string `json:"group_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.GroupID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Open database connection
	db, err := database.InitDB()
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Add user to group
	err = acl.AddUserToGroup(db, req.UserID, req.GroupID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add user to group: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User added to group successfully"))
}

func handleAddGroupPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
		GroupID      string `json:"group_id"`
		Permission   string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ResourceID == "" || req.ResourceType == "" || req.GroupID == "" || req.Permission == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Open database connection
	db, err := database.InitDB()
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Add group permission
	err = acl.AddGroupPermission(db, req.ResourceID, req.ResourceType, req.GroupID, req.Permission)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add group permission: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Group permission added successfully"))
}

func getConstructionNodeURL() (string, error) {
	discoveryServiceURL := os.Getenv("DISCOVERY_SERVICE_URL")
	if discoveryServiceURL == "" {
		discoveryServiceURL = "http://localhost:9000" // Default discovery service URL
	}

	resp, err := http.Get(discoveryServiceURL + "/lookup/construction")
	if err != nil {
		return "", fmt.Errorf("failed to query discovery service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery service returned status: %s", resp.Status)
	}

	var nodes []map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return "", fmt.Errorf("failed to decode response from discovery service: %v", err)
	}

	if len(nodes) == 0 {
		return "", fmt.Errorf("no construction nodes available")
	}

	// Randomly select a node (or implement a load-balancing strategy)
	selectedNode := nodes[rand.Intn(len(nodes))]
	return selectedNode["address"], nil
}

func handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BucketID string `json:"bucket_id"`
		Owner    string `json:"owner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.BucketID == "" || req.Owner == "" {
		http.Error(w, "Missing bucket_id or owner", http.StatusBadRequest)
		return
	}

	// Open database connection (replace with your DB initialization logic)
	db, err := database.InitDB()
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Create the bucket
	err = bucket.CreateBucket(db, req.BucketID, req.Owner)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create bucket: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Bucket created successfully"))
}

func handleDeleteBucket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BucketID string `json:"bucket_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.BucketID == "" {
		http.Error(w, "Missing bucket_id", http.StatusBadRequest)
		return
	}

	// Open database connection (replace with your DB initialization logic)
	db, err := database.InitDB()
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Delete the bucket
	err = bucket.DeleteBucket(db, req.BucketID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete bucket: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Bucket deleted successfully"))
}

func handleDownloadBucket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BucketID string `json:"bucket_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.BucketID == "" {
		http.Error(w, "Missing bucket_id", http.StatusBadRequest)
		return
	}

	// Open database connection (replace with your DB initialization logic)
	db, err := database.InitDB()
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Get all objects in the bucket
	objectIDs, err := bucket.GetObjectsInBucket(db, req.BucketID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve objects: %v", err), http.StatusInternalServerError)
		return
	}

	// Create a temporary .zip file
	zipFile, err := os.CreateTemp("", "bucket-*.zip")
	if err != nil {
		http.Error(w, "Failed to create zip file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(zipFile.Name()) // Clean up after sending the file
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	for _, objectID := range objectIDs {
		// Retrieve object data (replace with your logic to fetch object versions)
		objectData := []byte(fmt.Sprintf("Data for object %s", objectID)) // Placeholder

		// Add object to the zip file
		fileWriter, err := zipWriter.Create(objectID)
		if err != nil {
			http.Error(w, "Failed to add object to zip file", http.StatusInternalServerError)
			return
		}
		_, err = fileWriter.Write(objectData)
		if err != nil {
			http.Error(w, "Failed to write object data to zip file", http.StatusInternalServerError)
			return
		}
	}
	zipWriter.Close()

	// Send the zip file to the client
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zip", req.BucketID))
	http.ServeFile(w, r, zipFile.Name())
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s\n", r.Method, r.URL.Path)
	constructionNodeURL, err := getConstructionNodeURL()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get construction node: %v", err), http.StatusServiceUnavailable)
		return
	}

	err = r.ParseMultipartForm(10 << 20) // 10 MB max file size, for test
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse form %v", err), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to retrieve file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	bucketID := r.FormValue("bucket_id")
	if bucketID == "" {
		http.Error(w, "Missing bucket id", http.StatusBadRequest)
		return
	}

	// Calculate the filesize in MB
	fileSizeMB := float64(handler.Size) / (1024 * 1024)

	// Calculate the cost in tokens
	cost := fileSizeMB * tokensPerMBStorage

	// Check is the client has enought tokens
	if clientTokenBalance < cost {
		http.Error(w, "Insufficient token for storage, pls purchase more tokens", http.StatusPaymentRequired)
		return
	}

	var fileBuffer bytes.Buffer
	if _, err := io.Copy(&fileBuffer, file); err != nil {
		http.Error(w, fmt.Sprintf("failed to create a new request, %v", err), http.StatusInternalServerError)
		return
	}

	// Create the request with raw binary data
	req, err := http.NewRequest("POST", constructionNodeURL+"/process", &fileBuffer)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("X-Bucket-ID", bucketID)
	req.Header.Set("X-Filename", handler.Filename)
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request to construction node", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Construction node responded with: ", resp.Status)
		http.Error(w, fmt.Sprintf("Construction node responded with: %v", err), http.StatusInternalServerError)
		return
	}

	// Deduct tokens from the client's balance
	clientTokenBalance -= cost
	clientTokenBalance -= cost
	if resp.StatusCode == http.StatusOK {
		log.Println("File Upload Successful!")
	}

	// Pipe response back to client
	io.Copy(w, resp.Body)
}

func handleFileRetrieve(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s\n", r.Method, r.URL.Path)
	constructionNodeURL, err := getConstructionNodeURL()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get construction node: %v", err), http.StatusServiceUnavailable)
		return
	}

	var req struct {
		BucketID  string `json:"bucket_id"`
		ObjectID  string `json:"object_id"`
		VersionID string `json:"version_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Forward the request to the construction node
	data, _ := json.Marshal(req)
	resp, err := http.Post(constructionNodeURL+"/reconstruct", "application/json", bytes.NewReader(data))
	if err != nil {
		http.Error(w, "Failed to send request to construction node", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Construction node error", resp.StatusCode)
		return
	}

	// Calculate the size of the reconstructed file
	fileSizeMB := float64(resp.ContentLength) / (1024 * 1024)

	// Calculate the cost in tokens
	cost := fileSizeMB * tokensPerMBRetrieval

	// Check if the client has enough tokens
	if clientTokenBalance < cost {
		http.Error(w, "Insufficient tokens for retrieval", http.StatusPaymentRequired)
		return
	}

	// Deduct tokens from the client's balance
	clientTokenBalance -= cost
	if resp.StatusCode == http.StatusOK {
		log.Println("File Retrieval Successful!")
	}

	// Stream the reconstructed file back to the user
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=reconstructed.zip")
	io.Copy(w, resp.Body)
}

func handleClientTokenBalance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]float64{
		"token_balance": clientTokenBalance,
	})
}

func handleShardInfo(w http.ResponseWriter, r *http.Request) {
	constructionNodeURL, err := getConstructionNodeURL()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get construction node: %v", err), http.StatusServiceUnavailable)
		return
	}

	var req struct {
		BucketID  string `json:"bucket_id"`
		ObjectID  string `json:"object_id"`
		VersionID string `json:"version_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Forward the request to the construction node
	data, _ := json.Marshal(req)
	resp, err := http.Post(constructionNodeURL+"/shards/info", "application/json", bytes.NewReader(data))
	if err != nil {
		http.Error(w, "Failed to send request to construction node", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println(resp.StatusCode)
		http.Error(w, "Construction node error", resp.StatusCode)
		return
	}

	// Forward the shard info back to the client
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func handleFileDelete(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s\n", r.Method, r.URL.Path)

	// Parse the JSON request body
	var req struct {
		BucketID  string `json:"bucket_id"`
		ObjectID  string `json:"object_id"`
		VersionID string `json:"version_id"` // Optional: If empty, delete all versions
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.BucketID == "" || req.ObjectID == "" {
		http.Error(w, "Missing bucket_id or object_id", http.StatusBadRequest)
		return
	}

	// Get the construction node URL
	constructionNodeURL, err := getConstructionNodeURL()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get construction node: %v", err), http.StatusServiceUnavailable)
		return
	}

	// Prepare the request payload
	data, _ := json.Marshal(req)

	// Determine the endpoint to call based on whether VersionID is provided
	var endpoint string
	if req.VersionID == "" {
		// Delete all versions
		endpoint = "/delete/all-versions"
	} else {
		// Delete a specific version
		endpoint = "/delete/version"
	}

	// Forward the request to the construction node
	resp, err := http.Post(constructionNodeURL+endpoint, "application/json", bytes.NewReader(data))
	if err != nil {
		http.Error(w, "Failed to send request to construction node", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Handle the response from the construction node
	if resp.StatusCode != http.StatusOK {
		log.Printf("Construction node responded with: %d\n", resp.StatusCode)
		http.Error(w, "Construction node error", resp.StatusCode)
		return
	}

	// Forward the response back to the client
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func main() {
	r := mux.NewRouter()

	// Public endpoints
	r.HandleFunc("/login", handleLogin).Methods("POST")
	r.HandleFunc("/signup", handleSignup).Methods("POST")

	// Protected endpoints
	api := r.PathPrefix("/v0").Subrouter()
	api.Use(authMiddleware)
	api.HandleFunc("/upload", handleFileUpload).Methods("POST")
	api.HandleFunc("/retrieve", handleFileRetrieve).Methods("POST")
	api.HandleFunc("/delete", handleFileDelete).Methods("POST")
	api.HandleFunc("/shard-info", handleShardInfo).Methods("POST")
	api.HandleFunc("/token-balance", handleClientTokenBalance).Methods("GET")
	api.HandleFunc("/create-bucket", handleCreateBucket).Methods("POST")
	api.HandleFunc("/delete-bucket", handleDeleteBucket).Methods("POST")
	api.HandleFunc("/download-bucket", handleDownloadBucket).Methods("POST")
	api.HandleFunc("/add-permission", handleAddPermission).Methods("POST")
	api.HandleFunc("/create-group", handleCreateGroup).Methods("POST")
	api.HandleFunc("/add-user-to-group", handleAddUserToGroup).Methods("POST")
	api.HandleFunc("/add-group-permission", handleAddGroupPermission).Methods("POST")

	// Serve the static HTML frontend
	//r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	port := os.Getenv("WEB_CLIENT_PORT")
	if port == "" {
		port = "3000"
		log.Println("WEB_CLIENT_PORT set to default (3000)")
	}

	log.Printf("Starting Web Client Backend on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
