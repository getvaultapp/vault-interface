package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	tokenmanager "github.com/getvaultapp/storage-engine/vault-storage-engine/pkg/token"
	"github.com/spf13/cobra"
)

var publicURL = "http://localhost:3000"
var baseURL = "http://localhost:3000/v0"

// Login Command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to the Vault system",
	Run: func(cmd *cobra.Command, args []string) {
		var email, password, token string
		fmt.Print("Email: ")
		fmt.Scanln(&email)
		fmt.Print("Password: ")
		fmt.Scanln(&password)

		data := map[string]string{"email": email, "password": password}
		body, _ := json.Marshal(data)

		resp, err := http.Post(publicURL+"/login", "application/json", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to login: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Login failed with status: %d", resp.StatusCode)
		} else if resp.StatusCode == http.StatusOK {
			fmt.Println("Login successful! Token saved.")
		}

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		token = result["token"]

		err = tokenmanager.SaveToken(token)
		if err != nil {
			log.Fatal("failed to save token")
		}
	},
}

// Signup command
var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Signup for a Vault account",
	Run: func(cmd *cobra.Command, args []string) {
		var username, email, password, password_confirmation string
		fmt.Print("Username: ")
		fmt.Scanln(&username)
		fmt.Print("Email: ")
		fmt.Scanln(&email)
		fmt.Print("Password: ")
		fmt.Scanln(&password)
		fmt.Print("Retype Password (Confirmation): ")
		fmt.Scanln(&password_confirmation)

		data := map[string]string{"username": username, "email": email, "password": password, "password_confirmation": password_confirmation}
		body, _ := json.Marshal(data)

		resp, err := http.Post(publicURL+"/signup", "application/json", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to signup: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Signup failed with status: %d", resp.StatusCode)
		} else if resp.StatusCode == http.StatusOK {
			fmt.Println("Signup Successful. Please proceed to login")
		}

		defer resp.Body.Close()
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout of Vault",
	Run: func(cmd *cobra.Command, args []string) {
		err := tokenmanager.DeleteToken()
		if err != nil {
			log.Fatalf("logout failed: %v", err)
		} else {
			fmt.Println("Log out successful")
		}
	},
}

// Create Bucket Command
var createBucketCmd = &cobra.Command{
	Use:   "create-bucket [bucket_id] [owner]",
	Short: "Create a new bucket",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"bucket_id": args[0],
			"owner":     args[1],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/create-bucket", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)

		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to create bucket: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			log.Fatalf("Create bucket failed with status: %s", resp.Status)
		} else {
			fmt.Println("Bucket created successfully!")
		}
	},
}

// Delete Bucket Command
var deleteBucketCmd = &cobra.Command{
	Use:   "delete-bucket [bucket_id]",
	Short: "Delete a bucket and all its contents",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"bucket_id": args[0],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/delete-bucket", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to delete bucket: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Delete bucket failed with status: %d", resp.StatusCode)
		} else {
			fmt.Println("Bucket deleted successfully!")
		}
	},
}

// Download Bucket Command
var downloadBucketCmd = &cobra.Command{
	Use:   "download-bucket [bucket_id]",
	Short: "Download all objects and versions in a bucket as a .zip file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"bucket_id": args[0],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/download-bucket", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to download bucket: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Download bucket failed with status: %d", resp.StatusCode)
		}

		// Create a zip file for the bucket if the operation was successful
		if resp.StatusCode == http.StatusOK {
			// Save the .zip file
			outFile, err := os.Create(filepath.Base(args[0]) + ".zip")
			if err != nil {
				log.Fatalf("Failed to create output file: %v", err)
			}
			io.Copy(outFile, resp.Body)
			fmt.Printf("Bucket downloaded successfully! Saved as '%s.zip'.\n", args[0])

			defer outFile.Close()
		}
	},
}

// Upload Command
var uploadCmd = &cobra.Command{
	Use:   "upload [file] [bucket_id]",
	Short: "Upload a file to the Vault system",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		bucketID := args[1]

		file, err := os.Open(filePath)
		if err != nil {
			log.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", filepath.Base(filePath))
		io.Copy(part, file)
		writer.WriteField("bucket_id", bucketID)
		writer.Close()

		req, err := http.NewRequest("POST", baseURL+"/upload", body)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to upload file: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Upload failed with status: %d", resp.StatusCode)
		} else {
			fmt.Println("File uploaded successfully!")
		}
	},
}

// Retrieve Command
var retrieveCmd = &cobra.Command{
	Use:   "retrieve [bucket_id] [object_id] [version_id]",
	Short: "Retrieve a file from the Vault system",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"bucket_id":  args[0],
			"object_id":  args[1],
			"version_id": args[2],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/retrieve", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to retrieve file: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Retrieve failed with status: %d", resp.StatusCode)
		}

		if resp.StatusCode == http.StatusOK {
			outFile, err := os.Create("retrieved_file.zip")
			if err != nil {
				log.Fatalf("Failed to create output file: %v", err)
			}

			io.Copy(outFile, resp.Body)
			fmt.Println("File retrieved successfully! Saved as 'retrieved_file.zip'.")

			defer outFile.Close()
		}
	},
}

// Delete Command
var deleteCmd = &cobra.Command{
	Use:   "delete [bucket_id] [object_id] [version_id]",
	Short: "Delete a file or version from the Vault system",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"bucket_id":  args[0],
			"object_id":  args[1],
			"version_id": args[2],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/delete", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to delete file: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Delete failed with status: %d", resp.StatusCode)
		} else {
			fmt.Println("File deleted successfully!")
		}
	},
}

// Shard Info Command
var shardInfoCmd = &cobra.Command{
	Use:   "shard-info [bucket_id] [object_id] [version_id]",
	Short: "Get shard information for a file",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"bucket_id":  args[0],
			"object_id":  args[1],
			"version_id": args[2],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/shard-info", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to get shard info: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Shard info failed with status: %d", resp.StatusCode)
		} else {
			io.Copy(os.Stdout, resp.Body)
			fmt.Println("\nShard info retrieved successfully!")
		}
	},
}

// Token Balance Command
var tokenBalanceCmd = &cobra.Command{
	Use:   "token-balance",
	Short: "Check your token balance",
	Run: func(cmd *cobra.Command, args []string) {
		req, err := http.NewRequest("GET", baseURL+"/token-balance", nil)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to get token balance: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Token balance failed with status: %d", resp.StatusCode)
		} else {
			io.Copy(os.Stdout, resp.Body)
			fmt.Println("\nToken balance retrieved successfully!")
		}
	},
}

var addPermissionCmd = &cobra.Command{
	Use:   "add-permission [resource_id] [resource_type] [user_id] [permission]",
	Short: "Grant a user access to a resource",
	Args:  cobra.ExactArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"resource_id":   args[0],
			"resource_type": args[1],
			"user_id":       args[2],
			"permission":    args[3],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/add-permission", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to add permission: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			log.Fatalf("Add permission failed with status: %d", resp.StatusCode)
		} else {
			fmt.Println("Permission added successfully!")
		}
	},
}

var createGroupCmd = &cobra.Command{
	Use:   "create-group [group_id] [name]",
	Short: "Create a new group",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"group_id": args[0],
			"name":     args[1],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/create-group", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to create group: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			log.Fatalf("Create group failed with status: %d", resp.StatusCode)
		} else {
			fmt.Println("Group created successfully!")
		}
	},
}

var addUserToGroupCmd = &cobra.Command{
	Use:   "add-user-to-group [user_id] [group_id]",
	Short: "Add a user to a group",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]string{
			"user_id":  args[0],
			"group_id": args[1],
		}
		body, _ := json.Marshal(data)

		req, err := http.NewRequest("POST", baseURL+"/add-user-to-group", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		token, err := tokenmanager.LoadToken()
		if err != nil {
			log.Fatal("Authorization required")
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to add user to group: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			log.Fatalf("Add user to group failed with status: %d", resp.StatusCode)
		} else {
			fmt.Println("User added to group successfully!")
		}
	},
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "vault-cli",
		Short: "Vault CLI for interacting with the Vault backend",
	}

	// Add subcommands
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(signupCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(uploadCmd)
	rootCmd.AddCommand(retrieveCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(shardInfoCmd)
	rootCmd.AddCommand(tokenBalanceCmd)
	rootCmd.AddCommand(createBucketCmd)
	rootCmd.AddCommand(deleteBucketCmd)
	rootCmd.AddCommand(downloadBucketCmd)
	rootCmd.AddCommand(addPermissionCmd)
	rootCmd.AddCommand(createGroupCmd)
	rootCmd.AddCommand(addUserToGroupCmd)

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
