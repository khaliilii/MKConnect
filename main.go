package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/common-nighthawk/go-figure"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// Config holds the SSH and SOCKS5 connection details
type Config struct {
	UserSSH    string `json:"userssh"`
	SSHPassEnc string `json:"ssh_password_encrypted"` // Encrypted password
	IP         string `json:"ip"`
	SSHPort    string `json:"sshport"`
	SocksPort  string `json:"socksport"`
}

// Encryption key (should be securely managed in production)
var encryptionKey = []byte("12345678901234567890123456789012") // 32 bytes for AES-256

func main() {
	// Create a new figure
	myFigure := figure.NewFigure("MK", "big", true)
	myFigure.Print()
	myFigure2 := figure.NewFigure("Connect", "big", true)
	myFigure2.Print()

	// Define the root command with Cobra
	rootCmd := &cobra.Command{
		Use:   "sshtunnel",
		Short: "SSH tunnel with SOCKS5 proxy",
		Run: func(cmd *cobra.Command, args []string) {
			config, err := loadOrGetConfig()
			if err != nil {
				log.Fatalf("❌ Failed to load or get config: %v", err)
			}

			// Decrypt the password
			sshPass, err := decryptPassword(config.SSHPassEnc)
			if err != nil {
				log.Fatalf("❌ Failed to decrypt password: %v", err)
			}

			// SSH configuration
			sshConfig := &ssh.ClientConfig{
				User: config.UserSSH,
				Auth: []ssh.AuthMethod{
					ssh.Password(sshPass),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			}

			// Connect to SSH server with retry
			sshAddr := fmt.Sprintf("%s:%s", config.IP, config.SSHPort)
			var sshClient *ssh.Client
			for i := 0; i < 3; i++ {
				log.Printf("🔍 Attempt %d to connect to SSH server (%s)...", i+1, sshAddr)
				sshClient, err = ssh.Dial("tcp", sshAddr, sshConfig)
				if err == nil {
					break
				}
				log.Printf("⚠️ Attempt %d failed: %v", i+1, err)
				time.Sleep(2 * time.Second)
			}
			if err != nil {
				log.Fatalf("❌ Failed to connect to SSH server after 3 attempts: %v", err)
			}
			defer sshClient.Close()

			// Initial SSH tunnel test
			log.Println("🔍 Testing initial SSH tunnel connection...")
			testConn, err := sshClient.Dial("tcp", "8.8.8.8:53")
			if err != nil {
				log.Printf("⚠️ Initial connection test failed: %v", err)
			} else {
				log.Println("✅ Initial connection test succeeded")
				testConn.Close()
			}

			// Custom resolver that disables DNS resolving
			noOpResolver := &NoOpResolver{}

			// SOCKS5 server configuration without DNS resolving
			socks5Conf := &socks5.Config{
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var conn net.Conn
					for i := 0; i < 3; i++ {
						log.Printf("🔄 Attempt %d to forward raw domain %s via SSH tunnel", i+1, addr)
						conn, err = sshClient.Dial(network, addr)
						if err == nil {
							break
						}
						log.Printf("⚠️ Attempt %d failed: %v", i+1, err)
						time.Sleep(1 * time.Second)
					}
					if err != nil {
						log.Printf("❌ Failed to tunnel %s after 3 attempts: %v", addr, err)
						return nil, err
					}
					log.Printf("✅ Successfully tunneled %s", addr)
					return conn, nil
				},
				Resolver: noOpResolver,
			}

			// Create SOCKS5 server
			socks5Server, err := socks5.New(socks5Conf)
			if err != nil {
				log.Fatalf("❌ Failed to create SOCKS5 server: %v", err)
			}

			// Start SOCKS5 server
			socksAddr := fmt.Sprintf("127.0.0.1:%s", config.SocksPort)
			log.Printf("🚀 SOCKS5 server started at %s (DNS resolving disabled)", socksAddr)

			// Handle server lifecycle with signal management
			shutdown := make(chan os.Signal, 1)
			signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				if err := socks5Server.ListenAndServe("tcp", socksAddr); err != nil {
					log.Printf("❌ SOCKS5 server failed: %v", err)
				}
			}()

			<-shutdown
			log.Println("🛑 Shutting down...")
		},
	}

	// Execute the Cobra command
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("❌ Failed to execute command: %v", err)
	}
}

// NoOpResolver is a custom resolver that disables DNS resolving
type NoOpResolver struct{}

// Resolve method that does not perform DNS resolution
func (r *NoOpResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	log.Printf("🔧 Resolving disabled for %s, forwarding raw domain", name)
	return ctx, nil, nil
}

// loadOrGetConfig loads config from file or prompts the user if file doesn't exist
func loadOrGetConfig() (Config, error) {
	configFile := "config.json"
	var config Config

	// Check if config file exists
	if _, err := os.Stat(configFile); err == nil {
		// Load from file
		data, err := os.ReadFile(configFile)
		if err != nil {
			return Config{}, fmt.Errorf("failed to read config file: %v", err)
		}
		if err := json.Unmarshal(data, &config); err != nil {
			return Config{}, fmt.Errorf("failed to parse config file: %v", err)
		}
		log.Println("✅ Loaded config from config.json")
		return config, nil
	}

	// If file doesn't exist, prompt user with Cobra
	log.Println("📝 https://github.com/khaliilii/")
	log.Println("📝 MKConnect...")
	log.Println("📝 Config file not found, please enter connection details:")
	fmt.Print("Enter SSH username: ")
	fmt.Scanln(&config.UserSSH)
	fmt.Print("Enter SSH password: ")
	var sshPass string
	fmt.Scanln(&sshPass)
	fmt.Print("Enter SSH server IP: ")
	fmt.Scanln(&config.IP)
	fmt.Print("Enter SSH port: ")
	fmt.Scanln(&config.SSHPort)
	fmt.Print("Enter SOCKS5 port: ")
	fmt.Scanln(&config.SocksPort)

	// Encrypt the password
	encryptedPass, err := encryptPassword(sshPass)
	if err != nil {
		return Config{}, fmt.Errorf("failed to encrypt password: %v", err)
	}
	config.SSHPassEnc = encryptedPass

	// Save to file
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return Config{}, fmt.Errorf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return Config{}, fmt.Errorf("failed to write config file: %v", err)
	}
	log.Println("✅ Saved config to config.json")
	return config, nil
}

// encryptPassword encrypts the password using AES
func encryptPassword(password string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	// Pad password to be a multiple of block size
	padding := aes.BlockSize - len(password)%aes.BlockSize
	padText := append([]byte(password), byte(padding))
	for i := 1; i < padding; i++ {
		padText = append(padText, byte(padding))
	}

	ciphertext := make([]byte, aes.BlockSize+len(padText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], padText)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptPassword decrypts the password using AES
func decryptPassword(encrypted string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	padding := int(ciphertext[len(ciphertext)-1])
	if padding > len(ciphertext) || padding > aes.BlockSize {
		return "", fmt.Errorf("invalid padding")
	}
	return string(ciphertext[:len(ciphertext)-padding]), nil
}
