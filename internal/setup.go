package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gookit/slog"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func NewSetupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "setup",
		Run: setup,
	}
	return cmd
}

func fillWithDots(apiKey string) string {
	result := ""
	repeat := len(apiKey) - 7
	if repeat > 0 {
		for range repeat {
			result += "."
		}
		result = apiKey[0:4] + result + apiKey[len(apiKey)-3:]
	} else {
		for range len(apiKey) {
			result += "."
		}
	}
	return result
}

func setup(cmd *cobra.Command, args []string) {
	slog.Info("Setting up Titvo Security...")
	fmt.Print("Enter your user ID: ")
	var userId string
	fmt.Scanln(&userId)
	if strings.TrimSpace(userId) == "" {
		slog.Error("User ID is required")
		os.Exit(1)
	}
	fmt.Print("Enter your API Key: ")
	apiKey, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		slog.Error("Error reading API Key:", err)
		os.Exit(1)
	}
	fmt.Println()
	// Aquí puedes usar el apiKey
	stringApiKey := string(apiKey)
	stringUserId := string(strings.TrimSpace(userId))

	slog.Info("ID received successfully: ", stringUserId)
	slog.Info("API Key received successfully: ", fillWithDots(stringApiKey))

	// Crear y enviar la petición HTTP
	setupEndpoint := "https://3ovlfwktt3.execute-api.us-east-1.amazonaws.com/v1/auth/setup"

	// Preparar los datos para enviar
	requestData := map[string]interface{}{
		"source": "cli",
		"args": map[string]string{
			"user_id": stringUserId,
		},
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		slog.Error("Error al preparar datos para la petición:", err)
		os.Exit(1)
	}

	// Crear la petición HTTP
	req, err := http.NewRequest("POST", setupEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("Error al crear la petición HTTP:", err)
		os.Exit(1)
	}

	// Establecer headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", stringApiKey)

	// Enviar la petición
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error al enviar la petición HTTP:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Verificar respuesta
	if resp.StatusCode != http.StatusOK {
		// Extraer mensaje de error del cuerpo JSON
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				slog.Error("Error en la respuesta del servidor:", resp.Status, "- Mensaje:", message)
				os.Exit(1)
			}
		}
		// Si no se pudo extraer un mensaje o no había uno en el cuerpo, mostrar error genérico
		slog.Error("Error en la respuesta del servidor:", resp.Status)
		os.Exit(1)
	}

	slog.Info("Verificación con el servidor completada exitosamente")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Error("Error getting home directory:", err)
		os.Exit(1)
	}
	filePath := filepath.Join(homeDir, ".tvosec", "config.json")
	os.MkdirAll(filepath.Dir(filePath), 0755)
	config := NewConfig(stringUserId, stringApiKey)
	config.Save(filePath)
	slog.Info("Setup completed successfully. File saved in: ", filePath)
}
