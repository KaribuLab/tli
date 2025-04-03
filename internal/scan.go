package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

func execGitCommand(args []string) (string, error) {
	cmd := exec.Command("git", args...)
	output, err := cmd.Output()
	if err != nil {
		slog.Error("Error al ejecutar el comando git", "error", err)
		return "", err
	}
	return string(output), nil
}

func NewScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "scan",
		Run: scan,
	}
	cmd.Flags().StringP("path", "p", ".", "Path to scan")
	cmd.Flags().StringP("output", "o", "text", "Output format")
	cmd.Flags().BoolP("staged", "s", false, "Staged files only")
	return cmd
}

func scan(cmd *cobra.Command, args []string) {
	slog.Info("Iniciando escaneo...")
	path, err := cmd.Flags().GetString("path")
	if err != nil {
		slog.Error("Error al obtener la ruta", "error", err)
		os.Exit(1)
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		slog.Error("Error al obtener el formato de salida", "error", err)
		os.Exit(1)
	}
	if err != nil {
		slog.Error("Error al obtener el formato de salida", "error", err)
		os.Exit(1)
	}
	staged, err := cmd.Flags().GetBool("staged")
	if err != nil {
		slog.Error("Error al obtener el formato de salida", "error", err)
		os.Exit(1)
	}
	slog.Info("Ruta", "path", path)
	slog.Info("Formato de salida", "output", output)
	slog.Info("Escaneo de archivos estaged", "staged", staged)
	if staged {
		scanBatchId := uuid.NewString()
		files, err := execGitCommand([]string{"diff", "--cached", "--name-only"})
		if err != nil {
			slog.Error("Error al obtener los archivos", "error", err)
			os.Exit(1)
		}
		slog.Info("Generando lote de archivos:", scanBatchId)
		filesArray := strings.Split(files, "\n")

		// Crear la estructura de archivos para la petición
		var filesList []map[string]string
		for _, filePath := range filesArray {
			if filePath == "" {
				continue
			}
			filesList = append(filesList, map[string]string{
				"name":         filePath,
				"content_type": "text/plain",
			})
			slog.Info("Archivo", filePath)
		}

		// Crear el cuerpo de la petición
		requestBody := map[string]interface{}{
			"source": "cli",
			"args": map[string]interface{}{
				"batch_id": scanBatchId,
				"files":    filesList,
			},
		}

		// Convertir a JSON
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			slog.Error("Error al crear JSON para la petición", "error", err)
			os.Exit(1)
		}

		// Obtener API Key de la configuración
		homeDir, err := os.UserHomeDir()
		if err != nil {
			slog.Error("Error al obtener el directorio home", "error", err)
			os.Exit(1)
		}

		configPath := filepath.Join(homeDir, ".tvosec", "config.json")
		config := &Config{}
		if err := config.Load(configPath); err != nil {
			slog.Error("Error al cargar la configuración", "error", err)
			os.Exit(1)
		}

		// Crear la petición HTTP
		endpoint := "https://4psk9bcsud.execute-api.us-east-1.amazonaws.com/v1/cli-files"
		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			slog.Error("Error al crear la petición HTTP", "error", err)
			os.Exit(1)
		}

		// Establecer headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", config.APIKey)

		// Enviar la petición
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			slog.Error("Error al enviar la petición HTTP", "error", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		// Verificar respuesta
		if resp.StatusCode != http.StatusOK {
			var errorResponse map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
				if message, ok := errorResponse["message"].(string); ok {
					slog.Error("Error en la respuesta del servidor", "status", resp.Status, "message", message)
					os.Exit(1)
				}
			}
			slog.Error("Error en la respuesta del servidor", "status", resp.Status)
			os.Exit(1)
		}

		// Decodificar la respuesta
		var response struct {
			Message       string            `json:"message"`
			PresignedURLs map[string]string `json:"presigned_urls"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			slog.Error("Error al decodificar la respuesta", "error", err)
			os.Exit(1)
		}

		slog.Info("Petición enviada exitosamente", "batch_id", scanBatchId, "message", response.Message)

		// Iterar sobre los URLs prefirmados y subir los archivos
		for filePath, presignedURL := range response.PresignedURLs {
			slog.Info("Subiendo archivo", filePath)

			// Leer el contenido del archivo
			fileContent, err := os.ReadFile(filePath)
			if err != nil {
				slog.Error("Error al leer el archivo", "error", err, "ruta del archivo", filePath)
				continue
			}

			// Crear petición PUT para subir el archivo
			putReq, err := http.NewRequest("PUT", presignedURL, bytes.NewReader(fileContent))
			if err != nil {
				slog.Error("Error al crear la petición PUT", "error", err, "ruta del archivo", filePath)
				continue
			}

			putReq.Header.Set("Content-Type", "text/plain")

			// Enviar la petición PUT
			putResp, err := client.Do(putReq)
			if err != nil {
				slog.Error("Error al enviar la petición PUT", "error", err, "ruta del archivo", filePath)
				continue
			}

			// Leer y cerrar la respuesta
			io.Copy(io.Discard, putResp.Body)
			putResp.Body.Close()

			if putResp.StatusCode >= 200 && putResp.StatusCode < 300 {
				slog.Info("Archivo subido exitosamente", "ruta del archivo", filePath)
			} else {
				slog.Error("Error al subir el archivo", "status", putResp.Status, "ruta del archivo", filePath)
			}
		}

		slog.Info("Proceso de escaneo completado")
	} else {
		slog.Info("Escaneo de archivos del último commit")
	}
}
