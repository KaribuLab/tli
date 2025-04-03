package internal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
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
	cmd.Flags().StringP("commit", "c", "", "Commit hash to scan")
	cmd.Flags().BoolP("staged", "s", false, "Staged files only")
	return cmd
}

// getConfig obtiene la configuración (API key) del archivo de configuración
func getConfig() (*Config, error) {
	// Obtener API Key de la configuración
	homeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Error("Error al obtener el directorio home", "error", err)
		return nil, err
	}

	configPath := filepath.Join(homeDir, ".tvosec", "config.json")
	config := &Config{}
	if err := config.Load(configPath); err != nil {
		slog.Error("Error al cargar la configuración", "error", err)
		return nil, err
	}

	return config, nil
}

// uploadFilesAsGzip comprime la lista de archivos en un archivo gzip y lo sube usando una URL prefirmada
func uploadFilesAsGzip(filesArray []string, apiKey string, scanBatchId string) error {
	// Crear la estructura de archivos para la petición
	var filesList []map[string]string
	for _, filePath := range filesArray {
		if filePath == "" {
			continue
		}
		filesList = append(filesList, map[string]string{
			"name":         filePath,
			"content_type": "application/gzip",
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
		return err
	}

	// Crear la petición HTTP
	endpoint := "https://4psk9bcsud.execute-api.us-east-1.amazonaws.com/v1/cli-files"
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("Error al crear la petición HTTP", "error", err)
		return err
	}

	// Establecer headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	// Enviar la petición
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error al enviar la petición HTTP", "error", err)
		return err
	}
	defer resp.Body.Close()

	// Verificar respuesta
	if resp.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				slog.Error("Error en la respuesta del servidor", "status", resp.Status, "message", message)
				return fmt.Errorf("error en la respuesta del servidor: %s - %s", resp.Status, message)
			}
		}
		slog.Error("Error en la respuesta del servidor", "status", resp.Status)
		return fmt.Errorf("error en la respuesta del servidor: %s", resp.Status)
	}

	// Leer el cuerpo completo para depuración y procesamiento
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Error al leer el cuerpo de la respuesta", "error", err)
		return err
	}

	// Loguear respuesta para depuración
	slog.Debug("Respuesta recibida", "body", string(respBody))

	// Analizar la estructura de la respuesta como un mapa genérico primero
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &rawResponse); err != nil {
		slog.Error("Error al decodificar la respuesta como mapa", "error", err)
		return err
	}

	// Extraer la URL prefirmada de la respuesta, manejando diferentes formatos posibles
	var presignedURL string

	// Verificar si hay un campo presigned_url (formato singular)
	if url, ok := rawResponse["presigned_url"].(string); ok && url != "" {
		presignedURL = url
		slog.Debug("URL prefirmada encontrada en campo 'presigned_url'")
	} else if urlsMap, ok := rawResponse["presigned_urls"].(map[string]interface{}); ok {
		// Verificar si hay un campo presigned_urls (formato mapa)
		// Tomar la primera URL del mapa
		for _, url := range urlsMap {
			if urlStr, ok := url.(string); ok && urlStr != "" {
				presignedURL = urlStr
				slog.Debug("URL prefirmada encontrada en mapa 'presigned_urls'")
				break
			}
		}
	} else {
		// Buscar en cualquier otro campo que pueda contener una URL
		for key, value := range rawResponse {
			if strings.Contains(strings.ToLower(key), "url") {
				if urlStr, ok := value.(string); ok && urlStr != "" {
					presignedURL = urlStr
					slog.Debug("URL prefirmada encontrada en campo alternativo", "campo", key)
					break
				} else if urlMap, ok := value.(map[string]interface{}); ok {
					// Si es un mapa, intentar encontrar una URL dentro de él
					for _, mapValue := range urlMap {
						if urlStr, ok := mapValue.(string); ok && urlStr != "" && strings.HasPrefix(urlStr, "http") {
							presignedURL = urlStr
							slog.Debug("URL prefirmada encontrada en submapa", "campo", key)
							break
						}
					}
				}
			}
		}
	}

	if presignedURL == "" {
		slog.Error("No se pudo encontrar una URL prefirmada válida en la respuesta")
		return fmt.Errorf("no se pudo encontrar una URL prefirmada válida en la respuesta")
	}

	slog.Debug("URL prefirmada obtenida", "url", presignedURL)

	// Crear archivo gzip con todos los archivos
	slog.Info("Comprimiendo archivos...")

	// Crear un buffer para almacenar el archivo comprimido
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)

	// Añadir cada archivo al archivo tar
	for _, filePath := range filesArray {
		if filePath == "" {
			continue
		}

		// Leer el contenido del archivo
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			slog.Error("Error al leer el archivo", "error", err, "ruta del archivo", filePath)
			continue
		}

		// Crear el encabezado tar para el archivo
		header := &tar.Header{
			Name: filePath,
			Mode: 0600,
			Size: int64(len(fileContent)),
		}

		// Escribir el encabezado y el contenido en el archivo tar
		if err := tarWriter.WriteHeader(header); err != nil {
			slog.Error("Error al escribir el encabezado tar", "error", err, "ruta del archivo", filePath)
			continue
		}

		if _, err := tarWriter.Write(fileContent); err != nil {
			slog.Error("Error al escribir el contenido al tar", "error", err, "ruta del archivo", filePath)
			continue
		}

		slog.Info("Archivo añadido a la compresión", "ruta del archivo", filePath)
	}

	// Cerrar los escritores
	if err := tarWriter.Close(); err != nil {
		slog.Error("Error al cerrar el escritor tar", "error", err)
		return err
	}

	if err := gzipWriter.Close(); err != nil {
		slog.Error("Error al cerrar el escritor gzip", "error", err)
		return err
	}

	slog.Info("Archivos comprimidos exitosamente")

	// Subir el archivo comprimido
	slog.Info("Subiendo archivo comprimido...")

	putReq, err := http.NewRequest("PUT", presignedURL, &buf)
	if err != nil {
		slog.Error("Error al crear la petición PUT", "error", err)
		return err
	}

	putReq.Header.Set("Content-Type", "application/gzip")

	// Enviar la petición PUT
	putResp, err := client.Do(putReq)
	if err != nil {
		slog.Error("Error al enviar la petición PUT", "error", err)
		return err
	}

	// Leer y cerrar la respuesta
	io.Copy(io.Discard, putResp.Body)
	putResp.Body.Close()

	if putResp.StatusCode >= 200 && putResp.StatusCode < 300 {
		slog.Info("Archivo comprimido subido exitosamente")
	} else {
		slog.Error("Error al subir el archivo comprimido", "status", putResp.Status)
		return fmt.Errorf("error al subir el archivo comprimido: %s", putResp.Status)
	}

	return nil
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
	commit, err := cmd.Flags().GetString("commit")
	if err != nil {
		slog.Error("Error al obtener el hash del commit", "error", err)
		os.Exit(1)
	}
	staged, err := cmd.Flags().GetBool("staged")
	if err != nil {
		slog.Error("Error al obtener el formato de salida", "error", err)
		os.Exit(1)
	}

	// Verificar que se proporcione --commit o --staged
	if commit == "" && !staged {
		slog.Error("Debe especificar --commit o --staged")
		fmt.Println("Error: Debe proporcionar --commit <hash> o --staged para ejecutar el escaneo")
		os.Exit(1)
	}

	if commit != "" && staged {
		slog.Error("No se puede especificar un commit y staged al mismo tiempo")
		os.Exit(1)
	}

	slog.Info("Ruta", "path", path)
	slog.Info("Formato de salida", "output", output)

	if staged {
		slog.Info("Escaneo de archivos estaged", "staged", staged)
		scanBatchId := uuid.NewString()
		files, err := execGitCommand([]string{"diff", "--cached", "--name-only"})
		if err != nil {
			slog.Error("Error al obtener los archivos", "error", err)
			os.Exit(1)
		}
		slog.Info("Generando lote de archivos:", scanBatchId)
		filesArray := strings.Split(files, "\n")

		// Obtener configuración
		config, err := getConfig()
		if err != nil {
			os.Exit(1)
		}

		// Subir archivos como gzip
		if err := uploadFilesAsGzip(filesArray, config.APIKey, scanBatchId); err != nil {
			slog.Error("Error al subir los archivos", "error", err)
			os.Exit(1)
		}

		slog.Info("Proceso de escaneo completado")
	} else if commit != "" {
		slog.Info("Escaneo de archivos del commit", "commit", commit)

		scanBatchId := uuid.NewString()
		// Usar git show para obtener los archivos modificados en un commit específico
		files, err := execGitCommand([]string{"show", "--name-only", "--pretty=format:", commit})
		if err != nil {
			slog.Error("Error al obtener los archivos del commit", "error", err)
			os.Exit(1)
		}

		// Filtrar la salida, ya que podría contener líneas vacías al inicio
		var filteredFiles []string
		for _, filePath := range strings.Split(files, "\n") {
			if filePath != "" {
				filteredFiles = append(filteredFiles, filePath)
			}
		}

		if len(filteredFiles) == 0 {
			slog.Error("No se encontraron archivos en el commit", "commit", commit)
			os.Exit(1)
		}

		slog.Info("Generando lote de archivos:", scanBatchId, "cantidad", len(filteredFiles))

		// Obtener configuración
		config, err := getConfig()
		if err != nil {
			os.Exit(1)
		}

		// Subir archivos como gzip
		if err := uploadFilesAsGzip(filteredFiles, config.APIKey, scanBatchId); err != nil {
			slog.Error("Error al subir los archivos", "error", err)
			os.Exit(1)
		}

		slog.Info("Proceso de escaneo completado")
	}
}
