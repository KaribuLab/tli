package internal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gookit/slog"
)

type ScanFileInput struct {
	Path         string
	OriginalPath string
	File         *os.File
	Size         int64
}

type ScanFileResult struct {
	SecurityIssues []string `json:"security_issues" jsonschema:"the security issues found"`
}

type UploadFilesAsGzipInput struct {
	BatchId string
	Files   []ScanFileInput
}

type RunScanInput struct {
	BatchId       string
	RepositoryURL string
	Branch        string
}

type RunScanOutput struct {
	ScanID string `json:"scan_id"`
}

type GetScanStatusInput struct {
	ScanID string
}

type GetScanStatusOutput struct {
	Status string       `json:"status"`
	Result StatusResult `json:"result"`
}

func closeBody(resp http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func getAPIConfig() (*Config, error) {
	// Obtener API Key de la configuración
	homeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Error("Error al obtener el directorio home", "error", err)
		return nil, err
	}

	configPath := filepath.Join(homeDir, ".tli", "config.json")
	config := &Config{}
	if err := config.Load(configPath); err != nil {
		// Sin archivo de configuración: usar variables de entorno (CI/contenedores)
		if envConfig := configFromEnv(); envConfig != nil {
			slog.Debug("Usando configuración desde variables de entorno")
			return envConfig, nil
		}
		slog.Error("Error al cargar la configuración", "error", err)
		return nil, err
	}

	return config, nil
}

// configFromEnv builds the config from TLI_USER_ID, TLI_API_KEY and
// TLI_API_ENDPOINT. Returns nil unless all three are set. The values are the
// same ones `tli setup` writes to ~/.tli/config.json.
func configFromEnv() *Config {
	userID := os.Getenv("TLI_USER_ID")
	apiKey := os.Getenv("TLI_API_KEY")
	apiEndpoint := os.Getenv("TLI_API_ENDPOINT")
	if userID == "" || apiKey == "" || apiEndpoint == "" {
		return nil
	}
	return NewConfig(userID, apiKey, apiEndpoint)
}

func UploadFilesAsGzip(params *UploadFilesAsGzipInput) error {
	config, err := getAPIConfig()
	if err != nil {
		return err
	}

	tempFileName := fmt.Sprintf("tli-%s.tar.gz", uuid.New().String())
	tempDirPath, err := os.MkdirTemp("", "tli-")
	if err != nil {
		return err
	}
	slog.Debug("Directorio temporal creado", "ruta", tempDirPath)
	tempFilePath := filepath.Join(tempDirPath, tempFileName)
	slog.Debug("Ruta temporal creada", "ruta", tempFilePath)
	tempFile, err := os.OpenFile(tempFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer func() {
		slog.Debug("Cerrando archivo temporal", "ruta", tempFilePath)
		tempFile.Close()
		slog.Debug("Eliminando directorio temporal", "ruta", tempDirPath)
		err := os.RemoveAll(tempDirPath)
		if err != nil {
			slog.Debug("No se pudo eliminar el directorio temporal", "error", err, "ruta", tempDirPath)
		} else {
			slog.Debug("Directorio temporal eliminado", "ruta", tempDirPath)
		}
	}()

	gzipWriter := gzip.NewWriter(tempFile)
	slog.Debug("GzipWriter creado", "ruta", tempFilePath)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, file := range params.Files {
		// Crear el encabezado tar para el archivo usando el nombre seguro
		header := &tar.Header{
			Name: file.Path,
			Mode: 0600,
			Size: file.Size,
		}

		// Escribir el encabezado en el archivo tar
		if err := tarWriter.WriteHeader(header); err != nil {
			slog.Error("Error al escribir el encabezado tar", "error", err, "ruta del archivo", file.Path, "nombre_tar", file.Path)
			continue
		}

		// Copiar el contenido del archivo directamente desde el descriptor
		// Esto evita TOCTOU ya que usamos el mismo descriptor de archivo
		if _, err := io.Copy(tarWriter, file.File); err != nil {
			slog.Error("Error al escribir el contenido al tar", "error", err, "ruta del archivo", file.Path, "nombre_tar", file.Path)
			continue
		}

		slog.Info("Archivo añadido a la compresión", "ruta del archivo", file.Path, "nombre_tar", file.Path)
	}
	if err := tarWriter.Close(); err != nil {
		slog.Error("Error al cerrar el escritor tar", "error", err)
		return err
	}

	if err := gzipWriter.Close(); err != nil {
		slog.Error("Error al cerrar el escritor gzip", "error", err)
		return err
	}

	// Cerrar el archivo para asegurar que todos los datos se escriben
	tempFile.Close()

	// Obtener estadísticas del archivo para verificar tamaño
	fileInfo, err := os.Stat(tempFilePath)
	if err != nil {
		slog.Error("Error al obtener información del archivo temporal", "error", err)
		return err
	}

	fileSize := fileInfo.Size()
	slog.Debug("Archivo comprimido creado exitosamente", "tamaño (bytes)", fileSize, "ruta", tempFilePath)

	if fileSize == 0 {
		slog.Error("El archivo comprimido está vacío")
		return fmt.Errorf("el archivo comprimido está vacío")
	}

	requestBody := map[string]interface{}{
		"source": "cli",
		"args": map[string]interface{}{
			"batch_id": params.BatchId,
			// Solicitar una única URL para el archivo tar.gz
			"files": []map[string]string{
				{
					"name":         tempFileName, // Solo el nombre del archivo, no la ruta completa
					"content_type": "application/x-tar+gzip",
				},
			},
			// Añadir la lista de archivos originales como metadatos
			"original_files": func() []string {
				var originalPaths []string
				for _, file := range params.Files {
					originalPaths = append(originalPaths, file.OriginalPath)
				}
				return originalPaths
			}(),
		},
	}

	// Convertir a JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		slog.Error("Error al crear JSON para la petición", "error", err)
		return err
	}

	// Crear la petición HTTP
	endpoint := config.APIEndpoint + "/cli-files"
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("Error al crear la petición HTTP", "error", err)
		return err
	}

	// Establecer headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", fmt.Sprintf("ENC:%s", config.APIKey))

	// Enviar la petición
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error al enviar la petición HTTP", "error", err)
		return err
	}

	defer closeBody(*resp)

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
	slog.Debug("Respuesta recibida", "status", resp.Status)

	// Analizar la estructura de la respuesta como un mapa genérico primero
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &rawResponse); err != nil {
		slog.Error("Error al decodificar la respuesta como mapa", "error", err)
		return err
	}

	// Buscar la URL prefirmada para el archivo tar.gz
	var presignedURL string

	// Verificar si hay un campo presigned_urls (formato mapa)
	if urlsMap, ok := rawResponse["presigned_urls"].(map[string]interface{}); ok {
		// Buscar la URL para nuestro archivo tar.gz
		if url, ok := urlsMap[tempFileName].(string); ok &&
			url != "" &&
			strings.HasPrefix(url, "https://") {
			presignedURL = url
			slog.Debug("URL prefirmada encontrada para el archivo tar.gz")
		} else {
			slog.Error("No se pudo encontrar una URL prefirmada válida en la respuesta")
			return fmt.Errorf("no se pudo encontrar una URL prefirmada válida en la respuesta")
		}
	}

	if presignedURL == "" {
		slog.Error("No se pudo encontrar una URL prefirmada válida en la respuesta")
		return fmt.Errorf("no se pudo encontrar una URL prefirmada válida en la respuesta")
	}

	// Abrir el archivo para lectura
	file, err := os.Open(tempFilePath)
	if err != nil {
		slog.Error("Error al abrir el archivo temporal para lectura", "error", err)
		return err
	}
	defer file.Close()

	// Subir el archivo comprimido
	slog.Info("Subiendo archivo comprimido...")
	slog.Debug("Detalles del archivo comprimido", "nombre", tempFileName, "ruta", tempFilePath, "tamaño", fileSize)
	slog.Trace("URL prefirmada", "url", presignedURL)

	// Preparar la petición PUT con el archivo
	putReq, err := http.NewRequest("PUT", presignedURL, file)
	if err != nil {
		slog.Error("Error al crear la petición PUT", "error", err)
		return err
	}

	// Usar el Content-Type correcto para archivos tar.gz
	putReq.Header.Set("Content-Type", "application/x-tar+gzip")
	putReq.ContentLength = fileSize

	// Enviar la petición PUT
	putResp, err := client.Do(putReq)
	if err != nil {
		slog.Error("Error al enviar la petición PUT", "error", err)
		return err
	}

	// Leer y cerrar la respuesta
	if isTrace() {
		body, err := httputil.DumpResponse(putResp, true)
		if err != nil {
			slog.Error("Error al leer el cuerpo de la respuesta", "error", err)
			return err
		}
		slog.Trace("Cuerpo de la respuesta", "body", string(body))
	}

	defer closeBody(*putResp)

	if putResp.StatusCode >= 200 && putResp.StatusCode < 300 {
		slog.Info("Archivo comprimido subido exitosamente")
		slog.Debug("Detalles del archivo subido", "ruta", tempFilePath, "nombre", tempFileName)

		return nil
	}

	slog.Error("Error al subir el archivo comprimido", "status", putResp.StatusCode)
	return fmt.Errorf("error al subir el archivo comprimido: %s", putResp.Status)
}

func sanitizeRepositoryURL(repositoryURL string) string {
	// Limpiar espacios en blanco y saltos de línea
	cleanURL := strings.TrimSpace(strings.ReplaceAll(repositoryURL, "\n", ""))

	if !strings.HasPrefix("https://", cleanURL) {
		return cleanURL
	}

	// Intentar parsear como URL
	parsedURL, err := url.Parse(cleanURL)
	if err != nil {
		slog.Debug("No se pudo parsear como URL, devolviendo como string limpio", "error", err)
		return cleanURL
	}

	// Si contiene información de usuario (credenciales), eliminarla
	if parsedURL.User != nil {
		slog.Debug("Eliminando credenciales de la URL del repositorio")
		parsedURL.User = nil
		parsedURL.RawQuery = ""
		sanitizedURL := parsedURL.String()
		return sanitizedURL
	}

	// Si no contiene credenciales, devolver la URL limpia original
	slog.Debug("URL sin credenciales, devolviendo limpia")
	return cleanURL
}

func RunScan(params *RunScanInput) (*RunScanOutput, error) {
	config, err := getAPIConfig()
	if err != nil {
		return nil, err
	}
	requestBody := map[string]interface{}{
		"source": "cli",
		"args": map[string]interface{}{
			"repository_url": sanitizeRepositoryURL(params.RepositoryURL),
			"batch_id":       params.BatchId,
			"branch":         params.Branch,
		},
	}
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		slog.Error("Error al crear JSON para la petición de escaneo", "error", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", config.APIEndpoint+"/run-scan", bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("Error al crear la petición HTTP para ejecutar el escaneo", "error", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", fmt.Sprintf("ENC:%s", config.APIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error al ejecutar el escaneo", "error", err)
		return nil, err
	}

	if isTrace() {
		body, err := httputil.DumpResponse(resp, true)
		if err != nil {
			slog.Error("Error al leer el cuerpo de la respuesta", "error", err)
			return nil, err
		}
		slog.Trace("Cuerpo de la respuesta", "body", string(body))
	}

	defer closeBody(*resp)

	if resp.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				slog.Error("Error al ejecutar el escaneo", "status", resp.Status, "mensaje", message)
				return nil, fmt.Errorf("error al ejecutar el escaneo: %s - %s", resp.Status, message)
			}
		}
		slog.Error("Error al ejecutar el escaneo", "status", resp.Status)
		return nil, fmt.Errorf("error al ejecutar el escaneo: %s", resp.Status)
	}

	// Extraer scan_id de la respuesta
	var scanResponse struct {
		ScanID string `json:"scan_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&scanResponse); err != nil {
		slog.Error("Error al decodificar la respuesta del escaneo", "error", err)
		return nil, err
	}

	scanID := scanResponse.ScanID
	if scanID == "" {
		slog.Error("No se pudo obtener el scan_id de la respuesta")
		return nil, fmt.Errorf("no se pudo obtener el scan_id de la respuesta")
	}

	slog.Info("Escaneo iniciado correctamente", "scan_id", scanID)

	return &RunScanOutput{ScanID: scanID}, nil
}

func GetScanStatus(params *GetScanStatusInput) (*GetScanStatusOutput, error) {
	config, err := getAPIConfig()
	if err != nil {
		return nil, err
	}

	scanStatusURL := fmt.Sprintf("%s/scan-status", config.APIEndpoint)
	requestBody := map[string]interface{}{
		"scan_id": params.ScanID,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		slog.Error("Error al crear JSON para la petición de estado", "error", err)
		return nil, err
	}

	// Establecer tiempo límite de 1 hora
	deadline := time.Now().Add(1 * time.Hour)

	for time.Now().Before(deadline) {
		// Esperar 5 segundos entre peticiones
		time.Sleep(5 * time.Second)
		output, err := (func() (*GetScanStatusOutput, error) {

			// Crear nueva petición para verificar estado
			statusReq, err := http.NewRequest("POST", scanStatusURL, bytes.NewBuffer(jsonData))
			if err != nil {
				slog.Error("Error al crear la petición HTTP para verificar estado", "error", err)
				return nil, nil
			}

			statusReq.Header.Set("Content-Type", "application/json")
			statusReq.Header.Set("X-API-Key", fmt.Sprintf("ENC:%s", config.APIKey))

			statusResp, err := http.DefaultClient.Do(statusReq)
			defer closeBody(*statusResp)
			if err != nil {
				slog.Error("Error al verificar estado del escaneo", "error", err)
				return nil, nil
			}

			if statusResp.StatusCode != http.StatusOK {
				slog.Error("Error al verificar estado del escaneo", "status", statusResp.Status)
				return nil, nil
			}

			// Leer respuesta
			var statusResponse struct {
				Status string       `json:"status"`
				Result StatusResult `json:"result"`
			}

			body, err := io.ReadAll(statusResp.Body)
			if err != nil {
				slog.Error("Error al leer el cuerpo de la respuesta", "error", err)
				return nil, nil
			}

			slog.Debug("Respuesta de estado del escaneo", "body", string(body), "status", statusResp.Status)

			if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&statusResponse); err != nil {
				slog.Error("Error al decodificar la respuesta de estado", "error", err)
				return nil, nil
			}

			// Verificar estado
			slog.Info("Estado del escaneo", "scan_id", params.ScanID, "estado", statusResponse.Status)

			switch statusResponse.Status {
			case "COMPLETED":
				slog.Info("Escaneo completado correctamente", "scan_id", params.ScanID)
				return &GetScanStatusOutput{Status: statusResponse.Status, Result: statusResponse.Result}, nil
			case "FAILED":
				slog.Error("Escaneo finalizado con errores", "scan_id", params.ScanID, "estado", statusResponse.Status)
				return &GetScanStatusOutput{Status: statusResponse.Status, Result: statusResponse.Result}, nil
			case "ERROR":
				slog.Error("Escaneo finalizado con errores", "scan_id", params.ScanID, "estado", statusResponse.Status)
				return nil, fmt.Errorf("escaneo finalizado con estado: %s", statusResponse.Status)
			}
			// Si no es ninguno de los estados finales, continuar esperando
			return nil, nil
		})()
		if err != nil {
			return nil, err
		}
		if output != nil {
			return output, nil
		}
	}

	return nil, fmt.Errorf("escaneo no finalizado en el tiempo límite")
}
