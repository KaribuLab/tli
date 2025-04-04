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
	"time"

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

// runScanAndWaitForCompletion ejecuta el escaneo y espera hasta que se complete
func runScanAndWaitForCompletion(batchId string, apiKey string) error {
	apiBaseURL := "https://4psk9bcsud.execute-api.us-east-1.amazonaws.com/v1"

	// Registrar tiempo de inicio
	startTime := time.Now()

	// 1. Ejecutar el escaneo
	runScanURL := fmt.Sprintf("%s/run-scan", apiBaseURL)
	requestBody := map[string]interface{}{
		"source": "cli",
		"args": map[string]interface{}{
			"batch_id": batchId,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		slog.Error("Error al crear JSON para la petición de escaneo", "error", err)
		return err
	}

	req, err := http.NewRequest("POST", runScanURL, bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("Error al crear la petición HTTP para ejecutar el escaneo", "error", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error al ejecutar el escaneo", "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				slog.Error("Error al ejecutar el escaneo", "status", resp.Status, "mensaje", message)
				return fmt.Errorf("error al ejecutar el escaneo: %s - %s", resp.Status, message)
			}
		}
		slog.Error("Error al ejecutar el escaneo", "status", resp.Status)
		return fmt.Errorf("error al ejecutar el escaneo: %s", resp.Status)
	}

	// Extraer scan_id de la respuesta
	var scanResponse struct {
		ScanID string `json:"scan_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&scanResponse); err != nil {
		slog.Error("Error al decodificar la respuesta del escaneo", "error", err)
		return err
	}

	scanID := scanResponse.ScanID
	if scanID == "" {
		slog.Error("No se pudo obtener el scan_id de la respuesta")
		return fmt.Errorf("no se pudo obtener el scan_id de la respuesta")
	}

	slog.Info("Escaneo iniciado correctamente", "scan_id", scanID)

	// 2. Verificar estado del escaneo en bucle
	scanStatusURL := fmt.Sprintf("%s/scan-status", apiBaseURL)
	requestBody = map[string]interface{}{
		"scan_id": scanID,
	}

	jsonData, err = json.Marshal(requestBody)
	if err != nil {
		slog.Error("Error al crear JSON para la petición de estado", "error", err)
		return err
	}

	// Establecer tiempo límite de 1 hora
	deadline := time.Now().Add(1 * time.Hour)

	for time.Now().Before(deadline) {
		// Esperar 5 segundos entre peticiones
		time.Sleep(5 * time.Second)

		// Crear nueva petición para verificar estado
		statusReq, err := http.NewRequest("POST", scanStatusURL, bytes.NewBuffer(jsonData))
		if err != nil {
			slog.Error("Error al crear la petición HTTP para verificar estado", "error", err)
			continue
		}

		statusReq.Header.Set("Content-Type", "application/json")
		statusReq.Header.Set("X-API-Key", apiKey)

		statusResp, err := client.Do(statusReq)
		if err != nil {
			slog.Error("Error al verificar estado del escaneo", "error", err)
			continue
		}

		if statusResp.StatusCode != http.StatusOK {
			statusResp.Body.Close()
			slog.Error("Error al verificar estado del escaneo", "status", statusResp.Status)
			continue
		}

		// Leer respuesta
		var statusResponse struct {
			Status string `json:"status"`
		}

		if err := json.NewDecoder(statusResp.Body).Decode(&statusResponse); err != nil {
			statusResp.Body.Close()
			slog.Error("Error al decodificar la respuesta de estado", "error", err)
			continue
		}

		statusResp.Body.Close()

		// Verificar estado
		slog.Info("Estado del escaneo", "scan_id", scanID, "estado", statusResponse.Status)

		if statusResponse.Status == "COMPLETED" {
			// Calcular tiempo total
			elapsedTime := time.Since(startTime)
			hours := int(elapsedTime.Hours())
			minutes := int(elapsedTime.Minutes()) % 60
			seconds := int(elapsedTime.Seconds()) % 60
			milliseconds := int(elapsedTime.Milliseconds()) % 1000

			// Formatear tiempo transcurrido
			formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)

			slog.Info("Escaneo completado correctamente", "scan_id", scanID, "tiempo_total", formattedTime)
			return nil
		} else if statusResponse.Status == "ERROR" || statusResponse.Status == "FAILED" {
			// Calcular tiempo total
			elapsedTime := time.Since(startTime)
			hours := int(elapsedTime.Hours())
			minutes := int(elapsedTime.Minutes()) % 60
			seconds := int(elapsedTime.Seconds()) % 60
			milliseconds := int(elapsedTime.Milliseconds()) % 1000

			// Formatear tiempo transcurrido
			formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)

			slog.Error("Escaneo finalizado con errores", "scan_id", scanID, "estado", statusResponse.Status, "tiempo_total", formattedTime)
			return fmt.Errorf("escaneo finalizado con estado: %s", statusResponse.Status)
		}

		// Si no es ninguno de los estados finales, continuar esperando
	}

	// Si llegamos aquí, se ha superado el tiempo límite
	// Calcular tiempo total (será aproximadamente 1 hora)
	elapsedTime := time.Since(startTime)
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	milliseconds := int(elapsedTime.Milliseconds()) % 1000

	// Formatear tiempo transcurrido
	formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)

	slog.Error("Tiempo de espera agotado para el escaneo", "scan_id", scanID, "tiempo_total", formattedTime)
	return fmt.Errorf("tiempo de espera agotado para el escaneo (1 hora)")
}

// uploadFilesAsGzip comprime la lista de archivos en un archivo gzip y lo sube usando una URL prefirmada
func uploadFilesAsGzip(filesArray []string, apiKey string, scanBatchId string) error {
	// Verificar que haya archivos para procesar
	var validFiles []string
	for _, filePath := range filesArray {
		if filePath != "" {
			validFiles = append(validFiles, filePath)
			slog.Info("Archivo a comprimir", "ruta", filePath)
		}
	}

	if len(validFiles) == 0 {
		slog.Error("No hay archivos válidos para escanear")
		return fmt.Errorf("no hay archivos válidos para escanear")
	}

	// Crear un nombre de archivo específico para el archivo tar.gz
	tempFileName := fmt.Sprintf("tvosec-%s.tar.gz", scanBatchId)
	tempDir := os.TempDir()
	tempFilePath := filepath.Join(tempDir, tempFileName)

	// Crear el archivo con el nombre específico
	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		slog.Error("Error al crear archivo temporal", "error", err)
		return err
	}

	slog.Debug("Archivo temporal creado", "ruta", tempFilePath, "nombre", tempFileName)

	// Asegurar que el archivo temporal se borra al final
	defer func() {
		tempFile.Close()
		err := os.Remove(tempFilePath)
		if err != nil {
			slog.Debug("No se pudo eliminar el archivo temporal", "error", err, "ruta", tempFilePath)
		} else {
			slog.Debug("Archivo temporal eliminado", "ruta", tempFilePath)
		}
	}()

	// Crear los escritores para comprimir
	gzipWriter := gzip.NewWriter(tempFile)
	tarWriter := tar.NewWriter(gzipWriter)

	// Añadir cada archivo al archivo tar
	for _, filePath := range validFiles {
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

	// Cerrar los escritores en el orden correcto
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

	// Crear el cuerpo de la petición para solicitar una URL prefirmada para el archivo tar.gz
	requestBody := map[string]interface{}{
		"source": "cli",
		"args": map[string]interface{}{
			"batch_id": scanBatchId,
			// Solicitar una única URL para el archivo tar.gz
			"files": []map[string]string{
				{
					"name":         tempFileName, // Solo el nombre del archivo, no la ruta completa
					"content_type": "application/x-tar+gzip",
				},
			},
			// Añadir la lista de archivos originales como metadatos
			"original_files": validFiles,
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

	// Buscar la URL prefirmada para el archivo tar.gz
	var presignedURL string

	// Verificar si hay un campo presigned_url (formato singular)
	if url, ok := rawResponse["presigned_url"].(string); ok && url != "" {
		presignedURL = url
		slog.Debug("URL prefirmada encontrada en campo 'presigned_url'")
	} else if urlsMap, ok := rawResponse["presigned_urls"].(map[string]interface{}); ok {
		// Verificar si hay un campo presigned_urls (formato mapa)
		// Buscar la URL para nuestro archivo tar.gz
		if url, ok := urlsMap[tempFileName].(string); ok && url != "" {
			presignedURL = url
			slog.Debug("URL prefirmada encontrada para el archivo tar.gz")
		} else {
			// Si no encontramos exactamente para nuestro archivo, tomar la primera disponible
			for fileName, url := range urlsMap {
				if urlStr, ok := url.(string); ok && urlStr != "" {
					presignedURL = urlStr
					slog.Debug("URL prefirmada encontrada para otro archivo", "nombre", fileName)
					break
				}
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
					for fileName, mapValue := range urlMap {
						if urlStr, ok := mapValue.(string); ok && urlStr != "" && strings.HasPrefix(urlStr, "http") {
							presignedURL = urlStr
							slog.Debug("URL prefirmada encontrada en submapa", "campo", key, "nombre", fileName)
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
	io.Copy(io.Discard, putResp.Body)
	putResp.Body.Close()

	if putResp.StatusCode >= 200 && putResp.StatusCode < 300 {
		slog.Info("Archivo comprimido subido exitosamente")
		slog.Debug("Detalles del archivo subido", "ruta", tempFilePath, "nombre", tempFileName)

		// Ejecutar el escaneo y esperar a que se complete
		scanResult := runScanAndWaitForCompletion(scanBatchId, apiKey)
		if scanResult != nil {
			// Verificar si el error es por estado FAILED
			if strings.Contains(scanResult.Error(), "escaneo finalizado con estado: FAILED") {
				// Terminar con código de salida 1 para indicar fallo
				os.Exit(1)
			}
			return scanResult
		}
	} else {
		slog.Error("Error al subir el archivo comprimido", "status", putResp.Status)
		slog.Debug("Detalles del archivo con error", "ruta", tempFilePath, "nombre", tempFileName)
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
