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

type statusResult struct {
	ReportUrl string `json:"report_url"`
}

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
	cmd.Flags().StringP("output", "o", "none", "Output format")
	cmd.Flags().StringP("remote", "r", "origin", "Remote to scan")
	cmd.Flags().StringP("commit", "c", "", "Commit hash to scan")
	cmd.Flags().BoolP("staged", "s", false, "Staged files only")
	cmd.Flags().BoolP("githook", "g", false, "Githook mode")
	return cmd
}

func logInfo(enabled bool, args ...any) {
	if enabled {
		slog.Info(args...)
	}
}

func logDebug(enabled bool, args ...any) {
	if enabled {
		slog.Debug(args...)
	}
}

func logError(enabled bool, args ...any) {
	if enabled {
		slog.Error(args...)
	}
}

// getConfig obtiene la configuración (API key) del archivo de configuración
func getConfig(logEnabled bool) (*Config, error) {
	// Obtener API Key de la configuración
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logError(logEnabled, "Error al obtener el directorio home", "error", err)
		return nil, err
	}

	configPath := filepath.Join(homeDir, ".tli", "config.json")
	config := &Config{}
	if err := config.Load(configPath); err != nil {
		logError(logEnabled, "Error al cargar la configuración", "error", err)
		return nil, err
	}

	return config, nil
}

// runScanAndWaitForCompletion ejecuta el escaneo y espera hasta que se complete
func runScanAndWaitForCompletion(batchId string, apiKey string, apiEndpoint string, remote string, logEnabled bool) (string, error) {
	// Registrar tiempo de inicio
	startTime := time.Now()

	// 1. Ejecutar el escaneo
	runScanURL := fmt.Sprintf("%s/run-scan", apiEndpoint)
	repositoryUrl, err := execGitCommand([]string{"remote", "get-url", remote})
	if err != nil {
		logError(logEnabled, "Error al obtener el URL del remote", "error", err)
		return "", err
	}
	requestBody := map[string]interface{}{
		"source": "cli",
		"args": map[string]interface{}{
			"repository_url": strings.ReplaceAll(repositoryUrl, "\n", ""),
			"batch_id":       batchId,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		logError(logEnabled, "Error al crear JSON para la petición de escaneo", "error", err)
		return "", err
	}

	req, err := http.NewRequest("POST", runScanURL, bytes.NewBuffer(jsonData))
	if err != nil {
		logError(logEnabled, "Error al crear la petición HTTP para ejecutar el escaneo", "error", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", fmt.Sprintf("ENC:%s", apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logError(logEnabled, "Error al ejecutar el escaneo", "error", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				logError(logEnabled, "Error al ejecutar el escaneo", "status", resp.Status, "mensaje", message)
				return "", fmt.Errorf("error al ejecutar el escaneo: %s - %s", resp.Status, message)
			}
		}
		logError(logEnabled, "Error al ejecutar el escaneo", "status", resp.Status)
		return "", fmt.Errorf("error al ejecutar el escaneo: %s", resp.Status)
	}

	// Extraer scan_id de la respuesta
	var scanResponse struct {
		ScanID string `json:"scan_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&scanResponse); err != nil {
		logError(logEnabled, "Error al decodificar la respuesta del escaneo", "error", err)
		return "", err
	}

	scanID := scanResponse.ScanID
	if scanID == "" {
		logError(logEnabled, "No se pudo obtener el scan_id de la respuesta")
		return "", fmt.Errorf("no se pudo obtener el scan_id de la respuesta")
	}

	logInfo(logEnabled, "Escaneo iniciado correctamente", "scan_id", scanID)

	// 2. Verificar estado del escaneo en bucle
	scanStatusURL := fmt.Sprintf("%s/scan-status", apiEndpoint)
	requestBody = map[string]interface{}{
		"scan_id": scanID,
	}

	jsonData, err = json.Marshal(requestBody)
	if err != nil {
		logError(logEnabled, "Error al crear JSON para la petición de estado", "error", err)
		return "", err
	}

	// Establecer tiempo límite de 1 hora
	deadline := time.Now().Add(1 * time.Hour)

	for time.Now().Before(deadline) {
		// Esperar 5 segundos entre peticiones
		time.Sleep(5 * time.Second)

		// Crear nueva petición para verificar estado
		statusReq, err := http.NewRequest("POST", scanStatusURL, bytes.NewBuffer(jsonData))
		if err != nil {
			logError(logEnabled, "Error al crear la petición HTTP para verificar estado", "error", err)
			continue
		}

		statusReq.Header.Set("Content-Type", "application/json")
		statusReq.Header.Set("X-API-Key", fmt.Sprintf("ENC:%s", apiKey))

		statusResp, err := client.Do(statusReq)
		if err != nil {
			logError(logEnabled, "Error al verificar estado del escaneo", "error", err)
			continue
		}

		if statusResp.StatusCode != http.StatusOK {
			statusResp.Body.Close()
			logError(logEnabled, "Error al verificar estado del escaneo", "status", statusResp.Status)
			continue
		}

		// Leer respuesta
		var statusResponse struct {
			Status string       `json:"status"`
			Result statusResult `json:"result"`
		}

		if err := json.NewDecoder(statusResp.Body).Decode(&statusResponse); err != nil {
			statusResp.Body.Close()
			logError(logEnabled, "Error al decodificar la respuesta de estado", "error", err)
			continue
		}

		statusResp.Body.Close()

		// Verificar estado
		logInfo(logEnabled, "Estado del escaneo", "scan_id", scanID, "estado", statusResponse.Status)

		if statusResponse.Status == "COMPLETED" {
			// Calcular tiempo total
			elapsedTime := time.Since(startTime)
			hours := int(elapsedTime.Hours())
			minutes := int(elapsedTime.Minutes()) % 60
			seconds := int(elapsedTime.Seconds()) % 60
			milliseconds := int(elapsedTime.Milliseconds()) % 1000

			// Formatear tiempo transcurrido
			formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)

			logInfo(logEnabled, "Escaneo completado correctamente", "scan_id", scanID, "tiempo_total", formattedTime)
			return scanID, nil
		} else if statusResponse.Status == "ERROR" || statusResponse.Status == "FAILED" {
			// Calcular tiempo total
			elapsedTime := time.Since(startTime)
			hours := int(elapsedTime.Hours())
			minutes := int(elapsedTime.Minutes()) % 60
			seconds := int(elapsedTime.Seconds()) % 60
			milliseconds := int(elapsedTime.Milliseconds()) % 1000

			// Formatear tiempo transcurrido
			formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)

			logError(logEnabled, "Escaneo finalizado con errores", "scan_id", scanID, "estado", statusResponse.Status, "tiempo_total", formattedTime)
			return statusResponse.Result.ReportUrl, fmt.Errorf("escaneo finalizado con estado: %s", statusResponse.Status)
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

	logError(logEnabled, "Tiempo de espera agotado para el escaneo", "scan_id", scanID, "tiempo_total", formattedTime)
	return "", fmt.Errorf("tiempo de espera agotado para el escaneo (1 hora)")
}

// uploadFilesAsGzipAndRun comprime la lista de archivos en un archivo gzip y lo sube usando una URL prefirmada
func uploadFilesAsGzipAndRun(filesArray []string, apiKey string, scanBatchId string, remote string, apiEndpoint string, logEnabled bool) error {
	// Verificar que haya archivos para procesar
	var validFiles []string
	for _, filePath := range filesArray {
		if filePath != "" {
			validFiles = append(validFiles, filePath)
			logInfo(logEnabled, "Archivo a comprimir", "ruta", filePath)
		}
	}

	if len(validFiles) == 0 {
		logError(logEnabled, "No hay archivos válidos para escanear")
		return fmt.Errorf("no hay archivos válidos para escanear")
	}

	// Crear un nombre de archivo específico para el archivo tar.gz
	tempFileName := fmt.Sprintf("tli-%s.tar.gz", scanBatchId)
	tempDir := os.TempDir()
	tempFilePath := filepath.Join(tempDir, tempFileName)

	// Crear el archivo con el nombre específico
	tempFile, err := os.OpenFile(tempFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logError(logEnabled, "Error al crear archivo temporal", "error", err)
		return err
	}

	logDebug(logEnabled, "Archivo temporal creado", "ruta", tempFilePath, "nombre", tempFileName)

	// Asegurar que el archivo temporal se borra al final
	defer func() {
		tempFile.Close()
		err := os.Remove(tempFilePath)
		if err != nil {
			logDebug(logEnabled, "No se pudo eliminar el archivo temporal", "error", err, "ruta", tempFilePath)
		} else {
			logDebug(logEnabled, "Archivo temporal eliminado", "ruta", tempFilePath)
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
			logError(logEnabled, "Error al leer el archivo", "error", err, "ruta del archivo", filePath)
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
			logError(logEnabled, "Error al escribir el encabezado tar", "error", err, "ruta del archivo", filePath)
			continue
		}

		if _, err := tarWriter.Write(fileContent); err != nil {
			logError(logEnabled, "Error al escribir el contenido al tar", "error", err, "ruta del archivo", filePath)
			continue
		}

		logInfo(logEnabled, "Archivo añadido a la compresión", "ruta del archivo", filePath)
	}

	// Cerrar los escritores en el orden correcto
	if err := tarWriter.Close(); err != nil {
		logError(logEnabled, "Error al cerrar el escritor tar", "error", err)
		return err
	}

	if err := gzipWriter.Close(); err != nil {
		logError(logEnabled, "Error al cerrar el escritor gzip", "error", err)
		return err
	}

	// Cerrar el archivo para asegurar que todos los datos se escriben
	tempFile.Close()

	// Obtener estadísticas del archivo para verificar tamaño
	fileInfo, err := os.Stat(tempFilePath)
	if err != nil {
		logError(logEnabled, "Error al obtener información del archivo temporal", "error", err)
		return err
	}

	fileSize := fileInfo.Size()
	logDebug(logEnabled, "Archivo comprimido creado exitosamente", "tamaño (bytes)", fileSize, "ruta", tempFilePath)

	if fileSize == 0 {
		logError(logEnabled, "El archivo comprimido está vacío")
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
		logError(logEnabled, "Error al crear JSON para la petición", "error", err)
		return err
	}

	// Crear la petición HTTP
	endpoint := apiEndpoint + "/cli-files"
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		logError(logEnabled, "Error al crear la petición HTTP", "error", err)
		return err
	}

	// Establecer headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", fmt.Sprintf("ENC:%s", apiKey))

	// Enviar la petición
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logError(logEnabled, "Error al enviar la petición HTTP", "error", err)
		return err
	}
	defer resp.Body.Close()

	// Verificar respuesta
	if resp.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				logError(logEnabled, "Error en la respuesta del servidor", "status", resp.Status, "message", message)
				return fmt.Errorf("error en la respuesta del servidor: %s - %s", resp.Status, message)
			}
		}
		logError(logEnabled, "Error en la respuesta del servidor", "status", resp.Status)
		return fmt.Errorf("error en la respuesta del servidor: %s", resp.Status)
	}

	// Leer el cuerpo completo para depuración y procesamiento
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logError(logEnabled, "Error al leer el cuerpo de la respuesta", "error", err)
		return err
	}

	// Loguear respuesta para depuración
	logDebug(logEnabled, "Respuesta recibida", "status", resp.Status)

	// Analizar la estructura de la respuesta como un mapa genérico primero
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &rawResponse); err != nil {
		logError(logEnabled, "Error al decodificar la respuesta como mapa", "error", err)
		return err
	}

	// Buscar la URL prefirmada para el archivo tar.gz
	var presignedURL string

	// Verificar si hay un campo presigned_url (formato singular)
	if url, ok := rawResponse["presigned_url"].(string); ok && url != "" {
		presignedURL = url
		logDebug(logEnabled, "URL prefirmada encontrada en campo 'presigned_url'")
	} else if urlsMap, ok := rawResponse["presigned_urls"].(map[string]interface{}); ok {
		// Verificar si hay un campo presigned_urls (formato mapa)
		// Buscar la URL para nuestro archivo tar.gz
		if url, ok := urlsMap[tempFileName].(string); ok && url != "" {
			presignedURL = url
			logDebug(logEnabled, "URL prefirmada encontrada para el archivo tar.gz")
		} else {
			// Si no encontramos exactamente para nuestro archivo, tomar la primera disponible
			for fileName, url := range urlsMap {
				if urlStr, ok := url.(string); ok && urlStr != "" {
					presignedURL = urlStr
					logDebug(logEnabled, "URL prefirmada encontrada para otro archivo", "nombre", fileName)
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
					logDebug(logEnabled, "URL prefirmada encontrada en campo alternativo", "campo", key)
					break
				} else if urlMap, ok := value.(map[string]interface{}); ok {
					// Si es un mapa, intentar encontrar una URL dentro de él
					for fileName, mapValue := range urlMap {
						if urlStr, ok := mapValue.(string); ok && urlStr != "" && strings.HasPrefix(urlStr, "http") {
							presignedURL = urlStr
							logDebug(logEnabled, "URL prefirmada encontrada en submapa", "campo", key, "nombre", fileName)
							break
						}
					}
				}
			}
		}
	}

	if presignedURL == "" {
		logError(logEnabled, "No se pudo encontrar una URL prefirmada válida en la respuesta")
		return fmt.Errorf("no se pudo encontrar una URL prefirmada válida en la respuesta")
	}

	logDebug(logEnabled, "URL prefirmada obtenida", "url", presignedURL)

	// Abrir el archivo para lectura
	file, err := os.Open(tempFilePath)
	if err != nil {
		logError(logEnabled, "Error al abrir el archivo temporal para lectura", "error", err)
		return err
	}
	defer file.Close()

	// Subir el archivo comprimido
	logInfo(logEnabled, "Subiendo archivo comprimido...")
	logDebug(logEnabled, "Detalles del archivo comprimido", "nombre", tempFileName, "ruta", tempFilePath, "tamaño", fileSize)

	// Preparar la petición PUT con el archivo
	putReq, err := http.NewRequest("PUT", presignedURL, file)
	if err != nil {
		logError(logEnabled, "Error al crear la petición PUT", "error", err)
		return err
	}

	// Usar el Content-Type correcto para archivos tar.gz
	putReq.Header.Set("Content-Type", "application/x-tar+gzip")
	putReq.ContentLength = fileSize

	// Enviar la petición PUT
	putResp, err := client.Do(putReq)
	if err != nil {
		logError(logEnabled, "Error al enviar la petición PUT", "error", err)
		return err
	}

	// Leer y cerrar la respuesta
	io.Copy(io.Discard, putResp.Body)
	putResp.Body.Close()

	if putResp.StatusCode >= 200 && putResp.StatusCode < 300 {
		logInfo(logEnabled, "Archivo comprimido subido exitosamente")
		logDebug(logEnabled, "Detalles del archivo subido", "ruta", tempFilePath, "nombre", tempFileName)

		// Ejecutar el escaneo y esperar a que se complete
		reportUrl, err := runScanAndWaitForCompletion(scanBatchId, apiKey, apiEndpoint, remote, logEnabled)
		if err != nil {
			// Verificar si el error es por estado FAILED
			if strings.Contains(err.Error(), "escaneo finalizado con estado: FAILED") {
				// Terminar con código de salida 1 para indicar fallo
				fmt.Println("Error: El escaneo finalizó con estado: FAILED:", reportUrl)
				os.Exit(1)
			}
			return err
		}
	} else {
		logError(logEnabled, "Error al subir el archivo comprimido", "status", putResp.Status)
		logDebug(logEnabled, "Detalles del archivo con error", "ruta", tempFilePath, "nombre", tempFileName)
		return fmt.Errorf("error al subir el archivo comprimido: %s", putResp.Status)
	}

	return nil
}

func scan(cmd *cobra.Command, args []string) {
	gitHook, _ := cmd.Flags().GetBool("githook")
	logEnabled := !gitHook
	logInfo(logEnabled, "Iniciando escaneo...")
	path, err := cmd.Flags().GetString("path")
	if err != nil {
		logError(logEnabled, "Error al obtener la ruta", "error", err)
		fmt.Println("Error: Debe proporcionar --path <ruta>")
		os.Exit(1)
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		logError(logEnabled, "Error al obtener el formato de salida", "error", err)
		fmt.Println("Error: Debe proporcionar --output <formato>")
		os.Exit(1)
	}
	if err != nil {
		logError(logEnabled, "Error al obtener el formato de salida", "error", err)
		fmt.Println("Error: Debe proporcionar --output <formato>")
		os.Exit(1)
	}
	commit, err := cmd.Flags().GetString("commit")
	if err != nil {
		logError(logEnabled, "Error al obtener el hash del commit", "error", err)
		fmt.Println("Error: Debe proporcionar --commit <hash>")
		os.Exit(1)
	}
	staged, err := cmd.Flags().GetBool("staged")
	if err != nil {
		logError(logEnabled, "Error al obtener el formato de salida", "error", err)
		fmt.Println("Error: Debe proporcionar --staged")
		os.Exit(1)
	}
	remote, err := cmd.Flags().GetString("remote")
	if err != nil {
		logError(logEnabled, "Error al obtener el remote", "error", err)
		fmt.Println("Error: Debe proporcionar --remote <remote>")
		os.Exit(1)
	}

	// Verificar que se proporcione --commit o --staged
	if commit == "" && !staged {
		logError(logEnabled, "Debe especificar --commit o --staged")
		fmt.Println("Error: Debe proporcionar --commit <hash> o --staged para ejecutar el escaneo")
		os.Exit(1)
	}

	if commit != "" && staged {
		logError(logEnabled, "No se puede especificar un commit y staged al mismo tiempo")
		fmt.Println("Error: No se puede especificar un commit y staged al mismo tiempo")
		os.Exit(1)
	}

	logInfo(logEnabled, "Ruta", "path", path)
	logInfo(logEnabled, "Formato de salida", "output", output)

	if staged {
		logInfo(logEnabled, "Escaneo de archivos estaged", "staged", staged)
		scanBatchId := uuid.NewString()
		files, err := execGitCommand([]string{"diff", "--cached", "--name-only"})
		if err != nil {
			logError(logEnabled, "Error al obtener los archivos", "error", err)
			os.Exit(1)
		}
		logInfo(logEnabled, "Generando lote de archivos:", scanBatchId)
		filesArray := strings.Split(files, "\n")

		// Obtener configuración
		config, err := getConfig(logEnabled)
		if err != nil {
			os.Exit(1)
		}

		// Subir archivos como gzip
		if err := uploadFilesAsGzipAndRun(filesArray, config.APIKey, scanBatchId, remote, config.APIEndpoint, logEnabled); err != nil {
			logError(logEnabled, "Error al subir los archivos", "error", err)
			os.Exit(1)
		}

		logInfo(logEnabled, "Proceso de escaneo completado")
	} else if commit != "" {
		logInfo(logEnabled, "Escaneo de archivos del commit", "commit", commit)

		scanBatchId := uuid.NewString()
		// Usar git show para obtener los archivos modificados en un commit específico
		files, err := execGitCommand([]string{"show", "--name-only", "--pretty=format:", commit})
		if err != nil {
			logError(logEnabled, "Error al obtener los archivos del commit", "error", err)
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
			logError(logEnabled, "No se encontraron archivos en el commit", "commit", commit)
			os.Exit(1)
		}

		logInfo(logEnabled, "Generando lote de archivos:", scanBatchId, "cantidad", len(filteredFiles))

		// Obtener configuración
		config, err := getConfig(logEnabled)
		if err != nil {
			os.Exit(1)
		}

		// Subir archivos como gzip
		if err := uploadFilesAsGzipAndRun(filteredFiles, config.APIKey, scanBatchId, remote, config.APIEndpoint, logEnabled); err != nil {
			logError(logEnabled, "Error al subir los archivos", "error", err)
			os.Exit(1)
		}

		logInfo(logEnabled, "Proceso de escaneo completado")
	}
}
