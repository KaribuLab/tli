package internal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

type annotation struct {
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Path           string `json:"path"`
	Line           int    `json:"line"`
	Summary        string `json:"summary"`
	Code           string `json:"code"`
	Recommendation string `json:"recommendation"`
}
type scanResult struct {
	Status         string       `json:"status"`
	NumberOfIssues int          `json:"number_of_issues"`
	Annotations    []annotation `json:"annotations"`
}

type statusResult struct {
	ScanID    string     `json:"scan_id"`
	ReportUrl string     `json:"report_url"`
	Result    scanResult `json:"result"`
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
	cmd.Flags().StringP("output", "o", "markdown", "Output format")
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
func runScanAndWaitForCompletion(batchId string, apiKey string, apiEndpoint string, remote string, logEnabled bool) (statusResult, error) {
	// Registrar tiempo de inicio
	startTime := time.Now()

	// 1. Ejecutar el escaneo
	runScanURL := fmt.Sprintf("%s/run-scan", apiEndpoint)
	repositoryUrl, err := execGitCommand([]string{"remote", "get-url", remote})
	if err != nil {
		logError(logEnabled, "Error al obtener el URL del remote", "error", err)
		return statusResult{}, err
	}

	// Sanitizar la URL del repositorio para eliminar credenciales
	sanitizedURL := sanitizeRepositoryURL(repositoryUrl, logEnabled)

	requestBody := map[string]interface{}{
		"source": "cli",
		"args": map[string]interface{}{
			"repository_url": sanitizedURL,
			"batch_id":       batchId,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		logError(logEnabled, "Error al crear JSON para la petición de escaneo", "error", err)
		return statusResult{}, err
	}

	req, err := http.NewRequest("POST", runScanURL, bytes.NewBuffer(jsonData))
	if err != nil {
		logError(logEnabled, "Error al crear la petición HTTP para ejecutar el escaneo", "error", err)
		return statusResult{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", fmt.Sprintf("ENC:%s", apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logError(logEnabled, "Error al ejecutar el escaneo", "error", err)
		return statusResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				logError(logEnabled, "Error al ejecutar el escaneo", "status", resp.Status, "mensaje", message)
				return statusResult{}, fmt.Errorf("error al ejecutar el escaneo: %s - %s", resp.Status, message)
			}
		}
		logError(logEnabled, "Error al ejecutar el escaneo", "status", resp.Status)
		return statusResult{}, fmt.Errorf("error al ejecutar el escaneo: %s", resp.Status)
	}

	// Extraer scan_id de la respuesta
	var scanResponse struct {
		ScanID string `json:"scan_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&scanResponse); err != nil {
		logError(logEnabled, "Error al decodificar la respuesta del escaneo", "error", err)
		return statusResult{}, err
	}

	scanID := scanResponse.ScanID
	if scanID == "" {
		logError(logEnabled, "No se pudo obtener el scan_id de la respuesta")
		return statusResult{}, fmt.Errorf("no se pudo obtener el scan_id de la respuesta")
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
		return statusResult{}, err
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

		body, err := io.ReadAll(statusResp.Body)
		if err != nil {
			statusResp.Body.Close()
			logError(logEnabled, "Error al leer el cuerpo de la respuesta", "error", err)
			continue
		}

		// Cerrar el cuerpo explícitamente después de leer
		statusResp.Body.Close()

		logDebug(logEnabled, "Respuesta de estado del escaneo", "body", string(body), "status", statusResp.Status)

		if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&statusResponse); err != nil {
			logError(logEnabled, "Error al decodificar la respuesta de estado", "error", err)
			continue
		}

		// Verificar estado
		logInfo(logEnabled, "Estado del escaneo", "scan_id", scanID, "estado", statusResponse.Status)

		switch statusResponse.Status {
		case "COMPLETED":
			// Calcular tiempo total
			elapsedTime := time.Since(startTime)
			hours := int(elapsedTime.Hours())
			minutes := int(elapsedTime.Minutes()) % 60
			seconds := int(elapsedTime.Seconds()) % 60
			milliseconds := int(elapsedTime.Milliseconds()) % 1000

			// Formatear tiempo transcurrido
			formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)

			logInfo(logEnabled, "Escaneo completado correctamente", "scan_id", scanID, "tiempo_total", formattedTime)
			return statusResponse.Result, nil
		case "ERROR", "FAILED":
			// Calcular tiempo total
			elapsedTime := time.Since(startTime)
			hours := int(elapsedTime.Hours())
			minutes := int(elapsedTime.Minutes()) % 60
			seconds := int(elapsedTime.Seconds()) % 60
			milliseconds := int(elapsedTime.Milliseconds()) % 1000

			// Formatear tiempo transcurrido
			formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)

			logError(logEnabled, "Escaneo finalizado con errores", "scan_id", scanID, "estado", statusResponse.Status, "tiempo_total", formattedTime)
			return statusResponse.Result, fmt.Errorf("escaneo finalizado con estado: %s", statusResponse.Status)
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
	return statusResult{}, fmt.Errorf("tiempo de espera agotado para el escaneo (1 hora)")
}

// sanitizeRepositoryURL elimina credenciales de la URL del repositorio para evitar filtración
func sanitizeRepositoryURL(repositoryURL string, logEnabled bool) string {
	// Limpiar espacios en blanco y saltos de línea
	cleanURL := strings.TrimSpace(strings.ReplaceAll(repositoryURL, "\n", ""))

	// Intentar parsear como URL
	parsedURL, err := url.Parse(cleanURL)
	if err != nil {
		logDebug(logEnabled, "No se pudo parsear como URL, devolviendo como string limpio", "url", cleanURL, "error", err)
		return cleanURL
	}

	// Si contiene información de usuario (credenciales), eliminarla
	if parsedURL.User != nil {
		logDebug(logEnabled, "Eliminando credenciales de la URL del repositorio", "url_original", cleanURL)
		parsedURL.User = nil
		sanitizedURL := parsedURL.String()
		logDebug(logEnabled, "URL sanitizada", "url_sanitizada", sanitizedURL)
		return sanitizedURL
	}

	// Si no contiene credenciales, devolver la URL limpia original
	logDebug(logEnabled, "URL sin credenciales, devolviendo limpia", "url", cleanURL)
	return cleanURL
}

// getRepoRoot obtiene el directorio raíz del repositorio Git
func getRepoRoot(logEnabled bool) (string, error) {
	repoRoot, err := execGitCommand([]string{"rev-parse", "--show-toplevel"})
	if err != nil {
		logError(logEnabled, "Error al obtener el directorio raíz del repositorio", "error", err)
		return "", err
	}
	return strings.TrimSpace(repoRoot), nil
}

// secureFileInfo contiene información de un archivo seguro con descriptor abierto
type secureFileInfo struct {
	file         *os.File
	tarName      string
	size         int64
	originalPath string
}

// openFileSecurely valida y abre un archivo de forma segura para incluir en el tar
func openFileSecurely(filePath string, repoRoot string, logEnabled bool) (*secureFileInfo, error) {
	// Limpiar y normalizar la ruta
	cleanPath := filepath.Clean(filePath)

	// Obtener información del archivo usando Lstat (no sigue symlinks)
	fileInfo, err := os.Lstat(cleanPath)
	if err != nil {
		logError(logEnabled, "Error al obtener información del archivo", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Verificar que sea un archivo regular (no symlink, directorio, etc.)
	if !fileInfo.Mode().IsRegular() {
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			logError(logEnabled, "Archivo omitido: es un symlink", "ruta", cleanPath)
		} else {
			logError(logEnabled, "Archivo omitido: no es un archivo regular", "ruta", cleanPath, "mode", fileInfo.Mode())
		}
		return nil, nil // nil sin error indica archivo omitido
	}

	// Resolver la ruta absoluta del archivo
	absFilePath, err := filepath.Abs(cleanPath)
	if err != nil {
		logError(logEnabled, "Error al resolver ruta absoluta", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Resolver la ruta absoluta del repositorio
	absRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		logError(logEnabled, "Error al resolver ruta absoluta del repositorio", "ruta", repoRoot, "error", err)
		return nil, err
	}

	// Verificar que el archivo esté dentro del directorio del repositorio
	relPath, err := filepath.Rel(absRepoRoot, absFilePath)
	if err != nil || strings.HasPrefix(relPath, "..") {
		logError(logEnabled, "Archivo omitido: está fuera del directorio del repositorio", "ruta", cleanPath, "repo_root", absRepoRoot)
		return nil, nil // nil sin error indica archivo omitido
	}

	// Abrir el archivo de forma segura
	file, err := os.Open(cleanPath)
	if err != nil {
		logError(logEnabled, "Error al abrir el archivo", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Verificar nuevamente con Stat para evitar TOCTOU
	statInfo, err := file.Stat()
	if err != nil {
		file.Close()
		logError(logEnabled, "Error al obtener información del archivo abierto", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Verificar que el archivo sigue siendo regular después de abrirlo
	if !statInfo.Mode().IsRegular() {
		file.Close()
		logError(logEnabled, "Archivo cambió a no-regular después de abrirlo", "ruta", cleanPath, "mode", statInfo.Mode())
		return nil, nil // nil sin error indica archivo omitido
	}

	// Usar la ruta relativa normalizada como nombre en el tar
	safeTarName := filepath.ToSlash(relPath)

	logDebug(logEnabled, "Archivo abierto de forma segura", "ruta_original", filePath, "ruta_limpia", cleanPath, "nombre_tar", safeTarName, "tamaño", statInfo.Size())

	return &secureFileInfo{
		file:         file,
		tarName:      safeTarName,
		size:         statInfo.Size(),
		originalPath: filePath,
	}, nil
}

// uploadFilesAsGzipAndRun comprime la lista de archivos en un archivo gzip y lo sube usando una URL prefirmada
func uploadFilesAsGzipAndRun(filesArray []string, apiKey string, scanBatchId string, remote string, apiEndpoint string, logEnabled bool, output string) error {
	// Obtener el directorio raíz del repositorio
	repoRoot, err := getRepoRoot(logEnabled)
	if err != nil {
		return err
	}

	// Verificar que haya archivos para procesar y abrirlos de forma segura
	var secureFiles []*secureFileInfo

	for _, filePath := range filesArray {
		if filePath == "" {
			continue
		}

		secureFile, err := openFileSecurely(filePath, repoRoot, logEnabled)
		if err != nil {
			// Log del error pero continuar con otros archivos
			logError(logEnabled, "Error al abrir archivo de forma segura", "ruta", filePath, "error", err)
			continue
		}

		if secureFile != nil {
			secureFiles = append(secureFiles, secureFile)
			logInfo(logEnabled, "Archivo abierto de forma segura para comprimir", "ruta", filePath, "nombre_tar", secureFile.tarName)
		}
	}

	if len(secureFiles) == 0 {
		logError(logEnabled, "No hay archivos válidos y seguros para escanear")
		return fmt.Errorf("no hay archivos válidos y seguros para escanear")
	}

	// Asegurar que todos los archivos se cierren al final
	defer func() {
		for _, secureFile := range secureFiles {
			if secureFile.file != nil {
				secureFile.file.Close()
			}
		}
	}()

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

	// Añadir cada archivo al archivo tar usando descriptores seguros
	for _, secureFile := range secureFiles {
		// Crear el encabezado tar para el archivo usando el nombre seguro
		header := &tar.Header{
			Name: secureFile.tarName,
			Mode: 0600,
			Size: secureFile.size,
		}

		// Escribir el encabezado en el archivo tar
		if err := tarWriter.WriteHeader(header); err != nil {
			logError(logEnabled, "Error al escribir el encabezado tar", "error", err, "ruta del archivo", secureFile.originalPath, "nombre_tar", secureFile.tarName)
			continue
		}

		// Copiar el contenido del archivo directamente desde el descriptor
		// Esto evita TOCTOU ya que usamos el mismo descriptor de archivo
		if _, err := io.Copy(tarWriter, secureFile.file); err != nil {
			logError(logEnabled, "Error al escribir el contenido al tar", "error", err, "ruta del archivo", secureFile.originalPath, "nombre_tar", secureFile.tarName)
			continue
		}

		logInfo(logEnabled, "Archivo añadido a la compresión", "ruta del archivo", secureFile.originalPath, "nombre_tar", secureFile.tarName)
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
			"original_files": func() []string {
				var originalPaths []string
				for _, secureFile := range secureFiles {
					originalPaths = append(originalPaths, secureFile.originalPath)
				}
				return originalPaths
			}(),
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
		result, err := runScanAndWaitForCompletion(scanBatchId, apiKey, apiEndpoint, remote, logEnabled)
		if err != nil {
			// Verificar si el error es por estado FAILED
			if strings.Contains(err.Error(), "escaneo finalizado con estado: FAILED") {
				// Mostrar información del fallo pero no salir aquí (permite cleanup)
				if logEnabled {
					switch output {
					case "markdown":
						fmt.Println("# El escaneo finalizó con estado: FAILED")
						fmt.Println("Reporte:", result.ReportUrl)
						fmt.Println("Número de issues:", result.Result.NumberOfIssues)
						fmt.Println("Estado:", result.Result.Status)
						for index, annotation := range result.Result.Annotations {
							fmt.Println("## ", fmt.Sprintf("%02d", index+1), " - ", annotation.Title)
							fmt.Println("- **Descripción:**", annotation.Description)
							fmt.Println("- **Severidad:", annotation.Severity, "**")
							fmt.Println("- **Ruta:** `", annotation.Path, "`")
							fmt.Println("- **Línea:** `", annotation.Line, "`")
							fmt.Println("## Resumen")
							fmt.Println(annotation.Summary)
							fmt.Println("## Recomendación")
							fmt.Println(annotation.Recommendation)
							fmt.Println("```")
							fmt.Println(annotation.Code)
							fmt.Println("```")
						}
						fmt.Println("---")
					case "json":
						jsonData, err := json.MarshalIndent(result, "", "  ")
						if err != nil {
							logError(logEnabled, "Error al convertir el resultado a JSON", "error", err)
							return err
						}
						fmt.Println(string(jsonData))
					}
				} else {
					fmt.Println(result.ReportUrl)
				}
				// Retornar un error especial que indique que se debe salir con código 1
				return fmt.Errorf("SCAN_FAILED: %w", err)
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
		if err := uploadFilesAsGzipAndRun(filesArray, config.APIKey, scanBatchId, remote, config.APIEndpoint, logEnabled, output); err != nil {
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
		if err := uploadFilesAsGzipAndRun(filteredFiles, config.APIKey, scanBatchId, remote, config.APIEndpoint, logEnabled, output); err != nil {
			logError(logEnabled, "Error al subir los archivos", "error", err)
			os.Exit(1)
		}

		logInfo(logEnabled, "Proceso de escaneo completado")
	}
}
