package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

type Annotation struct {
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Path           string `json:"path"`
	Line           int    `json:"line"`
	Summary        string `json:"summary"`
	Code           string `json:"code"`
	Recommendation string `json:"recommendation"`
}
type ScanResult struct {
	Status         string          `json:"status"`
	NumberOfIssues int             `json:"number_of_issues"`
	Annotations    []Annotation    `json:"annotations"`
	Coverage       *ScanCoverage   `json:"coverage,omitempty"`
	Incomplete     *ScanIncomplete `json:"incomplete,omitempty"`
}

type ScanCoverage struct {
	Complete bool     `json:"complete"`
	Errors   []string `json:"errors"`
}

type ScanIncomplete struct {
	Message               string   `json:"message"`
	FilesNotFullyAnalyzed []string `json:"files_not_fully_analyzed"`
}

type StatusResult struct {
	ScanID    string     `json:"scan_id"`
	ReportUrl string     `json:"report_url"`
	Result    ScanResult `json:"result"`
}

// UnmarshalJSON acepta tanto el resultado plano actual como el formato anidado anterior.
func (r *StatusResult) UnmarshalJSON(data []byte) error {
	type statusResult StatusResult
	var wire struct {
		ScanID      string          `json:"scan_id"`
		ReportURL   string          `json:"report_url"`
		Result      json.RawMessage `json:"result"`
		IssuesCount *int            `json:"issues_count"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	var decoded statusResult
	if len(wire.Result) > 0 && string(wire.Result) != "null" {
		if err := json.Unmarshal(data, &decoded); err != nil {
			return err
		}
	} else {
		decoded.ScanID, decoded.ReportUrl = wire.ScanID, wire.ReportURL
		if err := json.Unmarshal(data, &decoded.Result); err != nil {
			return err
		}
		if wire.IssuesCount != nil {
			decoded.Result.NumberOfIssues = *wire.IssuesCount
		}
	}
	*r = StatusResult(decoded)
	return nil
}

func execGitCommand(args []string) (string, error) {
	if slog.Std().Level.ShouldHandling(slog.DebugLevel) {
		debugArgs := strings.Join(args, " ")
		slog.Debug("running git command",
			"command", "git "+debugArgs,
		)
	}
	cmd := exec.Command("git", args...)
	output, err := cmd.Output()
	if err != nil {
		slog.Error("Error al ejecutar el comando git", "error", err)
		return "", err
	}
	return string(output), nil
}

// remoteBranchSHA returns the commit the branch points to on the remote, or an
// empty string when the branch does not exist there.
func remoteBranchSHA(remote string, branch string) (string, error) {
	output, err := execGitCommand([]string{"ls-remote", "--heads", remote, "refs/heads/" + branch})
	if err != nil {
		return "", fmt.Errorf("ls-remote error: %w", err)
	}
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}

// currentRemoteBranch makes sure the current branch is published on the remote
// at the local HEAD commit, so the server scans exactly what the user has.
// It only pushes when the remote branch is missing or behind; in CI (Bitbucket,
// GitHub Actions) the branch is already there, so no push is attempted.
func currentRemoteBranch(remote string) (string, error) {
	currentBranch, err := execGitCommand([]string{"branch", "--show-current"})
	currentBranch = strings.TrimSpace(currentBranch)
	if err != nil {
		return "", fmt.Errorf("show current branch error: %w", err)
	}
	if currentBranch == "" {
		return "", fmt.Errorf("no hay una rama activa (HEAD detached); haz checkout de una rama antes de escanear")
	}

	localSHA, err := execGitCommand([]string{"rev-parse", "HEAD"})
	if err != nil {
		return "", fmt.Errorf("rev-parse HEAD error: %w", err)
	}
	localSHA = strings.TrimSpace(localSHA)

	remoteSHA, err := remoteBranchSHA(remote, currentBranch)
	if err != nil {
		return "", err
	}
	if remoteSHA == localSHA {
		slog.Debug("rama ya publicada en el remoto, se omite push",
			"remote", remote,
			"currentBranch", currentBranch,
			"sha", localSHA,
		)
		return currentBranch, nil
	}

	slog.Debug("realizando push al remoto",
		"remote", remote,
		"currentBranch", currentBranch,
		"localSHA", localSHA,
		"remoteSHA", remoteSHA,
	)
	output, err := execGitCommand([]string{"push", remote, currentBranch})
	if err != nil {
		slog.Error("error en push",
			"output", output,
		)
		return "", fmt.Errorf("push current branch error: %w", err)
	}
	return currentBranch, nil
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
	cmd.Flags().BoolP("full", "f", true, "Full scan")
	return cmd
}

func RunScanAndWaitForCompletion(batchId string, repositoryURL string, branch string) (StatusResult, error) {
	// Registrar tiempo de inicio
	startTime := time.Now()

	// 1. Ejecutar el escaneo
	runScanOutput, err := RunScan(&RunScanInput{
		BatchId:       batchId,
		RepositoryURL: repositoryURL,
		Branch:        branch,
	})
	if err != nil {
		return StatusResult{}, err
	}

	scanID := runScanOutput.ScanID
	if scanID == "" {
		slog.Error("No se pudo obtener el scan_id de la respuesta")
		return StatusResult{}, fmt.Errorf("no se pudo obtener el scan_id de la respuesta")
	}

	slog.Info("Escaneo iniciado correctamente", "scan_id", scanID)

	// 2. Verificar estado del escaneo en bucle
	// FIXME: El deadline debería depender del tamaño del lote de archivos
	// Establecer tiempo límite de 1 hora
	deadline := time.Now().Add(1 * time.Hour)

	for time.Now().Before(deadline) {
		// Esperar 5 segundos entre peticiones
		time.Sleep(5 * time.Second)

		scanStatusOutput, err := GetScanStatus(&GetScanStatusInput{
			ScanID: scanID,
		})
		if err != nil {
			return StatusResult{}, err
		}
		// Calcular tiempo total
		elapsedTime := time.Since(startTime)
		hours := int(elapsedTime.Hours())
		minutes := int(elapsedTime.Minutes()) % 60
		seconds := int(elapsedTime.Seconds()) % 60
		milliseconds := int(elapsedTime.Milliseconds()) % 1000
		// Formatear tiempo transcurrido
		formattedTime := fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)
		// Crear nueva petición para verificar estado
		switch scanStatusOutput.Status {
		case "COMPLETED":
			slog.Info("Escaneo completado correctamente", "scan_id", scanID, "tiempo_total", formattedTime)

			// Construir el StatusResult correcto desde la respuesta anidada
			result := StatusResult{
				ScanID:    scanID,
				ReportUrl: scanStatusOutput.Result.ReportUrl,
				Result:    scanStatusOutput.Result.Result,
			}
			return result, nil
		case "FAILED", "WARNING":

			slog.Error("Escaneo finalizado con errores", "scan_id", scanID, "estado", scanStatusOutput.Status, "tiempo_total", formattedTime)

			// Construir el StatusResult correcto desde la respuesta anidada
			result := StatusResult{
				ScanID:    scanID,
				ReportUrl: scanStatusOutput.Result.ReportUrl,
				Result:    scanStatusOutput.Result.Result,
			}
			return result, fmt.Errorf("escaneo finalizado con estado: %s", scanStatusOutput.Status)
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
	return StatusResult{}, fmt.Errorf("tiempo de espera agotado para el escaneo (1 hora)")
}

// getRepoRoot obtiene el directorio raíz del repositorio Git
func getRepoRoot() (string, error) {
	repoRoot, err := execGitCommand([]string{"rev-parse", "--show-toplevel"})
	if err != nil {
		slog.Error("Error al obtener el directorio raíz del repositorio", "error", err)
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
// binarySniffSize is how many leading bytes are inspected to decide whether a
// file is binary, the same window git uses.
const binarySniffSize = 8000

// isBinaryFile reports whether the file looks binary: a NUL byte or invalid
// UTF-8 within the first binarySniffSize bytes. The read offset is restored
// to the beginning of the file afterwards.
func isBinaryFile(file *os.File) (bool, error) {
	buf := make([]byte, binarySniffSize)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	return isBinaryContent(buf[:n], n == binarySniffSize), nil
}

// isBinaryContent applies the heuristic to a chunk. When truncated is true the
// chunk may end mid-rune, so an incomplete trailing sequence is tolerated.
func isBinaryContent(chunk []byte, truncated bool) bool {
	if bytes.IndexByte(chunk, 0) != -1 {
		return true
	}
	if truncated {
		// Drop a possibly incomplete multi-byte rune at the end (max 3 bytes).
		for i := 0; i < 3 && len(chunk) > 0; i++ {
			if utf8.Valid(chunk) {
				break
			}
			chunk = chunk[:len(chunk)-1]
		}
	}
	return !utf8.Valid(chunk)
}

func openFileSecurely(filePath string, repoRoot string) (*secureFileInfo, error) {
	// Limpiar y normalizar la ruta
	cleanPath := filepath.Clean(filePath)

	// Obtener información del archivo usando Lstat (no sigue symlinks)
	fileInfo, err := os.Lstat(cleanPath)
	if err != nil {
		slog.Error("Error al obtener información del archivo", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Verificar que sea un archivo regular (no symlink, directorio, etc.)
	if !fileInfo.Mode().IsRegular() {
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			slog.Error("Archivo omitido: es un symlink", "ruta", cleanPath)
		} else {
			slog.Error("Archivo omitido: no es un archivo regular", "ruta", cleanPath, "mode", fileInfo.Mode())
		}
		return nil, nil // nil sin error indica archivo omitido
	}

	// Resolver la ruta absoluta del archivo
	absFilePath, err := filepath.Abs(cleanPath)
	if err != nil {
		slog.Error("Error al resolver ruta absoluta", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Resolver la ruta absoluta del repositorio
	absRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		slog.Error("Error al resolver ruta absoluta del repositorio", "ruta", repoRoot, "error", err)
		return nil, err
	}

	// Verificar que el archivo esté dentro del directorio del repositorio
	relPath, err := filepath.Rel(absRepoRoot, absFilePath)
	if err != nil || strings.HasPrefix(relPath, "..") {
		slog.Error("Archivo omitido: está fuera del directorio del repositorio", "ruta", cleanPath, "repo_root", absRepoRoot)
		return nil, nil // nil sin error indica archivo omitido
	}

	// Abrir el archivo de forma segura
	file, err := os.Open(cleanPath)
	if err != nil {
		slog.Error("Error al abrir el archivo", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Verificar nuevamente con Stat para evitar TOCTOU
	statInfo, err := file.Stat()
	if err != nil {
		file.Close()
		slog.Error("Error al obtener información del archivo abierto", "ruta", cleanPath, "error", err)
		return nil, err
	}

	// Verificar que el archivo sigue siendo regular después de abrirlo
	if !statInfo.Mode().IsRegular() {
		file.Close()
		slog.Error("Archivo cambió a no-regular después de abrirlo", "ruta", cleanPath, "mode", statInfo.Mode())
		return nil, nil // nil sin error indica archivo omitido
	}

	// Verificación adicional TOCTOU: comparar información del archivo antes y después
	if fileInfo.Size() != statInfo.Size() || fileInfo.ModTime() != statInfo.ModTime() {
		file.Close()
		slog.Error("Archivo modificado durante la validación (posible ataque TOCTOU)",
			"ruta", cleanPath,
			"size_original", fileInfo.Size(),
			"size_actual", statInfo.Size(),
			"modtime_original", fileInfo.ModTime(),
			"modtime_actual", statInfo.ModTime())
		return nil, nil // nil sin error indica archivo omitido por seguridad
	}

	// Omitir archivos binarios (imágenes, ejecutables, etc.): el analizador
	// solo procesa texto y falla al decodificarlos como UTF-8.
	binary, err := isBinaryFile(file)
	if err != nil {
		file.Close()
		slog.Error("Error al inspeccionar el contenido del archivo", "ruta", cleanPath, "error", err)
		return nil, err
	}
	if binary {
		file.Close()
		slog.Info("Archivo omitido: contenido binario", "ruta", cleanPath)
		return nil, nil // nil sin error indica archivo omitido
	}

	// Usar la ruta relativa normalizada como nombre en el tar
	safeTarName := filepath.ToSlash(relPath)

	slog.Debug("Archivo abierto de forma segura", "ruta_original", filePath, "ruta_limpia", cleanPath, "nombre_tar", safeTarName, "tamaño", statInfo.Size())

	return &secureFileInfo{
		file:         file,
		tarName:      safeTarName,
		size:         statInfo.Size(),
		originalPath: filePath,
	}, nil
}

// uploadFilesAsGzipAndRun comprime la lista de archivos en un archivo gzip y lo sube usando una URL prefirmada
func uploadFilesAsGzipAndRun(filesArray []string, scanBatchId string, repositoryUrl string, logEnabled bool, output string, branch string) error {
	// Obtener el directorio raíz del repositorio
	repoRoot, err := getRepoRoot()
	if err != nil {
		return err
	}

	// Verificar que haya archivos para procesar y abrirlos de forma segura
	var secureFiles []ScanFileInput

	defer func() {
		for _, file := range secureFiles {
			file.File.Close()
		}
	}()

	for _, filePath := range filesArray {
		if filePath == "" {
			continue
		}

		secureFile, err := openFileSecurely(filePath, repoRoot)
		if err != nil {
			// Log del error pero continuar con otros archivos
			slog.Error("Error al abrir archivo de forma segura", "ruta", filePath, "error", err)
			continue
		}

		if secureFile != nil {
			secureFiles = append(secureFiles, ScanFileInput{
				File:         secureFile.file,
				Path:         secureFile.tarName,
				OriginalPath: secureFile.originalPath,
				Size:         secureFile.size,
			})
			slog.Info("Archivo abierto de forma segura para comprimir", "ruta", filePath, "nombre_tar", secureFile.tarName)
		}
	}

	if len(secureFiles) == 0 {
		slog.Error("No hay archivos válidos y seguros para escanear")
		return fmt.Errorf("no hay archivos válidos y seguros para escanear")
	}
	err = UploadFilesAsGzip(&UploadFilesAsGzipInput{
		BatchId: scanBatchId,
		Files:   secureFiles,
	})
	if err == nil {
		slog.Info("Archivo comprimido subido exitosamente")

		// Ejecutar el escaneo y esperar a que se complete
		result, err := RunScanAndWaitForCompletion(scanBatchId, repositoryUrl, branch)
		{
			// Mostrar resultados terminales, incluso cuando el análisis fue incompleto.
			if err == nil || result.Result.Status == "FAILED" || result.Result.Status == "WARNING" {
				if logEnabled {
					switch output {
					case "markdown":
						fmt.Println("# El escaneo finalizó con estado:", result.Result.Status)
						fmt.Println("Reporte:", result.ReportUrl)
						fmt.Println("Número de issues:", result.Result.NumberOfIssues)
						fmt.Println("Estado:", result.Result.Status)
						if result.Result.Incomplete != nil {
							fmt.Println("\n## Análisis incompleto")
							fmt.Println(result.Result.Incomplete.Message)
						}
						if result.Result.Coverage != nil {
							fmt.Println("Cobertura completa:", result.Result.Coverage.Complete)
							for _, cause := range result.Result.Coverage.Errors {
								fmt.Println("-", cause)
							}
						}
						if result.Result.NumberOfIssues > 0 && len(result.Result.Annotations) == 0 {
							fmt.Println("\nEl detalle de los hallazgos está disponible en el enlace del reporte; la respuesta no incluye anotaciones.")
						}
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
							slog.Error("Error al convertir el resultado a JSON", "error", err)
							return err
						}
						fmt.Println(string(jsonData))
					}
				} else {
					fmt.Println(result.ReportUrl)
				}
				// Retornar un error especial que indique que se debe salir con código 1
				if err != nil {
					return fmt.Errorf("SCAN_FAILED: %w", err)
				}
				return nil
			}
			return err
		}
	} else {
		return err
	}

	return nil
}

func scan(cmd *cobra.Command, args []string) {
	gitHook, _ := cmd.Flags().GetBool("githook")
	logEnabled := !gitHook
	if !logEnabled {
		slog.SetLevelByName("panic")
	}
	slog.Info("Iniciando escaneo...")
	path, err := cmd.Flags().GetString("path")
	if err != nil {
		slog.Error("Error al obtener la ruta", "error", err)
		fmt.Println("Error: Debe proporcionar --path <ruta>")
		os.Exit(1)
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		slog.Error("Error al obtener el formato de salida", "error", err)
		fmt.Println("Error: Debe proporcionar --output <formato>")
		os.Exit(1)
	}
	full, err := cmd.Flags().GetBool("full")
	if err != nil {
		slog.Error("Error al obtener opción full scan", "error", err)
		fmt.Println("Error: Debe proporcionar --full")
		os.Exit(1)
	}
	commit, err := cmd.Flags().GetString("commit")
	if err != nil {
		slog.Error("Error al obtener el hash del commit", "error", err)
		fmt.Println("Error: Debe proporcionar --commit <hash>")
		os.Exit(1)
	}
	staged, err := cmd.Flags().GetBool("staged")
	if err != nil {
		slog.Error("Error al obtener el formato de salida", "error", err)
		fmt.Println("Error: Debe proporcionar --staged")
		os.Exit(1)
	}
	remote, err := cmd.Flags().GetString("remote")
	if err != nil {
		slog.Error("Error al obtener el remote", "error", err)
		fmt.Println("Error: Debe proporcionar --remote <remote>")
		os.Exit(1)
	}

	// Verificar que se proporcione --commit o --staged
	if commit == "" && !staged && !full {
		slog.Error("Debe especificar --commit, --staged o --full")
		fmt.Println("Error: Debe proporcionar --commit <hash> , --staged o --full para ejecutar el escaneo")
		os.Exit(1)
	}

	if commit != "" && staged && full {
		slog.Error("No se puede especificar un commit y staged o full al mismo tiempo")
		fmt.Println("Error: No se puede especificar un commit y staged o full al mismo tiempo")
		os.Exit(1)
	}

	slog.Info("Ruta", "path", path)
	slog.Info("Formato de salida", "output", output)

	repositoryUrl, err := execGitCommand([]string{"remote", "get-url", remote})
	if err != nil {
		slog.Error("Error al obtener el URL del remote", "error", err)
		os.Exit(1)
	}

	branch, err := currentRemoteBranch(remote)
	if err != nil {
		slog.Error("Error al obtener rama remota", "error", err)
		os.Exit(1)
	}

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

		// Subir archivos como gzip
		if err := uploadFilesAsGzipAndRun(filesArray, scanBatchId, sanitizeRepositoryURL(repositoryUrl), logEnabled, output, branch); err != nil {
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
		// Subir archivos como gzip
		if err := uploadFilesAsGzipAndRun(filteredFiles, scanBatchId, sanitizeRepositoryURL(repositoryUrl), logEnabled, output, branch); err != nil {
			slog.Error("Error al subir los archivos", "error", err)
			os.Exit(1)
		}

		slog.Info("Proceso de escaneo completado")
	} else if full {
		slog.Info("Escaneo de archivos de todo el repositorio")

		scanBatchId := uuid.NewString()
		files, err := execGitCommand([]string{"ls-files"})
		if err != nil {
			slog.Error("Error al obtener los archivos del repositorio", "error", err)
			os.Exit(1)
		}
		slog.Info("Generando lote de archivos:", scanBatchId)
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
		// Subir archivos como gzip
		if err := uploadFilesAsGzipAndRun(filteredFiles, scanBatchId, sanitizeRepositoryURL(repositoryUrl), logEnabled, output, branch); err != nil {
			slog.Error("Error al subir los archivos", "error", err)
			os.Exit(1)
		}

		slog.Info("Proceso de escaneo completado")
	}
}
