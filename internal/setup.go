package internal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func NewSetupCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "setup", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		in, out := cmd.InOrStdin(), cmd.OutOrStdout()
		ctx := cmd.Context()
		fmt.Fprint(out, "Ingrese la URL de su API: ")
		endpoint, e := readInputLine(ctx, in)
		if e != nil {
			return e
		}
		if !safeHTTPS(endpoint) {
			return fmt.Errorf("la URL debe ser HTTPS y no contener credenciales")
		}
		fmt.Fprint(out, "Ingrese su ID de usuario: ")
		user, e := readInputLine(ctx, in)
		if e != nil {
			return e
		}
		if user == "" {
			return fmt.Errorf("el ID de usuario es obligatorio")
		}
		f, ok := in.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return fmt.Errorf("setup requiere terminal para introducir la clave sin mostrarla; en CI usa TLI_API_*")
		}
		fmt.Fprint(out, "Ingrese su API Key: ")
		key, e := readPasswordContext(ctx, f)
		fmt.Fprintln(out)
		if e != nil {
			return e
		}
		if len(key) == 0 {
			return fmt.Errorf("la clave es obligatoria")
		}
		client := &APIClient{Config: Config{APIEndpoint: strings.TrimRight(endpoint, "/"), APIKey: string(key)}}
		var response struct {
			TaskEndpoint    string `json:"task_endpoint"`
			EncryptedAPIKey string `json:"encrypted_api_key"`
		}
		if e = client.post(ctx, "/auth/setup", map[string]any{"source": "cli", "args": map[string]string{"user_id": user}}, &response); e != nil {
			return e
		}
		if !safeHTTPS(response.TaskEndpoint) || response.EncryptedAPIKey == "" {
			return fmt.Errorf("respuesta de configuración incompleta")
		}
		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		path := filepath.Join(home, ".tli", "config.json")
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return e
		}
		if e = NewConfig(user, response.EncryptedAPIKey, response.TaskEndpoint).Save(path); e != nil {
			return e
		}
		fmt.Fprintln(out, "Configuración guardada en ~/.tli/config.json")
		return nil
	}
	return cmd
}
func readPasswordContext(ctx context.Context, file *os.File) (key []byte, err error) {
	state, e := term.MakeRaw(int(file.Fd()))
	if e != nil {
		return nil, fmt.Errorf("no se pudo proteger la entrada de contraseña")
	}
	defer func() {
		if restoreErr := term.Restore(int(file.Fd()), state); restoreErr != nil && err == nil {
			err = fmt.Errorf("no se pudo restaurar el terminal")
		}
	}()
	value, e := readInputValue(ctx, file, true)
	if e != nil {
		return nil, e
	}
	return []byte(value), nil
}
