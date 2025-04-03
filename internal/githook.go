package internal

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

const preCommitHookLinux = `#!/bin/sh
cwd=$(pwd)
tvosec scan --path $cwd --staged
`

const preCommitHookWindows = `@echo off
set cwd=%cd%
tvosec scan --path %cwd% --staged
`

func NewGitHookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "githook",
		Run: gitHook,
	}
	return cmd
}

func gitHook(cmd *cobra.Command, args []string) {
	slog.Info("Creando git hook...")
	hookPath := filepath.Join(".git", "hooks")
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		slog.Error("Directorio de hooks no encontrado")
		return
	}
	hookPath = filepath.Join(hookPath, "pre-commit")
	os.MkdirAll(filepath.Dir(hookPath), 0755)
	if runtime.GOOS == "windows" {
		fileName := strings.Join([]string{hookPath, "bat"}, ".")
		err := os.WriteFile(fileName, []byte(preCommitHookWindows), 0755)
		if err != nil {
			slog.Error("Error al crear el archivo:", err)
			return
		}
		slog.Info("Githook creado:", fileName)
	} else {
		fileName := hookPath
		err := os.WriteFile(fileName, []byte(preCommitHookLinux), 0755) // Execute permission
		if err != nil {
			slog.Error("Error al crear el archivo:", err)
			return
		}

		// Asegurar permisos de ejecución en Linux
		err = os.Chmod(fileName, 0755)
		if err != nil {
			slog.Error("Error al establecer permisos de ejecución:", err)
			return
		}
		slog.Info("Githook creado:", fileName)
	}
}
