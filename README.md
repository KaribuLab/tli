# TVOSEC - CLI de Seguridad para Desarrollo

TVOSEC es una herramienta de línea de comandos para escanear código fuente en busca de problemas de seguridad. 

## Instalación

### Compilar desde el código fuente

Para compilar TVOSEC desde el código fuente, necesitarás Go 1.24 o superior:

```bash
# Clonar el repositorio
git clone https://github.com/KaribuLab/tvosec.git
cd tvosec

# Compilar la herramienta
go build -o bin/tvosec ./cmd/tvosec
```

Puedes usar [Task](https://taskfile.dev) para simplificar este proceso:

```bash
task build
```

## Configuración Inicial

Antes de utilizar TVOSEC, debes configurarlo con tu cuenta:

```bash
tvosec setup
```

Este comando te solicitará:
- Tu User ID
- Tu API Key (se introducirá de forma segura)

Esta información se almacenará en `~/.tvosec/config.json`.

## Comandos Disponibles

### Escanear Cambios Preparados (Staged)

Para escanear los archivos que están en el área de preparación de git:

```bash
tvosec scan --staged
```

### Escanear un Commit Específico

Para escanear los archivos modificados en un commit específico:

```bash
tvosec scan --commit <hash-del-commit>
```

### Opciones Adicionales

- `--path, -p`: Ruta base para el escaneo (por defecto: directorio actual)
- `--output, -o`: Formato de salida (por defecto: "text")

## Ejemplos de Uso

```bash
# Configuración inicial
tvosec setup

# Escanear archivos preparados en git
tvosec scan --staged

# Escanear archivos de un commit específico
tvosec scan --commit abc123def456

# Escanear archivos con formato de salida específico
tvosec scan --staged --output json
```

## Flujo de Trabajo

1. TVOSEC comprime los archivos seleccionados
2. Los envía a los servidores de análisis
3. Inicia un escaneo y consulta periódicamente su estado
4. Informa cuando el escaneo ha finalizado

## Integración con Git Hooks

TVOSEC se puede integrar con git hooks para automatizar el escaneo de seguridad:

```bash
tvosec githook
```

## Códigos de Retorno

- `0`: Operación completada con éxito
- `1`: Error durante el escaneo o escaneo fallido
- Otros códigos: Errores específicos de la operación

## Soporte

Para obtener ayuda o reportar problemas, contacta a Karibú Lab. 