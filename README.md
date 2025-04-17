# Titvo - CLI de Seguridad para Desarrollo

Titvo es una herramienta de línea de comandos para escanear código fuente en busca de problemas de seguridad. 

## Instalación

### Compilar desde el código fuente

Para compilar Titvo desde el código fuente, necesitarás Go 1.24 o superior:

```bash
# Clonar el repositorio
git clone https://github.com/KaribuLab/tli.git
cd tli

# Compilar la herramienta
go build -o bin/tli ./cmd/tli
```

Puedes usar [Task](https://taskfile.dev) para simplificar este proceso:

```bash
task build
```

## Configuración Inicial

Antes de utilizar Titvo, debes configurarlo con tu cuenta:

```bash
tli setup
```

Este comando te solicitará:
- Tu User ID
- Tu API Key (se introducirá de forma segura)

Esta información se almacenará en `~/.tli/config.json`.

## Comandos Disponibles

### Escanear Cambios Preparados (Staged)

Para escanear los archivos que están en el área de preparación de git:

```bash
tli scan --staged
```

### Escanear un Commit Específico

Para escanear los archivos modificados en un commit específico:

```bash
tli scan --commit <hash-del-commit>
```

### Opciones Adicionales

- `--path, -p`: Ruta base para el escaneo (por defecto: directorio actual)

## Ejemplos de Uso

```bash
# Configuración inicial
tli setup

# Escanear archivos preparados en git
tli scan --staged

# Escanear archivos de un commit específico
tli scan --commit abc123def456
```

## Integración con Git Hooks

Titvo se puede integrar con git hooks para automatizar el escaneo de seguridad:

```bash
tli githook
```

## Códigos de Retorno

- `0`: Operación completada con éxito
- `1`: Error durante el escaneo o escaneo fallido
- Otros códigos: Errores específicos de la operación

## Soporte

Para obtener ayuda o reportar problemas, contacta a Karibú Lab. 