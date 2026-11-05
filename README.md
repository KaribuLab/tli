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

### Imagen Docker

Cada release publica una imagen multi-arquitectura (amd64/arm64) en Docker Hub:

```bash
docker pull karibu/tli:latest   # o karibu/tli:X.Y.Z
docker run --rm karibu/tli:latest tli --version
```

Para construirla localmente:

```bash
docker build --build-arg VERSION=dev -t tli:local .
```

## Configuración Inicial

Antes de utilizar Titvo, debes configurarlo con tu cuenta:

```bash
tli setup
```

Este comando te solicitará:
- La URL de la API (debe comenzar con https://)
- Tu ID de usuario
- Tu API Key (se introducirá de forma segura)

La herramienta verificará tus credenciales con el servidor y almacenará la configuración en `~/.tli/config.json`.

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

## Uso en CI (Bitbucket Pipelines)

La imagen incluye `bash`, `git` y certificados CA, por lo que puede usarse directamente como imagen base de un step.
Como `tli setup` es interactivo, en CI la configuración se entrega por variables de entorno. Si no existe `~/.tli/config.json`,
Titvo usa:

| Variable           | Valor                                                   |
|--------------------|---------------------------------------------------------|
| `TLI_USER_ID`      | `user_id` de tu `~/.tli/config.json`                    |
| `TLI_API_KEY`      | `api_key` de tu `~/.tli/config.json` (ya viene cifrada) |
| `TLI_API_ENDPOINT` | `api_endpoint` de tu `~/.tli/config.json`               |

Ejecuta `tli setup` una vez en tu máquina, copia los tres valores del archivo generado y guárdalos como
variables seguras del repositorio en Bitbucket.

```yaml
image: karibu/tli:latest

pipelines:
  pull-requests:
    '**':
      - step:
          name: Titvo security scan
          script:
            - tli --version
            - tli scan --commit "$BITBUCKET_COMMIT"
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