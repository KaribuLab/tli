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

## Política de excepciones del repositorio

Los escaneos incluyen `.titvoignore.yml` desde la raíz del árbol de trabajo,
aunque no figure entre los archivos seleccionados por Git. Se incluye una sola
vez, con las mismas validaciones de apertura segura que los archivos fuente;
un archivo presente que no sea texto regular seguro produce un error.
La ausencia del archivo conserva el comportamiento anterior. La CLI transporta
el contenido sin interpretar YAML ni autorizar excepciones. Los archivos fuente
seleccionados siguen usando su contenido actual del árbol de trabajo.

## Comandos Disponibles

Cada `tli scan` sube el **árbol completo** de archivos de texto (para indexado RAG) y un
`scan-manifest.json` aparte en el mismo batch. El alcance (`--staged`, `--commit`, `--full`)
define el **foco** del análisis en ese manifesto (`focus_files`), no reduce el snapshot.

### Escanear Cambios Preparados (Staged)

Sube el índice completo; el foco son los paths del área de preparación:

```bash
tli scan --staged
```

### Escanear un Commit Específico

Sube el árbol de ese commit; el foco son los paths del diff contra el padre:

```bash
tli scan --commit <hash-del-commit>
```

### Repositorio Completo

Sube el working tree versionado; el foco queda vacío:

```bash
tli scan --full
```

### Opciones Adicionales

- `--path, -p`: Ruta base para el escaneo (por defecto: directorio actual)

## Ejemplos de Uso

```bash
# Configuración inicial
tli setup

# Escanear con foco en staged (snapshot = repo completo)
tli scan --staged

# Escanear con foco en un commit
tli scan --commit abc123def456
```

## Uso en CI (Bitbucket Pipelines)

La imagen incluye `bash`, `git` y certificados CA, por lo que puede usarse como imagen de un step.

`tli setup` **no se ejecuta en CI**: es interactivo y genera `~/.tli/config.json`, que en un contenedor
efímero se perdería. En su lugar, cuando ese archivo no existe, Titvo lee la configuración de variables de
entorno y envía la API key tal cual (sin cifrar); el servidor la valida directamente, igual que hace con la
GitHub Action.

| Variable           | Valor                                                                    |
|--------------------|--------------------------------------------------------------------------|
| `TLI_API_KEY`      | API key en claro (`tvok-...`), la misma que pedirías en `tli setup`       |
| `TLI_API_ENDPOINT` | URL base del API de tareas (`.../v1`), la misma que usa la GitHub Action  |

No hace falta ID de usuario: los escaneos se autentican solo con la API key.

Si prefieres reutilizar el `api_key` cifrado de un `~/.tli/config.json`, también funciona: pon el valor
con el prefijo `ENC:` en `TLI_API_KEY`.

### 1. Obtener los valores

- **API key**: la entrega el administrador de Titvo (consola de administración o instalador).
- **Endpoint**: la URL base del API de tareas de tu instalación de Titvo.

### 2. Guardarlos en Bitbucket

En el repositorio: **Repository settings → Pipelines → Repository variables**. Crea `TLI_API_KEY`
(marcada como **Secured**) y `TLI_API_ENDPOINT`. También pueden definirse a nivel de workspace
(**Workspace settings → Pipelines → Workspace variables**) para compartirlas entre repositorios, o como
*Deployment variables* si quieres acotarlas a un entorno.

Bitbucket inyecta esas variables como variables de entorno en todos los steps del pipeline; no hay que
declararlas en el YAML. Titvo las toma automáticamente.

### 3. Pipeline

`image` puede declararse a nivel de step, de modo que solo ese step use la imagen de Titvo y el resto del
pipeline conserve su propia imagen:

```yaml
image: node:20   # imagen por defecto del pipeline

pipelines:
  pull-requests:
    '**':
      - step:
          name: Build
          script:
            - npm ci
            - npm test
      - step:
          name: Titvo security scan
          image: karibu/tli:latest   # solo este step
          script:
            - tli --version
            - tli scan --commit "$BITBUCKET_COMMIT"
```

Si prefieres no exponer las credenciales al resto de los steps, usa *Deployment variables* y marca el step
con `deployment: <nombre>`; Bitbucket solo las inyecta en ese step.

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