# Manifest de escaneo CLI (`scan-manifest.json`)

Contrato del archivo de metadatos que `tli` sube junto al snapshot de código.
Lo consumen el agent (foco del análisis) y el indexador RAG (inventario + dedupe por hash).

## Ubicación en el bucket

El servicio `titvo-task-cli-files` genera URLs prefirmadas con clave:

```text
temp/<batch_id>/<nombre-archivo>
```

`batch_id` lo genera `tli` (UUID) y lo reutiliza en `/cli-files` y `/run-scan`.

Tras un `tli scan` exitoso, el batch queda así:

| Objeto S3 | Contenido |
|-----------|-----------|
| `temp/<batch_id>/snapshot.tar.gz` | Árbol completo de archivos de texto del alcance |
| `temp/<batch_id>/scan-manifest.json` | Metadatos (este documento) |

El bucket concreto lo resuelve el backend (`cli_files_bucket_name`). El CLI no elige bucket ni prefijo: solo pide esos `name` en `/cli-files`.

`scan-manifest.json` **no** va dentro del tar y **no** se lista en `original_files` (solo paths de código).

## Estructura JSON

`Content-Type` de subida: `application/json`.

```json
{
  "version": 1,
  "scope": "commit",
  "commit": "abc123def4567890abc123def4567890abc123de",
  "branch": "feature/login",
  "focus_files": [
    "auth/login.go",
    "old.go"
  ],
  "files": [
    {
      "path": "README.md",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 420
    },
    {
      "path": "auth/login.go",
      "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      "size": 1880
    },
    {
      "path": "go.mod",
      "sha256": "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
      "size": 95
    },
    {
      "path": "main.go",
      "sha256": "a3f2e8c19d0b4c7e8f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70",
      "size": 640
    }
  ]
}
```

## Campos

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `version` | number | Versión del schema. Hoy: `1`. |
| `scope` | string | Tipo de escaneo: `commit`, `staged` o `full`. |
| `commit` | string | SHA del commit resuelto al planear. |
| `branch` | string | Rama actual (o la que reporta el entorno CI). |
| `focus_files` | string[] | Paths del foco del agent. Orden lexicográfico. |
| `files` | object[] | Inventario de lo que está **dentro** de `snapshot.tar.gz`. Orden por `path`. |
| `files[].path` | string | Ruta relativa en el repo / en el tar. |
| `files[].sha256` | string | SHA-256 hex del contenido subido (dedupe RAG). |
| `files[].size` | number | Tamaño en bytes del contenido subido. |

## Semántica de `focus_files` por `scope`

| `scope` | Qué entra en `focus_files` |
|---------|----------------------------|
| `commit` | Diff del commit vs su primer padre (incluye borrados). Commit raíz: todos los paths del árbol. |
| `staged` | Paths del `git diff --cached`. |
| `full` | Lista vacía `[]`. |

Un path en `focus_files` puede no aparecer en `files` si fue borrado en el commit/staged: el agent ve el foco; el tar solo tiene archivos con contenido.

## Relación con el snapshot

- **`files`**: inventario RAG del tar completo (árbol de texto del alcance).
- **`focus_files`**: subset (o vacío) para el agent.
- El indexador puede saltar entradas cuyo `sha256` ya esté indexado.
- El agent debe usar `focus_files`, no tratar el manifest como código fuente.
