// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package i18n holds the small server/CLI message catalog. The web app has its
// own TypeScript catalog for bundled UI strings; this package keeps Go callers
// from scattering hard-coded operator-facing messages.
package i18n

import "strings"

const DefaultLocale = "en"

var supported = map[string]bool{
	"en": true,
	"es": true,
}

var catalog = map[string]map[string]string{
	"en": {
		"api.error.internal":     "Internal error",
		"api.error.bad_request":  "Bad request",
		"api.error.validation":   "Validation failed",
		"api.error.unauthorized": "Authentication required",
		"api.error.forbidden":    "Forbidden",
		"api.error.not_found":    "Not found",
		"api.error.conflict":     "Conflict",
		"api.error.unavailable":  "Service unavailable",
		"api.error.rate_limited": "Rate limited",
		"api.error.too_large":    "Payload too large",
		"cli.error.unknown":      "unknown command {command}",
		"cli.usage":              englishUsage,
	},
	"es": {
		"api.error.internal":     "Error interno",
		"api.error.bad_request":  "Solicitud incorrecta",
		"api.error.validation":   "Validacion fallida",
		"api.error.unauthorized": "Autenticacion requerida",
		"api.error.forbidden":    "Prohibido",
		"api.error.not_found":    "No encontrado",
		"api.error.conflict":     "Conflicto",
		"api.error.unavailable":  "Servicio no disponible",
		"api.error.rate_limited": "Limite de tasa excedido",
		"api.error.too_large":    "Carga demasiado grande",
		"cli.error.unknown":      "comando desconocido {command}", //nolint:misspell // Spanish locale copy.
		"cli.usage":              spanishUsage,
	},
}

// Resolve normalizes a requested locale such as "es-MX" or "en_US.UTF-8" to a
// shipped catalog locale, falling back to English.
func Resolve(raw string) string {
	locale := strings.ToLower(strings.TrimSpace(raw))
	if locale == "" {
		return DefaultLocale
	}
	for _, sep := range []string{"_", "-", "."} {
		if i := strings.Index(locale, sep); i >= 0 {
			locale = locale[:i]
		}
	}
	if supported[locale] {
		return locale
	}
	return DefaultLocale
}

// T returns a localized message for key. Missing locales/keys fall back to
// English, then the key itself so callers fail visibly in tests.
func T(locale, key string, vars map[string]string) string {
	resolved := Resolve(locale)
	if msg, ok := lookup(resolved, key); ok {
		return render(msg, vars)
	}
	if msg, ok := lookup(DefaultLocale, key); ok {
		return render(msg, vars)
	}
	return key
}

// ErrorMessage localizes a stable API error code while preserving the caller's
// fallback for unknown/custom codes.
func ErrorMessage(locale, code, fallback string) string {
	key := "api.error." + strings.ToLower(strings.TrimSpace(code))
	if msg, ok := lookup(Resolve(locale), key); ok {
		return render(msg, nil)
	}
	if msg, ok := lookup(DefaultLocale, key); ok {
		return render(msg, nil)
	}
	if strings.TrimSpace(fallback) != "" {
		return fallback
	}
	return T(locale, "api.error.internal", nil)
}

func lookup(locale, key string) (string, bool) {
	m, ok := catalog[locale]
	if !ok {
		return "", false
	}
	msg, ok := m[key]
	return msg, ok
}

func render(template string, vars map[string]string) string {
	out := template
	for key, value := range vars {
		out = strings.ReplaceAll(out, "{"+key+"}", value)
	}
	return out
}

const englishUsage = `probectl - control-plane CLI

Usage:
  probectl [global flags] <command> [args]

Commands:
  api <method> <path>            call any JSON /v1 API path directly
  test list                      list synthetic tests
  test get <id>                  show one test
  test create --name --type ...  create a test
  test update <id> --body JSON   update a test
  test delete <id>               delete a test
  test bundle                    download test bundle metadata
  test path <id> [--body JSON]   get or recompute a test path
  agent list                     list agents
  agent get <id>                 show one agent
  agent patch <id> --body JSON   patch an agent
  agent enroll-token --body JSON create an enrollment token
  agent ci <id>                  show CMDB CIs for an agent
  agent revoke <id>              revoke an agent
  agent delete <id>              deregister an agent
  lifecycle subject-export --subject ID [--redact]
                                stream a tenant-scoped subject export tar.gz
  lifecycle subject-erase --subject ID --confirm ID [--reason TEXT]
                                erase a subject inside the current tenant
  collector register --body JSON register a bus collector identity
  incident|alert|flow|topology|slo|compliance|cost|outage|rum|carbon ...
                                resource groups for served product surfaces
  version                        print the CLI version

Global flags:
  --url <url>       API base URL (env PROBECTL_API_URL, default http://localhost:8080)
  --token <token>   Bearer auth token (env PROBECTL_API_TOKEN)
  --tenant <uuid>   tenant scope (env PROBECTL_TENANT)
  --json            output JSON instead of a table

'test create' flags:
  --name <name>     required
  --type <type>     required: icmp|tcp|udp|dns|http|a2a|noop
  --target <target> required (except noop), e.g. host:port or an address
  --interval <sec>  default 60
  --timeout <sec>   default 3
  --param k=v       repeatable
  --disabled        create the test disabled

Raw resource flags:
  --query k=v       repeatable query parameter for resource/api commands
  --body JSON       JSON request body for create/update/action commands
`

//nolint:misspell // Spanish locale copy intentionally uses Spanish words.
const spanishUsage = `probectl - CLI del plano de control

Uso:
  probectl [flags globales] <comando> [args]

Comandos:
  api <metodo> <ruta>            llama directamente una ruta JSON /v1
  test list                      lista pruebas sinteticas
  test get <id>                  muestra una prueba
  test create --name --type ...  crea una prueba
  test update <id> --body JSON   actualiza una prueba
  test delete <id>               elimina una prueba
  test bundle                    descarga metadatos del paquete de pruebas
  test path <id> [--body JSON]   obtiene o recalcula la ruta de una prueba
  agent list                     lista agentes
  agent get <id>                 muestra un agente
  agent patch <id> --body JSON   modifica un agente
  agent enroll-token --body JSON crea un token de enrolamiento
  agent ci <id>                  muestra CIs de CMDB para un agente
  agent revoke <id>              revoca un agente
  agent delete <id>              desregistra un agente
  lifecycle subject-export --subject ID [--redact]
                                transmite un export tenant-scoped en tar.gz
  lifecycle subject-erase --subject ID --confirm ID [--reason TEXT]
                                borra un sujeto dentro del tenant actual
  collector register --body JSON registra una identidad de colector de bus
  incident|alert|flow|topology|slo|compliance|cost|outage|rum|carbon ...
                                grupos de recursos para superficies servidas
  version                        imprime la version de la CLI

Flags globales:
  --url <url>       URL base de API (env PROBECTL_API_URL, default http://localhost:8080)
  --token <token>   token Bearer de API (env PROBECTL_API_TOKEN)
  --tenant <uuid>   alcance de tenant (env PROBECTL_TENANT)
  --json            salida JSON en vez de tabla

Flags de 'test create':
  --name <name>     requerido
  --type <type>     requerido: icmp|tcp|udp|dns|http|a2a|noop
  --target <target> requerido (excepto noop), por ejemplo host:port o una direccion
  --interval <sec>  default 60
  --timeout <sec>   default 3
  --param k=v       repetible
  --disabled        crea la prueba desactivada

Flags de recursos raw:
  --query k=v       parametro query repetible para comandos resource/api
  --body JSON       cuerpo JSON para comandos create/update/action
`
