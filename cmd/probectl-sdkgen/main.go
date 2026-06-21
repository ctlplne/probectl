// SPDX-License-Identifier: LicenseRef-probectl-TBD

// probectl-sdkgen emits dependency-free REST SDKs from the committed OpenAPI
// contract. It intentionally covers the subset probectl's spec uses today, so
// the generator stays small, reviewed, and reproducible in CI.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

var methodOrder = []string{"get", "post", "put", "patch", "delete"}

type document struct {
	OpenAPI    string                                `json:"openapi"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components components                            `json:"components"`
}

type components struct {
	Schemas    map[string]*schema    `json:"schemas"`
	Parameters map[string]*parameter `json:"parameters"`
}

type op struct {
	OperationID string               `json:"operationId"`
	Summary     string               `json:"summary"`
	Parameters  []*parameter         `json:"parameters"`
	RequestBody *requestBody         `json:"requestBody"`
	Responses   map[string]*response `json:"responses"`
}

type parameter struct {
	Ref      string  `json:"$ref"`
	Name     string  `json:"name"`
	In       string  `json:"in"`
	Required bool    `json:"required"`
	Schema   *schema `json:"schema"`
}

type requestBody struct {
	Required bool                 `json:"required"`
	Content  map[string]mediaType `json:"content"`
}

type response struct {
	Description string               `json:"description"`
	Content     map[string]mediaType `json:"content"`
}

type mediaType struct {
	Schema *schema `json:"schema"`
}

type schema struct {
	Ref                  string             `json:"$ref"`
	Type                 any                `json:"type"`
	Format               string             `json:"format"`
	Description          string             `json:"description"`
	Properties           map[string]*schema `json:"properties"`
	Required             []string           `json:"required"`
	Items                *schema            `json:"items"`
	AdditionalProperties any                `json:"additionalProperties"`
	AllOf                []*schema          `json:"allOf"`
	Enum                 []any              `json:"enum"`
}

type operation struct {
	ID       string
	GoName   string
	TSName   string
	Method   string
	Path     string
	Summary  string
	Params   []resolvedParam
	Body     *schema
	BodyName string
	BodyReq  bool
	Resp     *schema
	JSONResp bool
	RawResp  bool
	NoResp   bool
}

type resolvedParam struct {
	Name     string
	In       string
	Required bool
	Schema   *schema
	GoField  string
	TSField  string
}

type generator struct {
	doc *document
}

func main() {
	specPath := flag.String("spec", "internal/control/openapi.json", "OpenAPI JSON input")
	goOut := flag.String("go-out", "pkg/sdk/sdk.gen.go", "generated Go SDK path")
	tsOut := flag.String("ts-out", "web/src/api/sdk.gen.ts", "generated TypeScript SDK path")
	flag.Parse()

	raw, err := os.ReadFile(*specPath)
	if err != nil {
		fatal(err)
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatal(err)
	}
	g := generator{doc: &doc}
	ops := g.operations()

	goSrc, err := g.goSDK(ops)
	if err != nil {
		fatal(err)
	}
	tsSrc := g.tsSDK(ops)

	if err := writeFile(*goOut, goSrc); err != nil {
		fatal(err)
	}
	if err := writeFile(*tsOut, tsSrc); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "probectl-sdkgen:", err)
	os.Exit(1)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (g generator) operations() []operation {
	paths := make([]string, 0, len(g.doc.Paths))
	for p := range g.doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var out []operation
	seen := map[string]int{}
	for _, path := range paths {
		byMethod := g.doc.Paths[path]
		for _, method := range methodOrder {
			raw := byMethod[method]
			if len(raw) == 0 {
				continue
			}
			var rawOp op
			if err := json.Unmarshal(raw, &rawOp); err != nil {
				fatal(fmt.Errorf("%s %s: %w", strings.ToUpper(method), path, err))
			}
			id := rawOp.OperationID
			if id == "" {
				id = derivedOperationID(method, path)
			}
			seen[id]++
			if seen[id] > 1 {
				id = fmt.Sprintf("%s%d", id, seen[id])
			}
			params := g.resolveParams(rawOp.Parameters)
			body, bodyRequired := jsonBody(rawOp.RequestBody)
			resp, jsonResp, rawResp := jsonResponse(rawOp.Responses)
			out = append(out, operation{
				ID:       id,
				GoName:   exportedName(id),
				TSName:   lowerCamel(id),
				Method:   strings.ToUpper(method),
				Path:     path,
				Summary:  rawOp.Summary,
				Params:   params,
				Body:     body,
				BodyName: exportedName(id) + "Body",
				BodyReq:  bodyRequired,
				Resp:     resp,
				JSONResp: jsonResp,
				RawResp:  rawResp,
				NoResp:   !jsonResp && !rawResp,
			})
		}
	}
	return out
}

func (g generator) resolveParams(params []*parameter) []resolvedParam {
	out := make([]resolvedParam, 0, len(params))
	used := map[string]int{}
	for _, p := range params {
		p = g.resolveParam(p)
		if p == nil || p.In == "header" {
			continue
		}
		field := exportedName(p.Name)
		used[field]++
		if used[field] > 1 {
			field = exportedName(p.In) + field
		}
		out = append(out, resolvedParam{
			Name:     p.Name,
			In:       p.In,
			Required: p.Required || p.In == "path",
			Schema:   p.Schema,
			GoField:  field,
			TSField:  lowerCamel(p.Name),
		})
	}
	return out
}

func (g generator) resolveParam(p *parameter) *parameter {
	if p == nil || p.Ref == "" {
		return p
	}
	name := refName(p.Ref, "#/components/parameters/")
	if name == "" {
		return p
	}
	return g.doc.Components.Parameters[name]
}

func jsonBody(rb *requestBody) (*schema, bool) {
	if rb == nil || rb.Content == nil {
		return nil, false
	}
	if mt, ok := rb.Content["application/json"]; ok {
		return mt.Schema, rb.Required
	}
	return nil, false
}

func jsonResponse(responses map[string]*response) (*schema, bool, bool) {
	for _, code := range []string{"200", "201", "202"} {
		r := responses[code]
		if r == nil {
			continue
		}
		if mt, ok := r.Content["application/json"]; ok {
			return mt.Schema, true, false
		}
		if len(r.Content) > 0 {
			return nil, false, true
		}
	}
	return nil, false, false
}

func (g generator) schemaRefName(s *schema) string {
	if s == nil {
		return ""
	}
	return refName(s.Ref, "#/components/schemas/")
}

func refName(ref, prefix string) string {
	if !strings.HasPrefix(ref, prefix) {
		return ""
	}
	name := strings.TrimPrefix(ref, prefix)
	name, _ = strings.CutPrefix(name, "/")
	return name
}

func (g generator) flattenObject(s *schema) (map[string]*schema, map[string]bool) {
	props := map[string]*schema{}
	required := map[string]bool{}
	var walk func(*schema)
	walk = func(cur *schema) {
		if cur == nil {
			return
		}
		if name := g.schemaRefName(cur); name != "" {
			walk(g.doc.Components.Schemas[name])
			return
		}
		for _, part := range cur.AllOf {
			walk(part)
		}
		for _, r := range cur.Required {
			required[r] = true
		}
		keys := sortedKeys(cur.Properties)
		for _, k := range keys {
			props[k] = cur.Properties[k]
		}
	}
	walk(s)
	return props, required
}

func typeName(s *schema) string {
	if s == nil {
		return ""
	}
	if name := refName(s.Ref, "#/components/schemas/"); name != "" {
		return name
	}
	return ""
}

func schemaType(s *schema) string {
	if s == nil {
		return ""
	}
	switch v := s.Type.(type) {
	case string:
		return v
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok && str != "null" {
				return str
			}
		}
	}
	if len(s.Properties) > 0 || len(s.AllOf) > 0 {
		return "object"
	}
	if s.Items != nil {
		return "array"
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func requiredList(props map[string]bool, key string) bool {
	return props[key]
}

func derivedOperationID(method, path string) string {
	parts := []string{strings.ToLower(method)}
	for _, p := range strings.Split(strings.Trim(path, "/"), "/") {
		if p == "" {
			continue
		}
		p = strings.Trim(p, "{}")
		parts = append(parts, p)
	}
	return lowerCamel(strings.Join(parts, "_"))
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]+`)

func exportedName(raw string) string {
	tokens := nameTokens(raw)
	if len(tokens) == 0 {
		return "Value"
	}
	for i, token := range tokens {
		tokens[i] = strings.ToUpper(token[:1]) + token[1:]
	}
	out := strings.Join(tokens, "")
	if out == "" || !unicode.IsLetter(rune(out[0])) {
		out = "N" + out
	}
	return out
}

func lowerCamel(raw string) string {
	name := exportedName(raw)
	return strings.ToLower(name[:1]) + name[1:]
}

func nameTokens(raw string) []string {
	raw = nonAlnum.ReplaceAllString(raw, " ")
	var split []string
	for _, word := range strings.Fields(raw) {
		start := 0
		runes := []rune(word)
		for i := 1; i < len(runes); i++ {
			if unicode.IsUpper(runes[i]) && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
				split = append(split, string(runes[start:i]))
				start = i
			}
		}
		split = append(split, string(runes[start:]))
	}
	out := split[:0]
	for _, token := range split {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		out = append(out, strings.ToLower(token))
	}
	return out
}

func jsonTag(name string, required bool) string {
	if required {
		return fmt.Sprintf("`json:%q`", name)
	}
	return fmt.Sprintf("`json:%q`", name+",omitempty")
}

func commentLine(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	return "// " + strings.ReplaceAll(text, "\n", " ") + "\n"
}

func (g generator) goSDK(ops []operation) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("// SPDX-License-Identifier: LicenseRef-probectl-TBD\n")
	b.WriteString("// Code generated by cmd/probectl-sdkgen from internal/control/openapi.json; DO NOT EDIT.\n\n")
	b.WriteString("package sdk\n\n")
	b.WriteString("import (\n")
	b.WriteString("\t\"bytes\"\n\t\"context\"\n\t\"encoding/json\"\n\t\"fmt\"\n\t\"io\"\n\t\"net/http\"\n\t\"net/url\"\n\t\"strconv\"\n\t\"strings\"\n\t\"time\"\n")
	b.WriteString(")\n\n")
	b.WriteString("type SDKError struct {\n\tStatusCode int\n\tCode string\n\tMessage string\n\tBody []byte\n}\n\n")
	b.WriteString("func (e *SDKError) Error() string {\n\tif e.Message != \"\" {\n\t\tif e.Code != \"\" { return fmt.Sprintf(\"%s (%s)\", e.Message, e.Code) }\n\t\treturn e.Message\n\t}\n\treturn fmt.Sprintf(\"probectl API status %d\", e.StatusCode)\n}\n\n")
	b.WriteString("type Client struct {\n\tBaseURL string\n\tToken string\n\tTenant string\n\tHTTPClient *http.Client\n\tUserAgent string\n}\n\n")
	b.WriteString("type Option func(*Client)\n\n")
	b.WriteString("func WithToken(token string) Option { return func(c *Client) { c.Token = token } }\n")
	b.WriteString("func WithTenant(tenant string) Option { return func(c *Client) { c.Tenant = tenant } }\n")
	b.WriteString("func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { if hc != nil { c.HTTPClient = hc } } }\n")
	b.WriteString("func WithUserAgent(userAgent string) Option { return func(c *Client) { c.UserAgent = userAgent } }\n\n")
	b.WriteString("func NewClient(baseURL string, opts ...Option) *Client {\n\tif strings.TrimSpace(baseURL) == \"\" { baseURL = \"http://localhost:8080\" }\n\tc := &Client{BaseURL: strings.TrimRight(baseURL, \"/\"), HTTPClient: &http.Client{Timeout: 15 * time.Second}, UserAgent: \"probectl-go-sdk\"}\n\tfor _, opt := range opts { opt(c) }\n\treturn c\n}\n\n")
	b.WriteString("func String(v string) *string { return &v }\nfunc Int(v int) *int { return &v }\nfunc Bool(v bool) *bool { return &v }\nfunc Float64(v float64) *float64 { return &v }\n\n")

	g.writeGoModels(&b)
	for _, op := range ops {
		g.writeGoOperation(&b, op)
	}
	g.writeGoRuntime(&b)

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated Go: %w", err)
	}
	return formatted, nil
}

func (g generator) writeGoModels(b *bytes.Buffer) {
	names := sortedKeys(g.doc.Components.Schemas)
	for _, name := range names {
		s := g.doc.Components.Schemas[name]
		if schemaType(s) != "object" {
			fmt.Fprintf(b, "type %s %s\n\n", name, g.goType(s))
			continue
		}
		props, required := g.flattenObject(s)
		if len(props) == 0 {
			fmt.Fprintf(b, "type %s map[string]any\n\n", name)
			continue
		}
		fmt.Fprintf(b, "%stype %s struct {\n", commentLine(s.Description), name)
		for _, prop := range sortedKeys(props) {
			requiredProp := requiredList(required, prop)
			fmt.Fprintf(b, "\t%s %s %s\n", exportedName(prop), g.goType(props[prop]), jsonTag(prop, requiredProp))
		}
		b.WriteString("}\n\n")
	}
}

func (g generator) goType(s *schema) string {
	if s == nil {
		return "any"
	}
	if name := typeName(s); name != "" {
		return name
	}
	if len(s.AllOf) > 0 {
		return "map[string]any"
	}
	switch schemaType(s) {
	case "string":
		return "string"
	case "integer":
		return "int"
	case "number":
		return "float64"
	case "boolean":
		return "bool"
	case "array":
		return "[]" + g.goType(s.Items)
	case "object":
		if len(s.Properties) > 0 {
			return "map[string]any"
		}
		if ap := additionalSchema(s); ap != nil {
			return "map[string]" + g.goType(ap)
		}
		return "map[string]any"
	default:
		return "any"
	}
}

func additionalSchema(s *schema) *schema {
	switch v := s.AdditionalProperties.(type) {
	case map[string]any:
		raw, _ := json.Marshal(v)
		var out schema
		if json.Unmarshal(raw, &out) == nil {
			return &out
		}
	}
	return nil
}

func (g generator) writeGoOperation(b *bytes.Buffer, op operation) {
	reqName := op.GoName + "Request"
	respType := g.goResponseType(op)
	fmt.Fprintf(b, "%stype %s struct {\n", commentLine(op.Summary), reqName)
	for _, p := range op.Params {
		if p.In == "path" {
			fmt.Fprintf(b, "\t%s %s `json:\"-\"`\n", p.GoField, g.goType(p.Schema))
			continue
		}
		fmt.Fprintf(b, "\t%s *%s `json:\"-\"`\n", p.GoField, g.goType(p.Schema))
	}
	if op.Body != nil {
		bodyType := g.goType(op.Body)
		if typeName(op.Body) == "" && bodyType == "map[string]any" {
			bodyType = "map[string]any"
		}
		fmt.Fprintf(b, "\tBody *%s `json:\"-\"`\n", bodyType)
	}
	b.WriteString("}\n\n")

	if respType == "" {
		fmt.Fprintf(b, "func (c *Client) %s(ctx context.Context, req %s) error {\n", op.GoName, reqName)
	} else {
		fmt.Fprintf(b, "func (c *Client) %s(ctx context.Context, req %s) (%s, error) {\n", op.GoName, reqName, goReturnType(respType))
	}
	fmt.Fprintf(b, "\tpath := %q\n", op.Path)
	for _, p := range op.Params {
		if p.In != "path" {
			continue
		}
		fmt.Fprintf(b, "\tif req.%s == \"\" {", p.GoField)
		if respType == "" {
			fmt.Fprintf(b, " return fmt.Errorf(%q) }\n", p.Name+" is required")
		} else {
			fmt.Fprintf(b, " return %s, fmt.Errorf(%q) }\n", goZeroReturn(respType), p.Name+" is required")
		}
		fmt.Fprintf(b, "\tpath = strings.ReplaceAll(path, %q, url.PathEscape(req.%s))\n", "{"+p.Name+"}", p.GoField)
	}
	b.WriteString("\tquery := url.Values{}\n")
	for _, p := range op.Params {
		if p.In != "query" {
			continue
		}
		fmt.Fprintf(b, "\tif req.%s != nil { query.Set(%q, formatQueryValue(*req.%s)) }\n", p.GoField, p.Name, p.GoField)
	}
	body := "nil"
	if op.Body != nil {
		body = "req.Body"
	}
	if respType == "" {
		if op.RawResp {
			fmt.Fprintf(b, "\t_, err := c.doRaw(ctx, http.Method%s, path, query, %s)\n\treturn err\n}\n\n", exportedName(strings.ToLower(op.Method)), body)
		} else {
			fmt.Fprintf(b, "\treturn c.doJSON(ctx, http.Method%s, path, query, %s, nil)\n}\n\n", exportedName(strings.ToLower(op.Method)), body)
		}
		return
	}
	if op.RawResp {
		fmt.Fprintf(b, "\treturn c.doRaw(ctx, http.Method%s, path, query, %s)\n}\n\n", exportedName(strings.ToLower(op.Method)), body)
		return
	}
	fmt.Fprintf(b, "\tvar out %s\n", respType)
	fmt.Fprintf(b, "\tif err := c.doJSON(ctx, http.Method%s, path, query, %s, &out); err != nil { return %s, err }\n", exportedName(strings.ToLower(op.Method)), body, goZeroReturn(respType))
	if strings.HasPrefix(respType, "map[") || strings.HasPrefix(respType, "[]") {
		b.WriteString("\treturn out, nil\n}\n\n")
	} else {
		b.WriteString("\treturn &out, nil\n}\n\n")
	}
}

func (g generator) goResponseType(op operation) string {
	if op.RawResp {
		return "[]byte"
	}
	if !op.JSONResp || op.Resp == nil {
		return ""
	}
	return g.goType(op.Resp)
}

func goReturnType(t string) string {
	if t == "[]byte" || strings.HasPrefix(t, "map[") || strings.HasPrefix(t, "[]") {
		return t
	}
	return "*" + t
}

func goZeroReturn(t string) string {
	if strings.HasPrefix(t, "map[") || strings.HasPrefix(t, "[]") || t == "[]byte" {
		return "nil"
	}
	return "nil"
}

func (g generator) writeGoRuntime(b *bytes.Buffer) {
	b.WriteString("func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body any, out any) error {\n")
	b.WriteString("\tdata, err := c.doRaw(ctx, method, path, query, body)\n\tif err != nil { return err }\n\tif out == nil || len(data) == 0 { return nil }\n\treturn json.Unmarshal(data, out)\n}\n\n")
	b.WriteString("func (c *Client) doRaw(ctx context.Context, method, path string, query url.Values, body any) ([]byte, error) {\n")
	b.WriteString("\tvar r io.Reader\n\tif body != nil {\n\t\tb, err := json.Marshal(body)\n\t\tif err != nil { return nil, err }\n\t\tr = bytes.NewReader(b)\n\t}\n")
	b.WriteString("\tu, err := url.Parse(c.BaseURL + path)\n\tif err != nil { return nil, err }\n\tif len(query) > 0 { u.RawQuery = query.Encode() }\n")
	b.WriteString("\treq, err := http.NewRequestWithContext(ctx, method, u.String(), r)\n\tif err != nil { return nil, err }\n")
	b.WriteString("\treq.Header.Set(\"Accept\", \"application/json\")\n\tif body != nil { req.Header.Set(\"Content-Type\", \"application/json\") }\n\tif c.UserAgent != \"\" { req.Header.Set(\"User-Agent\", c.UserAgent) }\n\tif c.Token != \"\" { req.Header.Set(\"Authorization\", \"Bearer \"+c.Token) }\n\tif c.Tenant != \"\" { req.Header.Set(\"X-Probectl-Tenant\", c.Tenant) }\n")
	b.WriteString("\thc := c.HTTPClient\n\tif hc == nil { hc = http.DefaultClient }\n\tresp, err := hc.Do(req)\n\tif err != nil { return nil, err }\n\tdefer resp.Body.Close()\n\tdata, _ := io.ReadAll(resp.Body)\n\tif resp.StatusCode/100 != 2 { return nil, decodeError(resp.StatusCode, data) }\n\treturn data, nil\n}\n\n")
	b.WriteString("func decodeError(status int, body []byte) error {\n\tvar env struct { Error struct { Code string `json:\"code\"`; Message string `json:\"message\"` } `json:\"error\"` }\n\t_ = json.Unmarshal(body, &env)\n\treturn &SDKError{StatusCode: status, Code: env.Error.Code, Message: env.Error.Message, Body: body}\n}\n\n")
	b.WriteString("func formatQueryValue(v any) string {\n\tswitch x := v.(type) {\n\tcase string:\n\t\treturn x\n\tcase int:\n\t\treturn strconv.Itoa(x)\n\tcase bool:\n\t\treturn strconv.FormatBool(x)\n\tcase float64:\n\t\treturn strconv.FormatFloat(x, 'f', -1, 64)\n\tdefault:\n\t\treturn fmt.Sprint(x)\n\t}\n}\n")
}

func (g generator) tsSDK(ops []operation) []byte {
	var b bytes.Buffer
	b.WriteString("// SPDX-License-Identifier: LicenseRef-probectl-TBD\n")
	b.WriteString("// Code generated by cmd/probectl-sdkgen from internal/control/openapi.json; DO NOT EDIT.\n\n")
	b.WriteString("/* eslint-disable */\n\n")
	b.WriteString("export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[]\n")
	b.WriteString("export interface JsonObject { [key: string]: JsonValue }\n\n")
	g.writeTSModels(&b)
	for _, op := range ops {
		g.writeTSOperationTypes(&b, op)
	}
	b.WriteString("export interface SDKClientOptions {\n  baseUrl?: string\n  token?: string\n  tenant?: string\n  fetch?: typeof fetch\n  userAgent?: string\n}\n\n")
	b.WriteString("export class ProbectlSDKClient {\n")
	b.WriteString("  private readonly baseUrl: string\n  private readonly fetcher: typeof fetch\n\n")
	b.WriteString("  constructor(private readonly options: SDKClientOptions = {}) {\n    this.baseUrl = (options.baseUrl ?? '').replace(/\\/$/, '')\n    this.fetcher = options.fetch ?? fetch\n  }\n\n")
	for _, op := range ops {
		g.writeTSMethod(&b, op)
	}
	b.WriteString("  private async requestJSON<T>(method: string, path: string, query: URLSearchParams, body: unknown | undefined): Promise<T> {\n    const response = await this.request(method, path, query, body)\n    if (response.status === 204) return undefined as T\n    return (await response.json()) as T\n  }\n\n")
	b.WriteString("  private async request(method: string, path: string, query: URLSearchParams, body: unknown | undefined): Promise<Response> {\n    const qs = query.toString()\n    const headers: Record<string, string> = { Accept: 'application/json' }\n    if (body !== undefined) headers['Content-Type'] = 'application/json'\n    if (this.options.token) headers.Authorization = `Bearer ${this.options.token}`\n    if (this.options.tenant) headers['X-Probectl-Tenant'] = this.options.tenant\n    if (this.options.userAgent) headers['User-Agent'] = this.options.userAgent\n    const response = await this.fetcher(`${this.baseUrl}${path}${qs ? `?${qs}` : ''}`, {\n      method,\n      headers,\n      body: body === undefined ? undefined : JSON.stringify(body),\n    })\n    if (!response.ok) throw await toSDKError(response)\n    return response\n  }\n")
	b.WriteString("}\n\n")
	b.WriteString("export class SDKError extends Error {\n  constructor(\n    readonly status: number,\n    readonly code: string | undefined,\n    message: string,\n  ) {\n    super(message)\n    this.name = 'SDKError'\n  }\n}\n\n")
	b.WriteString("async function toSDKError(response: Response): Promise<SDKError> {\n  let code: string | undefined\n  let message = `${response.status} ${response.statusText}`\n  try {\n    const body = (await response.json()) as { error?: { code?: string; message?: string } }\n    code = body.error?.code\n    if (body.error?.message) message = body.error.message\n  } catch {\n    // Non-JSON error bodies keep the status text.\n  }\n  return new SDKError(response.status, code, message)\n}\n")
	return b.Bytes()
}

func (g generator) writeTSModels(b *bytes.Buffer) {
	for _, name := range sortedKeys(g.doc.Components.Schemas) {
		s := g.doc.Components.Schemas[name]
		if schemaType(s) != "object" {
			fmt.Fprintf(b, "export type %s = %s\n\n", name, g.tsType(s))
			continue
		}
		props, required := g.flattenObject(s)
		if len(props) == 0 {
			fmt.Fprintf(b, "export type %s = JsonObject\n\n", name)
			continue
		}
		fmt.Fprintf(b, "export interface %s {\n", name)
		for _, prop := range sortedKeys(props) {
			opt := "?"
			if requiredList(required, prop) {
				opt = ""
			}
			fmt.Fprintf(b, "  %s%s: %s\n", quoteTSKey(prop), opt, g.tsType(props[prop]))
		}
		b.WriteString("}\n\n")
	}
}

func (g generator) tsType(s *schema) string {
	if s == nil {
		return "JsonValue"
	}
	if name := typeName(s); name != "" {
		return name
	}
	if len(s.AllOf) > 0 {
		parts := make([]string, 0, len(s.AllOf))
		for _, part := range s.AllOf {
			parts = append(parts, g.tsType(part))
		}
		return strings.Join(parts, " & ")
	}
	switch schemaType(s) {
	case "string":
		if len(s.Enum) > 0 {
			vals := make([]string, 0, len(s.Enum))
			for _, v := range s.Enum {
				if str, ok := v.(string); ok {
					vals = append(vals, strconv.Quote(str))
				}
			}
			if len(vals) > 0 {
				return strings.Join(vals, " | ")
			}
		}
		return "string"
	case "integer", "number":
		return "number"
	case "boolean":
		return "boolean"
	case "array":
		return g.tsType(s.Items) + "[]"
	case "object":
		if ap := additionalSchema(s); ap != nil {
			return "{ [key: string]: " + g.tsType(ap) + " }"
		}
		return "JsonObject"
	default:
		return "JsonValue"
	}
}

func (g generator) writeTSOperationTypes(b *bytes.Buffer, op operation) {
	reqName := op.GoName + "Request"
	fmt.Fprintf(b, "export interface %s {\n", reqName)
	for _, p := range op.Params {
		opt := "?"
		if p.In == "path" || p.Required {
			opt = ""
		}
		fmt.Fprintf(b, "  %s%s: %s\n", quoteTSKey(p.TSField), opt, g.tsType(p.Schema))
	}
	if op.Body != nil {
		opt := "?"
		if op.BodyReq {
			opt = ""
		}
		fmt.Fprintf(b, "  body%s: %s\n", opt, g.tsType(op.Body))
	}
	b.WriteString("}\n\n")
	respType := "void"
	if op.RawResp {
		respType = "Response"
	} else if op.JSONResp && op.Resp != nil {
		respType = g.tsType(op.Resp)
	}
	fmt.Fprintf(b, "export type %sResponse = %s\n\n", op.GoName, respType)
}

func (g generator) writeTSMethod(b *bytes.Buffer, op operation) {
	reqName := op.GoName + "Request"
	respName := op.GoName + "Response"
	required := false
	for _, p := range op.Params {
		if p.In == "path" || p.Required {
			required = true
		}
	}
	if op.Body != nil && op.BodyReq {
		required = true
	}
	hasRequestFields := len(op.Params) > 0 || op.Body != nil
	arg := ""
	if hasRequestFields {
		arg = fmt.Sprintf("request: %s", reqName)
	}
	if hasRequestFields && !required {
		arg = fmt.Sprintf("request: %s = {}", reqName)
	}
	fmt.Fprintf(b, "  async %s(%s): Promise<%s> {\n", op.TSName, arg, respName)
	fmt.Fprintf(b, "    let path = %q\n", op.Path)
	for _, p := range op.Params {
		if p.In == "path" {
			fmt.Fprintf(b, "    path = path.replace(%q, encodeURIComponent(String(request.%s)))\n", "{"+p.Name+"}", p.TSField)
		}
	}
	b.WriteString("    const query = new URLSearchParams()\n")
	for _, p := range op.Params {
		if p.In == "query" {
			fmt.Fprintf(b, "    if (request.%s !== undefined) query.set(%q, String(request.%s))\n", p.TSField, p.Name, p.TSField)
		}
	}
	body := "undefined"
	if op.Body != nil {
		body = "request.body"
	}
	if op.RawResp {
		fmt.Fprintf(b, "    return this.request(%q, path, query, %s)\n  }\n\n", op.Method, body)
		return
	}
	if op.JSONResp {
		fmt.Fprintf(b, "    return this.requestJSON<%s>(%q, path, query, %s)\n  }\n\n", respName, op.Method, body)
		return
	}
	fmt.Fprintf(b, "    await this.request(%q, path, query, %s)\n  }\n\n", op.Method, body)
}

func quoteTSKey(key string) string {
	if key == "" {
		return "value"
	}
	valid := true
	for i, r := range key {
		if i == 0 {
			valid = r == '_' || r == '$' || unicode.IsLetter(r)
		} else {
			valid = r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)
		}
		if !valid {
			break
		}
	}
	if valid {
		return key
	}
	return strconv.Quote(key)
}
