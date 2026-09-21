// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// HandoffContractVersion identifies the portable Ask investigation handoff
// schema. Bump it only when a consumer would need different parsing or trust
// semantics.
const HandoffContractVersion = "probectl-ai-handoff/v1"

type handoffCopy struct {
	title                 string
	pointInTime           string
	receipt               string
	contract              string
	answerID              string
	tenant                string
	question              string
	confidence            string
	insufficient          string
	degraded              string
	yes                   string
	no                    string
	model                 string
	reasoningAdapter      string
	reasoningExecution    string
	egressConsent         string
	attemptedAdapter      string
	suppressedClaims      string
	rootCause             string
	rootWithheld          string
	citations             string
	findings              string
	noFindings            string
	plan                  string
	noPlan                string
	status                string
	domain                string
	goal                  string
	summary               string
	limit                 string
	readOnly              string
	reason                string
	evidenceCount         string
	truncated             string
	selector              string
	node                  string
	window                string
	evidence              string
	otherPlane            string
	occurrence            string
	source                string
	citedBy               string
	notRecorded           string
	rootCauseReference    string
	findingReference      string
	fields                string
	limitations           string
	nonAuthoritativeLimit string
	direction             string
}

var handoffCopies = map[string]handoffCopy{
	"en": {
		title:       "probectl Ask investigation handoff",
		pointInTime: "Point-in-time, non-authoritative investigation note. This file is a local copy of one tenant- and RBAC-scoped answer. Evidence can age, permissions can change, and source records may be retained or deleted. Re-open probectl and re-authorize every cited source before making a decision.",
		receipt:     "Receipt", contract: "Contract", answerID: "Answer ID", tenant: "Tenant",
		question: "Question", confidence: "Confidence", insufficient: "Insufficient evidence",
		degraded: "Degraded fallback", yes: "yes", no: "no", model: "Model",
		reasoningAdapter: "Reasoning adapter", reasoningExecution: "Reasoning execution",
		egressConsent: "Egress consent", attemptedAdapter: "Attempted adapter",
		suppressedClaims: "Suppressed causal claims", rootCause: "Grounded root cause",
		rootWithheld: "Not exported: the root-cause claim was insufficient or its citations did not resolve in this exact answer.",
		citations:    "Citations", findings: "Grounded findings",
		noFindings:            "No grounded findings were available in this exact answer.",
		plan:                  "Read-only investigation plan",
		noPlan:                "No investigation steps were recorded.",
		status:                "Status",
		domain:                "Domain",
		goal:                  "Goal",
		summary:               "Summary",
		limit:                 "Limit",
		readOnly:              "Read-only",
		reason:                "Reason",
		evidenceCount:         "Evidence count",
		truncated:             "Truncated",
		selector:              "Selector",
		node:                  "Node",
		window:                "Window",
		evidence:              "Evidence by plane",
		otherPlane:            "other",
		occurrence:            "Occurred at",
		source:                "Source",
		citedBy:               "Cited by",
		notRecorded:           "not recorded",
		rootCauseReference:    "root cause",
		findingReference:      "finding {number}",
		fields:                "Fields",
		limitations:           "Limitations",
		nonAuthoritativeLimit: "This handoff is evidence, not live authoritative state, remediation approval, or permission to act. Validate current telemetry, authorization, and operating context in probectl.",
		direction:             "ltr",
	},
	"es": {
		title:       "Entrega de investigación de Ask de probectl",
		pointInTime: "Nota de investigación puntual y no autoritativa. Este archivo es una copia local de una respuesta limitada por tenant y RBAC. La evidencia puede envejecer, los permisos pueden cambiar y los registros de origen pueden conservarse o eliminarse. Vuelve a abrir probectl y autoriza de nuevo cada fuente citada antes de tomar una decisión.",
		receipt:     "Recibo", contract: "Contrato", answerID: "ID de respuesta", tenant: "Tenant",
		question: "Pregunta", confidence: "Confianza", insufficient: "Evidencia insuficiente",
		degraded: "Ruta de respaldo degradada", yes: "sí", no: "no", model: "Modelo",
		reasoningAdapter: "Adaptador de razonamiento", reasoningExecution: "Ejecución del razonamiento",
		egressConsent: "Consentimiento de salida", attemptedAdapter: "Adaptador intentado",
		suppressedClaims: "Afirmaciones causales suprimidas", rootCause: "Causa raíz fundamentada",
		rootWithheld: "No se exportó: la afirmación de causa raíz era insuficiente o sus citas no se resolvieron en esta respuesta exacta.",
		citations:    "Citas", findings: "Hallazgos fundamentados",
		noFindings:            "No había hallazgos fundamentados en esta respuesta exacta.",
		plan:                  "Plan de investigación de solo lectura",
		noPlan:                "No se registraron pasos de investigación.",
		status:                "Estado",
		domain:                "Dominio",
		goal:                  "Objetivo",
		summary:               "Resumen",
		limit:                 "Límite",
		readOnly:              "Solo lectura",
		reason:                "Motivo",
		evidenceCount:         "Cantidad de evidencias",
		truncated:             "Truncado",
		selector:              "Selector",
		node:                  "Nodo",
		window:                "Ventana",
		evidence:              "Evidencia por plano",
		otherPlane:            "otro",
		occurrence:            "Ocurrió en",
		source:                "Fuente",
		citedBy:               "Citado por",
		notRecorded:           "no registrado",
		rootCauseReference:    "causa raíz",
		findingReference:      "hallazgo {number}",
		fields:                "Campos",
		limitations:           "Limitaciones",
		nonAuthoritativeLimit: "Esta entrega es evidencia, no estado autoritativo en vivo, aprobación de remediación ni permiso para actuar. Valida la telemetría, la autorización y el contexto operativo actuales en probectl.",
		direction:             "ltr",
	},
	"ar": {
		title:       "تسليم تحقيق Ask من probectl",
		pointInTime: "ملاحظة تحقيق آنية وغير مرجعية. هذا الملف نسخة محلية من إجابة واحدة مقيّدة بالمستأجر وصلاحيات RBAC. قد تتقادم الأدلة، وقد تتغير الصلاحيات، وقد تُحفظ سجلات المصدر أو تُحذف. أعد فتح probectl وأعد التحقق من صلاحية كل مصدر مستشهد به قبل اتخاذ قرار.",
		receipt:     "الإيصال", contract: "العقد", answerID: "معرّف الإجابة", tenant: "المستأجر",
		question: "السؤال", confidence: "الثقة", insufficient: "الأدلة غير كافية",
		degraded: "مسار احتياطي متدهور", yes: "نعم", no: "لا", model: "النموذج",
		reasoningAdapter: "مهايئ الاستدلال", reasoningExecution: "تنفيذ الاستدلال",
		egressConsent: "موافقة خروج البيانات", attemptedAdapter: "المهايئ الذي تمت محاولته",
		suppressedClaims: "الادعاءات السببية المحجوبة", rootCause: "السبب الجذري الموثق",
		rootWithheld: "لم يُصدّر: ادعاء السبب الجذري غير كاف أو لم تُحل استشهاداته ضمن هذه الإجابة نفسها.",
		citations:    "الاستشهادات", findings: "النتائج الموثقة",
		noFindings:            "لا توجد نتائج موثقة ضمن هذه الإجابة نفسها.",
		plan:                  "خطة التحقيق للقراءة فقط",
		noPlan:                "لم تُسجّل خطوات تحقيق.",
		status:                "الحالة",
		domain:                "النطاق",
		goal:                  "الهدف",
		summary:               "الملخص",
		limit:                 "الحد",
		readOnly:              "للقراءة فقط",
		reason:                "السبب",
		evidenceCount:         "عدد الأدلة",
		truncated:             "مقتطع",
		selector:              "المحدِّد",
		node:                  "العقدة",
		window:                "النافذة الزمنية",
		evidence:              "الأدلة حسب المستوى",
		otherPlane:            "أخرى",
		occurrence:            "وقت الحدوث",
		source:                "المصدر",
		citedBy:               "مستشهد به في",
		notRecorded:           "غير مسجّل",
		rootCauseReference:    "السبب الجذري",
		findingReference:      "النتيجة {number}",
		fields:                "الحقول",
		limitations:           "القيود",
		nonAuthoritativeLimit: "هذا التسليم دليل، وليس حالة مرجعية مباشرة أو موافقة على معالجة أو إذنا بالتصرف. تحقّق من القياسات والصلاحيات والسياق التشغيلي الحالي في probectl.",
		direction:             "rtl",
	},
}

type handoffClaims struct {
	rootCitations   []Citation
	rootResolved    bool
	findings        []Finding
	suppressedCount int
}

type orderedHandoffEvidence struct {
	evidence Evidence
	anchor   int
}

// RenderHandoff returns a deterministic, offline Markdown representation of
// one already-authorized Answer. It performs no query, persistence, connector,
// or network work. Citation integrity is re-applied at this final display
// boundary, so unresolved causal prose never enters the handoff.
func RenderHandoff(answer Answer, locale string) string {
	locale = normalizeHandoffLocale(locale)
	text := handoffCopies[locale]
	claims := resolveHandoffClaims(answer)
	orderedEvidence, anchors := orderHandoffEvidence(answer.Evidence, text.otherPlane)
	citedBy := handoffBacklinks(claims)
	number := func(value int) string { return handoffNumber(locale, value) }

	var out strings.Builder
	fmt.Fprintf(&out, "<!-- %s; lang=%s; dir=%s -->\n", HandoffContractVersion, locale, text.direction)
	fmt.Fprintf(&out, "# %s\n\n", text.title)
	fmt.Fprintf(&out, "> **%s**\n\n", markdownText(text.pointInTime))

	fmt.Fprintf(&out, "## %s\n\n", text.receipt)
	handoffBullet(&out, text.contract, codeSpan(HandoffContractVersion))
	handoffBullet(&out, text.answerID, codeSpan(answer.ID))
	handoffBullet(&out, text.tenant, codeSpan(answer.Tenant))
	handoffBullet(&out, text.question, markdownText(answer.Question))
	handoffBullet(&out, text.confidence, codeSpan(string(answer.Confidence)))
	handoffBullet(&out, text.insufficient, boolLabel(text, answer.InsufficientEvidence))
	handoffBullet(&out, text.degraded, boolLabel(text, answer.Degraded))
	handoffBullet(&out, text.model, codeSpan(answer.Model))
	handoffBullet(&out, text.reasoningAdapter, codeSpan(answer.Reasoning.Adapter))
	handoffBullet(&out, text.reasoningExecution, codeSpan(answer.Reasoning.Execution))
	handoffBullet(&out, text.egressConsent, codeSpan(answer.Reasoning.EgressConsent))
	if answer.Reasoning.AttemptedAdapter != "" {
		handoffBullet(&out, text.attemptedAdapter, codeSpan(answer.Reasoning.AttemptedAdapter))
	}
	handoffBullet(&out, text.suppressedClaims, number(claims.suppressedCount))

	fmt.Fprintf(&out, "\n## %s\n\n", text.rootCause)
	if claims.rootResolved {
		fmt.Fprintf(&out, "> %s\n\n", markdownText(answer.RootCause))
		handoffBullet(&out, text.citations, renderHandoffCitations(claims.rootCitations, anchors))
	} else {
		fmt.Fprintf(&out, "> %s\n", markdownText(text.rootWithheld))
	}

	fmt.Fprintf(&out, "\n## %s\n\n", text.findings)
	if len(claims.findings) == 0 {
		fmt.Fprintf(&out, "%s\n", markdownText(text.noFindings))
	} else {
		for index, finding := range claims.findings {
			fmt.Fprintf(&out, "%s. %s\n", number(index+1), markdownText(finding.Statement))
			fmt.Fprintf(&out, "   - **%s:** %s\n", text.citations, renderHandoffCitations(finding.Citations, anchors))
		}
	}

	fmt.Fprintf(&out, "\n## %s\n\n", text.plan)
	plan := append([]InvestigationStep(nil), answer.InvestigationPlan...)
	sort.SliceStable(plan, func(i, j int) bool {
		if plan[i].Step != plan[j].Step {
			return plan[i].Step < plan[j].Step
		}
		if plan[i].Domain != plan[j].Domain {
			return handoffTextLess(string(plan[i].Domain), string(plan[j].Domain))
		}
		return handoffTextLess(plan[i].Goal, plan[j].Goal)
	})
	if len(plan) == 0 {
		fmt.Fprintf(&out, "%s\n", markdownText(text.noPlan))
	} else {
		for _, step := range plan {
			fmt.Fprintf(&out, "%s. %s\n", number(step.Step), markdownText(step.Goal))
			handoffNestedBullet(&out, text.domain, codeSpan(string(step.Domain)))
			handoffNestedBullet(&out, text.status, codeSpan(step.Status))
			handoffNestedBullet(&out, text.readOnly, boolLabel(text, step.ReadOnly))
			handoffNestedBullet(&out, text.limit, number(step.Limit))
			handoffNestedBullet(&out, text.evidenceCount, number(step.EvidenceCount))
			handoffNestedBullet(&out, text.truncated, boolLabel(text, step.Truncated))
			if step.Reason != "" {
				handoffNestedBullet(&out, text.reason, markdownText(step.Reason))
			}
			if len(step.Selector) > 0 {
				handoffNestedBullet(&out, text.selector, codeSpan(stableHandoffJSON(step.Selector)))
			}
			if step.NodeID != "" {
				handoffNestedBullet(&out, text.node, codeSpan(step.NodeID))
			}
			if !step.WindowStart.IsZero() || !step.WindowEnd.IsZero() {
				window := formatHandoffTime(step.WindowStart) + " — " + formatHandoffTime(step.WindowEnd)
				handoffNestedBullet(&out, text.window, codeSpan(window))
			}
		}
	}

	fmt.Fprintf(&out, "\n## %s\n", text.evidence)
	if len(orderedEvidence) == 0 {
		fmt.Fprintf(&out, "\n%s\n", markdownText(text.notRecorded))
	} else {
		currentPlane := ""
		for _, item := range orderedEvidence {
			evidence := item.evidence
			plane := handoffPlane(evidence, text.otherPlane)
			if plane != currentPlane {
				fmt.Fprintf(&out, "\n### %s\n", markdownText(plane))
				currentPlane = plane
			}
			fmt.Fprintf(&out, "\n<a id=\"evidence-%d\"></a>\n", item.anchor)
			title := evidence.Title
			if title == "" {
				title = evidence.Ref
			}
			if title == "" {
				title = evidence.ID
			}
			fmt.Fprintf(&out, "#### %s — %s\n\n", markdownText(evidence.ID), markdownText(title))
			handoffBullet(&out, text.domain, codeSpan(string(evidence.Domain)))
			if evidence.Severity != "" {
				handoffBullet(&out, text.status, codeSpan(evidence.Severity))
			}
			occurred := text.notRecorded
			if !evidence.OccurredAt.IsZero() {
				occurred = codeSpan(formatHandoffTime(evidence.OccurredAt))
			}
			handoffBullet(&out, text.occurrence, occurred)
			source := text.notRecorded
			if evidence.Ref != "" {
				source = codeSpan(evidence.Ref)
			}
			handoffBullet(&out, text.source, source)
			if evidence.Summary != "" {
				handoffBullet(&out, text.summary, markdownText(evidence.Summary))
			}
			relations := citedBy[evidence.ID]
			if len(relations) == 0 {
				handoffBullet(&out, text.citedBy, text.notRecorded)
			} else {
				localized := make([]string, 0, len(relations))
				for _, relation := range relations {
					if relation == 0 {
						localized = append(localized, text.rootCauseReference)
						continue
					}
					localized = append(localized, strings.ReplaceAll(text.findingReference, "{number}", number(relation)))
				}
				handoffBullet(&out, text.citedBy, strings.Join(localized, ", "))
			}
			if len(evidence.Fields) > 0 {
				handoffBullet(&out, text.fields, codeSpan(stableHandoffJSON(evidence.Fields)))
			}
		}
	}

	fmt.Fprintf(&out, "\n## %s\n\n", text.limitations)
	fmt.Fprintf(&out, "> **%s**\n", markdownText(text.nonAuthoritativeLimit))
	return out.String()
}

func normalizeHandoffLocale(locale string) string {
	locale = strings.ToLower(strings.TrimSpace(locale))
	for _, separator := range []string{"_", "-", "."} {
		if index := strings.Index(locale, separator); index >= 0 {
			locale = locale[:index]
		}
	}
	if _, ok := handoffCopies[locale]; ok {
		return locale
	}
	return "en"
}

func resolveHandoffClaims(answer Answer) handoffClaims {
	counts := make(map[string]int, len(answer.Evidence))
	for _, evidence := range answer.Evidence {
		counts[evidence.ID]++
	}
	resolves := func(citations []Citation) bool {
		if len(citations) == 0 {
			return false
		}
		for _, citation := range citations {
			if counts[citation.EvidenceID] != 1 {
				return false
			}
		}
		return true
	}
	rootResolved := answer.RootCauseGrounded && resolves(answer.RootCauseCitations)
	findings := make([]Finding, 0, len(answer.Findings))
	for _, finding := range answer.Findings {
		if resolves(finding.Citations) {
			findings = append(findings, finding)
		}
	}
	suppressed := len(answer.Findings) - len(findings)
	if !rootResolved && !answer.InsufficientEvidence {
		suppressed++
	}
	return handoffClaims{
		rootCitations:   answer.RootCauseCitations,
		rootResolved:    rootResolved,
		findings:        findings,
		suppressedCount: suppressed,
	}
}

func orderHandoffEvidence(evidence []Evidence, otherPlane string) ([]orderedHandoffEvidence, map[string]int) {
	ordered := append([]Evidence(nil), evidence...)
	sort.SliceStable(ordered, func(i, j int) bool {
		leftPlane := handoffPlane(ordered[i], otherPlane)
		rightPlane := handoffPlane(ordered[j], otherPlane)
		if leftPlane != rightPlane {
			return handoffTextLess(leftPlane, rightPlane)
		}
		leftTime := formatHandoffTime(ordered[i].OccurredAt)
		rightTime := formatHandoffTime(ordered[j].OccurredAt)
		if leftTime != rightTime {
			return handoffTextLess(rightTime, leftTime)
		}
		if ordered[i].ID != ordered[j].ID {
			return handoffTextLess(ordered[i].ID, ordered[j].ID)
		}
		return handoffTextLess(ordered[i].Title, ordered[j].Title)
	})
	out := make([]orderedHandoffEvidence, 0, len(ordered))
	anchors := make(map[string]int, len(ordered))
	for index, item := range ordered {
		anchor := index + 1
		out = append(out, orderedHandoffEvidence{evidence: item, anchor: anchor})
		if _, exists := anchors[item.ID]; !exists {
			anchors[item.ID] = anchor
		}
	}
	return out, anchors
}

func handoffPlane(evidence Evidence, otherPlane string) string {
	if evidence.Plane != "" {
		return evidence.Plane
	}
	if evidence.Domain != "" {
		return string(evidence.Domain)
	}
	return otherPlane
}

func handoffBacklinks(claims handoffClaims) map[string][]int {
	backlinks := map[string][]int{}
	if claims.rootResolved {
		for _, citation := range claims.rootCitations {
			backlinks[citation.EvidenceID] = appendUniqueInt(backlinks[citation.EvidenceID], 0)
		}
	}
	for index, finding := range claims.findings {
		for _, citation := range finding.Citations {
			backlinks[citation.EvidenceID] = appendUniqueInt(backlinks[citation.EvidenceID], index+1)
		}
	}
	return backlinks
}

func appendUniqueInt(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func renderHandoffCitations(citations []Citation, anchors map[string]int) string {
	out := make([]string, 0, len(citations))
	for _, citation := range citations {
		anchor, ok := anchors[citation.EvidenceID]
		if !ok {
			continue
		}
		out = append(out, fmt.Sprintf("[%s](#evidence-%d)", markdownText(citation.EvidenceID), anchor))
	}
	return strings.Join(out, ", ")
}

func handoffBullet(out *strings.Builder, label, value string) {
	fmt.Fprintf(out, "- **%s:** %s\n", label, value)
}

func handoffNestedBullet(out *strings.Builder, label, value string) {
	fmt.Fprintf(out, "   - **%s:** %s\n", label, value)
}

func boolLabel(text handoffCopy, value bool) string {
	if value {
		return text.yes
	}
	return text.no
}

func formatHandoffTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	// JavaScript Date has millisecond precision. Canonicalizing both renderers
	// to that shared precision keeps the CLI and browser byte-identical even
	// when a Go source timestamp carries nanoseconds.
	return value.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano)
}

func handoffNumber(locale string, value int) string {
	raw := fmt.Sprintf("%d", value)
	if locale != "ar" {
		return raw
	}
	return strings.NewReplacer(
		"0", "٠", "1", "١", "2", "٢", "3", "٣", "4", "٤",
		"5", "٥", "6", "٦", "7", "٧", "8", "٨", "9", "٩",
	).Replace(raw)
}

// handoffTextLess defines the portable contract's text order. JSON decoding
// produces valid UTF-8, whose bytewise lexical order preserves Unicode scalar
// order. The TypeScript renderer implements that same scalar comparison
// explicitly instead of using locale-sensitive collation.
func handoffTextLess(left, right string) bool {
	return left < right
}

func stableHandoffJSON(value any) string {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	// The JSON is already protected by a Markdown code span. Disabling the
	// encoder's HTML-only escapes matches JSON.stringify while encoding/json
	// continues to canonicalize U+2028/U+2029 and control characters.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "null"
	}
	return strings.TrimSuffix(out.String(), "\n")
}

func markdownText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	var out strings.Builder
	out.Grow(len(value))
	for _, char := range value {
		switch char {
		case '&':
			out.WriteString("&amp;")
		case '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '<', '>', '#', '+', '-', '.', '!', '|', '~':
			out.WriteByte('\\')
			out.WriteRune(char)
		case '\n':
			out.WriteString("  \n")
		default:
			out.WriteRune(char)
		}
	}
	return out.String()
}

func codeSpan(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.ReplaceAll(value, "\n", " ")
	content := value
	maxRun := 0
	run := 0
	for len(value) > 0 {
		char, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		if char == '`' {
			run++
			if run > maxRun {
				maxRun = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", maxRun+1)
	return fence + " " + content + " " + fence
}
