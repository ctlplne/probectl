// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package branding

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

const (
	wcagTextContrast = 4.5
	wcagUIContrast   = 3.0
	// chipWash is the tint alpha every shipped chip and tinted panel uses.
	chipWash = 0.12
)

// chipTones are the colors that ship as text on a tint of themselves.
var chipTones = []string{
	"--brand-accent", "--status-success", "--status-warning", "--status-info",
	"--status-neutral", "--destructive", "--risk-critical", "--risk-high",
	"--risk-medium", "--risk-low", "--risk-none",
}

type contrastColor struct {
	r float64
	g float64
	b float64
	a float64
}

type contrastPair struct {
	fg       string
	bg       string
	min      float64
	backdrop string
	// bgAlpha checks bg as a wash at this alpha over backdrop, the way a chip
	// ships. Zero means the background is used as-is.
	bgAlpha float64
}

// shippedContrastThemes is the base palette an operator override is validated
// against: the values web/src/styles/tokens.css actually ships, as bare HSL
// triplets. It is duplicated here because the control plane is a compiled binary
// that cannot read the web tree at runtime — palette_parity_test.go re-derives it
// from that stylesheet and fails on any drift, which is the check that was missing
// when the design-language port renamed every token and left this file validating
// a palette that no longer shipped.
var shippedContrastThemes = map[string]map[string]string{
	"light": {
		"--background":              "45 33% 95%",
		"--foreground":              "167 16% 11%",
		"--card":                    "48 100% 99%",
		"--card-foreground":         "167 16% 11%",
		"--muted":                   "75 12% 94%",
		"--muted-foreground":        "163 7% 35%",
		"--border":                  "120 7% 86%",
		"--sidebar":                 "60 15% 92%",
		"--sidebar-hover":           "108 10% 89%",
		"--sidebar-active":          "150 20% 89%",
		"--sidebar-foreground":      "163 14% 22%",
		"--primary":                 "28 85% 30%",
		"--primary-foreground":      "48 100% 99%",
		"--brand-accent":            "28 85% 30%",
		"--brand-accent-foreground": "0 0% 100%",
		"--focus":                   "167 48% 33%",
		"--destructive":             "3 53% 35%",
		"--destructive-foreground":  "0 0% 100%",
		"--status-success":          "166 55% 20%",
		"--status-warning":          "40 86% 27%",
		"--status-info":             "199 49% 31%",
		"--status-neutral":          "163 7% 36%",
		"--monitor":                 "199 49% 31%",
		"--monitor-foreground":      "0 0% 100%",
		"--analyze":                 "251 85% 62%",
		"--analyze-foreground":      "0 0% 100%",
		"--secure":                  "3 53% 35%",
		"--secure-foreground":       "0 0% 100%",
		"--operate":                 "28 85% 30%",
		"--operate-foreground":      "0 0% 100%",
		"--risk-critical":           "3 53% 35%",
		"--risk-high":               "24 70% 34%",
		"--risk-medium":             "40 86% 27%",
		"--risk-low":                "166 55% 20%",
		"--risk-none":               "163 7% 36%",
		"--chart-1":                 "28 85% 30%",
		"--chart-2":                 "213 62% 48%",
		"--chart-3":                 "251 85% 62%",
		"--chart-4":                 "174 72% 30%",
		"--chart-5":                 "350 62% 48%",
		"--chart-6":                 "314 42% 43%",
		"--chart-grid":              "223 11% 55%",
		"--chart-axis":              "227 14% 37%",
		"--chart-neutral":           "226 11% 45%",
	},
	"dark": {
		"--background":              "165 17% 7%",
		"--foreground":              "45 22% 93%",
		"--card":                    "160 16% 10%",
		"--card-foreground":         "45 22% 93%",
		"--muted":                   "156 13% 15%",
		"--muted-foreground":        "156 7% 70%",
		"--border":                  "156 10% 22%",
		"--sidebar":                 "165 18% 8%",
		"--sidebar-hover":           "160 16% 12%",
		"--sidebar-active":          "159 18% 16%",
		"--sidebar-foreground":      "156 7% 70%",
		"--primary":                 "34 100% 66%",
		"--primary-foreground":      "30 40% 8%",
		"--brand-accent":            "34 100% 66%",
		"--brand-accent-foreground": "30 40% 8%",
		"--focus":                   "171 77% 64%",
		"--destructive":             "0 100% 72%",
		"--destructive-foreground":  "0 45% 6%",
		"--status-success":          "158 64% 52%",
		"--status-warning":          "32 95% 54%",
		"--status-info":             "218 100% 77%",
		"--status-neutral":          "207 12% 65%",
		"--monitor":                 "218 100% 77%",
		"--monitor-foreground":      "223 30% 5%",
		"--analyze":                 "254 100% 77%",
		"--analyze-foreground":      "223 30% 5%",
		"--secure":                  "0 100% 72%",
		"--secure-foreground":       "0 45% 6%",
		"--operate":                 "34 100% 66%",
		"--operate-foreground":      "30 40% 8%",
		"--risk-critical":           "0 100% 72%",
		"--risk-high":               "24 95% 58%",
		"--risk-medium":             "45 93% 56%",
		"--risk-low":                "158 64% 52%",
		"--risk-none":               "207 12% 64%",
		"--chart-1":                 "34 100% 66%",
		"--chart-2":                 "206 74% 63%",
		"--chart-3":                 "254 100% 77%",
		"--chart-4":                 "174 62% 55%",
		"--chart-5":                 "350 82% 70%",
		"--chart-6":                 "312 51% 68%",
		"--chart-grid":              "218 14% 48%",
		"--chart-axis":              "219 16% 69%",
		"--chart-neutral":           "218 12% 55%",
	},
}

var requiredContrastPairs = buildContrastPairs()

// buildContrastPairs mirrors buildContrastPairs() in web/src/api/brand.ts. Both
// sides validate the same pairs so an override cannot pass the control plane and
// then be silently dropped by the browser.
func buildContrastPairs() []contrastPair {
	pairs := make([]contrastPair, 0, 80)
	// Body text must clear 4.5:1 on every surface it can land on, including the
	// rail, which is its own tint rather than the page background.
	backgrounds := []string{"--background", "--card", "--muted", "--sidebar"}
	for _, fg := range []string{"--foreground", "--muted-foreground"} {
		for _, bg := range backgrounds {
			pairs = append(pairs, contrastPair{fg: fg, bg: bg, min: wcagTextContrast})
		}
	}
	// A label on a filled action or a filled status is body text, so 4.5:1 too.
	for _, pair := range [][2]string{
		{"--primary-foreground", "--primary"},
		{"--brand-accent-foreground", "--brand-accent"},
		{"--destructive-foreground", "--destructive"},
		{"--monitor-foreground", "--monitor"},
		{"--analyze-foreground", "--analyze"},
		{"--secure-foreground", "--secure"},
		{"--operate-foreground", "--operate"},
	} {
		pairs = append(pairs, contrastPair{fg: pair[0], bg: pair[1], min: wcagTextContrast})
	}
	// A chip is colored text on a chipWash tint of itself, composited over
	// whatever it sits on — a card, a table header or hovered row (--muted), the
	// page, or the rail. Checking the tone against the plain card instead was
	// flattering: five light tones measured 3.94-4.30 in a real browser while this
	// function called them passing. The plain pair is kept too, because a tone is
	// also used as text directly on a surface.
	for _, tone := range chipTones {
		for _, bg := range backgrounds {
			pairs = append(pairs, contrastPair{fg: tone, bg: bg, min: wcagTextContrast})
			pairs = append(pairs, contrastPair{fg: tone, bg: tone, min: wcagTextContrast, backdrop: bg, bgAlpha: chipWash})
			// Secondary text inside a tinted panel, e.g. a <dt> on an info wash.
			pairs = append(pairs, contrastPair{fg: "--muted-foreground", bg: tone, min: wcagTextContrast, backdrop: bg, bgAlpha: chipWash})
		}
	}
	// Non-text graphics — focus ring, series strokes, axes — need 3:1. Series
	// also carry dash patterns, so color is never the only channel.
	for _, fg := range []string{
		"--focus", "--chart-1", "--chart-2", "--chart-3", "--chart-4", "--chart-5",
		"--chart-6", "--chart-grid", "--chart-axis", "--chart-neutral",
	} {
		for _, bg := range backgrounds {
			pairs = append(pairs, contrastPair{fg: fg, bg: bg, min: wcagUIContrast})
		}
	}
	return pairs
}

// isColorToken reports whether the shipped palette defines name. The palette IS
// the color allowlist, so a color token becomes overridable the moment it ships
// and a name the palette does not define can never be set from a deployment
// config — the same rule web/src/api/brand.ts applies on the client.
func isColorToken(name string) bool {
	for _, theme := range shippedContrastThemes {
		if _, ok := theme[name]; ok {
			return true
		}
	}
	return false
}

func validateOverrideContrast(overrides map[string]string) error {
	for theme, base := range shippedContrastThemes {
		tokens := make(map[string]string, len(base)+len(overrides))
		for name, value := range base {
			tokens[name] = value
		}
		for name, value := range overrides {
			if isColorToken(name) {
				tokens[name] = strings.TrimSpace(value)
			}
		}
		for _, pair := range requiredContrastPairs {
			fgValue, ok := tokens[pair.fg]
			if !ok {
				continue
			}
			bgValue, ok := tokens[pair.bg]
			if !ok {
				continue
			}
			if pair.bgAlpha > 0 {
				bgValue = fmt.Sprintf("%s / %g", bgValue, pair.bgAlpha)
			}
			fg, err := parseContrastColor(fgValue)
			if err != nil {
				return fmt.Errorf("branding: cannot parse %s for contrast: %w", pair.fg, err)
			}
			bg, err := parseContrastColor(bgValue)
			if err != nil {
				return fmt.Errorf("branding: cannot parse %s for contrast: %w", pair.bg, err)
			}
			if bg.a < 1 {
				backdrop := contrastColor{r: 1, g: 1, b: 1, a: 1}
				if pair.backdrop != "" {
					if backdropValue, ok := tokens[pair.backdrop]; ok {
						if parsed, err := parseContrastColor(backdropValue); err == nil {
							backdrop = parsed
						}
					}
				}
				bg = composite(bg, backdrop)
			}
			if fg.a < 1 {
				fg = composite(fg, bg)
			}
			if ratio := contrastRatio(fg, bg); ratio+1e-9 < pair.min {
				return fmt.Errorf("branding: %s contrast %.2f:1 against %s in %s theme is below %.1f:1", pair.fg, ratio, pair.bg, theme, pair.min)
			}
		}
	}
	return nil
}

func parseContrastColor(value string) (contrastColor, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasPrefix(value, "#") {
		return parseHexColor(value)
	}
	if strings.HasPrefix(value, "rgb(") || strings.HasPrefix(value, "rgba(") {
		return parseRGBColor(value)
	}
	if strings.HasPrefix(value, "hsl(") || strings.HasPrefix(value, "hsla(") {
		return parseHSLColor(value)
	}
	return parseHSLTriplet(value)
}

// hslTripletRe matches the bare triplet every design token now holds:
// "45 33% 95%", or "45 33% 95% / 0.12" for a soft tint. The stylesheet wraps
// these as hsl(var(--token) / <alpha-value>), so a token value is never itself a
// color function and every branch above would miss it.
var hslTripletRe = regexp.MustCompile(`^(-?[0-9.]+)\s+(-?[0-9.]+)%\s+(-?[0-9.]+)%(?:\s*/\s*([0-9.]+%?))?$`)

func parseHSLTriplet(value string) (contrastColor, error) {
	m := hslTripletRe.FindStringSubmatch(value)
	if m == nil {
		return contrastColor{}, fmt.Errorf("unsupported color %q", value)
	}
	alpha := "1"
	if m[4] != "" {
		alpha = m[4]
	}
	return parseHSLColor(fmt.Sprintf("hsl(%s %s%% %s%% / %s)", m[1], m[2], m[3], alpha))
}

func parseHexColor(value string) (contrastColor, error) {
	hex := strings.TrimPrefix(value, "#")
	switch len(hex) {
	case 3, 4:
		var expanded strings.Builder
		for _, ch := range hex {
			expanded.WriteRune(ch)
			expanded.WriteRune(ch)
		}
		hex = expanded.String()
	case 6, 8:
	default:
		return contrastColor{}, fmt.Errorf("invalid hex length")
	}
	parse := func(part string) (float64, error) {
		n, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return 0, err
		}
		return float64(n) / 255, nil
	}
	r, err := parse(hex[0:2])
	if err != nil {
		return contrastColor{}, err
	}
	g, err := parse(hex[2:4])
	if err != nil {
		return contrastColor{}, err
	}
	b, err := parse(hex[4:6])
	if err != nil {
		return contrastColor{}, err
	}
	a := 1.0
	if len(hex) == 8 {
		a, err = parse(hex[6:8])
		if err != nil {
			return contrastColor{}, err
		}
	}
	return contrastColor{r: r, g: g, b: b, a: a}, nil
}

func parseRGBColor(value string) (contrastColor, error) {
	args, err := colorFunctionArgs(value)
	if err != nil {
		return contrastColor{}, err
	}
	if len(args) < 3 || len(args) > 4 {
		return contrastColor{}, fmt.Errorf("rgb expects 3 or 4 components")
	}
	r, err := parseRGBComponent(args[0])
	if err != nil {
		return contrastColor{}, err
	}
	g, err := parseRGBComponent(args[1])
	if err != nil {
		return contrastColor{}, err
	}
	b, err := parseRGBComponent(args[2])
	if err != nil {
		return contrastColor{}, err
	}
	a := 1.0
	if len(args) == 4 {
		a, err = parseAlpha(args[3])
		if err != nil {
			return contrastColor{}, err
		}
	}
	return contrastColor{r: r, g: g, b: b, a: a}, nil
}

func parseHSLColor(value string) (contrastColor, error) {
	args, err := colorFunctionArgs(value)
	if err != nil {
		return contrastColor{}, err
	}
	if len(args) < 3 || len(args) > 4 {
		return contrastColor{}, fmt.Errorf("hsl expects 3 or 4 components")
	}
	h, err := parseHue(args[0])
	if err != nil {
		return contrastColor{}, err
	}
	s, err := parsePercent(args[1])
	if err != nil {
		return contrastColor{}, err
	}
	l, err := parsePercent(args[2])
	if err != nil {
		return contrastColor{}, err
	}
	a := 1.0
	if len(args) == 4 {
		a, err = parseAlpha(args[3])
		if err != nil {
			return contrastColor{}, err
		}
	}
	r, g, b := hslToRGB(h, s, l)
	return contrastColor{r: r, g: g, b: b, a: a}, nil
}

func colorFunctionArgs(value string) ([]string, error) {
	open := strings.IndexByte(value, '(')
	closeIdx := strings.LastIndexByte(value, ')')
	if open < 0 || closeIdx <= open {
		return nil, fmt.Errorf("invalid color function")
	}
	body := strings.NewReplacer(",", " ", "/", " ").Replace(value[open+1 : closeIdx])
	return strings.Fields(body), nil
}

func parseRGBComponent(value string) (float64, error) {
	if strings.HasSuffix(value, "%") {
		p, err := parsePercent(value)
		if err != nil {
			return 0, err
		}
		return p, nil
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 255 {
		return 0, fmt.Errorf("rgb component out of range")
	}
	return n / 255, nil
}

func parseHue(value string) (float64, error) {
	value = strings.TrimSuffix(value, "deg")
	h, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	h = math.Mod(h, 360)
	if h < 0 {
		h += 360
	}
	return h / 360, nil
}

func parsePercent(value string) (float64, error) {
	value = strings.TrimSuffix(value, "%")
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 100 {
		return 0, fmt.Errorf("percent out of range")
	}
	return n / 100, nil
}

func parseAlpha(value string) (float64, error) {
	if strings.HasSuffix(value, "%") {
		return parsePercent(value)
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 1 {
		return 0, fmt.Errorf("alpha out of range")
	}
	return n, nil
}

func hslToRGB(h, s, l float64) (float64, float64, float64) {
	if s == 0 {
		return l, l, l
	}
	var q float64
	if l < 0.5 {
		q = l * (1 + s)
	} else {
		q = l + s - l*s
	}
	p := 2*l - q
	return hueToRGB(p, q, h+1.0/3), hueToRGB(p, q, h), hueToRGB(p, q, h-1.0/3)
}

func hueToRGB(p, q, t float64) float64 {
	if t < 0 {
		t++
	}
	if t > 1 {
		t--
	}
	switch {
	case t < 1.0/6:
		return p + (q-p)*6*t
	case t < 1.0/2:
		return q
	case t < 2.0/3:
		return p + (q-p)*(2.0/3-t)*6
	default:
		return p
	}
}

func composite(over, under contrastColor) contrastColor {
	a := over.a + under.a*(1-over.a)
	if a == 0 {
		return contrastColor{}
	}
	return contrastColor{
		r: (over.r*over.a + under.r*under.a*(1-over.a)) / a,
		g: (over.g*over.a + under.g*under.a*(1-over.a)) / a,
		b: (over.b*over.a + under.b*under.a*(1-over.a)) / a,
		a: a,
	}
}

func contrastRatio(fg, bg contrastColor) float64 {
	l1 := relativeLuminance(fg)
	l2 := relativeLuminance(bg)
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

func relativeLuminance(c contrastColor) float64 {
	linear := func(v float64) float64 {
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*linear(c.r) + 0.7152*linear(c.g) + 0.0722*linear(c.b)
}
