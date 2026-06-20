// SPDX-License-Identifier: LicenseRef-probectl-TBD

package branding

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	wcagTextContrast = 4.5
	wcagUIContrast   = 3.0
)

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
}

var shippedContrastThemes = map[string]map[string]string{
	"dark": {
		"--color-bg":              "#0b0e14",
		"--color-surface":         "#11151f",
		"--color-surface-raised":  "#171c28",
		"--color-text":            "#e7eaf2",
		"--color-text-muted":      "#a6adbd",
		"--color-text-subtle":     "#808a9b",
		"--color-text-inverse":    "#0b0e14",
		"--color-accent":          "#2fb6a8",
		"--color-accent-hover":    "#3ccabb",
		"--color-accent-strong":   "#23a394",
		"--color-accent-contrast": "#04130f",
		"--color-success":         "#46c08a",
		"--color-success-soft":    "rgba(70, 192, 138, 0.14)",
		"--color-warning":         "#e0b25a",
		"--color-warning-soft":    "rgba(224, 178, 90, 0.14)",
		"--color-danger":          "#e8736b",
		"--color-danger-soft":     "rgba(232, 115, 107, 0.14)",
		"--color-info":            "#5aa9e6",
		"--color-info-soft":       "rgba(90, 169, 230, 0.14)",
		"--color-focus":           "#6fd2c6",
		"--color-chart-1":         "#2fb6a8",
		"--color-chart-2":         "#5aa9e6",
		"--color-chart-3":         "#a78bff",
		"--color-chart-4":         "#e0b25a",
		"--color-chart-5":         "#e8736b",
	},
	"aurora": {
		"--color-bg":              "#f6f7fb",
		"--color-surface":         "#ffffff",
		"--color-surface-raised":  "#ffffff",
		"--color-text":            "#1b1d2a",
		"--color-text-muted":      "#50566b",
		"--color-text-subtle":     "#676d80",
		"--color-text-inverse":    "#ffffff",
		"--color-accent":          "#6a4cf0",
		"--color-accent-hover":    "#5a3ce0",
		"--color-accent-strong":   "#4f33d6",
		"--color-accent-contrast": "#ffffff",
		"--color-success":         "#1f9d63",
		"--color-success-soft":    "rgba(31, 157, 99, 0.12)",
		"--color-warning":         "#b9821f",
		"--color-warning-soft":    "rgba(185, 130, 31, 0.12)",
		"--color-danger":          "#d2463c",
		"--color-danger-soft":     "rgba(210, 70, 60, 0.12)",
		"--color-info":            "#2f73c7",
		"--color-info-soft":       "rgba(47, 115, 199, 0.12)",
		"--color-focus":           "#6a4cf0",
		"--color-chart-1":         "#0e9e92",
		"--color-chart-2":         "#2f73c7",
		"--color-chart-3":         "#6a4cf0",
		"--color-chart-4":         "#b9821f",
		"--color-chart-5":         "#d2463c",
	},
}

var requiredContrastPairs = buildContrastPairs()

func buildContrastPairs() []contrastPair {
	text := []string{"--color-text", "--color-text-muted", "--color-text-subtle"}
	backgrounds := []string{"--color-bg", "--color-surface", "--color-surface-raised", "--color-surface-high"}
	pairs := make([]contrastPair, 0, 80)
	for _, fg := range text {
		for _, bg := range backgrounds {
			pairs = append(pairs, contrastPair{fg: fg, bg: bg, min: wcagTextContrast})
		}
	}
	for _, bg := range []string{"--color-accent", "--color-accent-hover", "--color-accent-strong"} {
		pairs = append(pairs, contrastPair{fg: "--color-accent-contrast", bg: bg, min: wcagTextContrast})
	}
	for _, bg := range []string{"--color-accent-soft", "--color-success-soft", "--color-warning-soft", "--color-danger-soft", "--color-info-soft"} {
		pairs = append(pairs, contrastPair{fg: "--color-text", bg: bg, min: wcagTextContrast, backdrop: "--color-surface"})
	}
	for _, fg := range []string{
		"--color-accent", "--color-accent-hover", "--color-accent-strong", "--color-focus",
		"--color-success", "--color-warning", "--color-danger", "--color-info",
		"--color-chart-1", "--color-chart-2", "--color-chart-3", "--color-chart-4", "--color-chart-5",
	} {
		for _, bg := range backgrounds {
			pairs = append(pairs, contrastPair{fg: fg, bg: bg, min: wcagUIContrast})
		}
	}
	return pairs
}

func validateOverrideContrast(overrides map[string]string) error {
	for theme, base := range shippedContrastThemes {
		tokens := make(map[string]string, len(base)+len(overrides))
		for name, value := range base {
			tokens[name] = value
		}
		for name, value := range overrides {
			if strings.HasPrefix(name, "--color-") {
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
	return contrastColor{}, fmt.Errorf("unsupported color %q", value)
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
	close := strings.LastIndexByte(value, ')')
	if open < 0 || close <= open {
		return nil, fmt.Errorf("invalid color function")
	}
	body := strings.NewReplacer(",", " ", "/", " ").Replace(value[open+1 : close])
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
