// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/go-text/typesetting/di"
	"github.com/go-text/typesetting/font"
	ot "github.com/go-text/typesetting/font/opentype"
	"github.com/go-text/typesetting/shaping"
	"golang.org/x/image/math/fixed"
)

// PDFLimits bounds complete logical table rows, serialized bytes and renderer
// workspace. A refused document is never a partially successful report. Source
// query limits and the caller's staging storage remain separately accounted.
type PDFLimits struct{ Bytes, TableRows, MemoryBytes int64 }
type PDFReceipt struct {
	Bytes, TableRows int64
	Pages            int
}

func DefaultPDFLimits() PDFLimits {
	return PDFLimits{Bytes: 256 << 20, TableRows: 4000, MemoryBytes: 128 << 20}
}

var ErrPDFLimit = errors.New("report PDF output budget exceeded")

func RenderPDF(d Document) ([]byte, error) { return RenderPDFContext(context.Background(), d) }

func RenderPDFContext(ctx context.Context, d Document) ([]byte, error) {
	var out bytes.Buffer
	if _, err := WritePDF(ctx, &out, d, DefaultPDFLimits()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// WritePDF writes only a complete validated document to caller-owned staging.
// The caller must discard staging on ANY error, including a late writer error.
// It neither fetches fonts nor executes a browser or external rendering process.
func WritePDF(ctx context.Context, target io.Writer, d Document, limits PDFLimits) (PDFReceipt, error) {
	if err := d.Validate(); err != nil {
		return PDFReceipt{}, err
	}
	if target == nil || limits.Bytes <= 0 || limits.TableRows <= 0 || limits.MemoryBytes <= 0 {
		return PDFReceipt{}, fmt.Errorf("report PDF writer and positive limits are required")
	}
	if err := ctx.Err(); err != nil {
		return PDFReceipt{}, err
	}
	remaining := limits.MemoryBytes
	if err := chargeCSVLegacy(d, &remaining); err != nil {
		return PDFReceipt{}, ErrPDFLimit
	}
	var rows int64
	if int64(len(d.Tables)) > remaining/128 {
		return PDFReceipt{}, ErrPDFLimit
	}
	remaining -= int64(len(d.Tables)) * 128
	identities := make(map[string]bool)
	for _, table := range d.Tables {
		if identities[table.ID] {
			return PDFReceipt{}, fmt.Errorf("report table identities must be unique")
		}
		if err := validateCSVTable(table, d.TenantScope, CSVLimits(limits), &remaining); err != nil {
			if errors.Is(err, ErrCSVLimit) {
				err = ErrPDFLimit
			}
			return PDFReceipt{}, err
		}
		if table.ExpectedRows > limits.TableRows-rows {
			return PDFReceipt{}, fmt.Errorf("%w: logical rows requested=%d available=%d", ErrPDFLimit, table.ExpectedRows, limits.TableRows-rows)
		}
		rows += table.ExpectedRows
		identities[table.ID] = true
	}
	fonts, err := loadPDFFonts(ctx)
	if err != nil {
		return PDFReceipt{}, err
	}
	p := &pdfDocument{ctx: ctx, remaining: remaining, limits: limits, fonts: fonts, objects: []string{"", ""}, glyphs: make(map[pdfGlyphKey]pdfGlyph), forms: make(map[pdfOutlineKey]int)}
	p.shaper.SetFontCacheSize(len(fonts.faces))
	header := []string{Banner, "Tenant: " + d.TenantName + " (" + d.TenantScope + ")", "Absolute time: " + d.AbsoluteFrom.UTC().Format(time.RFC3339Nano) + " to " + d.AbsoluteTo.UTC().Format(time.RFC3339Nano)}
	for _, value := range header {
		lines, shapeErr := p.layout(value)
		if shapeErr != nil {
			return PDFReceipt{}, shapeErr
		}
		p.header = append(p.header, lines...)
	}
	for _, line := range p.header {
		p.headerHeight += line.height
	}
	if p.headerHeight > 300 {
		return PDFReceipt{}, fmt.Errorf("report tenant header exceeds page capacity")
	}
	if err := p.newPage(); err != nil {
		return PDFReceipt{}, err
	}
	for _, value := range []string{d.Title + " - " + d.Preset, "Generated: " + d.GeneratedAt.UTC().Format(time.RFC3339Nano) + " by " + d.GeneratedBy, "Provenance: " + strings.Join(d.Provenance, "; "), "Redaction: " + d.RedactionState, "Coverage: " + strings.Join(d.CoverageLimitations, "; "), "Exact values"} {
		if err := p.text(value); err != nil {
			return PDFReceipt{}, err
		}
	}
	keys := make([]string, 0, len(d.Metrics))
	for key := range d.Metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := p.text(key + ": " + d.Metrics[key]); err != nil {
			return PDFReceipt{}, err
		}
	}
	for _, table := range d.Tables {
		if err := p.table(table); err != nil {
			return PDFReceipt{}, fmt.Errorf("PDF table rendering: %w", err)
		}
	}
	if err := p.finish(); err != nil {
		return PDFReceipt{}, fmt.Errorf("PDF document finalization: %w", err)
	}
	writer := &boundedPDFWriter{ctx: ctx, target: target, remaining: limits.Bytes}
	if err := p.serialize(writer); err != nil {
		return PDFReceipt{}, err
	}
	return PDFReceipt{Bytes: limits.Bytes - writer.remaining, TableRows: rows, Pages: len(p.pages)}, nil
}

const pdfSize = 10
const pdfLeft, pdfRight = 44.0, 568.0

type pdfLine struct {
	text                 []rune
	runs                 shaping.Line
	height, ascent, left float64
	start, end           int
}
type pdfOutlineKey struct {
	face *font.Face
	gid  font.GID
}
type pdfGlyphKey struct {
	pdfOutlineKey
	text string
	rtl  bool
}
type pdfGlyph struct{ subset, code int }
type pdfSubset struct {
	face   *font.Face
	object int
	keys   []pdfGlyphKey
	rtl    bool
}
type pdfPage struct {
	object, content int
	stream          *pdfBuffer
}
type pdfDocument struct {
	ctx             context.Context
	remaining       int64
	limits          PDFLimits
	fonts           *pdfFontSet
	shaper          shaping.HarfbuzzShaper
	objects         []string
	glyphs          map[pdfGlyphKey]pdfGlyph
	forms           map[pdfOutlineKey]int
	graphics        map[int]bool
	subsets         []pdfSubset
	header          []pdfLine
	headerHeight, y float64
	pages           []pdfPage
}

func (p *pdfDocument) charge(n int64) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if n < 0 || n > p.remaining {
		return fmt.Errorf("%w: renderer memory requested=%d available=%d", ErrPDFLimit, n, p.remaining)
	}
	p.remaining -= n
	return nil
}

// Font parsing is a process-wide immutable public-data cache; mutable faces,
// shaping buffers, outlines, tenant strings and PDF objects are document-local.
// The conservative charge covers retained data and transient shaping buffers.
func (p *pdfDocument) layout(value string) ([]pdfLine, error) {
	if !utf8.ValidString(value) {
		return nil, fmt.Errorf("PDF text is not complete UTF-8")
	}
	if int64(len(value)) > p.remaining/256 {
		return nil, fmt.Errorf("%w: text workspace exceeds renderer memory available=%d", ErrPDFLimit, p.remaining)
	}
	if err := p.charge(int64(len(value))*256 + 512); err != nil {
		return nil, err
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return nil, fmt.Errorf("PDF text contains unsupported control U+%04X", r)
		}
	}
	var result []pdfLine
	// Hard breaks remain semantic text. Tabs have explicit em-space geometry;
	// ActualText still carries the original tab rather than substituted spaces.
	paragraphs := strings.SplitAfter(value, "\n")
	for _, paragraph := range paragraphs {
		runes := []rune(paragraph)
		if len(runes) == 0 {
			result = append(result, pdfLine{height: 15, ascent: 11})
			continue
		}
		layoutRunes := append([]rune(nil), runes...)
		for i, r := range layoutRunes {
			if r == '\r' || r == '\n' {
				layoutRunes[i] = '\u200b'
			}
			if r == '\t' {
				layoutRunes[i] = '\u2003'
			}
		}
		p.fonts.current = nil
		p.fonts.missingSet = false
		var segmenter shaping.Segmenter
		inputs := segmenter.Split(shaping.Input{Text: layoutRunes, RunEnd: len(layoutRunes), Direction: di.DirectionLTR, Size: fixed.I(pdfSize)}, p.fonts)
		if p.fonts.missingSet {
			return nil, fmt.Errorf("PDF bundled fonts do not cover U+%04X", p.fonts.missing)
		}
		outputs := make([]shaping.Output, len(inputs))
		for i, input := range inputs {
			if err := p.ctx.Err(); err != nil {
				return nil, err
			}
			outputs[i] = p.shaper.Shape(input)
		}
		var wrapper shaping.LineWrapper
		lines, truncated := wrapper.WrapParagraphF(shaping.WrapConfig{Direction: di.DirectionLTR, BreakPolicy: shaping.WhenNecessary, DisableTrailingWhitespaceTrim: true}, fixed.I(516), layoutRunes, shaping.NewSliceIterator(outputs))
		if truncated != 0 {
			return nil, fmt.Errorf("PDF layout refused truncated text")
		}
		covered := make([]bool, len(runes))
		for _, runs := range lines {
			line := pdfLine{text: runes, runs: append(shaping.Line(nil), runs...), height: 15, ascent: 11, start: len(runes)}
			clusters := make(map[int]int)
			logicalCount := 0
			// VisualIndex, not slice order, describes bidirectional placement.
			sort.Slice(line.runs, func(i, j int) bool { return line.runs[i].VisualIndex < line.runs[j].VisualIndex })
			var x, minX, maxX, descent float64
			for _, run := range line.runs {
				for _, glyph := range run.Glyphs {
					start, count := glyph.TextIndex(), glyph.RunesCount()
					if start < 0 || count < 0 || start > len(runes)-count {
						return nil, fmt.Errorf("PDF layout returned an invalid text cluster")
					}
					if previous, ok := clusters[start]; ok {
						if previous != count {
							return nil, fmt.Errorf("PDF layout changed a text cluster")
						}
					} else {
						clusters[start] = count
						logicalCount += count
						for i := start; i < start+count; i++ {
							if covered[i] {
								return nil, fmt.Errorf("PDF layout duplicated a text cluster")
							}
							covered[i] = true
						}
					}
					line.start = min(line.start, start)
					line.end = max(line.end, start+count)
					if glyph.GlyphID == 0 && !pdfClusterIgnorable(layoutRunes[start:start+count]) {
						return nil, fmt.Errorf("PDF shaping returned a missing glyph")
					}
					gx := x + float64(glyph.XOffset+glyph.XBearing)/64
					minX = math.Min(minX, gx)
					maxX = math.Max(maxX, gx+float64(glyph.Width)/64)
					line.ascent = math.Max(line.ascent, float64(glyph.YOffset+glyph.YBearing)/64)
					descent = math.Min(descent, float64(glyph.YOffset+glyph.YBearing+glyph.Height)/64)
					x += float64(glyph.Advance) / 64
				}
			}
			maxX = math.Max(maxX, x)
			if line.start > line.end {
				line.start = line.end
			}
			if line.end-line.start != logicalCount {
				return nil, fmt.Errorf("PDF layout returned a noncontiguous logical line")
			}
			line.left = math.Max(0, -minX)
			if maxX-minX > pdfRight-pdfLeft {
				return nil, fmt.Errorf("PDF unbreakable glyph cluster exceeds page width")
			}
			line.height = math.Max(line.height, line.ascent-descent+3)
			if line.height > 300 {
				return nil, fmt.Errorf("PDF glyph exceeds page height")
			}
			result = append(result, line)
		}
		for i, ok := range covered {
			if !ok {
				return nil, fmt.Errorf("PDF layout omitted text at rune %d", i)
			}
		}
	}
	return result, nil
}

func pdfClusterIgnorable(runes []rune) bool {
	if len(runes) == 0 {
		return false
	}
	for _, r := range runes {
		if !pdfIgnorable(r) {
			return false
		}
	}
	return true
}

func (p *pdfDocument) text(value string) error {
	before := p.remaining
	lines, err := p.layout(value)
	if err != nil {
		return err
	}
	workspace := before - p.remaining
	defer func() { p.remaining += workspace }()
	for _, line := range lines {
		if p.y-line.height < 60 {
			if err := p.newPage(); err != nil {
				return err
			}
		}
		if err := p.paint(line); err != nil {
			return err
		}
	}
	return nil
}

func (p *pdfDocument) newPage() error {
	if err := p.charge(512); err != nil {
		return err
	}
	pageID := p.reserve()
	contentID := p.reserve()
	p.pages = append(p.pages, pdfPage{object: pageID, content: contentID, stream: &pdfBuffer{document: p}})
	p.y = 750
	for _, line := range p.header {
		if err := p.paint(line); err != nil {
			return err
		}
	}
	p.y -= 6
	return nil
}

type pdfPlacedGlyph struct {
	key         pdfGlyphKey
	x, y, width float64
	graphic     bool
}

type pdfPaintSpan struct {
	start, end int
	rtl        bool
	glyphs     []pdfPlacedGlyph
}

func (p *pdfDocument) placedSpans(line pdfLine, baseline float64) []pdfPaintSpan {
	runs := make([]pdfPaintSpan, 0, len(line.runs))
	x := pdfLeft + line.left
	for _, run := range line.runs {
		span := pdfPaintSpan{start: len(line.text), rtl: run.Direction == di.DirectionRTL, glyphs: make([]pdfPlacedGlyph, 0, len(run.Glyphs))}
		for i := 0; i < len(run.Glyphs); {
			first := run.Glyphs[i]
			end := i + 1
			for end < len(run.Glyphs) && run.Glyphs[end].TextIndex() == first.TextIndex() {
				end++
			}
			startGlyph := len(span.glyphs)
			semantic := -1
			for j := i; j < end; j++ {
				g := run.Glyphs[j]
				width := float64(run.Face.HorizontalAdvance(g.GlyphID)) * pdfSize / float64(run.Face.Upem())
				graphic := width == 0 || g.Advance == 0 && g.Width == 0 && g.Height == 0
				placed := pdfPlacedGlyph{key: pdfGlyphKey{pdfOutlineKey: pdfOutlineKey{run.Face, g.GlyphID}, rtl: span.rtl}, x: x + float64(g.XOffset)/64, y: baseline + float64(g.YOffset)/64, width: width, graphic: graphic}
				if semantic < 0 && !graphic {
					semantic = len(span.glyphs)
				}
				span.glyphs = append(span.glyphs, placed)
				x += float64(g.Advance) / 64
			}
			if semantic < 0 {
				semantic = startGlyph
			} // A real zero-width source glyph, never a substitute.
			span.glyphs[semantic].key.text = string(line.text[first.TextIndex() : first.TextIndex()+first.RunesCount()])
			span.start = min(span.start, first.TextIndex())
			span.end = max(span.end, first.TextIndex()+first.RunesCount())
			i = end
		}
		if len(span.glyphs) > 0 {
			runs = append(runs, span)
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].start < runs[j].start })
	spans := make([]pdfPaintSpan, 0, len(runs))
	for _, run := range runs {
		if len(spans) > 0 && spans[len(spans)-1].rtl == run.rtl && spans[len(spans)-1].end == run.start {
			previous := &spans[len(spans)-1]
			previous.end = run.end
			previous.glyphs = append(previous.glyphs, run.glyphs...)
		} else {
			spans = append(spans, run)
		}
	}
	return spans
}

func (p *pdfDocument) paint(line pdfLine) error {
	stream := p.pages[len(p.pages)-1].stream
	var count int64
	for _, run := range line.runs {
		count += int64(len(run.Glyphs))
	}
	if count > p.remaining/384 {
		return fmt.Errorf("%w: glyph workspace exceeds renderer memory available=%d", ErrPDFLimit, p.remaining)
	}
	workspace := count * 384
	if err := p.charge(workspace); err != nil {
		return err
	}
	defer func() { p.remaining += workspace }()
	p.y -= line.ascent
	for _, span := range p.placedSpans(line, p.y) {
		if err := p.paintSpan(stream, line.text, span); err != nil {
			return err
		}
	}
	p.y -= line.height - line.ascent
	return stream.err
}

func (p *pdfDocument) paintSpan(stream *pdfBuffer, text []rune, span pdfPaintSpan) error {
	actual, err := pdfUnicode(string(text[span.start:span.end]))
	if err != nil {
		return err
	}
	fmt.Fprintf(stream, "/Span << /ActualText <%s> >> BDC\n", actual)
	hasText := false
	for _, g := range span.glyphs {
		hasText = hasText || !g.graphic
	}
	// Combining outlines keep their exact shaped positions without introducing
	// a zero-length replacement-text advance into the enclosing directional span.
	for i, g := range span.glyphs {
		if !g.graphic {
			continue
		}
		if !hasText && i == 0 {
			span.glyphs[i].graphic = false
			continue
		}
		form, err := p.outline(g.key.pdfOutlineKey)
		if err != nil {
			return err
		}
		if p.graphics == nil {
			p.graphics = make(map[int]bool)
		}
		if !p.graphics[form] {
			if err := p.charge(64); err != nil {
				return err
			}
			p.graphics[form] = true
		}
		scale := float64(pdfSize) / float64(g.key.face.Upem())
		fmt.Fprintf(stream, "q %.10f 0 0 %.10f %.4f %.4f cm /G%d Do Q\n", scale, scale, g.x, g.y, form)
	}
	sort.SliceStable(span.glyphs, func(i, j int) bool {
		left, right := span.glyphs[i].x, span.glyphs[j].x
		if span.rtl {
			left += span.glyphs[i].width
			right += span.glyphs[j].width
			return left > right
		}
		return left < right
	})
	for _, g := range span.glyphs {
		if g.graphic {
			continue
		}
		glyph, err := p.glyph(g.key)
		if err != nil {
			return err
		}
		x := g.x
		if span.rtl {
			x += g.width
		}
		fmt.Fprintf(stream, "BT /F%d %d Tf 1 0 0 1 %.4f %.4f Tm <%02X> Tj ET\n", glyph.subset+1, pdfSize, x, g.y, glyph.code)
	}
	fmt.Fprint(stream, "EMC\n")
	return stream.err
}

func (p *pdfDocument) table(table CSVTable) error {
	metadata := []string{"Table: " + table.Title, "Table identity: " + table.ID, "Source: " + table.Source, "Tenant scope: " + table.TenantID, "Absolute time: " + table.AbsoluteFrom.UTC().Format(time.RFC3339Nano) + " to " + table.AbsoluteTo.UTC().Format(time.RFC3339Nano), "Logical rows: " + strconv.FormatInt(table.ExpectedRows, 10)}
	if table.TagRevision != "" {
		metadata = append(metadata, "Metadata revision: "+table.TagRevision, "Metadata captured: "+table.TagAsOf.UTC().Format(time.RFC3339Nano))
	}
	for _, name := range reportFieldNames(table.FieldIDs) {
		metadata = append(metadata, "Field identity "+name+": "+table.FieldIDs[name])
	}
	for _, value := range metadata {
		if err := p.text(value); err != nil {
			return err
		}
	}
	var count int64
	var rowErr error
	err := table.WalkRows(p.ctx, func(row []string) error {
		if rowErr != nil {
			return rowErr
		}
		if rowErr = p.ctx.Err(); rowErr != nil {
			return rowErr
		}
		if count >= table.ExpectedRows {
			rowErr = fmt.Errorf("report table row count differs from its captured source")
			return rowErr
		}
		if len(row) != len(table.Columns) {
			rowErr = fmt.Errorf("report table row schema differs from its captured source")
			return rowErr
		}
		if rowErr = p.text("Row " + strconv.FormatInt(count+1, 10)); rowErr != nil {
			return rowErr
		}
		for i, value := range row {
			if table.Columns[i].Numeric && !csvDecimal(value) {
				rowErr = fmt.Errorf("report table numeric cell is not a canonical exact decimal")
				return rowErr
			}
			if int64(len(value)) > p.remaining/256 {
				rowErr = fmt.Errorf("%w: cell workspace exceeds renderer memory available=%d", ErrPDFLimit, p.remaining)
				return rowErr
			}
			if rowErr = p.text(table.Columns[i].Name + ": " + value); rowErr != nil {
				return rowErr
			}
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	if count != table.ExpectedRows {
		return fmt.Errorf("report table row count differs from its captured source")
	}
	return nil
}

func (p *pdfDocument) reserve() int { p.objects = append(p.objects, ""); return len(p.objects) }
func (p *pdfDocument) object(body string) (int, error) {
	if err := p.charge(int64(len(body))*2 + 128); err != nil {
		return 0, err
	}
	id := p.reserve()
	p.objects[id-1] = body
	return id, nil
}
func (p *pdfDocument) stream(body string, dictionary string) (int, error) {
	return p.object(fmt.Sprintf("<< /Length %d %s >>\nstream\n%sendstream", len(body), dictionary, body))
}

func (p *pdfDocument) glyph(key pdfGlyphKey) (pdfGlyph, error) {
	if glyph, ok := p.glyphs[key]; ok {
		return glyph, nil
	}
	if err := p.charge(512 + int64(len(key.text))*4); err != nil {
		return pdfGlyph{}, err
	}
	subset := -1
	for i := range p.subsets {
		if p.subsets[i].face == key.face && p.subsets[i].rtl == key.rtl && len(p.subsets[i].keys) < 255 {
			subset = i
			break
		}
	}
	if subset < 0 {
		subset = len(p.subsets)
		p.subsets = append(p.subsets, pdfSubset{face: key.face, object: p.reserve(), rtl: key.rtl})
	}
	p.subsets[subset].keys = append(p.subsets[subset].keys, key)
	glyph := pdfGlyph{subset: subset, code: len(p.subsets[subset].keys)}
	p.glyphs[key] = glyph
	return glyph, nil
}

func (p *pdfDocument) outline(key pdfOutlineKey) (int, error) {
	if id, ok := p.forms[key]; ok {
		return id, nil
	}
	outline, ok := key.face.GlyphDataOutline(key.gid)
	if key.gid == 0 {
		outline = font.GlyphOutline{}
		ok = true
	} // Only admitted for default-ignorable clusters.
	if !ok {
		return 0, fmt.Errorf("PDF font has no monochrome outline for glyph %d", key.gid)
	}
	if int64(len(outline.Segments)) > p.remaining/256 {
		return 0, ErrPDFLimit
	}
	path := &pdfBuffer{document: p}
	var current ot.SegmentPoint
	var opened bool
	minX, minY, maxX, maxY := 0.0, 0.0, 0.0, 0.0
	for _, segment := range outline.Segments {
		if segment.Op > ot.SegmentOpCubeTo {
			return 0, fmt.Errorf("PDF font outline operation is unsupported")
		}
		for _, point := range segment.ArgsSlice() {
			if math.IsNaN(float64(point.X)) || math.IsNaN(float64(point.Y)) || math.IsInf(float64(point.X), 0) || math.IsInf(float64(point.Y), 0) {
				return 0, fmt.Errorf("PDF font outline is not finite")
			}
			minX = math.Min(minX, float64(point.X))
			maxX = math.Max(maxX, float64(point.X))
			minY = math.Min(minY, float64(point.Y))
			maxY = math.Max(maxY, float64(point.Y))
		}
		a := segment.Args
		switch segment.Op {
		case ot.SegmentOpMoveTo:
			if opened {
				fmt.Fprint(path, "h\n")
			}
			fmt.Fprintf(path, "%.4f %.4f m\n", a[0].X, a[0].Y)
			current = a[0]
			opened = true
		case ot.SegmentOpLineTo:
			fmt.Fprintf(path, "%.4f %.4f l\n", a[0].X, a[0].Y)
			current = a[0]
		case ot.SegmentOpQuadTo:
			fmt.Fprintf(path, "%.4f %.4f %.4f %.4f %.4f %.4f c\n", current.X+2*(a[0].X-current.X)/3, current.Y+2*(a[0].Y-current.Y)/3, a[1].X+2*(a[0].X-a[1].X)/3, a[1].Y+2*(a[0].Y-a[1].Y)/3, a[1].X, a[1].Y)
			current = a[1]
		case ot.SegmentOpCubeTo:
			fmt.Fprintf(path, "%.4f %.4f %.4f %.4f %.4f %.4f c\n", a[0].X, a[0].Y, a[1].X, a[1].Y, a[2].X, a[2].Y)
			current = a[2]
		}
	}
	if opened {
		fmt.Fprint(path, "h f\n")
	}
	if path.err != nil {
		return 0, path.err
	}
	id, err := p.stream(path.String(), fmt.Sprintf("/Type /XObject /Subtype /Form /BBox [%.4f %.4f %.4f %.4f] /Resources << >>", minX, minY, maxX, maxY))
	if err == nil {
		p.forms[key] = id
	}
	return id, err
}

func (p *pdfDocument) finishFonts() error {
	for _, subset := range p.subsets {
		charprocs, resources, widths, encoding, cmap := &pdfBuffer{document: p}, &pdfBuffer{document: p}, &pdfBuffer{document: p}, &pdfBuffer{document: p}, &pdfBuffer{document: p}
		fmt.Fprint(cmap, "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /probectlUnicode def\n/CMapType 2 def\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n")
		var mapped []int
		minX, minY, maxX, maxY := 0.0, 0.0, 0.0, 0.0
		for i, key := range subset.keys {
			code := i + 1
			if key.text != "" {
				mapped = append(mapped, i)
			}
			form, err := p.outline(key.pdfOutlineKey)
			if err != nil {
				return err
			}
			advance := key.face.HorizontalAdvance(key.gid)
			extents, _ := key.face.GlyphExtents(key.gid)
			left, bottom, right, top := float64(extents.XBearing), float64(extents.YBearing+extents.Height), float64(extents.XBearing+extents.Width), float64(extents.YBearing)
			if key.gid == 0 {
				left, bottom, right, top = 0, 0, 0, 0
			}
			shift := float64(0)
			if subset.rtl {
				shift = float64(advance)
				left, right = shift-right, shift-left
			}
			minX = math.Min(minX, left)
			minY = math.Min(minY, bottom)
			maxX = math.Max(maxX, right)
			maxY = math.Max(maxY, top)
			body := fmt.Sprintf("%.4f 0 %.4f %.4f %.4f %.4f d1\n", advance, left, bottom, right, top)
			if subset.rtl {
				body += fmt.Sprintf("q -1 0 0 1 %.4f 0 cm /g%d Do Q\n", shift, code)
			} else {
				body += fmt.Sprintf("/g%d Do\n", code)
			}
			proc, err := p.stream(body, "")
			if err != nil {
				return err
			}
			fmt.Fprintf(charprocs, "/c%d %d 0 R ", code, proc)
			fmt.Fprintf(resources, "/g%d %d 0 R ", code, form)
			fmt.Fprintf(widths, "%.4f ", advance)
			fmt.Fprintf(encoding, "/c%d ", code)
		}
		// One visible glyph maps each source cluster; directional ActualText
		// spans retain its complete logical Unicode without duplicating marks.
		for start := 0; start < len(mapped); start += 100 {
			end := min(start+100, len(mapped))
			fmt.Fprintf(cmap, "%d beginbfchar\n", end-start)
			for _, i := range mapped[start:end] {
				text, err := pdfUnicode(subset.keys[i].text)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmap, "<%02X> <%s>\n", i+1, strings.TrimPrefix(text, "FEFF"))
			}
			fmt.Fprint(cmap, "endbfchar\n")
		}
		fmt.Fprint(cmap, "endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
		for _, buf := range []*pdfBuffer{charprocs, resources, widths, encoding, cmap} {
			if buf.err != nil {
				return buf.err
			}
		}
		mapping, err := p.stream(cmap.String(), "")
		if err != nil {
			return err
		}
		scale := 1 / float64(subset.face.Upem())
		xScale := scale
		if subset.rtl {
			xScale = -scale
		}
		body := fmt.Sprintf("<< /Type /Font /Subtype /Type3 /FontBBox [%.4f %.4f %.4f %.4f] /FontMatrix [%.10f 0 0 %.10f 0 0] /CharProcs << %s >> /Encoding << /Type /Encoding /Differences [1 %s] >> /FirstChar 1 /LastChar %d /Widths [%s] /Resources << /XObject << %s >> >> /ToUnicode %d 0 R >>", minX, minY, maxX, maxY, xScale, scale, charprocs.String(), encoding.String(), len(subset.keys), widths.String(), resources.String(), mapping)
		if err := p.charge(int64(len(body))*2 + 128); err != nil {
			return err
		}
		p.objects[subset.object-1] = body
	}
	return nil
}

func (p *pdfDocument) finish() error {
	// Footer shaping can add glyphs; finalize fonts only after every page footer.
	total := len(p.pages)
	for i := range p.pages {
		lines, err := p.layout(fmt.Sprintf("Page %d of %d", i+1, total))
		if err != nil {
			return err
		}
		if len(lines) != 1 {
			return fmt.Errorf("PDF footer exceeds page width")
		}
		last := len(p.pages) - 1
		p.pages[i], p.pages[last] = p.pages[last], p.pages[i]
		p.y = 42 + lines[0].ascent
		err = p.paint(lines[0])
		p.pages[i], p.pages[last] = p.pages[last], p.pages[i]
		if err != nil {
			return err
		}
	}
	if err := p.finishFonts(); err != nil {
		return err
	}
	resources := &pdfBuffer{document: p}
	for i, subset := range p.subsets {
		fmt.Fprintf(resources, "/F%d %d 0 R ", i+1, subset.object)
	}
	if resources.err != nil {
		return resources.err
	}
	graphics := &pdfBuffer{document: p}
	ids := make([]int, 0, len(p.graphics))
	for id := range p.graphics {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		fmt.Fprintf(graphics, "/G%d %d 0 R ", id, id)
	}
	if graphics.err != nil {
		return graphics.err
	}
	kids := &pdfBuffer{document: p}
	for _, page := range p.pages {
		if page.stream.err != nil {
			return page.stream.err
		}
		body := page.stream.String()
		if err := p.charge(int64(len(body))*2 + 256); err != nil {
			return err
		}
		p.objects[page.content-1] = fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(body), body)
		p.objects[page.object-1] = fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << %s >> /XObject << %s >> >> /Contents %d 0 R >>", resources.String(), graphics.String(), page.content)
		fmt.Fprintf(kids, "%d 0 R ", page.object)
	}
	if kids.err != nil {
		return kids.err
	}
	p.objects[0] = "<< /Type /Catalog /Pages 2 0 R >>"
	p.objects[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), len(p.pages))
	return p.ctx.Err()
}

func (p *pdfDocument) serialize(out *boundedPDFWriter) error {
	fmt.Fprint(out, "%PDF-1.4\n%\xD0\xD4\xC5\xD8\n")
	if int64(len(p.objects)) > p.remaining/16 {
		return ErrPDFLimit
	}
	offsets := make([]int64, len(p.objects))
	for i, object := range p.objects {
		if object == "" {
			return fmt.Errorf("PDF contains an incomplete object")
		}
		offsets[i] = p.limits.Bytes - out.remaining
		fmt.Fprintf(out, "%d 0 obj\n%s\nendobj\n", i+1, object)
		if out.err != nil {
			return out.err
		}
	}
	xref := p.limits.Bytes - out.remaining
	fmt.Fprintf(out, "xref\n0 %d\n0000000000 65535 f \n", len(p.objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(p.objects)+1, xref)
	if out.err != nil {
		return out.err
	}
	return p.ctx.Err()
}

func pdfUnicode(text string) (string, error) {
	if !utf8.ValidString(text) {
		return "", fmt.Errorf("PDF semantic text is not complete UTF-8")
	}
	if len(text) > 3*32766 {
		return "", ErrPDFLimit
	}
	units := utf16.Encode([]rune(text))
	if len(units) > 32766 {
		return "", ErrPDFLimit
	}
	encoded := make([]byte, 2+2*len(units))
	encoded[0] = 0xfe
	encoded[1] = 0xff
	for i, u := range units {
		encoded[2+2*i] = byte(u >> 8)
		encoded[3+2*i] = byte(u)
	}
	return strings.ToUpper(hex.EncodeToString(encoded)), nil
}

type pdfBuffer struct {
	document *pdfDocument
	strings.Builder
	err error
}

func (b *pdfBuffer) Write(body []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.err = b.document.charge(int64(len(body)) * 2); b.err != nil {
		return 0, b.err
	}
	return b.Builder.Write(body)
}

type boundedPDFWriter struct {
	ctx       context.Context
	target    io.Writer
	remaining int64
	err       error
}

func (w *boundedPDFWriter) Write(body []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.err = w.ctx.Err(); w.err != nil {
		return 0, w.err
	}
	if int64(len(body)) > w.remaining {
		w.err = fmt.Errorf("%w: serialized bytes requested=%d available=%d", ErrPDFLimit, len(body), w.remaining)
		return 0, w.err
	}
	n, err := w.target.Write(body)
	w.remaining -= int64(n)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}
