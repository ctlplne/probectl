// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"context"
	"embed"
	"encoding/hex"
	"fmt"
	"sync"
	"unicode"

	"github.com/go-text/typesetting/font"
	ot "github.com/go-text/typesetting/font/opentype"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Source bytes and licenses are pinned in third_party/vendored-assets.json.
// There is no system-font discovery, caller-provided font or network fallback.
//
//go:embed fonts/*.ttf
var pdfFontFiles embed.FS

type pdfFontSpec struct{ name, path, digest string }
type pdfParsedFont struct {
	name string
	font *font.Font
}

var pdfFontsOnce sync.Once
var pdfParsedFonts []pdfParsedFont
var pdfFontsError error

func loadPDFFonts(ctx context.Context) (*pdfFontSet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Only immutable public font parsing is shared. Cancellation of the first
	// request cannot poison this cache; no tenant data enters its initialization.
	pdfFontsOnce.Do(func() {
		pdfParsedFonts, pdfFontsError = parsePDFFonts(pdfFontFiles, pdfBundledFontSpecs)
	})
	if pdfFontsError != nil {
		return nil, pdfFontsError
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	set := &pdfFontSet{}
	for _, parsed := range pdfParsedFonts {
		face := font.NewFace(parsed.font)
		face.SetVariations([]font.Variation{{Tag: ot.MustNewTag("wght"), Value: 400}})
		set.faces = append(set.faces, face)
	}
	return set, nil
}

type pdfFontReader interface{ ReadFile(string) ([]byte, error) }

func parsePDFFonts(files pdfFontReader, specs []pdfFontSpec) ([]pdfParsedFont, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("PDF font inventory is unavailable")
	}
	var fonts []pdfParsedFont
	var total int64
	for _, spec := range specs {
		body, err := files.ReadFile(spec.path)
		if err != nil {
			return nil, fmt.Errorf("PDF font %s is unavailable: %w", spec.name, err)
		}
		total += int64(len(body))
		if len(body) > 32<<20 || total > 64<<20 || hex.EncodeToString(crypto.Hash(body)) != spec.digest {
			return nil, fmt.Errorf("PDF font %s failed provenance verification", spec.name)
		}
		face, err := font.ParseTTF(bytes.NewReader(body))
		if err != nil || face == nil || face.Upem() == 0 {
			return nil, fmt.Errorf("PDF font %s could not be parsed", spec.name)
		}
		fonts = append(fonts, pdfParsedFont{name: spec.name, font: face.Font})
	}
	return fonts, nil
}

// Faces and the fallback cursor are per document: font.Face is mutable and
// explicitly not safe for concurrent use. Parsed font.Font objects are read-only.
type pdfFontSet struct {
	faces      []*font.Face
	current    *font.Face
	missing    rune
	missingSet bool
}

func (f *pdfFontSet) ResolveFace(r rune) *font.Face {
	if f.current != nil && (pdfIgnorable(r) || unicode.IsMark(r)) {
		if _, ok := f.current.NominalGlyph(r); ok || pdfIgnorable(r) {
			return f.current
		}
	}
	for _, face := range f.faces {
		if glyph, ok := face.NominalGlyph(r); ok && glyph != 0 {
			f.current = face
			return face
		}
	}
	if !pdfIgnorable(r) && !f.missingSet {
		f.missing = r
		f.missingSet = true
	}
	return f.faces[0] // Required by Fontmap; the caller checks missing before painting.
}

func pdfIgnorable(r rune) bool {
	return unicode.Is(unicode.Cf, r) || r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0100 && r <= 0xe01ef
}
