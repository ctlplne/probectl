// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PDFJSONFile is an already sealed, tenant-bound JSON evidence body. It is
// copied as a passive PDF attachment; it cannot add actions, scripts or URLs.
// Its request owner retains and closes Body after rendering/publication.
type PDFJSONFile struct {
	Name string
	Body *BodyStage
}
type pdfSealedFile struct {
	body    *BodyStage
	receipt BodyStageReceipt
}
type pdfFileName struct {
	name   string
	object int
}

func (p *pdfDocument) embedJSONFile(table CSVTable) error {
	file := table.PDFFile
	bound, ok := tenancy.FromContext(p.ctx)
	if !ok || bound.String() != table.TenantID || file == nil || file.Body == nil {
		return ErrBodyStageScope
	}
	if !strings.HasSuffix(file.Name, ".json") || file.Name == ".json" {
		return fmt.Errorf("PDF evidence file requires a JSON filename")
	}
	for _, c := range file.Name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("PDF evidence filename must be a plain local name")
		}
	}
	for _, existing := range p.files {
		if existing.name == file.Name {
			return fmt.Errorf("PDF evidence filenames must be unique")
		}
	}
	if err := p.charge(int64(len(file.Name))*16 + 1024 + 32<<10); err != nil {
		return err
	}
	receipt, err := file.Body.Receipt(p.ctx)
	if err != nil {
		return err
	}
	if receipt.Bytes <= 0 || receipt.Bytes > p.limits.Bytes {
		return ErrPDFLimit
	}
	embedded := p.reserve()
	p.objects[embedded-1] = pdfObject{file: &pdfSealedFile{body: file.Body, receipt: receipt}}
	unicode, err := pdfUnicode(file.Name)
	if err != nil {
		return err
	}
	name := hex.EncodeToString([]byte(file.Name))
	spec, err := p.object(fmt.Sprintf("<< /Type /Filespec /F <%s> /UF <%s> /EF << /F %d 0 R /UF %d 0 R >> >>", name, unicode, embedded, embedded))
	if err != nil {
		return err
	}
	p.files = append(p.files, pdfFileName{file.Name, spec})
	for _, value := range []string{"Complete signed originals: " + file.Name, "Attachment bytes: " + fmt.Sprint(receipt.Bytes), "Attachment SHA256: " + receipt.SHA256, "Extract the complete JSON attachment with your PDF reader; verify it offline using the deployment signing fingerprint obtained out of band."} {
		if err := p.text(value); err != nil {
			return err
		}
	}
	return nil
}

func (p *pdfDocument) fileCatalog() (string, error) {
	if len(p.files) == 0 {
		return "", nil
	}
	sort.Slice(p.files, func(i, j int) bool { return p.files[i].name < p.files[j].name })
	names := &pdfBuffer{document: p}
	fmt.Fprint(names, "/Names << /EmbeddedFiles << /Names [")
	for _, file := range p.files {
		name, err := pdfUnicode(file.name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(names, "<%s> %d 0 R ", name, file.object)
	}
	fmt.Fprint(names, "] >> >>")
	return names.String(), names.err
}

func (p *pdfDocument) serializeFile(out *boundedPDFWriter, id int, file *pdfSealedFile) error {
	reader, err := file.body.Open(p.ctx)
	if err != nil {
		return err
	}
	defer reader.Close()
	fmt.Fprintf(out, "%d 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fjson /Params << /Size %d >> /Length %d >>\nstream\n", id, file.receipt.Bytes, file.receipt.Bytes)
	if out.err != nil {
		return out.err
	}
	before := out.remaining
	digest, err := crypto.HashReader(io.TeeReader(reader, out))
	if err != nil {
		return err
	}
	if before-out.remaining != file.receipt.Bytes || hex.EncodeToString(digest) != file.receipt.SHA256 {
		return fmt.Errorf("PDF evidence attachment integrity changed")
	}
	fmt.Fprint(out, "\nendstream\nendobj\n")
	return out.err
}
