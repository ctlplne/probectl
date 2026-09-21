// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// The fixture is a hand-built ELF64 shared object rather than a compiled one,
// because the thing under test is address arithmetic and the cases that matter
// are awkward to produce with a compiler on demand: a symbol in a second
// PT_LOAD whose vaddr and file offset differ by a different amount from the
// first, a versioned symbol, an IFUNC, an undefined import, and a symbol with
// no file bytes behind it. A compiled fixture would also need a C toolchain and
// a Linux host, which would mean this test did not run where it is written.

type fixtureSym struct {
	name    string
	value   uint64
	info    byte
	section elf.SectionIndex
}

type fixtureSeg struct {
	vaddr  uint64
	off    uint64
	filesz uint64
	memsz  uint64
}

// buildSharedObject writes a minimal but genuinely parseable ELF64 little-endian
// ET_DYN image with a .dynsym/.dynstr pair.
func buildSharedObject(t *testing.T, segs []fixtureSeg, syms []fixtureSym) []byte {
	t.Helper()
	const (
		ehdrSize = 64
		phdrSize = 56
		shdrSize = 64
		symSize  = 24
	)

	// .dynstr
	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	nameOff := map[string]uint32{"": 0}
	for _, s := range syms {
		if _, ok := nameOff[s.name]; ok {
			continue
		}
		nameOff[s.name] = uint32(dynstr.Len())
		dynstr.WriteString(s.name)
		dynstr.WriteByte(0)
	}

	// .dynsym — index 0 is the reserved null entry.
	var dynsym bytes.Buffer
	dynsym.Write(make([]byte, symSize))
	for _, s := range syms {
		var e [symSize]byte
		binary.LittleEndian.PutUint32(e[0:], nameOff[s.name])
		e[4] = s.info
		e[5] = 0
		binary.LittleEndian.PutUint16(e[6:], uint16(s.section))
		binary.LittleEndian.PutUint64(e[8:], s.value)
		binary.LittleEndian.PutUint64(e[16:], 8) // st_size
		dynsym.Write(e[:])
	}

	shstr := []byte("\x00.dynsym\x00.dynstr\x00.shstrtab\x00")
	offDynsym := uint32(1)
	offDynstr := uint32(9)
	offShstrtab := uint32(17)

	phoff := uint64(ehdrSize)
	dynsymOff := phoff + uint64(len(segs)*phdrSize)
	dynstrOff := dynsymOff + uint64(dynsym.Len())
	shstrOff := dynstrOff + uint64(dynstr.Len())
	shoff := shstrOff + uint64(len(shstr))

	buf := &bytes.Buffer{}
	// Ehdr
	hdr := make([]byte, ehdrSize)
	copy(hdr[0:], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = byte(elf.ELFCLASS64)
	hdr[5] = byte(elf.ELFDATA2LSB)
	hdr[6] = byte(elf.EV_CURRENT)
	hdr[7] = byte(elf.ELFOSABI_NONE)
	binary.LittleEndian.PutUint16(hdr[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(hdr[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(hdr[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(hdr[32:], phoff)
	binary.LittleEndian.PutUint64(hdr[40:], shoff)
	binary.LittleEndian.PutUint16(hdr[52:], ehdrSize)
	binary.LittleEndian.PutUint16(hdr[54:], phdrSize)
	binary.LittleEndian.PutUint16(hdr[56:], uint16(len(segs)))
	binary.LittleEndian.PutUint16(hdr[58:], shdrSize)
	binary.LittleEndian.PutUint16(hdr[60:], 4) // null, .dynsym, .dynstr, .shstrtab
	binary.LittleEndian.PutUint16(hdr[62:], 3) // .shstrtab index
	buf.Write(hdr)

	for _, s := range segs {
		p := make([]byte, phdrSize)
		binary.LittleEndian.PutUint32(p[0:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(p[4:], uint32(elf.PF_R|elf.PF_X))
		binary.LittleEndian.PutUint64(p[8:], s.off)
		binary.LittleEndian.PutUint64(p[16:], s.vaddr)
		binary.LittleEndian.PutUint64(p[24:], s.vaddr)
		binary.LittleEndian.PutUint64(p[32:], s.filesz)
		binary.LittleEndian.PutUint64(p[40:], s.memsz)
		binary.LittleEndian.PutUint64(p[48:], 0x1000)
		buf.Write(p)
	}
	buf.Write(dynsym.Bytes())
	buf.Write(dynstr.Bytes())
	buf.Write(shstr)

	shdr := func(name uint32, typ elf.SectionType, off, size uint64, link uint32, entsize uint64) []byte {
		s := make([]byte, shdrSize)
		binary.LittleEndian.PutUint32(s[0:], name)
		binary.LittleEndian.PutUint32(s[4:], uint32(typ))
		binary.LittleEndian.PutUint64(s[24:], off)
		binary.LittleEndian.PutUint64(s[32:], size)
		binary.LittleEndian.PutUint32(s[40:], link)
		binary.LittleEndian.PutUint64(s[56:], entsize)
		return s
	}
	buf.Write(make([]byte, shdrSize)) // SHN_UNDEF
	buf.Write(shdr(offDynsym, elf.SHT_DYNSYM, dynsymOff, uint64(dynsym.Len()), 2, symSize))
	buf.Write(shdr(offDynstr, elf.SHT_STRTAB, dynstrOff, uint64(dynstr.Len()), 0, 0))
	buf.Write(shdr(offShstrtab, elf.SHT_STRTAB, shstrOff, uint64(len(shstr)), 0, 0))
	return buf.Bytes()
}

func sym(name string, value uint64) fixtureSym {
	return fixtureSym{name: name, value: value, info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC), section: 1}
}

func openFixture(t *testing.T, raw []byte) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the fixture is not a parseable ELF: %v", err)
	}
	return f
}

// DPR-125: the number handed to the kernel is a FILE offset, and a symbol's
// st_value is a virtual address. They differ by the containing segment's
// (vaddr - file offset), which is not the same for every segment in an image —
// so an implementation that returns st_value, or that assumes one segment,
// passes a naive test and probes the wrong bytes of a real libssl.
func TestSymbolFileOffsetTranslatesThroughTheContainingSegment(t *testing.T) {
	segs := []fixtureSeg{
		{vaddr: 0x1000, off: 0x1000, filesz: 0x2000, memsz: 0x2000},
		// A second mapping whose vaddr and file offset differ by a DIFFERENT
		// amount — exactly what a real shared object looks like.
		{vaddr: 0x204000, off: 0x3000, filesz: 0x1000, memsz: 0x2000},
	}
	raw := buildSharedObject(t, segs, []fixtureSym{
		sym("SSL_write", 0x1500),
		sym("SSL_read", 0x204800),
	})
	f := openFixture(t, raw)

	for _, tc := range []struct {
		symbol string
		want   uint64
	}{
		{"SSL_write", 0x1500},                      // first segment: vaddr == off, so unchanged
		{"SSL_read", 0x204800 - 0x204000 + 0x3000}, // second: 0x3800, NOT 0x204800
	} {
		got, err := symbolFileOffset(f, tc.symbol)
		if err != nil {
			t.Fatalf("%s: %v", tc.symbol, err)
		}
		if got != tc.want {
			t.Errorf("%s: file offset = 0x%x, want 0x%x", tc.symbol, got, tc.want)
		}
	}
}

// Versioned names are the normal case in a real libssl: the dynamic table
// carries SSL_write@@OPENSSL_3.0.0, and a caller asks for SSL_write.
func TestSymbolFileOffsetMatchesAVersionedName(t *testing.T) {
	segs := []fixtureSeg{{vaddr: 0x1000, off: 0x1000, filesz: 0x2000, memsz: 0x2000}}
	f := openFixture(t, buildSharedObject(t, segs, []fixtureSym{
		sym("SSL_write@OPENSSL_1.1.0", 0x1100),  // a compatibility alias
		sym("SSL_write@@OPENSSL_3.0.0", 0x1200), // the default version
	}))
	got, err := symbolFileOffset(f, "SSL_write")
	if err != nil {
		t.Fatalf("SSL_write: %v", err)
	}
	// The default version wins: probing the compatibility alias would measure
	// an older entry point that most callers never reach.
	if got != 0x1200 {
		t.Errorf("file offset = 0x%x, want the @@ default 0x1200", got)
	}
}

func TestSymbolFileOffsetRefusesWhatCannotBeProbed(t *testing.T) {
	segs := []fixtureSeg{
		{vaddr: 0x1000, off: 0x1000, filesz: 0x1000, memsz: 0x1000},
		// A segment with memory beyond its file bytes — .bss.
		{vaddr: 0x3000, off: 0x2000, filesz: 0x100, memsz: 0x1000},
	}
	raw := buildSharedObject(t, segs, []fixtureSym{
		{name: "resolver", value: 0x1400, info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_GNU_IFUNC), section: 1},
		{name: "imported", value: 0, info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC), section: elf.SHN_UNDEF},
		sym("in_bss", 0x3900),
		sym("nowhere", 0x900000),
	})
	f := openFixture(t, raw)

	for _, tc := range []struct{ symbol, want string }{
		{"resolver", "indirect function"},
		{"imported", "undefined in this image"},
		{"in_bss", "no file backing"},
		{"nowhere", "in no PT_LOAD segment"},
	} {
		_, err := symbolFileOffset(f, tc.symbol)
		if err == nil {
			t.Errorf("%s: expected a refusal, got an offset", tc.symbol)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not say %q", tc.symbol, err, tc.want)
		}
	}
}

func TestSymbolFileOffsetSaysWhenTheSymbolIsSimplyAbsent(t *testing.T) {
	segs := []fixtureSeg{{vaddr: 0x1000, off: 0x1000, filesz: 0x1000, memsz: 0x1000}}
	f := openFixture(t, buildSharedObject(t, segs, []fixtureSym{sym("SSL_write", 0x1100)}))
	_, err := symbolFileOffset(f, "SSL_read")
	if !errors.Is(err, errSymbolNotFound) {
		t.Fatalf("want errSymbolNotFound so a caller can say the library is the wrong one, got %v", err)
	}
}
