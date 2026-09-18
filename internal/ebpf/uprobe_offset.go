// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"
)

// Resolving a uprobe target ourselves, rather than through
// link.OpenExecutable.
//
// DPR-125: cilium/ebpf refuses any uprobe target without an execute bit, and
// Debian and Ubuntu package shared libraries 0644 — so on the distributions
// most operators run, the TLS capture could not attach to libssl at all. That
// check is the LIBRARY's policy, not the kernel's: trace_uprobe.c requires a
// regular file (d_is_reg) and says nothing about the execute bit. Attaching
// without going through OpenExecutable therefore needs two things the library
// was doing for us — the symbol's file offset, computed here, and the perf
// event itself, created in uprobe_tracefs_linux.go.
//
// This file has no build tag on purpose. debug/elf is portable, the arithmetic
// is where the subtle mistakes live, and a test that only runs on a Linux
// machine with an eBPF toolchain is a test that does not run.

// errSymbolNotFound is returned when the library has no such symbol. It is
// distinct so a caller can say "this library is the wrong one" rather than
// "the file is broken".
var errSymbolNotFound = errors.New("symbol not found")

// symbolFileOffset returns the file offset of symbol in an ELF image: what the
// kernel wants for a uprobe, which is not the symbol's virtual address.
//
// A symbol's st_value is a virtual address in the image's own address space.
// The kernel probes a file, so the address is translated through the PT_LOAD
// segment that contains it: offset = value - vaddr + file offset. Sections
// would usually give the same answer and do not have to; the loadable segment
// is what the kernel actually maps.
func symbolFileOffset(f *elf.File, symbol string) (uint64, error) {
	sym, err := lookupSymbol(f, symbol)
	if err != nil {
		return 0, err
	}
	// An indirect function is resolved at load time, so its st_value is a
	// resolver, not the implementation. Probing it silently measures the wrong
	// code, which is worse than refusing.
	if elf.ST_TYPE(sym.Info) == elf.STT_GNU_IFUNC {
		return 0, fmt.Errorf("%q is an indirect function (STT_GNU_IFUNC): its address is chosen at load time, so a static uprobe would attach to the resolver", symbol)
	}
	if sym.Section == elf.SHN_UNDEF {
		return 0, fmt.Errorf("%q is undefined in this image (it is imported, not implemented here)", symbol)
	}
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		// Memsz, not Filesz: a symbol in .bss has no file bytes, and catching
		// that here gives a better error than an offset past the end of file.
		if sym.Value < prog.Vaddr || sym.Value >= prog.Vaddr+prog.Memsz {
			continue
		}
		if sym.Value >= prog.Vaddr+prog.Filesz {
			return 0, fmt.Errorf("%q lives in a segment with no file backing (.bss or similar), so there is nothing to probe", symbol)
		}
		return sym.Value - prog.Vaddr + prog.Off, nil
	}
	return 0, fmt.Errorf("%q at 0x%x is in no PT_LOAD segment of this image", symbol, sym.Value)
}

// lookupSymbol finds symbol in the dynamic table first and the static table
// second, matching a versioned name (SSL_write@@OPENSSL_3.0.0) on its base.
func lookupSymbol(f *elf.File, symbol string) (elf.Symbol, error) {
	// A shared library exports through .dynsym; .symtab is often stripped, and
	// when both exist the dynamic one is what a caller actually calls.
	dyn, dynErr := f.DynamicSymbols()
	if sym, ok := matchSymbol(dyn, symbol); ok {
		return sym, nil
	}
	static, staticErr := f.Symbols()
	if sym, ok := matchSymbol(static, symbol); ok {
		return sym, nil
	}
	// Both tables missing is a different problem from the symbol being absent.
	if isMissingTable(dynErr) && isMissingTable(staticErr) {
		return elf.Symbol{}, fmt.Errorf("image has neither a dynamic nor a static symbol table: %w", errSymbolNotFound)
	}
	return elf.Symbol{}, fmt.Errorf("%q: %w", symbol, errSymbolNotFound)
}

func matchSymbol(syms []elf.Symbol, want string) (elf.Symbol, bool) {
	var versioned elf.Symbol
	var haveVersioned bool
	for _, s := range syms {
		if s.Name == want {
			return s, true
		}
		// "SSL_write@@OPENSSL_3.0.0" is the default version of SSL_write;
		// "SSL_write@OPENSSL_1.1.0" is a compatibility alias. Prefer an exact
		// name, then the default version, and take an alias only if nothing
		// better exists.
		base, ver, cut := strings.Cut(s.Name, "@")
		if !cut || base != want {
			continue
		}
		if strings.HasPrefix(ver, "@") {
			return s, true // @@ — the default version
		}
		if !haveVersioned {
			versioned, haveVersioned = s, true
		}
	}
	return versioned, haveVersioned
}

func isMissingTable(err error) bool {
	return errors.Is(err, elf.ErrNoSymbols)
}
