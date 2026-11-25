// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build darwin && cgo

package crypto

/*
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

// XNU defines these in bsd/sys/codesign.h and osfmk/kern/cs_blobs.h.
// The SDK does not promise this interface. Weak-link and fail closed if it
// is unavailable. Only query the kernel's record for this process.
extern int csops(pid_t, unsigned int, void *, size_t) __attribute__((weak_import));

enum {
    probectl_cs_status = 0,
    probectl_cs_cdhash = 5,
    probectl_cs_teamid = 14,
    probectl_cs_valid = 0x00000001,
    probectl_cs_adhoc = 0x00000002,
    probectl_cs_runtime = 0x00010000,
    probectl_cs_debugged = 0x10000000,
    probectl_cs_signed = 0x20000000,
    probectl_cdhash_size = 20,
    probectl_team_id_size = 10,
    probectl_cs_blob_header_size = 8
};

struct probectl_code_directory {
    unsigned char hash[probectl_cdhash_size];
    uint32_t flags;
    unsigned char has_team_id;
};

static unsigned char probectl_has_team_id(pid_t pid) {
    unsigned char blob[probectl_cs_blob_header_size + probectl_team_id_size + 1] = {0};
    if (csops(pid, probectl_cs_teamid, blob, sizeof(blob)) != 0 ||
        (blob[4] | blob[5] | blob[6]) != 0 || blob[7] != sizeof(blob) ||
        blob[sizeof(blob) - 1] != 0) {
        return 0;
    }
    for (size_t i = probectl_cs_blob_header_size; i < sizeof(blob) - 1; i++) {
        unsigned char ch = blob[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))) {
            return 0;
        }
    }
    return 1;
}

static int probectl_read_code_directory(struct probectl_code_directory *result) {
    if (csops == NULL) {
        return ENOSYS;
    }
    pid_t pid = getpid();
    if (csops(pid, probectl_cs_cdhash, result->hash, sizeof(result->hash)) != 0) {
        return errno;
    }
    // Process status flags can omit CS_ADHOC. The team must come from the
    // kernel's record for this same image, alongside the CDHash.
    result->has_team_id = probectl_has_team_id(pid);
    if (csops(pid, probectl_cs_status, &result->flags, sizeof(result->flags)) != 0) {
        return errno;
    }
    return 0;
}
*/
import "C"

import (
	"encoding/hex"
	"fmt"
)

// RunningCodeIdentity returns the active Mach-O slice's kernel code-directory
// hash for valid, signed code under Hardened Runtime. It never opens the
// executable path, which can already name a newer installed binary.
func RunningCodeIdentity() (string, error) {
	identity, valid, err := readRunningCodeDirectory()
	if err != nil {
		return "", err
	}
	if !valid {
		return "", fmt.Errorf("%w: expected a hardened, team-signed, and undebugged image", ErrRunningCodeIdentityUnavailable)
	}
	return identity, nil
}

func readRunningCodeDirectory() (string, bool, error) {
	var result C.struct_probectl_code_directory
	if code := C.probectl_read_code_directory(&result); code != 0 {
		return "", false, fmt.Errorf("%w: macOS query failed (%d)", ErrRunningCodeIdentityUnavailable, code)
	}
	var hash [C.probectl_cdhash_size]byte
	for i, value := range result.hash {
		hash[i] = byte(value)
	}
	if hash == ([C.probectl_cdhash_size]byte{}) {
		return "", false, ErrRunningCodeIdentityUnavailable
	}
	const required = C.probectl_cs_signed | C.probectl_cs_runtime | C.probectl_cs_valid
	const mask = required | C.probectl_cs_adhoc | C.probectl_cs_debugged
	return "cdhash:" + hex.EncodeToString(hash[:]), result.has_team_id != 0 && result.flags&mask == required, nil
}
