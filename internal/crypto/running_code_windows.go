// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

const maxRunningWindowsImageBytes = 256 << 20

// Resolve the native comparison only from the system DLL. Windows does not
// document it as a stable Win32 API. An absent export or a failed comparison
// leaves the process without executable evidence.
var compareWindowsImageMappings = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtAreMappedFilesTheSame")

// RunningCodeIdentity hashes the file backing the current process's image.
// The hash covers the complete bytes, including the release signature. A path
// reported by the loader is only a candidate until the kernel confirms that
// its read-only data mapping and the loaded module have the same backing file.
func RunningCodeIdentity() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("%w: resolve Windows executable: %v", ErrRunningCodeIdentityUnavailable, err)
	}
	return runningWindowsImageIdentity(path)
}

func runningWindowsImageIdentity(path string) (string, error) {
	if err := compareWindowsImageMappings.Find(); err != nil {
		return "", fmt.Errorf("%w: Windows image comparison unavailable", ErrRunningCodeIdentityUnavailable)
	}
	var image windows.Handle
	if err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, nil, &image); err != nil || image == 0 {
		return "", fmt.Errorf("%w: loaded Windows image unavailable", ErrRunningCodeIdentityUnavailable)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("%w: invalid Windows image path", ErrRunningCodeIdentityUnavailable)
	}
	// Deny write and delete sharing until the digest is complete, including
	// attempts to open a writable mapping. Hash the same open handle used to
	// establish the backing file match.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", fmt.Errorf("%w: open running Windows image: %v", ErrRunningCodeIdentityUnavailable, err)
	}
	file := os.NewFile(uintptr(handle), "running Windows image")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return "", ErrRunningCodeIdentityUnavailable
	}
	defer func() { _ = file.Close() }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", fmt.Errorf("%w: read Windows image properties: %v", ErrRunningCodeIdentityUnavailable, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > maxRunningWindowsImageBytes {
		return "", fmt.Errorf("%w: Windows image has an invalid file type or size", ErrRunningCodeIdentityUnavailable)
	}
	mapping, err := windows.CreateFileMapping(handle, nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return "", fmt.Errorf("%w: map Windows image candidate: %v", ErrRunningCodeIdentityUnavailable, err)
	}
	defer func() { _ = windows.CloseHandle(mapping) }()
	view, err := windows.MapViewOfFile(mapping, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return "", fmt.Errorf("%w: open read-only Windows image view: %v", ErrRunningCodeIdentityUnavailable, err)
	}
	defer func() { _ = windows.UnmapViewOfFile(view) }()
	if status, _, _ := compareWindowsImageMappings.Call(uintptr(image), view); status != 0 {
		return "", fmt.Errorf("%w: opened file differs from the loaded Windows image (status %#x)", ErrRunningCodeIdentityUnavailable, status)
	}
	source := &io.LimitedReader{R: file, N: int64(info.FileSizeLow) + 1}
	digest, err := HashReader(source)
	if err != nil {
		return "", fmt.Errorf("%w: digest loaded Windows image: %v", ErrRunningCodeIdentityUnavailable, err)
	}
	if source.N != 1 || len(digest) != 32 {
		return "", fmt.Errorf("%w: incomplete Windows image digest", ErrRunningCodeIdentityUnavailable)
	}
	return "sha256:" + hex.EncodeToString(digest), nil
}
