// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsIdentityFileLimit = 1 << 20

// LockWindowsIdentityDirectory serializes enrollment and renewal across
// processes. Windows releases the share denial if the process exits.
func LockWindowsIdentityDirectory(dir string) (func(), error) {
	if err := prepareWindowsIdentityDirectory(dir); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(filepath.Join(dir, ".identity.lock"))
	if err != nil {
		return nil, err
	}
	attrs, err := privateWindowsIdentityAttributes(false)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		0, attrs, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	unlock := func() { _ = windows.CloseHandle(handle) }
	if err := validateWindowsIdentityPath(handle, false); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// prepareWindowsIdentityDirectory creates a dedicated identity directory with a
// protected DACL for the running account and SYSTEM. An existing directory is
// accepted only if it already has private permissions and is on local NTFS.
func prepareWindowsIdentityDirectory(dir string) error {
	if err := requireFixedWindowsVolume(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := privateWindowsIdentityAttributes(true)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, attrs); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return validateWindowsIdentityDirectory(dir)
}

func validateWindowsIdentityDirectory(dir string) error {
	if err := requireFixedWindowsVolume(dir); err != nil {
		return err
	}
	handle, err := openWindowsIdentityPath(dir, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_FLAG_BACKUP_SEMANTICS, true)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var resolved [32768]uint16 // Win32 extended-length path maximum plus NUL
	length, err := windows.GetFinalPathNameByHandle(handle, &resolved[0], uint32(len(resolved)), 0)
	if err != nil {
		return err
	}
	if length == 0 || length >= uint32(len(resolved)) {
		return errors.New("cannot resolve the Windows identity directory")
	}
	if err := requireFixedWindowsVolume(strings.TrimPrefix(windows.UTF16ToString(resolved[:length]), `\\?\`)); err != nil {
		return err
	}
	var filesystem [32]uint16
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, nil,
		&filesystem[0], uint32(len(filesystem))); err != nil {
		return err
	}
	if windows.UTF16ToString(filesystem[:]) != "NTFS" {
		return errors.New("identity directory requires a local fixed NTFS volume")
	}
	return nil
}

func requireFixedWindowsVolume(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("Windows identity directory requires an absolute local path")
	}
	volume, err := windows.UTF16PtrFromString(filepath.VolumeName(path) + `\`)
	if err != nil {
		return err
	}
	if windows.GetDriveType(volume) != windows.DRIVE_FIXED {
		return errors.New("identity directory requires a local fixed NTFS volume")
	}
	return nil
}

// ReadWindowsIdentityFile opens and validates one protected local record. A
// reader may finish reading the old record while a renewal replaces its name.
func ReadWindowsIdentityFile(path string) ([]byte, error) {
	if err := validateWindowsIdentityDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	handle, err := openWindowsIdentityPath(path, windows.GENERIC_READ|windows.READ_CONTROL, 0, false)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, windowsIdentityFileLimit+1))
	if err != nil || len(data) > windowsIdentityFileLimit {
		Zeroize(data)
		return nil, errors.New("cannot read the bounded Windows identity record")
	}
	return data, nil
}

// WriteWindowsIdentityFile flushes a protected temporary file and replaces the
// record in the same directory. Readers see the old or new complete record.
func WriteWindowsIdentityFile(path string, data []byte) error {
	if len(data) == 0 || len(data) > windowsIdentityFileLimit {
		return errors.New("invalid Windows identity record size")
	}
	if err := prepareWindowsIdentityDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	attrs, err := privateWindowsIdentityAttributes(false)
	if err != nil {
		return err
	}
	id, err := UUIDv4()
	if err != nil {
		return err
	}
	temp := filepath.Join(filepath.Dir(path), ".identity-"+id+".tmp")
	source, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(source, windows.GENERIC_WRITE, 0, attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temp) }()
	file := os.NewFile(uintptr(handle), temp)
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func privateWindowsIdentityAttributes(directory bool) (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid.String()
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("O:%sD:P(A;%s;FA;;;%s)", sid, flags, sid)
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		sddl += "(A;" + flags + ";FA;;;SY)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func openWindowsIdentityPath(path string, access, flags uint32, directory bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		flags|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	if err := validateWindowsIdentityPath(handle, directory); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

func validateWindowsIdentityPath(handle windows.Handle, directory bool) error {
	var stat windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &stat); err != nil {
		return err
	}
	if stat.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(stat.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("invalid Windows identity directory or record type")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !user.User.Sid.Equals(owner) {
		return errors.New("Windows identity must be owned by the running account")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("Windows identity requires permissions protected from inheritance")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("Windows identity requires a private access list")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var entry *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &entry); err != nil || entry.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unrecognized Windows identity access rule")
		}
		// The Windows ACCESS_ALLOWED_ACE structure stores the SID starting at SidStart.
		sid := (*windows.SID)(unsafe.Pointer(&entry.SidStart)) //nolint:gosec // Windows ACE layout
		if !user.User.Sid.Equals(sid) && !sid.IsWellKnown(windows.WinLocalSystemSid) {
			return errors.New("Windows identity grants access to another account")
		}
	}
	return nil
}
