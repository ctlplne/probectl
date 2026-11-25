// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/ctlplne/probectl/internal/crypto"
)

type WindowsEnrollmentStore struct{ directory string }

type windowsIdentityRecord struct {
	Version int                `json:"version"`
	Device  EnrollmentMaterial `json:"device"`
}

func NewWindowsEnrollmentStore(directory string) *WindowsEnrollmentStore {
	return &WindowsEnrollmentStore{directory: directory}
}

func (s *WindowsEnrollmentStore) Lock() (func(), error) {
	return crypto.LockWindowsIdentityDirectory(s.directory)
}

func (s *WindowsEnrollmentStore) Load() (EnrollmentMaterial, error) {
	if !filepath.IsAbs(s.directory) {
		return EnrollmentMaterial{}, errors.New("Windows identity directory requires an absolute path")
	}
	data, err := crypto.ReadWindowsIdentityFile(filepath.Join(s.directory, "endpoint-identity.json"))
	if err != nil {
		return EnrollmentMaterial{}, err
	}
	defer crypto.Zeroize(data)
	var record windowsIdentityRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Version != 1 {
		crypto.Zeroize(record.Device.PrivateKey)
		return EnrollmentMaterial{}, errors.New("invalid Windows endpoint identity record")
	}
	return record.Device, nil
}

func (s *WindowsEnrollmentStore) Save(device EnrollmentMaterial) error {
	identity, _, _, err := crypto.StoredWindowsAgentIdentity(device.Certificate, device.PrivateKey)
	if err != nil {
		return err
	}
	current, err := s.Load()
	if err == nil {
		defer crypto.Zeroize(current.PrivateKey)
		previous, _, _, err := crypto.StoredWindowsAgentIdentity(current.Certificate, current.PrivateKey)
		if err != nil || previous != identity {
			return errors.New("refusing to replace a different Windows device identity")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := crypto.CertPoolFromPEM(device.IssuerCA); err != nil {
		return err
	}
	if _, err := crypto.CertPoolFromPEM(device.ServerCA); err != nil {
		return err
	}
	data, err := json.Marshal(windowsIdentityRecord{Version: 1, Device: device})
	if err != nil {
		return err
	}
	defer crypto.Zeroize(data)
	return crypto.WriteWindowsIdentityFile(filepath.Join(s.directory, "endpoint-identity.json"), data)
}

// Dial connects using the current account's stored identity on every handshake.
func (s *WindowsEnrollmentStore) Dial(addr string, expected crypto.SPIFFEID, serverCA []byte) (*Client, error) {
	cfg, err := crypto.WindowsAgentTLSConfig(serverCA, expected, func() ([]byte, []byte, error) {
		device, err := s.Load()
		return device.Certificate, device.PrivateKey, err
	})
	if err != nil {
		return nil, err
	}
	return dialWithTLS(addr, cfg)
}
