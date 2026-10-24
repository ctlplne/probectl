// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"math"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/l7redact"
)

// D-65: a DNS question name is minimized before it leaves the agent (templated
// left of its registered domain, or only the registered domain under the
// regulated profile), so the NDR detectors cannot read the raw name downstream.
// They keep their signal from features computed HERE, from the raw name, while
// it exists only in agent memory: the first label's entropy and length, the
// name's length, and keyed tokens that let a detector count DISTINCT names and
// subdomains without learning any of them. The key is random per agent
// process and never leaves it.

// dnsTokenBytes is the token length: enough to count distinct names in a
// detector window, too short to carry content.
const dnsTokenBytes = 8

// newDNSKey mints the per-process token key. A failure leaves tokens off (the
// detectors then fall back to the stored, minimized name).
func newDNSKey() []byte {
	k, err := crypto.Random(32)
	if err != nil {
		return nil
	}
	return k
}

// dnsFeatures computes the detector features of one raw question name.
func dnsFeatures(raw string, key []byte) *ebpfv1.DNSFeatures {
	name := strings.TrimSuffix(raw, ".")
	if name == "" {
		return nil
	}
	first := name
	if i := strings.IndexByte(name, '.'); i > 0 {
		first = name[:i]
	}
	f := &ebpfv1.DNSFeatures{
		FirstLabelEntropy: shannonEntropy(first),
		FirstLabelLength:  uint32(len(first)),
		QnameBytes:        uint32(len(raw)),
	}
	if len(key) == 0 {
		return f
	}
	f.NameToken = dnsToken(key, "n:"+strings.ToLower(name))
	if domain := l7redact.RegisteredDomain(name); domain != "" && len(domain) < len(name) {
		f.SubdomainToken = dnsToken(key, "s:"+strings.ToLower(name[:len(name)-len(domain)-1]))
	}
	return f
}

func dnsToken(key []byte, v string) []byte {
	return crypto.Default.Sign(key, []byte(v))[:dnsTokenBytes]
}

// shannonEntropy is the per-byte Shannon entropy (bits) of s — the same
// measure the control plane's DGA detector applies.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// dnsOptions is the deployment's DNS-name rule as this agent knows it: the
// registered domain only unless the control plane said otherwise (a missing or
// unreachable channel applies the strictest rule).
func (a *Agent) dnsOptions() l7redact.Options {
	only := true
	if a.policy != nil {
		only = a.policy.DNSRegisteredDomainOnly()
	}
	return l7redact.Options{DNSRegisteredDomainOnly: only}
}
