// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import "math/big"

type ddosVectorCoverage struct {
	before, after, deficit *big.Rat
}

// currentDDoSFieldsCouldHidePressure only tests whether a quiet conclusion
// is supported. Hypothetical packets never contribute to a detection.
func currentDDoSFieldsCouldHidePressure(earlier, latest ddosCounts, floor *big.Rat, limits DDoSThresholds) bool {
	shared := latest.unknownTransport
	if shared.Sign() == 0 && latest.possibleReflection.Sign() == 0 && latest.possibleSYN.Cmp(latest.syn) == 0 {
		return false
	}
	flags := new(big.Rat).Sub(latest.possibleSYN, latest.syn)
	flags.Sub(flags, shared)
	ports := new(big.Rat).Sub(latest.possibleReflection, shared)
	growth := int64(limits.GrowthBasisPoints)
	// Observed historical vector counts are lower bounds. A quiet verdict
	// needs to hold even if the omitted historical packets were ordinary.
	vectors := []ddosVectorCoverage{ddosVectorWithCoverage(earlier.syn, latest.syn, floor, growth)}
	zero := new(big.Rat)
	for _, service := range ddosReflectionServiceNames {
		before, after := earlier.reflected[service], latest.reflected[service]
		if before == nil {
			before = zero
		}
		if after == nil {
			after = zero
		}
		vectors = append(vectors, ddosVectorWithCoverage(before, after, floor, growth))
	}

	// There are six possible vectors. Check every nonempty subset because
	// unknown transport can fill either family's deficits, but only once.
	for mask := 1; mask < 1<<len(vectors); mask++ {
		var before, after, udpDeficit big.Rat
		available := new(big.Rat).Set(shared)
		tcpDeficit := new(big.Rat)
		if mask&1 != 0 {
			available.Add(available, flags)
			tcpDeficit.Sub(vectors[0].deficit, flags)
		}
		if mask>>1 != 0 {
			available.Add(available, ports)
		}
		if available.Sign() == 0 {
			continue
		}
		count := 0
		for i, vector := range vectors {
			if mask&(1<<i) == 0 {
				continue
			}
			count++
			before.Add(&before, vector.before)
			after.Add(&after, vector.after)
			if i != 0 {
				udpDeficit.Add(&udpDeficit, vector.deficit)
			}
		}
		udpDeficit.Sub(&udpDeficit, ports)
		needShared := new(big.Rat).Add(zeroIfNegative(tcpDeficit), zeroIfNegative(&udpDeficit))
		if needShared.Cmp(shared) > 0 || !hasDDoSShare(after.Add(&after, available), latest.packets, limits.VectorShareBasisPoints) {
			continue
		}
		if count == 1 || earlier.packets.Sign() == 0 ||
			new(big.Rat).Mul(&after, earlier.packets).Cmp(new(big.Rat).Mul(&before, latest.packets)) > 0 {
			return true
		}
	}
	return false
}

func ddosVectorWithCoverage(before, after, floor *big.Rat, growth int64) ddosVectorCoverage {
	// Counters are integers. Round growth up and still require a strict
	// increase when the previous count was zero.
	required := new(big.Int).Mul(before.Num(), big.NewInt(10000+growth))
	required.Add(required, big.NewInt(9999)).Quo(required, big.NewInt(10000))
	if required.Cmp(before.Num()) <= 0 {
		required.Add(before.Num(), big.NewInt(1))
	}
	if required.Cmp(floor.Num()) < 0 {
		required.Set(floor.Num())
	}
	deficit := new(big.Rat).SetInt(required)
	return ddosVectorCoverage{before, after, zeroIfNegative(deficit.Sub(deficit, after))}
}

func zeroIfNegative(value *big.Rat) *big.Rat {
	if value.Sign() < 0 {
		value.SetInt64(0)
	}
	return value
}
