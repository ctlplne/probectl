// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import land110m from './land-110m.json'

/**
 * Minimal TopoJSON decoder for the vendored Natural Earth land geometry
 * (world-atlas land-110m; public-domain data, see NOTICE). Decoding ~50 lines
 * beats adding a topojson-client dependency for one static file, and the
 * geometry ships INSIDE the lazy geo chunk — no tile server, no third-party
 * call, air-gap identical to production (§7.11).
 */

interface TopoTransform {
  scale: [number, number]
  translate: [number, number]
}

interface Topology {
  transform?: TopoTransform
  arcs: number[][][]
  objects: {
    land: { geometries: { type: string; arcs: number[][][] }[] }
  }
}

const topo = land110m as unknown as Topology

function decodeArc(index: number): [number, number][] {
  const raw = topo.arcs[index]
  const scale = topo.transform?.scale ?? [1, 1]
  const translate = topo.transform?.translate ?? [0, 0]
  let x = 0
  let y = 0
  return raw.map(([dx, dy]) => {
    x += dx
    y += dy
    return [x * scale[0] + translate[0], y * scale[1] + translate[1]] as [number, number]
  })
}

function ringFromArcs(arcRefs: number[]): [number, number][] {
  const points: [number, number][] = []
  for (const ref of arcRefs) {
    const arc = ref >= 0 ? decodeArc(ref) : decodeArc(~ref).slice().reverse()
    // Adjacent arcs share their joint point; drop the duplicate.
    const start = points.length > 0 ? 1 : 0
    for (let i = start; i < arc.length; i++) points.push(arc[i])
  }
  return points
}

/** Every land ring (outer boundaries and holes) as lon/lat point lists. */
export function landRings(): [number, number][][] {
  const rings: [number, number][][] = []
  for (const geometry of topo.objects.land.geometries) {
    for (const polygon of geometry.arcs) {
      for (const ring of polygon) rings.push(ringFromArcs(ring))
    }
  }
  return rings
}

export const MAP_W = 960
export const MAP_H = 480

/** Equirectangular projection onto the fixed viewBox. */
export function project(lon: number, lat: number): [number, number] {
  return [((lon + 180) / 360) * MAP_W, ((90 - lat) / 180) * MAP_H]
}

/** SVG path data for the whole landmass (fill-rule evenodd handles holes). */
export function landPathD(): string {
  return landRings()
    .map(
      (ring) =>
        'M' +
        ring
          .map(([lon, lat]) => {
            const [x, y] = project(lon, lat)
            return `${x.toFixed(1)},${y.toFixed(1)}`
          })
          .join('L') +
        'Z',
    )
    .join('')
}
