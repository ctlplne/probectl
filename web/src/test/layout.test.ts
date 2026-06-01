import { describe, expect, test } from 'vitest'
import { layoutPath, lossByHop, lossTone } from '../viz/layout'
import { samplePath } from './pathFixture'
import type { Path } from '../api/paths'

describe('path layout', () => {
  test('positions hops in TTL columns with ECMP branches stacked', () => {
    const { nodes, edges } = layoutPath(samplePath)
    // source + 1 + 2 + 1 = 5 nodes.
    expect(nodes.length).toBe(5)
    expect(nodes.some((n) => n.isSource)).toBe(true)

    // The ECMP branch at TTL 2 = two nodes, same column (x), different rows (y).
    const ttl2 = nodes.filter((n) => n.ttl === 2)
    expect(ttl2.length).toBe(2)
    expect(ttl2[0].x).toBe(ttl2[1].x)
    expect(ttl2[0].y).not.toBe(ttl2[1].y)

    // Distinct columns: source + 3 TTLs, increasing left→right.
    const xs = [...new Set(nodes.map((n) => n.x))].sort((a, b) => a - b)
    expect(xs.length).toBe(4)

    // Edges: source → the single first hop, plus the 4 observed links.
    expect(edges.length).toBe(1 + 4)
    expect(nodes.find((n) => n.isDestination)?.ip).toBe('9.9.9.9')
  })

  test('lossByHop pinpoints the worst hop', () => {
    const s = lossByHop(samplePath)
    expect(s.length).toBe(3)
    expect(s[1].loss).toBeCloseTo(0.66)
    expect(s[1].ip).toBe('10.0.0.2')
    expect(s[0].loss).toBe(0)
  })

  test('lossTone thresholds', () => {
    expect(lossTone(0)).toBe('ok')
    expect(lossTone(0.1)).toBe('warning')
    expect(lossTone(0.5)).toBe('danger')
  })

  test('dense graph lays out fast and completely', () => {
    const hops = Array.from({ length: 30 }, (_, i) => ({
      ttl: i + 1,
      nodes: Array.from({ length: 4 }, (_, j) => ({
        ip: `10.${i}.${j}.1`, sent: 3, received: 3, loss_ratio: 0,
        rtt_min_ms: 1, rtt_avg_ms: 1, rtt_max_ms: 1,
      })),
    }))
    const dense: Path = { ...samplePath, hops, links: [] }
    const t0 = performance.now()
    const { nodes } = layoutPath(dense)
    expect(nodes.length).toBe(1 + 30 * 4)
    expect(performance.now() - t0).toBeLessThan(50)
  })
})
