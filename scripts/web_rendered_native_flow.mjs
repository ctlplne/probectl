// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Native flow cases for the canonical production-build Chromium gate.
// Synthetic API data proves rendering/accessibility, not SSO, real senders,
// query execution or tenant storage isolation. Existing gate owns the browser,
// server and accessibility checks; every case receives its own isolated context.
import { join } from "node:path";

export const NATIVE_FLOW_VIEWS = ["bar", "line", "matrix"];

export function validateNativeFlowMatrix(checks, themes, viewports) {
  const failures = [];
  const expected = themes.length * viewports.length * NATIVE_FLOW_VIEWS.length;
  if (checks.length !== expected)
    failures.push(
      `native flow matrix incomplete: expected ${expected}, recorded ${checks.length}`,
    );
  for (const theme of themes)
    for (const viewport of viewports)
      for (const view of NATIVE_FLOW_VIEWS) {
        const matches = checks.filter(
          (record) =>
            record.theme === theme &&
            record.viewport === viewport.name &&
            record.view === view,
        );
        if (matches.length !== 1)
          failures.push(
            `native flow matrix ${viewport.name} ${theme} ${view}: expected one record, found ${matches.length}`,
          );
        else if (matches[0].passed !== true)
          failures.push(
            `native flow ${viewport.name} ${theme} ${view}: ${JSON.stringify(matches[0])}`,
          );
      }
  return failures;
}

const rowFields = [
  "src_addr",
  "src_port",
  "protocol",
  "exporter",
  "in_if",
  "vlan",
  "dscp",
  "src_asn",
];
const columnFields = [
  "dst_addr",
  "dst_port",
  "transport",
  "next_hop",
  "out_if",
  "tos",
  "net_type",
  "dst_country",
];
const metric = "bytes:total";
const secondaryMetric = "packets:total";
const previousFrom = "2020-01-01T00:00:00.123456789Z";
const previousTimestamp = (milliseconds) =>
  new Date(milliseconds).toISOString().replace(/\.\d{3}Z$/, ".123456789Z");
const previousTo = previousTimestamp(
  Date.parse(previousFrom) +
    Date.parse("2026-10-07T01:00:00Z") -
    Date.parse("2025-09-01T00:00:00Z"),
);
const activeBuckets = [...Array.from({ length: 30 }, (_, i) => i), 40, 57];
const tuple = (fields, i) =>
  Object.fromEntries(
    fields.map((field) => [
      field,
      `${field.includes("addr") ? "192.0.2." : ""}${i + 1}`,
    ]),
  );

function definition(view) {
  return {
    name: `Synthetic ${view} rendering proof`,
    visibility: "private",
    time: { mode: "absolute" },
    ...(view === "line"
      ? { comparison: { mode: "absolute", from: previousFrom, to: previousTo } }
      : {}),
    plan: {
      from: "2025-09-01T00:00:00Z",
      to: "2026-10-07T01:00:00Z",
      view,
      group_by: rowFields,
      matrix_with: view === "matrix" ? columnFields : [],
      bucket_seconds: 604800,
      row_limit: view === "table" ? 50000 : 350,
      page_size: view === "table" ? 5000 : 350,
      series_depth: 40,
      matrix_depth: 15,
      metrics: [
        { measure: "bytes", calculation: "total", role: "primary" },
        ...(view === "line"
          ? [{ measure: "packets", calculation: "total", role: "secondary" }]
          : []),
      ],
      filter: {
        conditions: [
          { field: "raw_bytes", op: "lt", values: ["18446744073709551615"] },
        ],
      },
    },
  };
}
function result(view, offset = 0) {
  const plan = definition(view).plan;
  const bucketDuration = (bucket) =>
    String(
      Math.min(
        604800,
        (Date.parse(plan.to) - Date.parse(plan.from)) / 1000 - bucket * 604800,
      ),
    );
  const count = view === "table" ? 50000 : 350;
  const makeRow = (i) => ({
    group: tuple(rowFields, i),
    other: false,
    metrics: {
      [metric]: String(9007199254740993n + BigInt(i)),
      ...(view === "line" ? { [secondaryMetric]: String(1000 + i) } : {}),
    },
  });
  const rows = Array.from(
    { length: Math.min(plan.page_size, count - offset) },
    (_, i) => makeRow(offset + i),
  );
  const chartRows = Array.from({ length: 40 }, (_, i) => makeRow(i));
  const matrixRows = chartRows.slice(0, 15);
  const matrixColumns = Array.from({ length: 15 }, (_, i) => ({
    group: tuple(columnFields, i),
    other: false,
    metrics: { [metric]: String(i + 1) },
  }));
  const flow = {
    query: plan,
    source: "rollup",
    resolution_seconds: 60,
    total_groups: count + 3,
    detail_limited: true,
    rows,
    chart_rows: view === "matrix" ? [] : chartRows,
    chart_other:
      view === "matrix"
        ? undefined
        : {
            group: {},
            other: true,
            metrics: { [metric]: "18446744073709551617" },
          },
    matrix_rows: matrixRows,
    matrix_columns: matrixColumns,
    totals: { [metric]: "98765432109876543210987" },
    other: { group: {}, other: true, metrics: { [metric]: "17" } },
    series: chartRows.flatMap((r) =>
      [0, 2, 40].map((bucket) => ({
        ...r,
        ts: new Date(Date.parse(plan.from) + bucket * 604800000).toISOString(),
        duration_seconds: bucketDuration(bucket),
      })),
    ),
    other_series: [],
    matrix: matrixRows.flatMap((r, i) =>
      matrixColumns.map((c, j) => ({
        row: r.group,
        column: c.group,
        row_other: false,
        column_other: false,
        metrics: { [metric]: String(1000 + i * 100 + j) },
      })),
    ),
    coverage: {
      fields: rowFields,
      resolution_seconds: 60,
      complete_inputs: true,
    },
  };
  const sum = (start, n) =>
    BigInt(n) * 9007199254740993n +
    (BigInt(n) * BigInt(2 * start + n - 1)) / 2n;
  const detailOther = 18446744073709551617n;
  flow.other.metrics[metric] = String(detailOther);
  flow.totals[metric] = String(sum(0, count) + detailOther);
  if (view === "matrix") {
    for (const [i, r] of matrixRows.entries()) {
      const selected = flow.matrix
        .filter(
          (cell) => !cell.row_other && cell.row.src_addr === r.group.src_addr,
        )
        .reduce((total, cell) => total + BigInt(cell.metrics[metric]), 0n);
      flow.matrix.push({
        row: r.group,
        column: {},
        row_other: false,
        column_other: true,
        metrics: { [metric]: String(BigInt(r.metrics[metric]) - selected) },
      });
    }
    for (const c of matrixColumns)
      c.metrics[metric] = String(
        flow.matrix
          .filter(
            (cell) =>
              !cell.column_other && cell.column.dst_addr === c.group.dst_addr,
          )
          .reduce((total, cell) => total + BigInt(cell.metrics[metric]), 0n),
      );
    flow.matrix.push({
      row: {},
      column: {},
      row_other: true,
      column_other: true,
      metrics: { [metric]: String(sum(15, count - 15) + detailOther) },
    });
  } else {
    flow.matrix = [];
    flow.matrix_rows = undefined;
    flow.matrix_columns = undefined;
    flow.chart_other.metrics[metric] = String(
      sum(40, count - 40) + detailOther,
    );
    const parts = BigInt(activeBuckets.length);
    if (view === "line") {
      const packetSum = (start, n) =>
        BigInt(n) * 1000n + (BigInt(n) * BigInt(2 * start + n - 1)) / 2n;
      flow.other.metrics[secondaryMetric] = "17";
      flow.totals[secondaryMetric] = String(packetSum(0, count) + 17n);
      flow.chart_other.metrics[secondaryMetric] = String(
        packetSum(40, count - 40) + 17n,
      );
    }
    const split = (values, part) =>
      Object.fromEntries(
        Object.entries(values).map(([key, value]) => [
          key,
          String(
            BigInt(value) / parts + (part === 0 ? BigInt(value) % parts : 0n),
          ),
        ]),
      );
    flow.series = chartRows.flatMap((r) =>
      activeBuckets.map((bucket, part) => ({
        ...r,
        metrics: split(r.metrics, part),
        ts: new Date(Date.parse(plan.from) + bucket * 604800000).toISOString(),
        duration_seconds: bucketDuration(bucket),
      })),
    );
    flow.other_series = activeBuckets.map((bucket, part) => ({
      ...flow.chart_other,
      metrics: split(flow.chart_other.metrics, part),
      ts: new Date(Date.parse(plan.from) + bucket * 604800000).toISOString(),
      duration_seconds: bucketDuration(bucket),
    }));
    // Additive fixture bytes/packets only: this is a synthetic source, not
    // product aggregation of cardinalities/statistics.
    const byTime = new Map();
    for (const point of [...flow.series, ...flow.other_series]) {
      if (!byTime.has(point.ts)) byTime.set(point.ts, {});
      const values = byTime.get(point.ts);
      for (const [key, value] of Object.entries(point.metrics))
        values[key] = (values[key] ?? 0n) + BigInt(value);
    }
    flow.total_series = [...byTime].map(([ts, values]) => ({
      group: {},
      other: false,
      ts,
      duration_seconds: String(
        Math.min(604800, (Date.parse(plan.to) - Date.parse(ts)) / 1000),
      ),
      metrics: Object.fromEntries(
        Object.entries(values).map(([key, value]) => [key, String(value)]),
      ),
    }));
  }
  return {
    flow,
    flow_paging: {
      snapshot_id: "synthetic-render-" + view,
      expires_at: "2099-01-01T00:00:00Z",
      selected_rows: count,
      offset,
      page_size: plan.page_size,
      more: offset + rows.length < count,
      next_cursor:
        offset + rows.length < count
          ? `synthetic:${view}:${offset + rows.length}`
          : undefined,
    },
    query: { source: "flow", flow: plan },
    rows: [],
    columns: [],
    suggestions: {},
    preview: "",
    evidence_path: "/planes/flow",
    truncated: true,
    execution: { tenant_scoped: true },
  };
}

function sourceResponse(view) {
  const first = result(view);
  if (view !== "line") return first;
  const current = first.flow,
    previous = structuredClone(current);
  const shift = Date.parse(previousFrom) - Date.parse(current.query.from);
  previous.query.from = previousFrom;
  previous.query.to = previousTo;
  const twice = (metrics) =>
    Object.fromEntries(
      Object.entries(metrics).map(([key, value]) => [
        key,
        String(BigInt(value) * 2n),
      ]),
    );
  for (const field of ["rows", "chart_rows"])
    for (const row of previous[field] ?? []) row.metrics = twice(row.metrics);
  for (const field of ["other", "chart_other"])
    if (previous[field])
      previous[field].metrics = twice(previous[field].metrics);
  previous.totals = twice(previous.totals);
  for (const field of ["series", "other_series", "total_series"])
    for (const point of previous[field]) {
      point.metrics = twice(point.metrics);
      point.ts = previousTimestamp(Date.parse(point.ts) + shift);
    }
  const rows = current.rows.flatMap((row, i) =>
    current.query.metrics.map((m) => {
      const key = `${m.measure}:${m.calculation}`,
        value = row.metrics[key],
        prior = previous.rows[i].metrics[key];
      return {
        group: row.group,
        measure: key,
        aggregation: m.calculation,
        current_value_str: value,
        previous_value_str: prior,
        delta_str: String(BigInt(value) - BigInt(prior)),
        percent_change_str: "-50",
        current_value: Number(value),
        previous_value: Number(prior),
        delta: Number(value) - Number(prior),
        percent_change: -50,
        delta_state: "comparable",
      };
    }),
  );
  return {
    contract_version: "flow-explorer-comparison/v2",
    current: first.query,
    previous: { ...first.query, flow: previous.query },
    current_preview: "",
    previous_preview: "",
    groupings: current.query.group_by,
    rows,
    suggestions: {},
    evidence_path: "/planes/flow",
    state: "comparable",
    current_truncated: false,
    previous_truncated: false,
    rows_truncated: false,
    flow: {
      current,
      previous,
      membership: "shared_top_groups_ranked_by_larger_period_value",
    },
    flow_paging: first.flow_paging,
    execution: {
      contract_version: "flow-explorer-comparison-execution/v2",
      tenant_scoped: true,
      current: first.execution,
      previous: first.execution,
      alignment: {
        row_limit: 350,
        returned_rows: 350,
        truncated: false,
        truncation_reason: "none",
        elapsed_ms: 0,
      },
      total_ms: 0,
    },
  };
}

function nativeSource(view, schema) {
  return `(() => {
    const base = window.fetch;
    window.__nativeChartLabels = [];
    if (typeof CanvasRenderingContext2D !== 'undefined') {
      const originalFillText = CanvasRenderingContext2D.prototype.fillText;
      CanvasRenderingContext2D.prototype.fillText = function(text, ...coordinates) {
        const label = String(text);
        if (this.canvas.closest('.uplot') && /^[-+]?\\d/.test(label) && window.__nativeChartLabels.length < 2000) {
          const x = Number(coordinates[0]); const width = this.measureText(label).width;
          const left = this.textAlign === 'right' || this.textAlign === 'end' ? x - width : this.textAlign === 'center' ? x - width / 2 : x;
          window.__nativeChartLabels.push({text:label,x,left,width,align:this.textAlign});
        }
        return originalFillText.call(this, text, ...coordinates);
      };
    }
    let definition = ${JSON.stringify(definition(view))};
    let version="9007199254740993";
    const first = ${JSON.stringify(sourceResponse(view))};
    const schema = ${JSON.stringify(schema)};
    const encode = (body, status=200) => new Response(JSON.stringify(body), {status,headers:{'Content-Type':'application/json'}});
    window.__nativeFlowRequests = [];
    let proposalReviewed = false;
    window.fetch = async (input, init={}) => {
      const url = new URL(String(input), location.origin);
      window.__nativeFlowRequests.push({path:url.pathname, method:init.method||'GET', body:init.body});
      if(url.pathname === '/v1/me') { const response = await base(input,init); const user = await response.json(); user.permissions = [...user.permissions,'flow.read','flow.views.write','flow.filters.write']; return encode(user); }
      if(url.pathname === '/v1/explorer/schema') return encode({flow:schema,templates:[],visualizations:[],max_rows:50000});
      if(url.pathname === '/v1/explorer/query' && JSON.parse(init.body || '{}').plan_only === true) {
        proposalReviewed = true;
        return encode({proposal:{status:'ready',plan:definition.plan,comparison:definition.comparison,display:definition.display,guidance:'Synthetic stateless proposal for browser rendering.',needs_confirmation:true}});
      }
      if(proposalReviewed && ['/v1/explorer/query','/v1/explorer/compare'].includes(url.pathname)) return encode(first);
      if(url.pathname === '/v1/explorer/flow-filters' || url.pathname === '/v1/explorer/flow-views') return encode({items:[]});
      if(url.pathname === '/v1/explorer/flow-views/proof-${view}') {
        if(init.method==='PUT') {const body=JSON.parse(init.body); if(body.version!==version) return encode({error:{code:'conflict',message:'revision mismatch'}},409); definition=body.definition;version=String(BigInt(version)+1n);window.__nativeSavedDisplay=definition.display;}
        return encode({id:'proof-${view}',owner_id:'u_test',version,definition,created_at:'2026-10-28T00:00:00Z',updated_at:'2026-10-28T00:00:00Z',favorite:false});
      }
      if(url.pathname === '/v1/explorer/flow-views/proof-${view}/query') return encode(first);
      return base(input,init);
    };
  })();`;
}

async function actualPlots(page, geometry = false) {
  return page
    .locator('[role="img"][aria-label*="global flow time series"]')
    .evaluateAll(
      (nodes, geometry) =>
        nodes.map((node) => {
          const root = node.querySelector(".uplot");
          let fiber =
            node[
              Object.keys(node).find((key) => key.startsWith("__reactFiber$"))
            ];
          for (
            let parent = 0;
            fiber && parent < 24;
            parent++, fiber = fiber.return
          ) {
            let hook = fiber.memoizedState;
            for (
              let i = 0;
              hook && typeof hook === "object" && i < 100;
              i++, hook = hook.next
            ) {
              const plot = hook.memoizedState?.current;
              if (
                plot?.root === root &&
                plot?.scales?.y &&
                typeof plot.setScale === "function"
              ) {
                const zeroAt = plot.data[0].indexOf(
                  Date.parse("2025-09-01T00:00:00Z") / 1000 + 30 * 604800,
                );
                const axis = plot.axes[1];
                if (!Array.isArray(axis?._splits) || !Array.isArray(axis.font))
                  return { error: "Actual axis layout not ready" };
                const grid = axis.grid.filter(
                  plot,
                  axis._splits,
                  1,
                  axis._found[1],
                  axis._found[0],
                );
                const positions = grid
                  .filter((value) => value != null)
                  .map((value) => plot.valToPos(value, "y"))
                  .sort((a, b) => a - b);
                const minimumGridGap =
                  positions.length < 2
                    ? null
                    : Math.min(
                        ...positions
                          .slice(1)
                          .map(
                            (position, index) => position - positions[index],
                          ),
                      );
                const inspectPaths = (entry, index) => {
                  if (!geometry) return undefined;
                  // Execute the actual production path builder against the
                  // actual engine's scales. Capture its Path2D commands without
                  // assigning them back or changing the plotted source data.
                  const Original = window.Path2D;
                  class Capture extends Original {
                    rectangles = [];
                    vertices = [];
                    rect(...args) {
                      this.rectangles.push(args);
                      super.rect(...args);
                    }
                    moveTo(...args) {
                      this.vertices.push(args);
                      super.moveTo(...args);
                    }
                    lineTo(...args) {
                      this.vertices.push(args);
                      super.lineTo(...args);
                    }
                  }
                  try {
                    window.Path2D = Capture;
                    const paths = entry.paths(
                      plot,
                      index + 1,
                      0,
                      plot.data[0].length - 1,
                    );
                    const rectangles = paths?.stroke?.rectangles ?? [];
                    const vertices = paths?.fill?.vertices ?? [];
                    const bandPaths =
                      paths?.fill instanceof Map
                        ? [...paths.fill.values()]
                        : paths?.stroke instanceof Map
                          ? [...paths.stroke.values()]
                          : [];
                    const bandVertices = bandPaths.flatMap(
                      (path) => path.vertices ?? [],
                    );
                    let horizonCoverage;
                    if (
                      paths?.fill instanceof Map &&
                      entry.label.startsWith("Current") &&
                      entry.label.includes("Other (unselected groups)")
                    ) {
                      const identities = [
                        ...new Set(
                          plot.series
                            .slice(1)
                            .map((series) =>
                              series.label.replace(
                                /^(Current|Previous) · /,
                                "",
                              ),
                            ),
                        ),
                      ];
                      const base =
                        identities.length -
                        identities.indexOf(
                          entry.label.replace(/^(Current|Previous) · /, ""),
                        ) -
                        1;
                      const firstBand = [...paths.fill.values()][0];
                      plot.ctx.save();
                      try {
                        plot.ctx.resetTransform();
                        const test = (at) =>
                          plot.ctx.isPointInPath(
                            firstBand,
                            plot.valToPos(plot.data[0][0] + at, "x", true),
                            plot.valToPos(base + 0.25, "y", true),
                          );
                        horizonCoverage = {
                          isolated: test(40 * 604800 + 302400),
                          partial: test(57 * 604800 + 88200),
                          zeroGap: test(35 * 604800 + 302400),
                        };
                      } finally {
                        plot.ctx.restore();
                      }
                    }
                    let percentageCoverage;
                    if (
                      paths?.fill &&
                      node
                        .getAttribute("aria-label")
                        .includes("percentage of group observations") &&
                      entry.label.startsWith("Current") &&
                      entry.label.includes("Other (unselected groups)")
                    ) {
                      plot.ctx.save();
                      try {
                        plot.ctx.resetTransform();
                        const test = (at) =>
                          plot.ctx.isPointInPath(
                            paths.fill,
                            plot.valToPos(plot.data[0][0] + at, "x", true),
                            plot.valToPos(50, "y", true),
                          );
                        percentageCoverage = {
                          isolated: test(40 * 604800 + 302400),
                          partial: test(57 * 604800 + 88200),
                          undefinedGap: test(35 * 604800 + 302400),
                        };
                      } finally {
                        plot.ctx.restore();
                      }
                    }
                    return {
                      percentageCoverage,
                      horizonCoverage,
                      bandFillCount:
                        paths?.fill instanceof Map ? paths.fill.size : 0,
                      bandStrokeCount:
                        paths?.stroke instanceof Map ? paths.stroke.size : 0,
                      bandColors:
                        paths?.stroke instanceof Map
                          ? [...paths.stroke.keys()]
                          : [],
                      bandFinite: bandVertices.flat().every(Number.isFinite),
                      painted: Boolean(entry._paths?.stroke),
                      rectangles: rectangles.length,
                      firstRectangle: rectangles[0],
                      lastRectangle: rectangles.at(-1),
                      fill: Boolean(paths?.fill),
                      fillColor: entry._fill,
                      finite: [...rectangles.flat(), ...vertices.flat()].every(
                        Number.isFinite,
                      ),
                      maximumFillY: vertices.length
                        ? Math.max(...vertices.map((v) => v[1]))
                        : null,
                    };
                  } finally {
                    window.Path2D = Original;
                  }
                };
                return {
                  label: node.getAttribute("aria-label"),
                  min: plot.scales.y.min,
                  max: plot.scales.y.max,
                  distr: plot.scales.y.distr,
                  series: plot.series.slice(1).map((entry, index) => ({
                    label: entry.label,
                    width: entry.width,
                    dash: entry.dash,
                    zeroCoordinate: plot.data[index + 1][zeroAt],
                    firstCoordinate: geometry
                      ? plot.data[index + 1][0]
                      : undefined,
                    geometry: inspectPaths(entry, index),
                  })),
                  canvasHeight: plot.height,
                  minimumGridGap,
                  axisFontPx: axis.font[2],
                  axisValues: geometry ? axis._values : undefined,
                  plotBottom: geometry
                    ? plot.bbox.top + plot.bbox.height
                    : undefined,
                  columnPointer: geometry
                    ? {
                        x:
                          root.querySelector(".u-over").getBoundingClientRect()
                            .x +
                          plot.valToPos(plot.data[0][0] + 0.75 * 604800, "x"),
                        y:
                          root.querySelector(".u-over").getBoundingClientRect()
                            .y +
                          root.querySelector(".u-over").getBoundingClientRect()
                            .height /
                            2,
                      }
                    : undefined,
                  partialColumnPointer: geometry
                    ? {
                        x:
                          root.querySelector(".u-over").getBoundingClientRect()
                            .x +
                          plot.valToPos(
                            plot.data[0][0] + 57 * 604800 + 0.75 * 176400,
                            "x",
                          ),
                        y:
                          root.querySelector(".u-over").getBoundingClientRect()
                            .y +
                          root.querySelector(".u-over").getBoundingClientRect()
                            .height /
                            2,
                      }
                    : undefined,
                  columnZoom: geometry
                    ? {
                        start:
                          root.querySelector(".u-over").getBoundingClientRect()
                            .x +
                          plot.valToPos(plot.data[0][0] + 54 * 604800, "x"),
                        end:
                          root.querySelector(".u-over").getBoundingClientRect()
                            .x +
                          plot.valToPos(plot.data[0].at(-1) - 0.001, "x"),
                        y:
                          root.querySelector(".u-over").getBoundingClientRect()
                            .y +
                          root.querySelector(".u-over").getBoundingClientRect()
                            .height /
                            2,
                      }
                    : undefined,
                  xRange: geometry
                    ? [plot.scales.x.min, plot.scales.x.max]
                    : undefined,
                  cursor: geometry
                    ? { left: plot.cursor.left, indices: plot.cursor.idxs }
                    : undefined,
                };
              }
            }
          }
          return { error: "Actual uPlot ref not ready" };
        }),
      geometry,
    );
}

async function expectPlotHeights(page, count, height) {
  for (let attempt = 0; attempt < 40; attempt++) {
    const plots = await actualPlots(page);
    if (
      plots.length === count &&
      plots.every(
        (plot) => !plot.error && Math.abs(plot.canvasHeight - height) < 1,
      )
    )
      return;
    await page.waitForTimeout(50);
  }
  throw Error(`Actual ${count} uPlot heights did not reach ${height}`);
}

async function checkTimeStyles(page, visuals, record) {
  record.time_styles = [];
  const source = sourceResponse("line").flow;
  const near = (a, b) =>
    Number.isFinite(a) && Math.abs(a - b) <= Math.max(1, Math.abs(b)) * 1e-12;
  for (const style of ["stacked_area", "stacked_columns"]) {
    await page
      .getByLabel("Time chart style", { exact: true })
      .selectOption(style);
    for (const scale of ["linear", "log"]) {
      await page
        .getByLabel("Scale for bytes:total", { exact: true })
        .selectOption(scale);
      let plots;
      for (let attempt = 0; attempt < 40; attempt++) {
        plots = await actualPlots(page, true);
        const painted = plots[0]?.series?.[0]?.geometry;
        if (
          plots.length === 2 &&
          plots.every((p) => !p.error) &&
          plots[0].distr === (scale === "log" ? 3 : 1) &&
          painted?.painted &&
          (style === "stacked_columns" ? painted.rectangles > 0 : painted.fill)
        )
          break;
        await page.waitForTimeout(50);
      }
      if (plots?.length !== 2 || plots.some((p) => p.error))
        throw Error("Stacked plots were not constructed");
      for (const [metricIndex, key] of [metric, secondaryMetric].entries()) {
        const plot = plots[metricIndex];
        for (const [period, origin] of [
          ["Current", source.current],
          ["Previous", source.previous],
        ]) {
          const entries = plot.series.filter(
            (s) =>
              s.label.startsWith(period) &&
              !s.label.includes("Total (all matching inputs)"),
          );
          if (entries.length !== 41)
            throw Error("A stack dropped a selected group or Other");
          let cumulative = 0;
          const inputs = [
            ...origin.series.filter(
              (p) =>
                p.ts === origin.query.from ||
                Date.parse(p.ts) === Date.parse(origin.query.from),
            ),
            ...origin.other_series.filter(
              (p) => Date.parse(p.ts) === Date.parse(origin.query.from),
            ),
          ];
          for (const [index, entry] of entries.entries()) {
            cumulative += Number(inputs[index].metrics[key]);
            if (!near(entry.firstCoordinate, cumulative))
              throw Error(
                "Painted stack mixed periods, metrics or source totals",
              );
            const path = entry.geometry;
            if (
              !path?.painted ||
              !path.finite ||
              path.fill !== (period === "Current")
            )
              throw Error(
                "Actual stack paths lack finite filled-current/outlined-previous geometry",
              );
            if (style === "stacked_columns") {
              const expectedRatio =
                Number(origin.series.at(-1).duration_seconds) / 604800;
              if (
                path.rectangles !== activeBuckets.length ||
                !near(
                  path.lastRectangle[2] / path.firstRectangle[2],
                  expectedRatio,
                )
              )
                throw Error(
                  "Actual column widths lost partial source bucket intervals or drew empty sparse buckets",
                );
            }
          }
          const total = plot.series.find(
            (s) =>
              s.label.startsWith(period) &&
              s.label.includes("Total (all matching inputs)"),
          );
          if (
            !near(
              total?.firstCoordinate,
              Number(origin.total_series[0].metrics[key]),
            )
          )
            throw Error(
              "Source total was stacked or reconstructed from groups",
            );
        }
        if (plot.min !== plots[0].min || plot.max !== plots[0].max)
          throw Error("Stacked metric axes lost synchronization");
      }
      const first = plots[0].series[0].geometry;
      if (scale === "log") {
        const bottom =
          style === "stacked_columns"
            ? first.firstRectangle[1] + first.firstRectangle[3]
            : first.maximumFillY;
        if (!near(bottom, plots[0].plotBottom))
          throw Error(
            "Logarithmic zero baseline was not clipped at the canvas boundary",
          );
      }
      const plotNode = visuals
        .getByRole("img", { name: /global flow time series/ })
        .first();
      await plotNode.focus();
      await plotNode.press("Home");
      await plotNode.press("ArrowDown");
      const exact = source.current.series.find(
        (p) => p.group.src_addr === "192.0.2.2",
      ).metrics[metric];
      if (
        !(
          await plotNode.locator("..").getByRole("status").textContent()
        ).includes(exact)
      )
        throw Error(
          "Stacked keyboard readout replaced the original exact value with a cumulative coordinate",
        );
      await plotNode.press("Escape");
      if (style === "stacked_columns") {
        await plotNode.scrollIntoViewIfNeeded();
        const currentPlots = await actualPlots(page, true);
        await page.mouse.move(
          currentPlots[0].columnPointer.x,
          currentPlots[0].columnPointer.y,
        );
        const readout = plotNode
          .locator("..")
          .locator('span[class*="readoutValue"]')
          .nth(1);
        await page.waitForFunction(
          (node) => node.textContent.trim() !== "—",
          await readout.elementHandle(),
        );
        const shown = (await readout.textContent()).trim();
        if (shown !== exact)
          throw Error(
            `Column pointer selected a neighboring bucket: expected ${exact}, received ${shown}`,
          );
        record.column_pointer_exact = shown;
        const previousPoint = source.previous.series.find(
          (p) => p.group.src_addr === "192.0.2.2",
        );
        const previousReadout = plotNode
          .locator("..")
          .locator('span[class*="readoutValue"]')
          .nth(43);
        if (
          (await previousReadout.textContent()).trim() !==
          `${previousPoint.metrics[metric]} (previous ${previousPoint.ts})`
        )
          throw Error(
            "Column pointer lost independent previous interval/exact timestamp",
          );
        await page.mouse.move(
          currentPlots[0].partialColumnPointer.x,
          currentPlots[0].partialColumnPointer.y,
        );
        const partial = source.current.series
          .filter((p) => p.group.src_addr === "192.0.2.2")
          .at(-1).metrics[metric];
        if (record.viewport === "mobile") {
          // At this retained range the final partial column is subpixel on
          // mobile. Check exact keyboard access before using actual drag zoom
          // to make a pointer hit physically resolvable, as a user would.
          await plotNode.press("End");
          await plotNode.press("ArrowLeft");
          if (
            !(
              await plotNode.locator("..").getByRole("status").textContent()
            ).includes(partial)
          )
            throw Error("Narrow column lost exact keyboard access before zoom");
          await plotNode.press("Escape");
          const zoom = currentPlots[0].columnZoom;
          record.subpixel_column_width = first.lastRectangle[2];
          record.partial_pointer_edge_distance = first.lastRectangle[2] / 4;
          if (record.partial_pointer_edge_distance >= 1)
            throw Error(
              "Mobile pointer oracle no longer exercises the engine edge-snap case",
            );
          await page.mouse.move(zoom.start, zoom.y);
          await page.mouse.down();
          await page.mouse.move(zoom.end, zoom.y, { steps: 10 });
          await page.mouse.up();
          let zoomed;
          for (let attempt = 0; attempt < 40; attempt++) {
            zoomed = (await actualPlots(page, true))[0];
            if (
              zoomed?.xRange &&
              zoomed.xRange[1] - zoomed.xRange[0] < 60 * 86400
            )
              break;
            await page.waitForTimeout(50);
          }
          if (
            !zoomed?.xRange ||
            zoomed.xRange[1] - zoomed.xRange[0] >= 60 * 86400
          )
            throw Error("Actual drag did not zoom the column time range");
          record.partial_pointer_zoom_range = zoomed.xRange;
          await page.mouse.move(
            zoomed.partialColumnPointer.x,
            zoomed.partialColumnPointer.y,
          );
        }
        await page.waitForFunction(
          ({ node, value }) => node.textContent.trim() === value,
          { node: await readout.elementHandle(), value: partial },
        );
        record.partial_column_pointer_exact = (
          await readout.textContent()
        ).trim();
      }
      record.time_styles.push({
        style,
        scale,
        groups_per_period: 41,
        independent_total: true,
        original_exact_value: exact,
        column_intervals:
          style === "stacked_columns"
            ? {
                count: first.rectangles,
                first: first.firstRectangle,
                last: first.lastRectangle,
              }
            : undefined,
      });
    }
  }
}

async function checkPercentageStyle(page, visuals, record, proof) {
  const source = sourceResponse("line").flow;
  const near = (a, b) => Number.isFinite(a) && Math.abs(a - b) < 1e-9;
  await page
    .getByLabel("Time chart style", { exact: true })
    .selectOption("percent_area");
  await page
    .getByLabel("Percentage basis", { exact: true })
    .selectOption("returned");
  const waitPlots = async (count, ready = () => true) => {
    for (let attempt = 0; attempt < 60; attempt++) {
      const plots = await actualPlots(page, true);
      if (
        plots.length === count &&
        plots.every((p) => !p.error) &&
        ready(plots)
      )
        return plots;
      await page.waitForTimeout(50);
    }
    throw Error(`Percentage charts did not reach ${count} actual plots`);
  };
  let plots = await waitPlots(4);
  const percentPlots = plots.filter((p) =>
    p.label.includes("percentage of group observations"),
  );
  const totals = plots.filter((p) => p.label.includes("absolute scale"));
  if (percentPlots.length !== 2 || totals.length !== 2)
    throw Error("Percentage/source-total scales were not separated");
  for (const [metricIndex, key] of [metric, secondaryMetric].entries()) {
    const plot = percentPlots[metricIndex];
    if (
      plot.distr !== 1 ||
      plot.min !== 0 ||
      plot.max !== 100 ||
      !plot.axisValues.filter(Boolean).every((label) => label.endsWith("%"))
    )
      throw Error("Actual percentage axis is not linear0–100percent");
    if (plot.series.some((s) => s.zeroCoordinate !== null))
      throw Error("Zero denominators manufactured a percentage observation");
    for (const [period, origin] of [
      ["Current", source.current],
      ["Previous", source.previous],
    ]) {
      const entries = plot.series.filter((s) => s.label.startsWith(period));
      const inputs = [...origin.series, ...origin.other_series].filter(
        (p) => Date.parse(p.ts) === Date.parse(origin.query.from),
      );
      if (entries.length !== 41)
        throw Error(
          "Percentage stack dropped groups/Other or included a total",
        );
      const sum = inputs.reduce(
        (total, p) => total + Number(p.metrics[key]),
        0,
      );
      let cumulative = 0;
      for (const [index, entry] of entries.entries()) {
        cumulative += (100 * Number(inputs[index].metrics[key])) / sum;
        if (
          period === "Current" &&
          index === 40 &&
          (!entry.geometry.percentageCoverage?.isolated ||
            !entry.geometry.percentageCoverage?.partial ||
            entry.geometry.percentageCoverage?.undefinedGap !== false)
        )
          throw Error(
            "Percentage area omits an isolated or partial defined source bucket",
          );
        if (
          !near(entry.firstCoordinate, cumulative) ||
          !entry.geometry.finite ||
          entry.geometry.fill !== (period === "Current")
        )
          throw Error(
            "Actual percentage paths mixed periods/metrics or source totals",
          );
      }
    }
    if (
      totals[metricIndex].series.length !== 2 ||
      !near(
        totals[metricIndex].series[0].firstCoordinate,
        Number(source.current.total_series[0].metrics[key]),
      )
    )
      throw Error("Independent source total changed into percentage geometry");
  }
  const firstPlot = visuals
    .getByRole("img", { name: /percentage of group observations/ })
    .first();
  await firstPlot.focus();
  await firstPlot.press("Home");
  await firstPlot.press("ArrowDown");
  const exact = source.current.series.find(
    (p) => p.group.src_addr === "192.0.2.2",
  ).metrics[metric];
  if (
    !(await firstPlot.locator("..").getByRole("status").textContent()).includes(
      exact,
    )
  )
    throw Error("Percentage keyboard readout replaced the exact count");
  await firstPlot.press("Escape");
  await firstPlot.scrollIntoViewIfNeeded();
  const percentagePointer = (await actualPlots(page, true)).find((p) =>
    p.label.includes("percentage of group observations"),
  );
  await page.mouse.move(
    percentagePointer.columnPointer.x,
    percentagePointer.columnPointer.y,
  );
  const pointerValue = firstPlot
    .locator("..")
    .locator('span[class*="readoutValue"]')
    .nth(1);
  await page.waitForFunction(
    (node) => node.textContent.trim() !== "—",
    await pointerValue.elementHandle(),
  );
  if ((await pointerValue.textContent()).trim() !== exact)
    throw Error(
      "Stepped percentage pointer selected a neighboring source interval",
    );
  const previousPoint = source.previous.series.find(
    (p) => p.group.src_addr === "192.0.2.2",
  );
  if (
    (
      await firstPlot
        .locator("..")
        .locator('span[class*="readoutValue"]')
        .nth(42)
        .textContent()
    ).trim() !==
    `${previousPoint.metrics[metric]} (previous ${previousPoint.ts})`
  )
    throw Error(
      "Stepped percentage pointer lost the previous source timestamp",
    );
  const summary = visuals
    .locator("summary")
    .filter({ hasText: /^Chart groups/ });
  const controls = visuals.getByRole("region", {
    name: "All global chart group controls",
  });
  if (!(await controls.isVisible())) await summary.press("Enter");
  await controls
    .getByRole("button", { name: /^Only show chart group/ })
    .nth(39)
    .click();
  plots = await waitPlots(4, (plots) =>
    plots
      .filter((p) => p.label.includes("percentage of group observations"))
      .every((p) => p.series.length === 2),
  );
  const solo = plots.find((p) =>
    p.label.includes("percentage of group observations"),
  );
  const selected = source.current.series.find(
    (p) => p.group.src_addr === "192.0.2.40",
  );
  const share =
    (100 * Number(selected.metrics[metric])) /
    Number(source.current.total_series[0].metrics[metric]);
  if (solo.series.length !== 2 || !near(solo.series[0].firstCoordinate, share))
    throw Error("Returned-group denominator changed when groups hid");
  await page
    .getByLabel("Percentage basis", { exact: true })
    .selectOption("visible");
  plots = await waitPlots(4, (plots) =>
    plots
      .filter((p) => p.label.includes("percentage of group observations"))
      .every((p) => p.series.every((s) => near(s.firstCoordinate, 100))),
  );
  const visible = plots.filter((p) =>
    p.label.includes("percentage of group observations"),
  );
  if (visible.some((p) => p.series.some((s) => !near(s.firstCoordinate, 100))))
    throw Error(
      "Visible-group percentage did not re-normalize each period independently",
    );
  await visuals
    .getByRole("button", { name: "Show all chart groups", exact: true })
    .click();
  await page
    .getByLabel("Percentage basis", { exact: true })
    .selectOption("returned");
  await summary.press("Enter");
  await page
    .getByLabel("One chart per group", { exact: true })
    .selectOption("on");
  await page.getByLabel("Charts per row", { exact: true }).selectOption("4");
  await page.getByLabel("Chart height", { exact: true }).selectOption("short");
  plots = await waitPlots(84);
  const facets = plots.filter((p) =>
    p.label.includes("percentage of group observations"),
  );
  if (
    facets.length !== 82 ||
    facets.some((p) => p.series.length !== 2 || p.min !== 0 || p.max !== 100)
  )
    throw Error(
      "Generated percentage charts dropped groups/periods or lost absolute totals",
    );
  const firstShare =
    (100 * Number(source.current.series[0].metrics[metric])) /
    Number(source.current.total_series[0].metrics[metric]);
  if (!near(facets[0].series[0].firstCoordinate, firstShare))
    throw Error("Generated facet silently became its own denominator");
  const violations = proof
    .blockingAxeResults(await proof.runAxe(page, proof.axeSource))
    .map((v) => v.id);
  const layout = [
    ...(await proof.horizontalOverflowCheck(page)),
    ...(await proof.interactiveClippingCheck(page)),
  ];
  if (violations.length || layout.length)
    throw Error(
      `Percentage accessibility/layout findings: ${JSON.stringify({ violations, layout })}`,
    );
  record.percentage = {
    axes: "linear0–100%",
    groups_per_period: 41,
    independent_total_figures: 2,
    returned_solo_share: share,
    visible_solo_share: 100,
    generated_percentage_charts: facets.length,
    original_exact_count: exact,
    pointer_exact_count: exact,
    undefined_zero: true,
    interval_coverage: percentPlots.map(
      (p) =>
        p.series.find(
          (s) =>
            s.label.startsWith("Current") &&
            s.label.includes("Other (unselected groups)"),
        ).geometry.percentageCoverage,
    ),
    axe: violations,
    layout,
  };
  await page.screenshot({
    path: join(
      proof.receiptDir,
      `native-flow-${record.theme}-${record.viewport}-percent.png`,
    ),
  });
  await page
    .getByLabel("One chart per group", { exact: true })
    .selectOption("off");
  await page.getByLabel("Chart height", { exact: true }).selectOption("medium");
  await page
    .getByLabel("Time chart style", { exact: true })
    .selectOption("stacked_columns");
  await waitPlots(2);
}

async function checkHorizonStyle(page, visuals, record, proof) {
  const source = sourceResponse("line").flow,
    near = (a, b) => Number.isFinite(a) && Math.abs(a - b) < 1e-8;
  const fold = (value, amplitude) => {
    const q = amplitude === 0 ? 0 : 5 * (value / amplitude);
    return q === 0 ? 0 : q - Math.max(0, Math.ceil(q) - 1);
  };
  const groupKey = (point) =>
    JSON.stringify(point.group) + ":" + Boolean(point.other);
  const maximum = (key, group) =>
    Math.max(
      0,
      ...[source.current, source.previous]
        .flatMap((period) => [...period.series, ...period.other_series])
        .filter((point) => !group || groupKey(point) === group)
        .map((point) => Number(point.metrics[key])),
    );
  const waitPlots = async (count, ready = () => true) => {
    for (let i = 0; i < 60; i++) {
      const plots = await actualPlots(page, true);
      if (
        plots.length === count &&
        plots.every((plot) => !plot.error) &&
        ready(plots)
      )
        return plots;
      await page.waitForTimeout(50);
    }
    throw Error("Horizon plots did not reach " + count);
  };
  await page
    .getByLabel("Time chart style", { exact: true })
    .selectOption("horizon");
  await page
    .getByLabel("Horizon density scale", { exact: true })
    .selectOption("shared");
  let plots = await waitPlots(4),
    horizons = plots.filter((plot) => plot.label.includes("horizon five-band"));
  if (
    horizons.length !== 2 ||
    plots.filter((plot) => plot.label.includes("absolute scale")).length !== 2
  )
    throw Error("Horizon/source-total plots are not separated");
  for (const [metricIndex, key] of [metric, secondaryMetric].entries()) {
    const plot = horizons[metricIndex],
      amplitude = maximum(key);
    if (
      plot.distr !== 1 ||
      plot.min !== 0 ||
      plot.max !== 41 ||
      plot.minimumGridGap < plot.axisFontPx
    )
      throw Error("Horizon lanes lost readable equal linear scales");
    if (plot.series.length !== 82)
      throw Error("Horizon dropped groups or previous period");
    for (const [periodIndex, period] of [
      source.current,
      source.previous,
    ].entries()) {
      const inputs = [...period.series, ...period.other_series].filter(
        (point) => Date.parse(point.ts) === Date.parse(period.query.from),
      );
      for (const [lane, point] of inputs.entries()) {
        const entry = plot.series[periodIndex * 41 + lane],
          base = 40 - lane;
        if (
          !near(
            entry.firstCoordinate,
            base + fold(Number(point.metrics[key]), amplitude),
          ) ||
          entry.zeroCoordinate !== base ||
          entry.geometry.bandStrokeCount !== 5 ||
          entry.geometry.bandFillCount !== (periodIndex ? 0 : 5) ||
          !entry.geometry.bandFinite
        )
          throw Error(
            "Horizon bands altered counts, mixed scales or lost source zeros",
          );
      }
    }
    const coverage = plot.series[40].geometry.horizonCoverage;
    if (!coverage?.isolated || !coverage?.partial || coverage.zeroGap !== false)
      throw Error(
        "Horizon failed isolated/partial source interval or zero-gap coverage",
      );
  }
  const firstPlot = visuals
    .getByRole("img", { name: /horizon five-band/ })
    .first();
  await firstPlot.focus();
  await firstPlot.press("Home");
  await firstPlot.press("ArrowDown");
  const point = source.current.series.find(
    (point) => point.group.src_addr === "192.0.2.2",
  );
  if (
    !(await firstPlot.locator("..").getByRole("status").textContent()).includes(
      point.metrics[metric],
    )
  )
    throw Error("Horizon keyboard readout replaced the source value");
  await firstPlot.press("Escape");
  await firstPlot.scrollIntoViewIfNeeded();
  const pointer = (await actualPlots(page, true)).find((plot) =>
    plot.label.includes("horizon five-band"),
  ).columnPointer;
  await page.mouse.move(pointer.x, pointer.y);
  const readout = firstPlot
    .locator("..")
    .locator('span[class*="readoutValue"]');
  await page.waitForFunction(
    (node) => node.textContent.trim() !== "—",
    await readout.nth(1).elementHandle(),
  );
  const previous = source.previous.series.find(
    (point) => point.group.src_addr === "192.0.2.2",
  );
  if (
    (await readout.nth(1).textContent()).trim() !== point.metrics[metric] ||
    (await readout.nth(42).textContent()).trim() !==
      `${previous.metrics[metric]} (previous ${previous.ts})`
  )
    throw Error("Horizon pointer lost exact current/previous source values");
  await firstPlot.screenshot({
    path: join(
      proof.receiptDir,
      `native-flow-${record.theme}-${record.viewport}-horizon.png`,
    ),
  });
  const contrasts = await page.evaluate(() => {
    const css = getComputedStyle(document.documentElement),
      canvas = document.createElement("canvas");
    canvas.width = canvas.height = 1;
    const ctx = canvas.getContext("2d");
    const rgba = (color) => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = color;
      ctx.fillRect(0, 0, 1, 1);
      return [...ctx.getImageData(0, 0, 1, 1).data];
    };
    const luminance = (rgb) =>
      rgb
        .slice(0, 3)
        .map((c) => {
          c /= 255;
          return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
        })
        .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);
    const background = luminance(
      rgba(`hsl(${css.getPropertyValue("--card")})`),
    );
    return [1, 2, 3, 4, 5].map((band) => {
      const color = css.getPropertyValue(`--viz-horizon-band-${band}`).trim(),
        rgb = rgba(color),
        lum = luminance(rgb);
      return {
        band,
        supported: CSS.supports("color", color),
        alpha: rgb[3],
        ratio:
          (Math.max(lum, background) + 0.05) /
          (Math.min(lum, background) + 0.05),
      };
    });
  });
  if (
    contrasts.some(
      (color) => !color.supported || color.alpha !== 255 || color.ratio < 3,
    )
  )
    throw Error("Horizon density bands are not opaque accessible theme colors");
  await page
    .getByLabel("One chart per group", { exact: true })
    .selectOption("on");
  await page.getByLabel("Charts per row", { exact: true }).selectOption("4");
  await page.getByLabel("Chart height", { exact: true }).selectOption("short");
  plots = await waitPlots(84);
  let facets = plots.filter((plot) => plot.label.includes("horizon five-band"));
  if (
    facets.length !== 82 ||
    facets.some(
      (plot) => plot.series.length !== 2 || plot.min !== 0 || plot.max !== 1,
    )
  )
    throw Error("Horizon generated facets omitted groups/periods");
  if (
    !near(
      facets[0].series[0].firstCoordinate,
      fold(Number(source.current.series[0].metrics[metric]), maximum(metric)),
    )
  )
    throw Error("Horizon generated chart silently changed shared amplitude");
  await page
    .getByLabel("Horizon density scale", { exact: true })
    .selectOption("lane");
  const ownAmplitude = maximum(metric, groupKey(source.current.series[0]));
  plots = await waitPlots(84, (plots) =>
    near(
      plots.filter((plot) => plot.label.includes("horizon five-band"))[0]
        ?.series[0]?.firstCoordinate,
      fold(Number(source.current.series[0].metrics[metric]), ownAmplitude),
    ),
  );
  facets = plots.filter((plot) => plot.label.includes("horizon five-band"));
  if (
    !near(
      facets[0].series[1].firstCoordinate,
      fold(Number(source.previous.series[0].metrics[metric]), ownAmplitude),
    )
  )
    throw Error("Horizon paired periods used different amplitudes");
  const violations = proof
      .blockingAxeResults(await proof.runAxe(page, proof.axeSource))
      .map((v) => v.id),
    layout = [
      ...(await proof.horizontalOverflowCheck(page)),
      ...(await proof.interactiveClippingCheck(page)),
    ];
  if (violations.length || layout.length)
    throw Error(
      "Horizon accessibility/layout findings: " +
        JSON.stringify({ violations, layout }),
    );
  record.horizon = {
    lanes: 41,
    groups_per_period: 41,
    bands: 5,
    shared_and_per_lane: true,
    generated_facets: facets.length,
    exact_current: point.metrics[metric],
    exact_previous: previous.metrics[metric],
    previous_timestamp: previous.ts,
    interval_coverage: horizons.map(
      (plot) => plot.series[40].geometry.horizonCoverage,
    ),
    contrasts,
    axe: violations,
    layout,
  };
  await page
    .getByLabel("One chart per group", { exact: true })
    .selectOption("off");
  await page.getByLabel("Chart height", { exact: true }).selectOption("medium");
  await page
    .getByLabel("Time chart style", { exact: true })
    .selectOption("stacked_columns");
  await waitPlots(2);
}

async function checkDisplaySettings(
  page,
  visuals,
  view,
  viewport,
  record,
  proof,
) {
  const {
    axeSource,
    receiptDir,
    runAxe,
    blockingAxeResults,
    horizontalOverflowCheck,
    interactiveClippingCheck,
  } = proof;
  await page.getByLabel("Total overlay", { exact: true }).selectOption("on");
  if (view === "line") {
    await page
      .getByLabel("Scale for bytes:total", { exact: true })
      .selectOption("log");
    await page
      .getByLabel("Synchronize metric axes", { exact: true })
      .selectOption("on");
    await page.waitForFunction(
      () =>
        document.querySelectorAll(
          '[role="img"][aria-label*="global flow time series"] .uplot canvas',
        ).length === 2,
    );
    let plots = await actualPlots(page);
    for (let i = 0; i < 30 && plots.some((p) => p.error); i++) {
      await page.waitForTimeout(50);
      plots = await actualPlots(page);
    }
    if (plots.length !== 2 || plots.some((p) => p.error))
      throw Error(
        "Actual primary+secondary uPlot instances were not available",
      );
    const mediumHeight = plots[0].canvasHeight;
    if (!(mediumHeight > 0))
      throw Error("Actual medium plot height unavailable");
    if (
      plots[0].distr !== 3 ||
      plots[1].distr !== 1 ||
      plots[0].min !== plots[1].min ||
      plots[0].max !== plots[1].max ||
      !(plots[0].min > 0)
    )
      throw Error(
        "Actual logarithmic/mixed shared axes do not match the saved display choice",
      );
    if (
      plots.some(
        (p) =>
          p.series.filter((s) =>
            s.label.includes("Total (all matching inputs)"),
          ).length !== 2,
      )
    )
      throw Error("Actual plot did not draw an independent total overlay");
    const totalWidth = Number(
      await page
        .locator("html")
        .evaluate((node) =>
          getComputedStyle(node).getPropertyValue("--viz-total-width"),
        ),
    );
    if (
      plots.some(
        (p) =>
          p.series.find((s) => s.label.includes("Total (all matching inputs)"))
            .width !== totalWidth,
      )
    )
      throw Error("Total emphasis did not use its actual stroke token");
    if (plots[0].series.some((s) => s.zeroCoordinate !== null))
      throw Error(
        "Logarithmic plot manufactured a nonzero floor for a known empty bucket",
      );
    record.actual_axes = plots.map((p) => ({
      label: p.label,
      min: p.min,
      max: p.max,
      distr: p.distr,
      totalWidth: p.series.find((s) =>
        s.label.includes("Total (all matching inputs)"),
      ).width,
    }));
    const priorTotal = plots[0].series.find(
      (entry) =>
        entry.label.startsWith("Previous") &&
        entry.label.includes("Total (all matching inputs)"),
    );
    if (!Array.isArray(priorTotal?.dash) || !priorTotal.dash.length)
      throw Error("Previous total did not use actual dashed strokes");
    record.previous_total_dash = priorTotal.dash;

    const firstPlot = visuals
      .getByRole("img", { name: /global flow time series/ })
      .first();
    const summary = firstPlot.locator("..").locator("summary");
    await summary.press("Enter");
    const inspector = summary.locator("..");
    const totalColumn = await inspector
      .locator('th[scope="col"]')
      .allTextContents();
    if (
      !totalColumn.some((text) => text.includes("Total (all matching inputs)"))
    )
      throw Error("Exact sample inspector omitted total overlay values");
    const exactTotal = result("line").flow.total_series.at(-1).metrics[metric];
    if (
      (await inspector
        .getByRole("cell", { name: exactTotal, exact: true })
        .count()) === 0
    )
      throw Error("Total inspector rounded the source decimal value");
    record.exact_total_value = exactTotal;

    if (
      (await inspector
        .getByRole("cell", { name: "0", exact: true })
        .count()) === 0
    )
      throw Error("Logarithmic sample inspector lost exact zero observations");
    await summary.press("Enter");
    await checkTimeStyles(page, visuals, record);
    await checkPercentageStyle(page, visuals, record, proof);
    await checkHorizonStyle(page, visuals, record, proof);
    await page
      .getByLabel("One chart per group", { exact: true })
      .selectOption("on");
    await page.getByLabel("Charts per row", { exact: true }).selectOption("4");
    await page
      .getByLabel("Chart height", { exact: true })
      .selectOption("short");
    await page.waitForFunction(
      () =>
        document.querySelectorAll(
          '[role="img"][aria-label*="global flow time series"] .uplot canvas',
        ).length === 82,
    );
    record.generated_charts = await visuals.locator("figure").count();
    if (record.generated_charts !== 82)
      throw Error("Generated charts dropped a selected group/Other/metric");
    const shortHeight = (mediumHeight * 5) / 8;
    await expectPlotHeights(page, 82, shortHeight);
    record.generated_heights = { medium: mediumHeight, short: shortHeight };
    const generatedPlots = (await actualPlots(page)).filter(
      (plot) => plot.distr === 3,
    );
    record.generated_log_grid = generatedPlots.map((plot) => ({
      gap: plot.minimumGridGap,
      font: plot.axisFontPx,
    }));
    if (
      !generatedPlots.length ||
      generatedPlots.some(
        (plot) =>
          plot.minimumGridGap !== null &&
          plot.minimumGridGap < plot.axisFontPx - 0.5,
      )
    )
      throw Error(
        `Logarithmic grid spacing obscures short plots: ${JSON.stringify(record.generated_log_grid[0])}`,
      );
    if (viewport.name === "desktop") {
      await page.setViewportSize({ width: 1920, height: 900 });
      await page.waitForTimeout(100);
      const columns = await visuals
        .locator("figure")
        .evaluateAll(
          (nodes) =>
            new Set(
              nodes
                .slice(0, 4)
                .map((n) => Math.round(n.getBoundingClientRect().left)),
            ).size,
        );
      if (columns !== 4)
        throw Error(
          "Wide generated layout did not reach the requested4columns",
        );
      record.generated_wide_columns = columns;
      await page.screenshot({
        path: join(
          receiptDir,
          `native-flow-${record.theme}-${viewport.name}-generated.png`,
        ),
      });
      await page.setViewportSize({
        width: viewport.width,
        height: viewport.height,
      });
    } else {
      record.generated_mobile_columns = await visuals
        .locator("figure")
        .evaluateAll(
          (nodes) =>
            new Set(
              nodes
                .slice(0, 4)
                .map((node) => Math.round(node.getBoundingClientRect().left)),
            ).size,
        );
      if (record.generated_mobile_columns !== 1)
        throw Error("Narrow generated charts did not collapse to one column");
      await page.screenshot({
        path: join(
          receiptDir,
          `native-flow-${record.theme}-${viewport.name}-generated.png`,
        ),
      });
    }
    record.generated_axe = blockingAxeResults(
      await runAxe(page, axeSource),
    ).map((violation) => violation.id);
    record.generated_errors = [
      ...(await horizontalOverflowCheck(page)),
      ...(await interactiveClippingCheck(page)),
    ];
    if (record.generated_axe.length || record.generated_errors.length)
      throw Error(
        `Generated chart layout has accessibility/overflow/clipping findings: ${JSON.stringify({ axe: record.generated_axe, errors: record.generated_errors })}`,
      );
    const groupSummary = visuals
      .locator("summary")
      .filter({ hasText: /^Chart groups/ });
    await groupSummary.press("Enter");
    const controls = visuals.getByRole("region", {
      name: "All global chart group controls",
    });
    await controls
      .getByRole("button", { name: /^Only show chart group/ })
      .nth(39)
      .click();
    await controls.getByRole("button", { name: /^Hide chart group/ }).click();
    await page.waitForFunction(
      () =>
        document.querySelectorAll(
          '[role="img"][aria-label*="global flow time series"] .uplot canvas',
        ).length === 2,
    );
    plots = await actualPlots(page);
    if (
      plots.some(
        (p) =>
          p.error ||
          p.series.length !== 2 ||
          !p.series.every((entry) =>
            entry.label.includes("Total (all matching inputs)"),
          ),
      )
    )
      throw Error("Hiding all groups removed or changed the independent total");
    record.total_survives_hidden_groups = true;
    await visuals
      .getByRole("button", { name: "Show all chart groups", exact: true })
      .click();
    await groupSummary.press("Enter");
    await page
      .getByLabel("One chart per group", { exact: true })
      .selectOption("off");
    await page.getByLabel("Chart height", { exact: true }).selectOption("tall");
    await expectPlotHeights(page, 2, (mediumHeight * 12) / 8);
    record.generated_heights.tall = (mediumHeight * 12) / 8;
    await page
      .getByLabel("Chart height", { exact: true })
      .selectOption("medium");
    await expectPlotHeights(page, 2, mediumHeight);
  } else {
    await visuals
      .getByText(`Total current: ${result(view).flow.totals[metric]}`, {
        exact: true,
      })
      .waitFor();
    record.exact_bar_total = result(view).flow.totals[metric];
  }
  const beforeSave = await page.evaluate(
    () =>
      window.__nativeFlowRequests.filter(
        (r) => r.method === "POST" && r.path.endsWith("/query"),
      ).length,
  );
  if (beforeSave !== 1)
    throw Error("Display settings reran the frozen data query");
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  await page.waitForFunction(
    () => window.__nativeSavedDisplay?.total_overlay === true,
  );
  record.saved_display = await page.evaluate(() => window.__nativeSavedDisplay);
  await page
    .getByRole("button", { name: "Run flow query", exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Frozen flow results", exact: true })
    .waitFor();
  if (
    (await page.getByLabel("Total overlay", { exact: true }).inputValue()) !==
    "on"
  )
    throw Error("Display choice did not survive saved-view reload/run");
  if (
    view === "line" &&
    (await page
      .getByLabel("Time chart style", { exact: true })
      .inputValue()) !== "stacked_columns"
  )
    throw Error("Saved time style did not survive reload/run");
  record.display_query_runs = {
    beforeSave,
    afterExplicitRun: await page.evaluate(
      () =>
        window.__nativeFlowRequests.filter(
          (r) => r.method === "POST" && r.path.endsWith("/query"),
        ).length,
    ),
  };
  if (record.display_query_runs.afterExplicitRun !== 2)
    throw Error("Saved display caused an unexpected query execution count");
}

export function nativeFlowSelfTest() {
  const themes = ["light", "dark"],
    viewports = [{ name: "desktop" }, { name: "mobile" }];
  const checks = themes.flatMap((theme) =>
    viewports.flatMap((viewport) =>
      NATIVE_FLOW_VIEWS.map((view) => ({
        theme,
        viewport: viewport.name,
        view,
        passed: true,
      })),
    ),
  );
  const assert = (condition, message) => {
    if (!condition) throw Error("native flow self-check: " + message);
  };
  assert(
    !validateNativeFlowMatrix(checks, themes, viewports).length,
    "complete matrix refused",
  );
  assert(
    validateNativeFlowMatrix(checks.slice(1), themes, viewports).length > 0,
    "missing case accepted",
  );
  assert(
    validateNativeFlowMatrix([...checks.slice(1), checks[1]], themes, viewports)
      .length > 0,
    "duplicate substituted for missing case",
  );
  assert(
    validateNativeFlowMatrix(
      checks.map((c, i) => (i ? c : { ...c, passed: false })),
      themes,
      viewports,
    ).length > 0,
    "failed case accepted",
  );
  assert(
    !validateNativeFlowMatrix(
      checks.filter((c) => c.theme === "dark"),
      ["dark"],
      viewports,
    ).length,
    "single-theme matrix refused",
  );
  const sum = (rows, key) =>
    rows.reduce((total, row) => total + BigInt(row.metrics[key]), 0n);
  for (const view of NATIVE_FLOW_VIEWS) {
    const response = sourceResponse(view),
      flow = response.flow.current ?? response.flow;
    assert(flow.query.group_by.length === 8, "row dimensions incomplete");
    assert(
      sum([...flow.rows, flow.other], metric) === BigInt(flow.totals[metric]),
      "detail fixture totals inconsistent",
    );
    if (view === "matrix") {
      assert(
        flow.query.matrix_with.length === 8 && flow.matrix.length === 241,
        "matrix source populations incomplete",
      );
      assert(
        sum(flow.matrix, metric) === BigInt(flow.totals[metric]),
        "matrix fixture totals inconsistent",
      );
    } else {
      for (const key of view === "line"
        ? [metric, secondaryMetric]
        : [metric]) {
        assert(
          sum([...flow.chart_rows, flow.chart_other], key) ===
            BigInt(flow.totals[key]),
          "chart fixture total inconsistent",
        );
        assert(
          sum([...flow.series, ...flow.other_series], key) ===
            BigInt(flow.totals[key]),
          "bucket fixture totals inconsistent",
        );
        assert(
          sum(flow.total_series, key) === BigInt(flow.totals[key]),
          "total stream inconsistent",
        );
      }
    }
    if (view === "line") {
      assert(
        response.flow.previous.total_series[0].ts === previousFrom,
        "previous nanosecond timestamp rounded",
      );
      assert(
        BigInt(response.flow.previous.totals[metric]) ===
          2n * BigInt(flow.totals[metric]),
        "previous fixture total inconsistent",
      );
    }
  }
}

export async function runNativeFlowChecks({
  browser,
  baseURL,
  schema,
  axeSource,
  receiptDir,
  themes,
  viewports,
  helpers,
}) {
  const {
    fetchStubSource,
    runAxe,
    blockingAxeResults,
    targetAndTabChecks,
    horizontalOverflowCheck,
    interactiveClippingCheck,
  } = helpers;
  const checks = [];
  for (const viewport of viewports)
    for (const theme of themes)
      for (const view of NATIVE_FLOW_VIEWS) {
        const record = {
          theme,
          view,
          viewport: viewport.name,
          errors: [],
          runtime: [],
          passed: false,
        };
        checks.push(record);
        const context = await browser.newContext({
          viewport,
          colorScheme: theme,
          locale: "en-US",
          hasTouch: viewport.name === "mobile",
        });
        const page = await context.newPage();
        page.on("pageerror", (error) => record.runtime.push(error.message));
        try {
          await context.addInitScript(
            fetchStubSource(theme) + nativeSource(view, schema),
          );
          await page.goto(`${baseURL}/ui/explore?flow_view=proof-${view}`, {
            waitUntil: "networkidle",
          });
          await page.addStyleTag({
            content:
              "*, *::before, *::after { transition-duration: 0s !important; animation-duration: 0s !important; }",
          });
          await page
            .getByRole("heading", { name: "Native flow query", exact: true })
            .waitFor();
          await page
            .getByRole("button", { name: "Run flow query", exact: true })
            .click();
          await page
            .getByRole("heading", { name: "Frozen flow results", exact: true })
            .waitFor();
          const visuals = page.getByRole("region", {
            name: "Global flow visualizations",
          });
          await visuals.scrollIntoViewIfNeeded();
          if (view === "line") {
            await page
              .locator(".uplot canvas")
              .first()
              .waitFor({ state: "attached" });
            const plots = await page
              .locator(".uplot canvas")
              .evaluateAll((nodes) =>
                nodes.map((node) => ({
                  width: node.width,
                  height: node.height,
                })),
              );
            if (
              !plots.length ||
              plots.some((plot) => !plot.width || !plot.height)
            )
              throw Error("Current canvas has no actual plot dimensions");
            record.plots = plots;
            const labels = await page.evaluate(() =>
              window.__nativeChartLabels.filter(
                (item) =>
                  (item.align === "right" || item.align === "end") &&
                  item.x < 100,
              ),
            );
            if (!labels.some((item) => /e[+-]/.test(item.text)))
              throw Error(
                "Large coordinate labels did not use readable exponent notation",
              );
            if (labels.some((item) => item.left < -1 || item.text.length > 10))
              throw Error(
                "A numeric axis label still extends outside the canvas",
              );
            record.axis_labels = [
              ...new Set(labels.map((item) => item.text)),
            ].slice(0, 20);
            const plot = visuals
              .getByRole("img", { name: /global flow time series/ })
              .first();
            const status = plot.locator("..").getByRole("status");
            await plot.focus();
            await plot.press("Home");
            const firstExact = result(view).flow.series[0].metrics[metric];
            await page.waitForFunction(
              ({ element, value }) =>
                element.textContent.includes("Sample 1 of ") &&
                element.textContent.includes(value),
              { element: await status.elementHandle(), value: firstExact },
            );
            const first = await status.textContent();
            await plot.press("ArrowDown");
            await page.waitForFunction(
              (element) => element.textContent.includes("src_addr: 192.0.2.2"),
              await status.elementHandle(),
            );
            const second = await status.textContent();
            await plot.press("End");
            const last = await status.textContent();
            if (!last.match(/Sample (\d+) of \1\./))
              throw Error(
                "Keyboard End did not reach the final plotted sample",
              );
            await plot.press("Escape");
            if ((await status.textContent()).trim())
              throw Error("Keyboard Escape did not clear its exact readout");
            const summary = visuals
              .locator("summary")
              .filter({ hasText: /Inspect all \d+ plotted samples/ })
              .first();
            await summary.press("Enter");
            const inspector = summary.locator("..");
            const total = Number(
              (await summary.textContent()).match(/all (\d+)/)?.[1],
            );
            if (!(total > 24))
              throw Error(
                "Full sample inspection proof did not exceed the former24-sample window",
              );
            await inspector
              .getByRole("button", { name: "First samples", exact: true })
              .click();
            const firstCaption = await inspector
              .locator("caption")
              .textContent();
            if (!firstCaption.includes(`samples 1–24 of ${total}`))
              throw Error(
                "First sample page did not expose the earliest24samples",
              );
            if (
              (await inspector.locator("tbody td").first().textContent()) !==
              firstExact
            )
              throw Error(
                "First sample page changed the authoritative exact value",
              );
            await inspector
              .getByRole("button", { name: "Latest samples", exact: true })
              .click();
            const lastCaption = await inspector
              .locator("caption")
              .textContent();
            if (!lastCaption.includes(`–${total} of ${total}`))
              throw Error("Latest sample page did not reach the final sample");
            record.keyboard_samples = {
              total,
              first,
              second,
              last,
              firstCaption,
              lastCaption,
              exactFirst: firstExact,
            };
            record.open_sample_inspector_axe = blockingAxeResults(
              await runAxe(page, axeSource),
            ).map((v) => v.id);
            if (record.open_sample_inspector_axe.length)
              throw Error(
                "Opened complete sample inspector has blocking accessibility findings",
              );
            await summary.press("Enter");
          }
          if (view === "matrix") {
            const cells = await visuals.locator("tbody td").count();
            if (cells !== 256)
              throw Error(`Expected complete16x16matrix cells, got${cells}`);
            record.matrix_cells = cells;
            await visuals.getByText("Current: 2414", { exact: true }).waitFor();
            await visuals
              .locator("tbody tr")
              .nth(14)
              .locator("td")
              .nth(14)
              .getByText("Filter to cell", { exact: true })
              .click();
            const finalField = await page
              .getByLabel("Condition 1.17 field", { exact: true })
              .inputValue();
            if (finalField !== "dst_country")
              throw Error(
                "Full8+8matrix tuple was not added to the actual condition editor",
              );
            record.matrix_complete_tuple_drill = true;
            await visuals
              .locator("tbody tr")
              .nth(14)
              .locator("td")
              .nth(14)
              .getByText("Exclude cell", { exact: true })
              .click();
            const excludedMode = await page
              .getByLabel("Group 1.1 inclusion", { exact: true })
              .inputValue();
            const excludedMatch = await page
              .getByLabel("Group 1.1 match", { exact: true })
              .inputValue();
            const excludedLast = await page
              .getByLabel("Condition 1.1.16 field", { exact: true })
              .inputValue();
            if (
              excludedMode !== "exclude" ||
              excludedMatch !== "all" ||
              excludedLast !== "dst_country"
            )
              throw Error(
                "Matrix exclusion did not preserve the full16-field excluded conjunction",
              );
            record.matrix_complete_tuple_exclusion = {
              mode: excludedMode,
              match: excludedMatch,
              lastField: excludedLast,
            };
            record.matrix_heading_geometry = await visuals
              .locator('[aria-label="Global flow matrix scroll region"]')
              .evaluate((region) => {
                const box = (element) => {
                  const r = element.getBoundingClientRect();
                  return {
                    left: r.left,
                    top: r.top,
                    right: r.right,
                    bottom: r.bottom,
                    width: r.width,
                    height: r.height,
                    position: getComputedStyle(element).position,
                  };
                };
                const row = region
                  .querySelectorAll("tbody tr")[14]
                  .querySelector("th");
                const column = region.querySelectorAll("thead th")[15];
                const corner = region.querySelector("thead th");
                return {
                  region: box(region),
                  row: box(row),
                  column: box(column),
                  corner: box(corner),
                  scrollLeft: region.scrollLeft,
                  scrollTop: region.scrollTop,
                };
              });
            const g = record.matrix_heading_geometry;
            if (
              g.row.position !== "sticky" ||
              g.column.position !== "sticky" ||
              Math.abs(g.row.left - g.region.left) > 4 ||
              Math.abs(g.column.top - g.region.top) > 4 ||
              g.region.width - g.corner.width < 90 ||
              g.column.top < 0 ||
              g.column.bottom > viewport.height
            )
              throw Error(
                "Scrolled matrix headings do not preserve visible row/column context and usable cell width",
              );
            const lastColumn = visuals.locator("thead th").nth(15);
            const summary = lastColumn.locator("summary");
            await summary.press("Enter");
            const values = lastColumn.getByRole("region");
            await values.focus();
            await values.press("End");
            await page.waitForFunction(
              (element) =>
                element.scrollHeight <= element.clientHeight ||
                element.scrollTop >=
                  element.scrollHeight - element.clientHeight - 1,
              await values.elementHandle(),
              { timeout: 5000 },
            );
            const metadata = await values.evaluate((element) => ({
              fields: element.querySelectorAll("dt").length,
              scrollTop: element.scrollTop,
              height: element.clientHeight,
              fullHeight: element.scrollHeight,
            }));
            if (metadata.fields !== 8)
              throw Error("Expanded matrix column dropped a tuple field");
            if (
              metadata.fullHeight > metadata.height &&
              metadata.scrollTop <= 0
            )
              throw Error("Expanded tuple values are not keyboard-scrollable");
            record.matrix_keyboard_metadata = metadata;
            await summary.press("Enter");
            await page.waitForFunction(
              (region) =>
                Math.abs(
                  parseFloat(
                    region.style.getPropertyValue("--matrix-header-block"),
                  ) -
                    region.querySelector("thead").getBoundingClientRect()
                      .height,
                ) < 1,
              await visuals
                .locator('[aria-label="Global flow matrix scroll region"]')
                .elementHandle(),
            );
            record.matrix_corner_occlusion = await visuals
              .locator("thead th")
              .first()
              .evaluate((corner) => {
                const r = corner.getBoundingClientRect();
                return [0.15, 0.5, 0.85].flatMap((x) =>
                  [0.15, 0.5, 0.85].map((y) => {
                    const element = document.elementFromPoint(
                      r.left + r.width * x,
                      r.top + r.height * y,
                    );
                    return {
                      x,
                      y,
                      covered: !element || !corner.contains(element),
                      tag: element?.tagName,
                    };
                  }),
                );
              });
            if (record.matrix_corner_occlusion.some((p) => p.covered))
              throw Error(
                "Scrolled matrix corner is overlapped by another header or row control",
              );
          }
          if (view === "bar") {
            const bars = await visuals.locator("ol > li").count();
            if (bars !== 41) throw Error(`Expected40groups+Other, got${bars}`);
            record.bar_groups_including_other = bars;
          }
          if (view !== "matrix") {
            const summary = visuals
              .locator("summary")
              .filter({ hasText: /^Chart groups/ });
            await summary.press("Enter");
            const controls = visuals.getByRole("region", {
              name: "All global chart group controls",
            });
            await controls
              .getByRole("button", { name: /^Only show chart group/ })
              .nth(39)
              .click();
            if (!(await summary.textContent()).includes("(1 of 41 shown)"))
              throw Error("Only failed to select the40thglobal group");
            if (
              view === "bar" &&
              (await visuals.locator("ol > li").count()) !== 1
            )
              throw Error("Only did not narrow painted bars");
            await controls
              .getByRole("button", { name: /^Show all except chart group/ })
              .nth(39)
              .click();
            if (!(await summary.textContent()).includes("(40 of 41 shown)"))
              throw Error(
                "All-except did not restore every other group after solo",
              );
            if (
              view === "bar" &&
              (await visuals.locator("ol > li").count()) !== 40
            )
              throw Error("All-except did not paint every other group");
            await controls
              .getByRole("button", { name: /^Only show chart group/ })
              .nth(39)
              .click();
            await controls
              .getByRole("button", { name: /^Hide chart group/ })
              .click();
            await visuals
              .getByText(
                "No chart groups are visible. Use Show all chart groups to restore them.",
                { exact: true },
              )
              .waitFor();
            await visuals
              .getByRole("button", {
                name: "Show all chart groups",
                exact: true,
              })
              .click();
            if (!(await summary.textContent()).includes("(41 of 41 shown)"))
              throw Error("Restore did not recover all40groups+Other");
            if (
              view === "bar" &&
              (await visuals.locator("ol > li").count()) !== 41
            )
              throw Error("Restore did not recover every bar");
            if (view === "line")
              await page
                .locator(".uplot canvas")
                .first()
                .waitFor({ state: "attached" });
            const executions = await page.evaluate(
              () =>
                window.__nativeFlowRequests.filter(
                  (r) => r.method === "POST" && r.path.endsWith("/query"),
                ).length,
            );
            if (executions !== 1)
              throw Error(
                "Chart visibility unexpectedly reran the frozen data query",
              );
            record.group_controls = {
              select40th: true,
              allExcept40th: true,
              hideAll: true,
              restore41: true,
              queryExecutions: executions,
            };
            await controls
              .getByRole("button", { name: /^Exclude chart group/ })
              .first()
              .click();
            const excludedMode = await page
              .getByLabel("Group 1.1 inclusion", { exact: true })
              .inputValue();
            const excludedMatch = await page
              .getByLabel("Group 1.1 match", { exact: true })
              .inputValue();
            const excludedLast = await page
              .getByLabel("Condition 1.1.8 field", { exact: true })
              .inputValue();
            const preserved = await page
              .getByLabel("Condition 1.1 field", { exact: true })
              .inputValue();
            if (
              excludedMode !== "exclude" ||
              excludedMatch !== "all" ||
              excludedLast !== "src_asn" ||
              preserved !== "raw_bytes"
            )
              throw Error(
                "Chart exclusion did not preserve the existing predicate and full8-field excluded conjunction",
              );
            record.chart_complete_tuple_exclusion = {
              mode: excludedMode,
              match: excludedMatch,
              lastField: excludedLast,
              preserved,
            };
            record.open_group_controls_axe = blockingAxeResults(
              await runAxe(page, axeSource),
            ).map((v) => v.id);
            if (record.open_group_controls_axe.length)
              throw Error(
                "Opened global group controls have blocking accessibility findings",
              );
            await summary.press("Enter");
          }
          if (view !== "matrix")
            await checkDisplaySettings(page, visuals, view, viewport, record, {
              axeSource,
              receiptDir,
              runAxe,
              blockingAxeResults,
              horizontalOverflowCheck,
              interactiveClippingCheck,
            });
          const dataReads = () =>
            page.evaluate(
              () =>
                window.__nativeFlowRequests
                  .filter(
                    (request) =>
                      request.path.endsWith("/query") ||
                      request.path === "/v1/explorer/compare",
                  )
                  .filter(
                    (request) => !JSON.parse(request.body || "{}").plan_only,
                  ).length,
            );
          const readsBeforePreview = await dataReads();
          await page
            .getByLabel("Ask a flow question", { exact: true })
            .fill("show bytes by source");
          await page
            .getByRole("button", { name: "Preview query plan", exact: true })
            .click();
          await page
            .getByText(
              "Proposed plan ready for review. Run flow query to execute.",
              { exact: true },
            )
            .waitFor();
          if (
            (await dataReads()) !== readsBeforePreview ||
            (await page
              .getByRole("heading", {
                name: "Frozen flow results",
                exact: true,
              })
              .count()) !== 0
          )
            throw Error(
              "Stateless preview executed telemetry or retained a stale result",
            );
          const planRequest = await page.evaluate(() =>
            window.__nativeFlowRequests
              .map((request) => JSON.parse(request.body || "{}"))
              .findLast((body) => body.plan_only === true),
          );
          if (
            JSON.stringify(Object.keys(planRequest).sort()) !==
              JSON.stringify(["plan_only", "question", "source"]) ||
            planRequest.source !== "flow"
          )
            throw Error(
              "Stateless preview sent undeclared authority or history input",
            );
          await page
            .getByRole("button", { name: "Run flow query", exact: true })
            .click();
          await page
            .getByRole("heading", { name: "Frozen flow results", exact: true })
            .waitFor();
          if ((await dataReads()) !== readsBeforePreview + 1)
            throw Error(
              "Explicit Run did not issue exactly one structured execution",
            );
          record.stateless_plan_review = {
            passed: true,
            planRequest,
            telemetry_reads_before_run: 0,
            explicit_execution: true,
          };
          await page.screenshot({
            path: join(
              receiptDir,
              `native-flow-${theme}-${viewport.name}-${view}.png`,
            ),
          });
          record.axe = blockingAxeResults(await runAxe(page, axeSource)).map(
            (v) => ({
              id: v.id,
              impact: v.impact,
              targets: v.nodes.map((n) => n.target),
            }),
          );
          await page.keyboard.press("Tab");
          record.errors.push(
            ...(await targetAndTabChecks(page)),
            ...(await horizontalOverflowCheck(page)),
            ...(await interactiveClippingCheck(page)),
          );
          record.passed =
            !record.axe.length &&
            !record.errors.length &&
            !record.runtime.length;
        } catch (error) {
          record.errors.push(error.message);
          record.diagnostics = await page
            .evaluate(() => ({
              canvas: typeof CanvasRenderingContext2D,
              alerts: [...document.querySelectorAll('[role="alert"]')].map(
                (node) => node.textContent,
              ),
              tables: [...document.querySelectorAll("caption")].map(
                (node) => node.textContent,
              ),
            }))
            .catch((diagnosticError) => ({ error: diagnosticError.message }));
          await page
            .screenshot({
              path: join(
                receiptDir,
                `native-flow-${theme}-${viewport.name}-${view}-failed.png`,
              ),
            })
            .catch((screenshotError) =>
              record.errors.push(
                "Failure screenshot: " + screenshotError.message,
              ),
            );
        } finally {
          await context.close();
        }
      }
  return {
    checks,
    failures: validateNativeFlowMatrix(checks, themes, viewports),
  };
}
