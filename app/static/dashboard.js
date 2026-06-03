(() => {
  const EMPTY_MESSAGES = {
    verifyRows: "No verification attempts recorded yet.",
    latencyRows: "No provider latency samples recorded yet.",
    rateLimitRows: "No rate-limit hits recorded yet.",
  };

  /**
   * Keep the card copy in one place so the initial server render and the
   * client-side refresh path can reuse the same derived values.
   */
  const CARD_DEFINITIONS = {
    check_requests: {
      detail: (snapshot) =>
        "Bypasses, valid cookies, and challenge redirects since startup.",
      value: (snapshot) => formatInteger(snapshot.checkRequests),
    },
    checks_allowed: {
      detail: (snapshot) => "Allowed check requests without challenge since startup.",
      value: (snapshot) => formatInteger(snapshot.checksAllowed),
    },
    checks_challenge_required: {
      detail: (snapshot) =>
        "Check requests that triggered a challenge since startup.",
      value: (snapshot) => formatInteger(snapshot.checksChallengeRequired),
    },
    rendered_challenges: {
      detail: () => "rendered challenges since startup.",
      value: (snapshot) => formatInteger(snapshot.renderedChallenges),
    },
    unsolved_challenges: {
      detail: () =>
        "Explicit challenge attempts without success since startup. Abandoned pages are not observable.",
      value: (snapshot) => formatInteger(snapshot.unsolvedChallenges),
    },
    verify_success_rate: {
      detail: (snapshot) =>
        `${formatInteger(snapshot.verifySuccess)} successful verifies out of ${formatInteger(snapshot.verifyTotal)}.`,
      value: (snapshot) => formatRate(snapshot.verifySuccess, snapshot.verifyTotal),
    },
    skip_routes: {
      detail: () => "Requests bypassed by configured skip_routes since startup.",
      value: (snapshot) => formatInteger(snapshot.skipRoutes),
    },
    rate_limit_hits: {
      detail: () => "Blocked challenge or verify requests since startup.",
      value: (snapshot) => formatInteger(snapshot.rateLimitHits),
    },
    backend_fallbacks: {
      detail: () => "Valkey backend failures that fell back to in-memory checks.",
      value: (snapshot) => formatInteger(snapshot.backendFailures),
    },
  };

  /**
   * Prometheus escapes label values inside the text exposition. The dashboard
   * decodes the subset that can appear in our labels before rebuilding rows.
   */
  function parseMetricLabels(source) {
    if (!source) {
      return {};
    }

    const labels = {};
    const labelPattern = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"/g;
    for (const match of source.matchAll(labelPattern)) {
      labels[match[1]] = match[2]
        .replace(/\\n/g, "\n")
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, "\\");
    }
    return labels;
  }

  /**
   * Parse the Prometheus text exposition into a metric-name -> samples map so the
   * browser can rebuild the same snapshot shape that the server renders initially.
   */
  function parsePrometheusMetrics(payload) {
    const samples = new Map();
    const linePattern = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?|[+-]?Inf|NaN)(?:\s+\d+)?$/;

    for (const rawLine of payload.split(/\r?\n/u)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) {
        continue;
      }

      const match = line.match(linePattern);
      if (!match) {
        continue;
      }

      const [, name, labelSource = "", rawValue] = match;
      const value = Number(rawValue);
      if (Number.isNaN(value)) {
        continue;
      }

      const metricSamples = samples.get(name) ?? [];
      metricSamples.push({
        labels: parseMetricLabels(labelSource),
        value,
      });
      samples.set(name, metricSamples);
    }

    return samples;
  }

  /**
   * Sum all samples for one metric name regardless of labels.
   */
  function sumSamples(samples, name) {
    return (samples.get(name) ?? []).reduce((total, sample) => total + sample.value, 0);
  }

  /**
   * Some cards depend on one metric with a fixed label subset, such as the
   * dedicated skip_route bypass counter.
   */
  function sumLabeledSamples(samples, name, expectedLabels) {
    return (samples.get(name) ?? []).reduce((total, sample) => {
      const matches = Object.entries(expectedLabels).every(
        ([key, value]) => sample.labels[key] === value,
      );
      return matches ? total + sample.value : total;
    }, 0);
  }

  /**
   * Collapse all verify-attempt samples into one success/total pair for the
   * summary card before the per-host and per-provider breakdown.
   */
  function verifyTotals(samples) {
    return (samples.get("crykeeper_verify_attempts_total") ?? []).reduce(
      (result, sample) => {
        result.total += sample.value;
        if (sample.labels.outcome === "success") {
          result.success += sample.value;
        }
        return result;
      },
      { success: 0, total: 0 },
    );
  }

  /**
   * Group verify attempts by host/provider first so the dashboard can show one
   * row per slice with collapsed failure reasons.
   */
  function buildVerifyRows(samples) {
    const grouped = new Map();

    // First, collect all hosts from check_requests to ensure hosts with only checks appear
    for (const sample of samples.get("crykeeper_check_requests_total") ?? []) {
      const host = sample.labels.host ?? "default";
      // Use "dummy" as default provider for hosts with only checks
      const key = `${host}\u0000dummy`;
      grouped.set(key, {
        host,
        provider: "dummy",
        reasons: new Map(),
        success: 0,
        total: 0,
      });
    }

    // Then, collect verify attempts to populate actual provider and outcome data
    for (const sample of samples.get("crykeeper_verify_attempts_total") ?? []) {
      const host = sample.labels.host ?? "default";
      const provider = sample.labels.provider ?? "dummy";
      const key = `${host}\u0000${provider}`;
      const row = grouped.get(key) ?? {
        host,
        provider,
        reasons: new Map(),
        success: 0,
        total: 0,
      };

      row.total += sample.value;
      if (sample.labels.outcome === "success") {
        row.success += sample.value;
      } else {
        const reason = sample.labels.reason ?? "unknown";
        row.reasons.set(reason, (row.reasons.get(reason) ?? 0) + sample.value);
      }

      grouped.set(key, row);
    }

    return [...grouped.values()]
      .map((row) => {
        const failures = row.reasons.size
          ? [...row.reasons.entries()]
              .sort((left, right) => {
                if (right[1] !== left[1]) {
                  return right[1] - left[1];
                }
                return left[0].localeCompare(right[0]);
              })
              .map(([reason, count]) => `${reason} ${formatInteger(count)}`)
              .join(", ")
          : "none";

        const checkRequests = sumLabeledSamples(
          samples,
          "crykeeper_check_requests_total",
          { host: row.host },
        );
        const checksAllowed = sumLabeledSamples(
          samples,
          "crykeeper_check_requests_total",
          { host: row.host, outcome: "allowed" },
        );
        const checksChallengeRequired = sumLabeledSamples(
          samples,
          "crykeeper_check_requests_total",
          { host: row.host, outcome: "challenge_required" },
        );
        const renderedChallenges = sumLabeledSamples(
          samples,
          "crykeeper_challenge_requests_total",
          { host: row.host, provider: row.provider, outcome: "rendered" },
        );
        const rateLimitHits = sumLabeledSamples(
          samples,
          "crykeeper_rate_limit_hits_total",
          { host: row.host },
        );

        return {
          failures,
          host: row.host,
          provider: row.provider,
          success_rate: formatRate(row.success, row.total),
          successful: formatInteger(row.success),
          total: formatInteger(row.total),
          check_requests: formatInteger(checkRequests),
          checks_allowed: formatInteger(checksAllowed),
          checks_challenge_required: formatInteger(checksChallengeRequired),
          rendered_challenges: formatInteger(renderedChallenges),
          rate_limit_hits: formatInteger(rateLimitHits),
        };
      })
      .sort((left, right) =>
        left.host.localeCompare(right.host) || left.provider.localeCompare(right.provider),
      );
  }

  /**
   * Mirror the server-side histogram folding in the browser so p95 and averages
   * stay aligned with the initial HTML snapshot.
   */
  function histogramSnapshot(samples, baseName) {
    const buckets = new Map();
    const sums = new Map();
    const counts = new Map();

    for (const sample of samples.get(`${baseName}_bucket`) ?? []) {
      const labels = { ...sample.labels };
      const upperBound = labels.le === "+Inf" ? Infinity : Number(labels.le);
      delete labels.le;
      const key = stableKey(labels);
      const bucketValues = buckets.get(key) ?? { labels, values: [] };
      bucketValues.values.push([upperBound, sample.value]);
      buckets.set(key, bucketValues);
    }

    for (const sample of samples.get(`${baseName}_sum`) ?? []) {
      sums.set(stableKey(sample.labels), sample.value);
    }

    for (const sample of samples.get(`${baseName}_count`) ?? []) {
      counts.set(stableKey(sample.labels), sample.value);
    }

    const snapshot = [];
    for (const [key, bucketEntry] of buckets.entries()) {
      const count = counts.get(key) ?? 0;
      const sum = sums.get(key) ?? 0;
      snapshot.push({
        average: count > 0 ? sum / count : Number.NaN,
        count,
        labels: bucketEntry.labels,
        p95: histogramQuantile(0.95, bucketEntry.values),
      });
    }
    return snapshot;
  }

  /**
   * Calculate the requested quantile over the histogram buckets using the same
   * algorithm as Prometheus's histogram_quantile function. This is a best-effort
   * approximation since the client doesn't have the raw observation values, but
   * it should be sufficient for tracking changes over time and between providers.
   */
  function histogramQuantile(quantile, bucketValues) {
    if (!bucketValues.length) {
      return Number.NaN;
    }

    const ordered = [...bucketValues].sort((left, right) => left[0] - right[0]);
    const totalCount = ordered[ordered.length - 1][1];
    if (totalCount <= 0) {
      return Number.NaN;
    }

    const wanted = quantile * totalCount;
    let previousCount = 0;
    let previousUpper = 0;

    for (const [upperBound, cumulativeCount] of ordered) {
      if (cumulativeCount < wanted) {
        previousCount = cumulativeCount;
        if (Number.isFinite(upperBound)) {
          previousUpper = upperBound;
        }
        continue;
      }

      const bucketCount = cumulativeCount - previousCount;
      if (bucketCount <= 0) {
        return previousUpper;
      }
      if (!Number.isFinite(upperBound)) {
        return previousUpper;
      }

      const position = (wanted - previousCount) / bucketCount;
      return previousUpper + ((upperBound - previousUpper) * position);
    }

    return previousUpper;
  }

  /**
   * Build provider latency rows from the histogram snapshot used by the latency
   * table in the dashboard.
   */
  function buildProviderLatencyRows(samples) {
    return histogramSnapshot(samples, "crykeeper_provider_latency_seconds")
      .map((row) => ({
        average: formatDuration(row.average),
        count: formatInteger(row.count),
        host: row.labels.host ?? "default",
        operation: row.labels.operation ?? "verify",
        p95: formatDuration(row.p95),
        provider: row.labels.provider ?? "dummy",
      }))
      .sort((left, right) =>
        left.host.localeCompare(right.host) ||
        left.provider.localeCompare(right.provider) ||
        left.operation.localeCompare(right.operation),
      );
  }

  /**
   * Build one rate-limit row per host, scope, and backend combination.
   */
  function buildRateLimitRows(samples) {
    return (samples.get("crykeeper_rate_limit_hits_total") ?? [])
      .map((sample) => ({
        backend: sample.labels.backend ?? "memory",
        hits: formatInteger(sample.value),
        host: sample.labels.host ?? "default",
        scope: sample.labels.scope ?? "challenge",
      }))
      .sort((left, right) =>
        left.host.localeCompare(right.host) ||
        left.scope.localeCompare(right.scope) ||
        left.backend.localeCompare(right.backend),
      );
  }

  /**
   * Build the fallback table rows from backend failure counters.
   */
  function buildBackendFailureRows(samples) {
    return (samples.get("crykeeper_rate_limit_backend_failures_total") ?? [])
      .map((sample) => ({
        backend: sample.labels.backend ?? "valkey",
        count: formatInteger(sample.value),
      }))
      .sort((left, right) => left.backend.localeCompare(right.backend));
  }

  /**
   * Recreate the same high-level snapshot that app/observability.py builds for
   * the initial render, but from freshly fetched metrics text.
   */
  function buildSnapshot(samples) {
    const totals = verifyTotals(samples);
    return {
      backendFailureRows: buildBackendFailureRows(samples),
      backendFailures: sumSamples(samples, "crykeeper_rate_limit_backend_failures_total"),
      checkRequests: sumSamples(samples, "crykeeper_check_requests_total"),
      checksAllowed: sumLabeledSamples(
        samples,
        "crykeeper_check_requests_total",
        { outcome: "allowed" },
      ),
      checksChallengeRequired: sumLabeledSamples(
        samples,
        "crykeeper_check_requests_total",
        { outcome: "challenge_required" },
      ),
      renderedChallenges: sumLabeledSamples(
        samples,
        "crykeeper_challenge_requests_total",
        { outcome: "rendered" },
      ),
      latencyRows: buildProviderLatencyRows(samples),
      rateLimitHits: sumSamples(samples, "crykeeper_rate_limit_hits_total"),
      rateLimitRows: buildRateLimitRows(samples),
      skipRoutes: sumLabeledSamples(samples, "crykeeper_auth_bypass_total", {
        reason: "skip_route",
      }),
      unsolvedChallenges: sumSamples(
        samples,
        "crykeeper_unsolved_challenge_attempts_total",
      ),
      verifyRows: buildVerifyRows(samples),
      verifySuccess: totals.success,
      verifyTotal: totals.total,
    };
  }

  /**
   * Build one stable key for a label set so related histogram samples can be
   * grouped back together after parsing the text exposition.
   */
  function stableKey(labels) {
    return Object.entries(labels)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => `${key}=${value}`)
      .join("\u0000");
  }

  /**
   * Format counters and totals without a fractional part.
   */
  function formatInteger(value) {
    return Math.trunc(value).toLocaleString("en-US");
  }

  /**
   * Format one success ratio as a percentage when a denominator exists.
   */
  function formatRate(success, total) {
    if (total <= 0) {
      return "n/a";
    }
    return `${((success / total) * 100).toFixed(1)}%`;
  }

  /**
   * Format latency values into the same human-readable units as the server
   * snapshot shown on first render.
   */
  function formatDuration(value) {
    if (Number.isNaN(value)) {
      return "n/a";
    }

    const milliseconds = value * 1000;
    if (milliseconds >= 1000) {
      return `${value.toFixed(2)} s`;
    }
    if (milliseconds >= 100) {
      return `${milliseconds.toFixed(0)} ms`;
    }
    if (milliseconds >= 10) {
      return `${milliseconds.toFixed(1)} ms`;
    }
    return `${milliseconds.toFixed(2)} ms`;
  }

  /**
   * Escape dynamic content before injecting locally rendered rows into the DOM.
   */
  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  /**
   * Render the shared empty-state paragraph for panels without rows.
   */
  function renderEmpty(message) {
    return `<p class="empty">${escapeHtml(message)}</p>`;
  }

  /**
   * Render one table for a set of rows so periodic refreshes replace only the
   * section markup instead of reloading the whole page.
   */
  function renderTable(columns, rows) {
    const headings = columns
      .map((column) => `<th>${escapeHtml(column.heading)}</th>`)
      .join("");
    const body = rows
      .map(
        (row) =>
          `<tr>${columns
            .map((column) => `<td>${column.render(row)}</td>`)
            .join("")}</tr>`,
      )
      .join("");

    return `
      <table>
        <thead>
          <tr>${headings}</tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    `;
  }

  /**
   * Render the verify outcomes panel body.
   */
  function renderVerifyRows(rows) {
    if (!rows.length) {
      return renderEmpty(EMPTY_MESSAGES.verifyRows);
    }

    return renderTable(
      [
        { heading: "Host", render: (row) => escapeHtml(row.host) },
        {
          heading: "Provider",
          render: (row) => `<span class="badge">${escapeHtml(row.provider)}</span>`,
        },
        { heading: "Success rate", render: (row) => escapeHtml(row.success_rate) },
        { heading: "Successful", render: (row) => escapeHtml(row.successful) },
        { heading: "Total", render: (row) => escapeHtml(row.total) },
        { heading: "Failures", render: (row) => escapeHtml(row.failures) },
        { heading: "Check requests", render: (row) => escapeHtml(row.check_requests) },
        { heading: "Checks allowed", render: (row) => escapeHtml(row.checks_allowed) },
        { heading: "Checks challenge required", render: (row) => escapeHtml(row.checks_challenge_required) },
        { heading: "Rendered challenges", render: (row) => escapeHtml(row.rendered_challenges) },
        { heading: "Rate limit hits", render: (row) => escapeHtml(row.rate_limit_hits) },
      ],
      rows,
    );
  }

  /**
   * Render the provider latency panel body.
   */
  function renderLatencyRows(rows) {
    if (!rows.length) {
      return renderEmpty(EMPTY_MESSAGES.latencyRows);
    }

    return renderTable(
      [
        { heading: "Host", render: (row) => escapeHtml(row.host) },
        {
          heading: "Provider",
          render: (row) => `<span class="badge">${escapeHtml(row.provider)}</span>`,
        },
        { heading: "Operation", render: (row) => escapeHtml(row.operation) },
        { heading: "Requests", render: (row) => escapeHtml(row.count) },
        { heading: "p95", render: (row) => escapeHtml(row.p95) },
        { heading: "Average", render: (row) => escapeHtml(row.average) },
      ],
      rows,
    );
  }

  /**
   * Render the rate-limit panel body.
   */
  function renderRateLimitRows(rows) {
    if (!rows.length) {
      return renderEmpty(EMPTY_MESSAGES.rateLimitRows);
    }

    return renderTable(
      [
        { heading: "Host", render: (row) => escapeHtml(row.host) },
        { heading: "Scope", render: (row) => escapeHtml(row.scope) },
        { heading: "Backend", render: (row) => escapeHtml(row.backend) },
        { heading: "Hits", render: (row) => escapeHtml(row.hits) },
      ],
      rows,
    );
  }

  /**
   * Render the fallback table when backend failure rows exist.
   */
  function renderBackendFailureRows(rows) {
    if (!rows.length) {
      return "";
    }

    return renderTable(
      [
        {
          heading: "Fallback source",
          render: (row) => `<span class="badge danger">${escapeHtml(row.backend)}</span>`,
        },
        { heading: "Count", render: (row) => escapeHtml(row.count) },
      ],
      rows,
    );
  }

  /**
   * Update the card values without replacing the surrounding server-rendered
   * dashboard shell.
   */
  function updateCards(root, snapshot) {
    for (const card of root.querySelectorAll("[data-card-key]")) {
      const definition = CARD_DEFINITIONS[card.dataset.cardKey];
      if (!definition) {
        continue;
      }

      const valueElement = card.querySelector("[data-card-value]");
      const detailElement = card.querySelector("[data-card-detail]");
      if (valueElement) {
        valueElement.textContent = definition.value(snapshot);
      }
      if (detailElement) {
        detailElement.textContent = definition.detail(snapshot);
      }
    }
  }

  /**
   * Update each panel section with the freshly rendered row markup.
   */
  function updateSections(root, snapshot) {
    const verifySection = root.querySelector('[data-section="verify-rows"]');
    const latencySection = root.querySelector('[data-section="latency-rows"]');
    const rateLimitSection = root.querySelector('[data-section="rate-limit-rows"]');
    const backendFailureSection = root.querySelector('[data-section="backend-failure-rows"]');

    if (verifySection) {
      verifySection.innerHTML = renderVerifyRows(snapshot.verifyRows);
    }
    if (latencySection) {
      latencySection.innerHTML = renderLatencyRows(snapshot.latencyRows);
    }
    if (rateLimitSection) {
      rateLimitSection.innerHTML = renderRateLimitRows(snapshot.rateLimitRows);
    }
    if (backendFailureSection) {
      backendFailureSection.innerHTML = renderBackendFailureRows(snapshot.backendFailureRows);
    }
  }

  /**
   * Update the refresh status text and error state on the shared status shell.
   */
  function setStatus(root, message, isError = false) {
    const shell = root.querySelector("[data-refresh-shell]");
    const element = root.querySelector("[data-refresh-status-text]");
    if (!element) {
      return;
    }
    element.textContent = message;
    if (shell) {
      shell.dataset.state = isError ? "error" : "ok";
    }
  }

  /**
   * Reflect the current refresh state on the icon button so manual and scheduled
   * refreshes share the same visual feedback.
   */
  function setRefreshButtonState(root, isRefreshing) {
    const button = root.querySelector("[data-manual-refresh]");
    if (!button) {
      return;
    }
    button.disabled = isRefreshing;
    button.dataset.loading = isRefreshing ? "true" : "false";
    button.title = isRefreshing ? "Refreshing dashboard" : "Refresh dashboard";
  }

  /**
   * Fetch the raw metrics payload and rebuild the full dashboard snapshot locally
   * instead of asking the server to rerender the whole page.
   */
  async function refreshDashboard(root) {
    const metricsPath = root.dataset.metricsPath;
    const response = await fetch(metricsPath, {
      cache: "no-store",
      headers: {
        Accept: "text/plain",
      },
    });

    if (!response.ok) {
      throw new Error(`Metrics request failed with status ${response.status}`);
    }

    const payload = await response.text();
    const snapshot = buildSnapshot(parsePrometheusMetrics(payload));
    updateCards(root, snapshot);
    updateSections(root, snapshot);
    setStatus(root, `Last updated ${new Date().toLocaleTimeString("en-GB")}`);
  }

  /**
   * Coordinate the periodic polling timer and the manual refresh button so both
   * converge on identical request, status, and retry behavior.
   */
  function startDashboardRefresh() {
    const root = document.querySelector("[data-dashboard-root]");
    if (!root) {
      return;
    }

    const refreshIntervalMs = Number.parseInt(root.dataset.refreshIntervalMs ?? "15000", 10);
    let refreshInFlight = null;

    /**
     * Trigger one refresh cycle while guarding against overlapping requests.
     */
    const refreshOnce = async (isManual = false) => {
      if (refreshInFlight) {
        return refreshInFlight;
      }

      if (isManual) {
        setStatus(root, "Refreshing dashboard now...");
      }
      setRefreshButtonState(root, true);

      refreshInFlight = (async () => {
        try {
          await refreshDashboard(root);
        } catch (error) {
          console.error("Failed to refresh dashboard metrics", error);
          setStatus(root, "Refresh failed.", true);
        } finally {
          setRefreshButtonState(root, false);
          refreshInFlight = null;
        }
      })();

      return refreshInFlight;
    };

    const manualRefreshButton = root.querySelector("[data-manual-refresh]");
    if (manualRefreshButton) {
      manualRefreshButton.addEventListener("click", () => {
        void refreshOnce(true);
      });
    }

    /**
     * Schedule the next automatic refresh without duplicating the error handling
     * inside the main refresh path.
     */
    const scheduleRefresh = () => {
      try {
        void refreshOnce(false);
      } catch (error) {
        console.error("Failed to schedule dashboard refresh", error);
      }
    };

    void refreshOnce(false);
    window.setInterval(
      scheduleRefresh,
      Number.isFinite(refreshIntervalMs) ? refreshIntervalMs : 15000,
    );
  }

  startDashboardRefresh();
})();
