(function () {
  "use strict";

  var RISK_RANK = { Critical: 5, High: 4, Medium: 3, Low: 2, Unknown: 1 };
  var RISK_LEVELS = ["Critical", "High", "Medium", "Low"];

  var state = {
    data: null,
    report: null,
    reportHtml: null,
    sbomUrl: null,
    loading: false,
    sbomLoading: false
  };

  var elements = {};

  function byId(id) {
    return document.getElementById(id);
  }

  function cacheElements() {
    [
      "analysis-form",
      "project-directory",
      "analyze-button",
      "directory-error",
      "status-banner",
      "banner-title",
      "banner-message",
      "banner-list",
      "initial-state",
      "results",
      "project-badge",
      "metric-total",
      "metric-vulnerable",
      "metric-vulnerabilities",
      "metric-critical",
      "metric-high",
      "metric-medium",
      "metric-low",
      "metric-unknown",
      "metric-unresolved",
      "metric-incomplete",
      "metric-checked",
      "project-risk-badge",
      "risk-overview-badge",
      "coverage-status",
      "inventory-note",
      "inventory-search",
      "inventory-risk-filter",
      "inventory-body",
      "inventory-table",
      "inventory-empty",
      "findings-note",
      "vulnerability-filter",
      "vulnerability-body",
      "vulnerability-table",
      "vulnerability-empty",
      "project-risk-reason",
      "risk-warning-list",
      "risk-body",
      "risk-table",
      "risk-empty",
      "sbom-button",
      "sbom-status",
      "sbom-download",
      "report-json",
      "report-html",
      "report-meta"
    ].forEach(function (id) {
      elements[id] = byId(id);
    });
  }

  function node(tag, className, text) {
    var element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    if (text !== undefined && text !== null) {
      element.textContent = String(text);
    }
    return element;
  }

  function addCell(row, content, className) {
    var cell = document.createElement("td");
    if (className) {
      cell.className = className;
    }

    if (content instanceof Node) {
      cell.appendChild(content);
    } else if (content === undefined || content === null || content === "") {
      cell.textContent = "—";
      if (cell.textContent === "—") {
        cell.classList.add("muted");
      }
    } else {
      cell.textContent = String(content);
    }

    row.appendChild(cell);
    return cell;
  }

  function titleCase(value) {
    var text = String(value || "").trim();
    if (!text) {
      return "Unknown";
    }
    return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
  }

  function riskBadge(risk) {
    var label = RISK_LEVELS.indexOf(risk) >= 0 ? risk : "Unknown";
    return node("span", "badge risk-" + label.toLowerCase(), label);
  }

  function coverageBadge(value) {
    var normalized = String(value || "unavailable").toLowerCase();
    var labels = {
      complete: "Complete",
      partial: "Partial",
      unavailable: "Unavailable",
      unresolved: "Unresolved",
      empty: "Empty"
    };
    return node(
      "span",
      "badge coverage-" + normalized,
      labels[normalized] || titleCase(normalized)
    );
  }

  function severityBadge(finding) {
    var raw = finding.severity || finding.severity_label || "Unknown";
    var label = finding.severity_label || "Unknown";
    var normalized = ["Critical", "High", "Medium", "Low"].indexOf(label) >= 0
      ? label
      : "Unknown";
    var badge = node("span", "badge risk-" + normalized.toLowerCase(), label);
    if (raw && raw !== label) {
      badge.title = "Reported severity: " + raw;
    }
    return badge;
  }

  function setText(id, value) {
    var element = elements[id];
    if (element) {
      element.textContent = value === undefined || value === null ? "0" : String(value);
    }
  }

  function setBanner(kind, title, message, details) {
    var banner = elements["status-banner"];
    var list = elements["banner-list"];

    banner.className = "banner is-" + kind;
    elements["banner-title"].textContent = title;
    elements["banner-message"].textContent = message || "";
    list.innerHTML = "";

    var items = Array.isArray(details) ? details.filter(Boolean) : [];
    if (items.length) {
      items.slice(0, 6).forEach(function (item) {
        list.appendChild(node("li", "", item));
      });
      if (items.length > 6) {
        list.appendChild(node("li", "", "and " + (items.length - 6) + " more"));
      }
      list.hidden = false;
    } else {
      list.hidden = true;
    }

    banner.hidden = false;
  }

  function hideBanner() {
    elements["status-banner"].hidden = true;
  }

  function setLoading(isLoading) {
    state.loading = isLoading;
    var button = elements["analyze-button"];
    var label = button.querySelector(".button-label");
    var spinner = button.querySelector(".spinner");

    button.disabled = isLoading;
    label.textContent = isLoading ? "Analyzing…" : "Run analysis";
    spinner.hidden = !isLoading;
    elements["analysis-form"].setAttribute("aria-busy", isLoading ? "true" : "false");
  }

  function showFieldError(message) {
    var error = elements["directory-error"];
    error.textContent = message;
    error.hidden = false;
    elements["project-directory"].setAttribute("aria-invalid", "true");
  }

  function clearFieldError() {
    var error = elements["directory-error"];
    error.textContent = "";
    error.hidden = true;
    elements["project-directory"].removeAttribute("aria-invalid");
  }

  function readJson(response) {
    return response.text().then(function (text) {
      if (!text) {
        return {};
      }
      try {
        return JSON.parse(text);
      } catch (error) {
        throw new Error("The server returned an invalid response.");
      }
    });
  }

  function runAnalysis(directory) {
    if (state.loading) {
      return;
    }

    setLoading(true);
    hideBanner();
    elements["initial-state"].hidden = true;
    elements["results"].hidden = true;
    setBanner(
      "loading",
      "Running analysis",
      "Discovering manifests and checking resolved dependencies against OSV."
    );

    fetch("/api/dashboard/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_directory: directory })
    })
      .then(function (response) {
        return readJson(response).then(function (payload) {
          if (!response.ok || payload.status === "error") {
            throw new Error(
              payload.error ||
                (payload.errors && payload.errors[0]) ||
                (payload.warnings && payload.warnings[0]) ||
                "Analysis failed with HTTP " + response.status + "."
            );
          }
          return payload;
        });
      })
      .then(function (payload) {
        state.data = payload;
        state.report = payload.report || null;
        state.reportHtml = payload.report_html || null;
        render(payload);
        renderStatus(payload, directory);
      })
      .catch(function (error) {
        state.data = null;
        state.report = null;
        state.reportHtml = null;
        elements["results"].hidden = true;
        elements["initial-state"].hidden = true;
        setBanner("error", "Analysis failed", error.message || String(error));
      })
      .finally(function () {
        setLoading(false);
      });
  }

  function renderStatus(payload, directory) {
    var summary = payload.summary || {};
    var details = (payload.errors || []).concat(payload.warnings || []);
    var coverage = String(summary.scan_coverage || "unavailable");
    var risk = summary.project_risk || "Unknown";

    if (payload.status === "empty") {
      setBanner(
        "empty",
        "No dependencies found",
        "No requirements.txt or pyproject.toml declarations were found in " +
          directory +
          ". Add a supported manifest and run the analysis again.",
        details
      );
      return;
    }

    if (payload.status === "partial") {
      setBanner(
        "partial",
        "Analysis complete with limitations",
        "Coverage is " +
          coverage +
          ". Project risk is " +
          risk +
          "; review warnings and unresolved dependencies before treating this snapshot as complete.",
        details
      );
      return;
    }

    setBanner(
      "success",
      "Analysis complete",
      summary.total_dependencies +
        " dependencies analyzed · " +
        summary.total_vulnerabilities +
        " vulnerabilities · coverage " +
        coverage +
        " · project risk " +
        risk +
        ".",
      details
    );
  }

  function render(payload) {
    var summary = payload.summary || {};
    var project = payload.project || {};
    var riskCounts = summary.risk_counts || {};

    elements["project-badge"].textContent =
      (project.name || "project") + " · " + (project.directory || "");
    elements["project-badge"].title = project.directory || "";

    setText("metric-total", summary.total_dependencies);
    setText("metric-vulnerable", summary.vulnerable_dependencies);
    setText("metric-vulnerabilities", summary.total_vulnerabilities);
    setText("metric-critical", riskCounts.Critical || 0);
    setText("metric-high", riskCounts.High || 0);
    setText("metric-medium", riskCounts.Medium || 0);
    setText("metric-low", riskCounts.Low || 0);
    setText("metric-unknown", riskCounts.Unknown || 0);
    setText("metric-unresolved", summary.unresolved_dependencies || 0);
    setText("metric-incomplete", summary.incomplete_coverage_dependencies || 0);
    setText("metric-checked", summary.dependencies_checked || 0);

    replaceBadge("project-risk-badge", summary.project_risk || "Unknown");
    replaceBadge("risk-overview-badge", summary.project_risk || "Unknown");

    var coverage = elements["coverage-status"];
    coverage.className =
      "badge coverage-" + String(summary.scan_coverage || "unavailable").toLowerCase();
    coverage.textContent = titleCase(summary.scan_coverage || "unavailable");

    elements["project-risk-reason"].textContent =
      summary.risk_reason || "No project risk reason was reported.";

    renderInventory(payload, summary, project);
    renderFindings(payload, summary);
    renderRisk(payload, summary);
    renderReport(payload);

    elements["results"].hidden = false;
    elements["initial-state"].hidden = true;
  }

  function replaceBadge(id, risk) {
    var current = elements[id];
    var badge = riskBadge(risk);
    badge.id = id;
    current.replaceWith(badge);
    elements[id] = badge;
  }

  function manifestLabel(project) {
    var manifests = project.manifests || [];
    if (!manifests.length) {
      return "No manifests detected";
    }
    return "Manifests: " + manifests.map(function (item) {
      return item.filename || "manifest";
    }).join(", ");
  }

  function renderInventory(payload, summary, project) {
    var dependencies = payload.dependencies || [];
    var body = elements["inventory-body"];
    body.innerHTML = "";

    dependencies.forEach(function (dependency) {
      var packageName = dependency.package_name || dependency.name || "unknown";
      var displayName = dependency.name || packageName;
      var risk = dependency.risk_classification || "Unknown";
      var row = document.createElement("tr");
      row.dataset.search = (packageName + " " + displayName).toLowerCase();
      row.dataset.risk = risk;

      var packageCell = document.createElement("div");
      packageCell.appendChild(node("span", "package-name", displayName));
      if (displayName !== packageName) {
        packageCell.appendChild(node("span", "muted small", " · " + packageName));
      }
      addCell(row, packageCell);

      var constraints = (dependency.declared_constraints || []).join(" · ");
      if (constraints) {
        addCell(row, node("span", "constraint-code", constraints));
      } else {
        addCell(row, node("span", "muted", "Any version"));
      }

      if (dependency.resolved_version) {
        addCell(row, node("span", "version-code", dependency.resolved_version));
      } else {
        var unresolved = node("span", "tag-unresolved", "Unresolved");
        unresolved.title =
          "No explicit resolved version was available, so this dependency was not sent to OSV.";
        addCell(row, unresolved);
      }

      var sources = dependency.manifest_sources || [];
      if (sources.length) {
        var list = node("ul", "source-list");
        sources.forEach(function (source) {
          list.appendChild(node("li", "small", source));
        });
        addCell(row, list);
      } else {
        addCell(row, "", "muted");
      }

      addCell(row, riskBadge(risk));
      addCell(
        row,
        dependency.vulnerability_count || 0,
        "numeric"
      );

      body.appendChild(row);
    });

    var noteParts = [manifestLabel(project)];
    noteParts.push(
      dependencies.length +
        " normalized dependencies · " +
        (summary.unresolved_dependencies || 0) +
        " unresolved"
    );
    elements["inventory-note"].textContent = noteParts.join(" · ");

    elements["inventory-table"].hidden = dependencies.length === 0;
    elements["inventory-empty"].hidden = true;
    elements["inventory-empty"].textContent = dependencies.length
      ? "No dependencies match the current filters."
      : "No dependencies were discovered in this project.";

    applyInventoryFilter();
  }

  function applyInventoryFilter() {
    var term = (elements["inventory-search"].value || "").trim().toLowerCase();
    var risk = elements["inventory-risk-filter"].value || "";
    var rows = elements["inventory-body"].querySelectorAll("tr");
    var visible = 0;

    rows.forEach(function (row) {
      var matchesTerm = !term || (row.dataset.search || "").indexOf(term) >= 0;
      var matchesRisk = !risk || row.dataset.risk === risk;
      var shown = matchesTerm && matchesRisk;
      row.hidden = !shown;
      if (shown) {
        visible += 1;
      }
    });

    if (!rows.length) {
      elements["inventory-table"].hidden = true;
      elements["inventory-empty"].hidden = false;
      return;
    }

    elements["inventory-table"].hidden = visible === 0;
    elements["inventory-empty"].hidden = visible !== 0;
  }

  function findingRank(finding) {
    var label = finding.severity_label || "Unknown";
    return RISK_RANK[label] || 0;
  }

  function renderFindings(payload, summary) {
    var findings = (payload.vulnerabilities || []).slice();
    var body = elements["vulnerability-body"];
    body.innerHTML = "";

    findings.sort(function (left, right) {
      var rank = findingRank(right) - findingRank(left);
      if (rank !== 0) {
        return rank;
      }
      return String(left.package_name || "").localeCompare(
        String(right.package_name || "")
      );
    });

    findings.forEach(function (finding) {
      var row = document.createElement("tr");
      var severity = finding.severity_label || "Unknown";
      row.dataset.severity = severity;

      var packageCell = document.createElement("div");
      packageCell.appendChild(
        node("span", "package-name", finding.package_name || "unknown")
      );
      packageCell.appendChild(
        node("span", "muted small", " " + (finding.package_version || ""))
      );
      addCell(row, packageCell);

      var idCell = document.createElement("div");
      idCell.appendChild(
        node("span", "version-code", finding.vulnerability_id || "unknown")
      );
      var aliases = finding.aliases || [];
      if (aliases.length) {
        idCell.appendChild(node("div", "muted small", aliases.join(", ")));
      }
      addCell(row, idCell);

      addCell(row, severityBadge(finding));

      var summaryCell = addCell(row, finding.summary || "No summary provided.", "summary-cell");
      if (finding.summary) {
        summaryCell.title = finding.summary;
      }

      var fixed = finding.fixed_versions || [];
      if (fixed.length) {
        var fixedList = node("div", "fixed-cell");
        fixed.forEach(function (version) {
          fixedList.appendChild(node("span", "version-code", version));
        });
        addCell(row, fixedList);
      } else {
        addCell(row, node("span", "muted small", "Not specified"));
      }

      var references = finding.references || [];
      if (references.length) {
        var refList = node("ul", "ref-list");
        references.slice(0, 4).forEach(function (reference) {
          var url = reference.url || "";
          var link = node("a", "", reference.type || "Advisory");
          if (isHttpUrl(url)) {
            link.href = url;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.title = url;
          } else {
            link.removeAttribute("href");
          }
          var item = document.createElement("li");
          item.appendChild(link);
          refList.appendChild(item);
        });
        if (references.length > 4) {
          refList.appendChild(
            node("li", "muted small", "+" + (references.length - 4) + " more")
          );
        }
        addCell(row, refList);
      } else {
        addCell(row, "", "muted");
      }

      body.appendChild(row);
    });

    var note = findings.length
      ? findings.length +
        " finding(s) across " +
        (summary.vulnerable_dependencies || 0) +
        " vulnerable dependency(ies). Only dependencies with explicit resolved versions are scanned."
      : "No known vulnerabilities were reported for the scanned dependencies.";
    if (!findings.length && (summary.unresolved_dependencies || 0) > 0) {
      note += " Unresolved dependencies were not sent to OSV.";
    }
    elements["findings-note"].textContent = note;

    elements["vulnerability-table"].hidden = findings.length === 0;
    elements["vulnerability-empty"].hidden = findings.length !== 0;
    elements["vulnerability-empty"].textContent = findings.length
      ? "No findings match the current severity filter."
      : "No OSV findings were reported for the scanned dependencies.";

    applyVulnerabilityFilter();
  }

  function applyVulnerabilityFilter() {
    var severity = elements["vulnerability-filter"].value || "";
    var rows = elements["vulnerability-body"].querySelectorAll("tr");
    var visible = 0;

    rows.forEach(function (row) {
      var shown = !severity || row.dataset.severity === severity;
      row.hidden = !shown;
      if (shown) {
        visible += 1;
      }
    });

    if (!rows.length) {
      elements["vulnerability-table"].hidden = true;
      elements["vulnerability-empty"].hidden = false;
      return;
    }

    elements["vulnerability-table"].hidden = visible === 0;
    elements["vulnerability-empty"].hidden = visible !== 0;
  }

  function renderRisk(payload, summary) {
    var risk = payload.risk || {};
    var dependencies = risk.dependencies || [];
    var body = elements["risk-body"];
    body.innerHTML = "";

    dependencies.forEach(function (dependency) {
      var row = document.createElement("tr");
      var packageName = dependency.package_name || "unknown";

      addCell(row, node("span", "package-name", packageName));

      if (dependency.resolved_version) {
        addCell(row, node("span", "version-code", dependency.resolved_version));
      } else {
        addCell(row, node("span", "tag-unresolved", "Unresolved"));
      }

      addCell(row, riskBadge(dependency.risk_classification || "Unknown"));
      addCell(row, coverageBadge(dependency.scan_coverage || "unavailable"));
      addCell(row, dependency.vulnerability_count || 0, "numeric");

      var reasons = dependency.reasons || [];
      if (reasons.length) {
        var list = node("ul", "reason-list");
        reasons.forEach(function (reason) {
          list.appendChild(node("li", "", reason));
        });
        addCell(row, list);
      } else {
        addCell(row, "", "muted");
      }

      body.appendChild(row);
    });

    elements["risk-table"].hidden = dependencies.length === 0;
    elements["risk-empty"].hidden = dependencies.length !== 0;
    renderRiskWarnings(payload, summary);
  }

  function renderRiskWarnings(payload, summary) {
    var container = elements["risk-warning-list"];
    container.innerHTML = "";

    var notices = [];
    var unresolved = summary.unresolved_dependencies || 0;
    var incomplete = summary.incomplete_coverage_dependencies || 0;
    var coverage = summary.scan_coverage || "unavailable";

    if (unresolved > 0) {
      notices.push({
        title: "Unresolved dependencies",
        text:
          unresolved +
          " dependency(ies) have no explicit resolved version and were excluded from OSV scanning. Their risk is Unknown."
      });
    }

    if (incomplete > 0) {
      notices.push({
        title: "Incomplete coverage",
        text:
          incomplete +
          " resolved dependency(ies) did not receive complete OSV coverage. Absence of findings is not proof of safety."
      });
    }

    if (coverage !== "complete" && summary.total_dependencies > 0) {
      notices.push({
        title: "Coverage status: " + titleCase(coverage),
        text:
          summary.risk_reason ||
          "The project risk classification reflects incomplete or unavailable scan coverage."
      });
    }

    (payload.errors || []).slice(0, 3).forEach(function (error) {
      notices.push({ title: "Scan error", text: error });
    });

    notices.forEach(function (notice) {
      var element = document.createElement("div");
      element.className = "notice";
      element.appendChild(node("strong", "", notice.title + ": "));
      element.appendChild(document.createTextNode(notice.text));
      container.appendChild(element);
    });

    container.hidden = notices.length === 0;
  }

  function renderReport(payload) {
    var report = payload.report;
    var jsonButton = elements["report-json"];
    var htmlButton = elements["report-html"];
    var meta = elements["report-meta"];

    jsonButton.disabled = !report;
    htmlButton.disabled = !report || !payload.report_html;

    if (!report) {
      meta.textContent = "Run an analysis to create a report snapshot.";
      meta.className = "inline-status";
      return;
    }

    var summary = report.scan_summary || {};
    meta.textContent =
      "Snapshot " +
      formatTimestamp(report.generated_at) +
      " · " +
      (summary.total_dependencies || 0) +
      " dependencies · " +
      (summary.total_vulnerabilities || 0) +
      " findings · coverage " +
      (summary.scan_coverage || "unavailable") +
      " · project risk " +
      (summary.project_risk || "Unknown") +
      ".";
    meta.className = "inline-status";
  }

  function formatTimestamp(value) {
    if (!value) {
      return "unknown time";
    }
    var date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return String(value);
    }
    return date.toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short"
    });
  }

  function isHttpUrl(value) {
    try {
      var url = new URL(value);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch (error) {
      return false;
    }
  }

  function slug(value) {
    return String(value || "project")
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "project";
  }

  function dateStamp(value) {
    if (typeof value === "string" && value.length >= 10) {
      return value.slice(0, 10);
    }
    return "latest";
  }

  function downloadText(filename, content, mimetype) {
    var blob = new Blob([content], { type: mimetype });
    var url = URL.createObjectURL(blob);
    triggerDownload(url, filename);
    window.setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1500);
  }

  function triggerDownload(url, filename) {
    var link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  function downloadReport(kind) {
    if (!state.report) {
      return;
    }

    var projectName = (state.report.project && state.report.project.name) || "project";
    var base =
      slug(projectName) +
      "-security-report-" +
      dateStamp(state.report.generated_at);

    if (kind === "json") {
      downloadText(
        base + ".json",
        JSON.stringify(state.report, null, 2),
        "application/json"
      );
      return;
    }

    if (!state.reportHtml) {
      setBanner(
        "error",
        "HTML report unavailable",
        "Run the analysis again to generate a downloadable HTML report."
      );
      return;
    }

    downloadText(base + ".html", state.reportHtml, "text/html");
  }

  function setSbomBusy(isBusy) {
    state.sbomLoading = isBusy;
    var button = elements["sbom-button"];
    var label = button.querySelector(".button-label");
    var spinner = button.querySelector(".spinner");
    button.disabled = isBusy;
    label.textContent = isBusy ? "Generating…" : "Generate SBOM";
    spinner.hidden = !isBusy;
  }

  function generateSbom() {
    if (state.sbomLoading) {
      return;
    }

    var directory = elements["project-directory"].value.trim();
    clearFieldError();

    if (!directory) {
      showFieldError("Enter a project directory before generating an SBOM.");
      return;
    }

    setSbomBusy(true);
    elements["sbom-status"].className = "inline-status";
    elements["sbom-status"].textContent = "Generating CycloneDX SBOM…";
    elements["sbom-download"].hidden = true;

    fetch("/api/sbom/download", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_directory: directory })
    })
      .then(function (response) {
        return response.text().then(function (text) {
          var document;
          try {
            document = JSON.parse(text);
          } catch (error) {
            throw new Error("The server returned an invalid SBOM response.");
          }
          if (!response.ok) {
            throw new Error(
              document.error ||
                (document.warnings && document.warnings[0]) ||
                "SBOM generation failed."
            );
          }
          return {
            document: document,
            text: text,
            filename:
              filenameFromDisposition(
                response.headers.get("Content-Disposition")
              ) || slug(directory.split(/[\\/]/).pop()) + "-sbom.json"
          };
        });
      })
      .then(function (result) {
        if (state.sbomUrl) {
          URL.revokeObjectURL(state.sbomUrl);
        }

        var blob = new Blob([result.text], { type: "application/json" });
        state.sbomUrl = URL.createObjectURL(blob);

        var link = elements["sbom-download"];
        link.href = state.sbomUrl;
        link.download = result.filename;
        link.hidden = false;

        var components = result.document.components || [];
        elements["sbom-status"].className = "inline-status is-success";
        elements["sbom-status"].textContent =
          (result.document.bomFormat || "CycloneDX") +
          " " +
          (result.document.specVersion || "1.5") +
          " · " +
          components.length +
          " component(s) · " +
          result.filename;

        triggerDownload(state.sbomUrl, result.filename);
      })
      .catch(function (error) {
        elements["sbom-status"].className = "inline-status is-error";
        elements["sbom-status"].textContent = error.message || String(error);
        elements["sbom-download"].hidden = true;
      })
      .finally(function () {
        setSbomBusy(false);
      });
  }

  function filenameFromDisposition(value) {
    var match = /filename="([^"]+)"/i.exec(value || "");
    return match ? match[1] : "";
  }

  function bindEvents() {
    elements["analysis-form"].addEventListener("submit", function (event) {
      event.preventDefault();
      var directory = elements["project-directory"].value.trim();
      clearFieldError();

      if (!directory) {
        showFieldError("Enter a local project directory to analyze.");
        elements["project-directory"].focus();
        return;
      }

      runAnalysis(directory);
    });

    elements["project-directory"].addEventListener("input", clearFieldError);
    elements["inventory-search"].addEventListener("input", applyInventoryFilter);
    elements["inventory-risk-filter"].addEventListener(
      "change",
      applyInventoryFilter
    );
    elements["vulnerability-filter"].addEventListener(
      "change",
      applyVulnerabilityFilter
    );
    elements["sbom-button"].addEventListener("click", generateSbom);
    elements["report-json"].addEventListener("click", function () {
      downloadReport("json");
    });
    elements["report-html"].addEventListener("click", function () {
      downloadReport("html");
    });
  }

  function init() {
    cacheElements();
    bindEvents();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
