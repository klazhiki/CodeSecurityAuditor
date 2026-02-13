const demoFindings = [
  {
    id: 12,
    title: "Python SQL injection via f-string query",
    severity: "high",
    confidence: 0.9,
    file: "api/users.py:41",
    attackPath: "HTTP query param 'email' flows from Flask handler into SQL string formatting and reaches cursor.execute without parameterization.",
    graph: ["HTTP q=email", "users handler", "cursor.execute(SQL)"],
    patch: `- query = f"SELECT * FROM users WHERE email = '{email}'"
- cursor.execute(query)
+ query = "SELECT * FROM users WHERE email = %s"
+ cursor.execute(query, (email,))`,
    verification: [
      { status: "pass", text: "pytest tests/security/test_sqli.py passed" },
      { status: "pass", text: "Semgrep rule python.sql-injection returned no findings in file" }
    ]
  },
  {
    id: 21,
    title: "TypeScript command injection in child_process.exec",
    severity: "critical",
    confidence: 0.94,
    file: "scripts/backup.ts:17",
    attackPath: "CLI argument 'target' is concatenated into exec command; attacker can append shell operators and execute arbitrary commands.",
    graph: ["CLI arg target", "backup command builder", "exec(shell command)"],
    patch: `- exec('tar -czf backup.tgz ' + target)
+ execFile('tar', ['-czf', 'backup.tgz', target])`,
    verification: [
      { status: "pass", text: "npm test -- backup.spec.ts passed" },
      { status: "warn", text: "No sanitizer rule found; marked for manual review" }
    ]
  },
  {
    id: 33,
    title: "Potential SSRF via unvalidated fetch URL",
    severity: "medium",
    confidence: 0.78,
    file: "src/routes/proxy.ts:58",
    attackPath: "User-controlled URL from request body is forwarded to fetch; internal metadata endpoints could be reached.",
    graph: ["POST body.targetUrl", "proxy route", "fetch(targetUrl)"],
    patch: `+ if (!isAllowedHost(targetUrl)) throw new Error('Blocked host')
  const response = await fetch(targetUrl)`,
    verification: [
      { status: "pass", text: "Unit test added for blocked private CIDR targets" },
      { status: "pass", text: "Static check confirms allowlist guard before sink" }
    ]
  }
];

const state = {
  findings: [],
  selectedId: null,
  filter: "all"
};

const scanBtn = document.getElementById("scanBtn");
const exportSarifBtn = document.getElementById("exportSarifBtn");
const findingsList = document.getElementById("findingsList");
const details = document.getElementById("issueDetails");
const summary = document.getElementById("summary");
const severityFilter = document.getElementById("severityFilter");

function prettyPercent(value) {
  return `${Math.round(value * 100)}%`;
}

function severityToSarifLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function parseLocation(rawLocation) {
  const match = /^(.*):(\d+)$/.exec(rawLocation);
  if (!match) return { uri: rawLocation, line: 1 };
  return { uri: match[1], line: Number(match[2]) || 1 };
}

function buildSarifReport(findings) {
  const results = findings.map((finding) => {
    const { uri, line } = parseLocation(finding.file);
    return {
      ruleId: `AEGIS-${finding.id}`,
      level: severityToSarifLevel(finding.severity),
      message: {
        text: `${finding.title}. Attack path: ${finding.attackPath}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine: line }
          }
        }
      ],
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        verification: finding.verification.map((v) => `${v.status}: ${v.text}`)
      }
    };
  });

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Aegis Frontend Demo",
            version: "0.3.0",
            rules: findings.map((finding) => ({
              id: `AEGIS-${finding.id}`,
              name: finding.title,
              shortDescription: { text: finding.title },
              fullDescription: { text: finding.attackPath }
            }))
          }
        },
        results
      }
    ]
  };
}

function downloadSarif() {
  if (!state.findings.length) {
    summary.textContent = "Run a scan first to export SARIF.";
    return;
  }

  const report = buildSarifReport(state.findings);
  const json = JSON.stringify(report, null, 2);
  const blob = new Blob([json], { type: "application/sarif+json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "aegis-report.sarif";
  a.click();
  URL.revokeObjectURL(url);

  summary.innerHTML = `${summary.innerHTML}<br><strong>SARIF exported:</strong> aegis-report.sarif`;
}

function buildExploitSketch(finding) {
  const nodes = finding.graph || ["entrypoint", "application flow", "security-sensitive sink"];
  return `Attacker controls ${nodes[0]}, which reaches ${nodes[1]}, and then influences ${nodes[2]}. Impact depends on runtime guardrails; this is a safe simulation sketch only.`;
}

function renderAttackGraph(container, nodes) {
  const width = 760;
  const height = 140;
  const boxW = 200;
  const boxH = 38;
  const y = 48;

  const xPositions = [20, (width - boxW) / 2, width - boxW - 20];
  const safeNodes = (nodes && nodes.length === 3) ? nodes : ["Entry", "Flow", "Sink"];

  const svg = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack surface flow graph">
      <defs>
        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill="#6f8ed1" />
        </marker>
      </defs>
      <line class="edge" x1="${xPositions[0] + boxW}" y1="${y + boxH / 2}" x2="${xPositions[1]}" y2="${y + boxH / 2}" />
      <line class="edge" x1="${xPositions[1] + boxW}" y1="${y + boxH / 2}" x2="${xPositions[2]}" y2="${y + boxH / 2}" />

      <rect class="node" x="${xPositions[0]}" y="${y}" width="${boxW}" height="${boxH}" rx="8" />
      <rect class="node" x="${xPositions[1]}" y="${y}" width="${boxW}" height="${boxH}" rx="8" />
      <rect class="node" x="${xPositions[2]}" y="${y}" width="${boxW}" height="${boxH}" rx="8" />

      <text class="node-label" x="${xPositions[0] + 12}" y="${y + 23}">${safeNodes[0]}</text>
      <text class="node-label" x="${xPositions[1] + 12}" y="${y + 23}">${safeNodes[1]}</text>
      <text class="node-label" x="${xPositions[2] + 12}" y="${y + 23}">${safeNodes[2]}</text>
    </svg>
  `;

  container.innerHTML = svg;
}

function renderSummary() {
  if (!state.findings.length) {
    summary.textContent = "No scan has been run yet.";
    return;
  }
  const grouped = state.findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});

  summary.innerHTML = `
    <strong>Scan complete:</strong> ${state.findings.length} findings<br>
    Critical: ${grouped.critical || 0} · High: ${grouped.high || 0} · Medium: ${grouped.medium || 0} · Low: ${grouped.low || 0}
  `;
}

function renderList() {
  findingsList.innerHTML = "";
  const filtered = state.findings.filter((f) => state.filter === "all" || f.severity === state.filter);

  if (!filtered.length) {
    findingsList.innerHTML = `<li class="finding-meta">No findings match the selected severity.</li>`;
    return;
  }

  filtered.forEach((finding) => {
    const li = document.createElement("li");
    li.className = `finding-item ${state.selectedId === finding.id ? "active" : ""}`;
    li.innerHTML = `
      <div class="finding-title">${finding.title}</div>
      <div class="finding-meta">
        <span class="sev-${finding.severity}">${finding.severity.toUpperCase()}</span>
        · Confidence ${prettyPercent(finding.confidence)}
        · ${finding.file}
      </div>
    `;
    li.onclick = () => {
      state.selectedId = finding.id;
      renderList();
      renderDetails();
    };
    findingsList.appendChild(li);
  });
}

function renderDetails() {
  const finding = state.findings.find((f) => f.id === state.selectedId);
  if (!finding) {
    details.innerHTML = `<div class="issue-empty">Select a finding to inspect attack path, patch, and proof.</div>`;
    return;
  }

  const tpl = document.getElementById("detailTemplate");
  const node = tpl.content.cloneNode(true);
  node.querySelector("h3").textContent = `#${finding.id} · ${finding.title}`;
  node.querySelector(".meta").textContent = `Severity: ${finding.severity.toUpperCase()} · Confidence: ${prettyPercent(finding.confidence)} · Location: ${finding.file}`;
  node.querySelector(".attack-path").textContent = finding.attackPath;
  node.querySelector(".exploit-sketch").textContent = buildExploitSketch(finding);
  node.querySelector(".patch").textContent = finding.patch;

  const graphContainer = node.querySelector(".attack-graph-canvas");
  renderAttackGraph(graphContainer, finding.graph);

  const verificationList = node.querySelector(".verification");
  finding.verification.forEach((item) => {
    const li = document.createElement("li");
    li.className = item.status;
    li.textContent = item.text;
    verificationList.appendChild(li);
  });

  details.innerHTML = "";
  details.appendChild(node);
}

scanBtn.addEventListener("click", () => {
  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";

  setTimeout(() => {
    state.findings = demoFindings;
    state.selectedId = demoFindings[0].id;
    scanBtn.disabled = false;
    scanBtn.textContent = "Run Scan";
    renderSummary();
    renderList();
    renderDetails();
  }, 500);
});

exportSarifBtn.addEventListener("click", downloadSarif);

severityFilter.addEventListener("change", (e) => {
  state.filter = e.target.value;
  renderList();
});

renderSummary();
renderList();
renderDetails();
