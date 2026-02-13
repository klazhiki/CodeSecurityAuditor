const demoFindings = [
  {
    id: 12,
    title: "Python SQL injection via f-string query",
    severity: "high",
    confidence: 0.9,
    file: "api/users.py:41",
    attackPath: "HTTP query param 'email' flows from Flask handler into SQL string formatting and reaches cursor.execute without parameterization.",
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
const findingsList = document.getElementById("findingsList");
const details = document.getElementById("issueDetails");
const summary = document.getElementById("summary");
const severityFilter = document.getElementById("severityFilter");

function prettyPercent(value) {
  return `${Math.round(value * 100)}%`;
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
  node.querySelector(".patch").textContent = finding.patch;

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

severityFilter.addEventListener("change", (e) => {
  state.filter = e.target.value;
  renderList();
});

renderSummary();
renderList();
renderDetails();
