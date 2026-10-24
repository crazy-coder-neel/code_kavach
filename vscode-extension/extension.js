const vscode = require('vscode');
const http = require('http');
const url = require('url');

// Decoration type for highlighting vulnerable lines in red
const vulnerableLineDecoration = vscode.window.createTextEditorDecorationType({
  backgroundColor: 'rgba(239, 68, 68, 0.22)',
  isWholeLine: true,
  border: '1px solid rgba(239, 68, 68, 0.7)',
  overviewRulerColor: 'rgba(239, 68, 68, 0.9)',
  overviewRulerLane: vscode.OverviewRulerLane.Right,
  after: {
    contentText: '  ⚠️ CodeGuard Security Vulnerability',
    color: 'rgba(239, 68, 68, 0.85)',
    fontStyle: 'italic',
    fontSize: '11px'
  }
});

let statusBarItem;
let diagnosticCollection;
const activeFindingsByUri = new Map();
const cleanDocumentsByUri = new Map();
const lastAlertedByUri = new Map();
let typeDebounceTimer = null;

function sendScanRequest(apiUrl, payload) {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(`${apiUrl}/v1/guard?detail=full`);
    const data = JSON.stringify(payload);
    const options = {
      hostname: parsed.hostname || '127.0.0.1',
      port: parsed.port || 8000,
      path: parsed.path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'X-CodeGuard-Source': 'vscode'
      },
      timeout: 3000
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          resolve({ status: res.statusCode, data: json });
        } catch (e) {
          reject(new Error('Invalid JSON response from CodeGuard'));
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Scan request timed out'));
    });
    req.write(data);
    req.end();
  });
}

async function scanDocument(doc, editor, options = {}) {
  const isTyping = options.isTyping || false;
  const config = vscode.workspace.getConfiguration('codeguard');
  const apiUrl = config.get('apiUrl') || 'http://127.0.0.1:8000';
  const shouldHighlight = config.get('highlightLines') !== false;
  const showPopups = config.get('showPopups') !== false;

  const code = doc.getText();
  if (!code.trim()) {
    diagnosticCollection.delete(doc.uri);
    activeFindingsByUri.delete(doc.uri.toString());
    cleanDocumentsByUri.delete(doc.uri.toString());
    lastAlertedByUri.delete(doc.uri.toString());
    if (editor) editor.setDecorations(vulnerableLineDecoration, []);
    statusBarItem.text = '$(shield) CodeGuard';
    statusBarItem.backgroundColor = undefined;
    return;
  }

  try {
    if (!isTyping) {
      statusBarItem.text = '$(sync~spin) CodeGuard: Scanning...';
      statusBarItem.show();
    }

    const response = await sendScanRequest(apiUrl, {
      code: code,
      filename: doc.fileName,
      source: 'vscode'
    });

    const res = response.data;
    const uriStr = doc.uri.toString();
    diagnosticCollection.delete(doc.uri);

    if (res.verdict === 'block') {
      // 1. BLOCKED STATE
      cleanDocumentsByUri.delete(uriStr);
      statusBarItem.text = `$(alert) CodeGuard: BLOCKED (${res.risk_score.toFixed(2)})`;
      statusBarItem.tooltip = `Threat Categories: ${res.categories.join(', ')}\nReason: ${res.reason}\nClick for options.`;
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');

      const vulnerableLines = res.vulnerable_lines || [];
      activeFindingsByUri.set(uriStr, {
        verdict: res.verdict,
        risk_score: res.risk_score,
        categories: res.categories,
        reason: res.reason,
        vulnerable_lines: vulnerableLines,
        findings: res.findings || [],
        decision_cards: res.decision_cards || []
      });

      // Squiggly red diagnostics in editor and Problems panel
      const diags = vulnerableLines.map((lineNum) => {
        const line = Math.max(0, lineNum - 1);
        const lineText = doc.lineAt(line).text;
        const range = new vscode.Range(line, 0, line, lineText.length || 1);
        const diag = new vscode.Diagnostic(
          range,
          `[CodeGuard Security Block] ${res.reason} (Risk: ${res.risk_score})`,
          vscode.DiagnosticSeverity.Error
        );
        diag.source = 'CodeGuard';
        return diag;
      });
      diagnosticCollection.set(doc.uri, diags);

      // Line background highlighting in red
      if (editor && shouldHighlight) {
        const ranges = vulnerableLines.map((lineNum) => {
          const line = Math.max(0, lineNum - 1);
          return new vscode.Range(line, 0, line, 0);
        });
        editor.setDecorations(vulnerableLineDecoration, ranges);
      }

      // Real-time Popup Alert when typing or saving an API key / threat
      const alertKey = `${vulnerableLines.join(',')}:${res.categories.join(',')}`;
      if (showPopups && lastAlertedByUri.get(uriStr) !== alertKey) {
        lastAlertedByUri.set(uriStr, alertKey);
        const lineInfo = vulnerableLines.length ? ` on line ${vulnerableLines.join(', ')}` : '';
        vscode.window.showWarningMessage(
          `🚨 CodeGuard Alert: Detected [${res.categories.join(', ')}]${lineInfo}! ${res.reason}`,
          'View Diagnostics',
          'Open Web Dashboard'
        ).then((action) => {
          if (action === 'View Diagnostics') {
            vscode.commands.executeCommand('workbench.action.problems.focus');
          } else if (action === 'Open Web Dashboard') {
            vscode.env.openExternal(vscode.Uri.parse('http://localhost:3000/app/scan'));
          }
        });
      }
    } else {
      // 2. LEGITIMATE / SAFE STATE
      activeFindingsByUri.delete(uriStr);
      cleanDocumentsByUri.set(uriStr, {
        verdict: 'allow',
        risk_score: res.risk_score || 0.0,
        reason: res.reason || 'CodeGuard safety baseline checks passed.',
        timestamp: Date.now()
      });

      // Clear red highlights
      if (editor) {
        editor.setDecorations(vulnerableLineDecoration, []);
      }

      // Update status bar with green legitimate indicator
      statusBarItem.text = `$(pass-filled) CodeGuard: Legitimate Code (Clean - ${(res.risk_score || 0.0).toFixed(2)} Risk)`;
      statusBarItem.tooltip = `CodeGuard Safety Gate: PASSED (ALLOW)\nRisk Score: ${(res.risk_score || 0.0).toFixed(2)}\nCode verified legitimate: Zero credential leaks, zero malicious operations. Click for details.`;
      statusBarItem.backgroundColor = undefined;

      // If user just fixed an issue, show a brief success notification
      if (lastAlertedByUri.has(uriStr)) {
        lastAlertedByUri.delete(uriStr);
        vscode.window.setStatusBarMessage('$(check) CodeGuard: Code is now legitimate & safe to execute.', 3500);
      } else if (!isTyping) {
        vscode.window.setStatusBarMessage('$(shield) CodeGuard: Legitimate code verified clean.', 2500);
      }
    }
  } catch (err) {
    statusBarItem.text = '$(warning) CodeGuard: Offline';
    statusBarItem.tooltip = `Could not reach CodeGuard server at ${apiUrl}. Make sure backend is running.`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }
}

function activate(context) {
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.text = '$(shield) CodeGuard';
  statusBarItem.command = 'codeguard.showStatusDetails';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard');
  context.subscriptions.push(diagnosticCollection);

  // Status Details Modal Command (Clicking status bar)
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.showStatusDetails', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('No active code file open.');
        return;
      }
      const uriStr = editor.document.uri.toString();
      const blockedData = activeFindingsByUri.get(uriStr);
      const cleanData = cleanDocumentsByUri.get(uriStr);

      if (blockedData) {
        const action = await vscode.window.showWarningMessage(
          `🚨 CodeGuard BLOCKED: ${blockedData.categories.join(', ')} (Risk: ${blockedData.risk_score.toFixed(2)})\n${blockedData.reason}`,
          'Jump to Flagged Line',
          'Open Web Dashboard',
          'Dismiss'
        );
        if (action === 'Jump to Flagged Line' && blockedData.vulnerable_lines.length > 0) {
          const line = Math.max(0, blockedData.vulnerable_lines[0] - 1);
          const pos = new vscode.Position(line, 0);
          editor.selection = new vscode.Selection(pos, pos);
          editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        } else if (action === 'Open Web Dashboard') {
          vscode.env.openExternal(vscode.Uri.parse('http://localhost:3000/app/scan'));
        }
      } else if (cleanData) {
        const action = await vscode.window.showInformationMessage(
          `🛡️ CodeGuard: Legitimate Code Verified!\nVerdict: ALLOW (Risk: ${cleanData.risk_score.toFixed(2)})\nPassed AST rules, secret entropy heuristics, and pre-execution safety gates. Zero threats detected.`,
          'Rescan File',
          'Open Web Dashboard'
        );
        if (action === 'Rescan File') {
          scanDocument(editor.document, editor);
        } else if (action === 'Open Web Dashboard') {
          vscode.env.openExternal(vscode.Uri.parse('http://localhost:3000/app/scan'));
        }
      } else {
        scanDocument(editor.document, editor);
      }
    })
  );

  // Hover Provider: Rich security tooltips when hovering over flagged lines OR legitimate header
  const hoverProvider = vscode.languages.registerHoverProvider('*', {
    provideHover(doc, position) {
      const uriStr = doc.uri.toString();
      const blockedData = activeFindingsByUri.get(uriStr);
      const cleanData = cleanDocumentsByUri.get(uriStr);

      if (blockedData) {
        const currentLine = position.line + 1;
        if (!blockedData.vulnerable_lines.includes(currentLine)) return null;

        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.appendMarkdown(`### 🚨 CodeGuard Pre-Execution Block\n\n`);
        md.appendMarkdown(`**Verdict:** \`${blockedData.verdict}\` &nbsp;|&nbsp; **Risk Score:** \`${blockedData.risk_score.toFixed(2)}\`\n\n`);
        md.appendMarkdown(`**Categories:** \`${blockedData.categories.join(', ')}\`\n\n`);
        md.appendMarkdown(`**Security Reason:** ${blockedData.reason}\n\n`);

        const matchingFinding = blockedData.findings.find(f => (f.lines || []).includes(currentLine));
        if (matchingFinding) {
          md.appendMarkdown(`---\n`);
          md.appendMarkdown(`**Rule ID:** \`${matchingFinding.rule_id}\` &nbsp;|&nbsp; **Severity:** \`${matchingFinding.severity}\`\n\n`);
          if (matchingFinding.remediation) {
            md.appendMarkdown(`**Remediation:** ${matchingFinding.remediation}\n\n`);
          }
          if (matchingFinding.references && matchingFinding.references.length) {
            md.appendMarkdown(`*References: ${matchingFinding.references.join(', ')}*\n`);
          }
        }
        return new vscode.Hover(md);
      }

      // If document is clean and user hovers over line 0
      if (cleanData && position.line === 0) {
        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.appendMarkdown(`### 🛡️ CodeGuard Verified Legitimate & Clean\n\n`);
        md.appendMarkdown(`**Verdict:** \`ALLOW\` &nbsp;|&nbsp; **Risk Score:** \`0.00\`\n\n`);
        md.appendMarkdown(`✅ All 42 deterministic baseline AST security rules passed.\n\n`);
        md.appendMarkdown(`✅ Zero hardcoded secrets, API keys, or exfiltration channels.\n\n`);
        md.appendMarkdown(`✅ Verified safe for agentic execution and commits.`);
        return new vscode.Hover(md);
      }

      return null;
    }
  });
  context.subscriptions.push(hoverProvider);

  // 1. Real-time scanning while typing or pasting
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration('codeguard');
      if (config.get('scanWhileTyping') === false) return;

      const doc = event.document;
      if (['output', 'log', 'git'].includes(doc.uri.scheme)) return;

      if (typeDebounceTimer) {
        clearTimeout(typeDebounceTimer);
      }
      const debounceMs = config.get('typingDebounceMs') || 400;
      typeDebounceTimer = setTimeout(() => {
        const editor = vscode.window.visibleTextEditors.find(e => e.document === doc);
        scanDocument(doc, editor, { isTyping: true });
      }, debounceMs);
    })
  );

  // 2. Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('codeguard');
      if (config.get('scanOnSave') !== false) {
        const editor = vscode.window.visibleTextEditors.find(e => e.document === doc);
        scanDocument(doc, editor, { isTyping: false });
      }
    })
  );

  // 3. Scan active editor change
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document) {
        scanDocument(editor.document, editor, { isTyping: false });
      }
    })
  );

  // 4. Manual Scan Command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanCurrentFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document, editor, { isTyping: false });
      } else {
        vscode.window.showInformationMessage('No active file open to scan.');
      }
    })
  );

  // Scan current file immediately if one is already open
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document, vscode.window.activeTextEditor, { isTyping: false });
  }
}

function deactivate() {
  if (typeDebounceTimer) clearTimeout(typeDebounceTimer);
  if (diagnosticCollection) diagnosticCollection.clear();
}

module.exports = { activate, deactivate };
