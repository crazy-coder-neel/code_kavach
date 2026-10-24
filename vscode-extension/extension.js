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
let activeFindingsByUri = new Map();

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

async function scanDocument(doc, editor) {
  const config = vscode.workspace.getConfiguration('codeguard');
  const apiUrl = config.get('apiUrl') || 'http://127.0.0.1:8000';
  const shouldHighlight = config.get('highlightLines') !== false;

  const code = doc.getText();
  if (!code.trim()) return;

  try {
    statusBarItem.text = '$(sync~spin) CodeGuard: Scanning...';
    statusBarItem.show();

    const response = await sendScanRequest(apiUrl, {
      code: code,
      filename: doc.fileName,
      source: 'vscode'
    });

    const res = response.data;
    diagnosticCollection.delete(doc.uri);

    if (res.verdict === 'block') {
      statusBarItem.text = `$(alert) CodeGuard: BLOCKED (${res.risk_score.toFixed(2)})`;
      statusBarItem.tooltip = `Threat Categories: ${res.categories.join(', ')}\nReason: ${res.reason}`;
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');

      const vulnerableLines = res.vulnerable_lines || [];
      activeFindingsByUri.set(doc.uri.toString(), {
        verdict: res.verdict,
        risk_score: res.risk_score,
        categories: res.categories,
        reason: res.reason,
        vulnerable_lines: vulnerableLines,
        findings: res.findings || [],
        decision_cards: res.decision_cards || []
      });

      // 1. Diagnostics (Squiggly red lines)
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

      // 2. Line background highlighting
      if (editor && shouldHighlight) {
        const ranges = vulnerableLines.map((lineNum) => {
          const line = Math.max(0, lineNum - 1);
          return new vscode.Range(line, 0, line, 0);
        });
        editor.setDecorations(vulnerableLineDecoration, ranges);
      }
    } else {
      statusBarItem.text = `$(shield) CodeGuard: Clean (${res.risk_score.toFixed(2)})`;
      statusBarItem.tooltip = 'CodeGuard safety baseline checks passed. Zero blocking findings.';
      statusBarItem.backgroundColor = undefined;
      activeFindingsByUri.delete(doc.uri.toString());

      if (editor) {
        editor.setDecorations(vulnerableLineDecoration, []);
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
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard');
  context.subscriptions.push(diagnosticCollection);

  // Hover Provider: Rich security tooltips when hovering over flagged lines
  const hoverProvider = vscode.languages.registerHoverProvider('*', {
    provideHover(doc, position) {
      const data = activeFindingsByUri.get(doc.uri.toString());
      if (!data) return null;

      const currentLine = position.line + 1;
      if (!data.vulnerable_lines.includes(currentLine)) return null;

      const md = new vscode.MarkdownString();
      md.isTrusted = true;
      md.appendMarkdown(`### 🚨 CodeGuard Pre-Execution Block\n\n`);
      md.appendMarkdown(`**Verdict:** \`${data.verdict}\` &nbsp;|&nbsp; **Risk Score:** \`${data.risk_score.toFixed(2)}\`\n\n`);
      md.appendMarkdown(`**Categories:** \`${data.categories.join(', ')}\`\n\n`);
      md.appendMarkdown(`**Security Reason:** ${data.reason}\n\n`);

      const matchingFinding = data.findings.find(f => (f.lines || []).includes(currentLine));
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
  });
  context.subscriptions.push(hoverProvider);

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('codeguard');
      if (config.get('scanOnSave') !== false) {
        const editor = vscode.window.visibleTextEditors.find(e => e.document === doc);
        scanDocument(doc, editor);
      }
    })
  );

  // Scan active editor change
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document) {
        scanDocument(editor.document, editor);
      }
    })
  );

  // Manual Scan Command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanCurrentFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document, editor);
      } else {
        vscode.window.showInformationMessage('No active file open to scan.');
      }
    })
  );

  // Scan current file immediately if one is already open
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document, vscode.window.activeTextEditor);
  }
}

function deactivate() {
  if (diagnosticCollection) diagnosticCollection.clear();
}

module.exports = { activate, deactivate };
