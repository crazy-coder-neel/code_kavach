# CodeGuard VS Code Extension

Real-time pre-execution safety firewall for AI-generated code directly inside VS Code and Cursor.

## Features
- **Red Line Highlights:** Highlights vulnerable lines with background color and warning glyphs.
- **Rich Hover Tooltips:** Hovering over any flagged line displays the exact threat category, root cause, remediation steps, and CWE citations.
- **Diagnostics:** Red squiggly lines in the Problems tab and code editor.
- **Status Bar Integration:** Shows `🛡️ CodeGuard: Clean` or `🚨 CodeGuard: BLOCKED (0.95)` at the bottom right.
- **Live Sync Bridge:** Pushes code directly to the CodeGuard Web Studio dashboard.

## 1-Minute Installation into VS Code

### Method 1: Instant Local Install (No compilation required!)
Simply copy this folder into your local VS Code extensions directory:

**On Linux / macOS:**
```bash
cp -r /home/neelay/Desktop/code_kavach/vscode-extension ~/.vscode/extensions/codeguard-safety-gate
```

**On Windows:**
```powershell
Copy-Item -Recurse "C:\path\to\code_kavach\vscode-extension" "$env:USERPROFILE\.vscode\extensions\codeguard-safety-gate"
```

Then restart or reload VS Code (`Ctrl+Shift+P` -> `Developer: Reload Window`).

### Method 2: Debug / Run Extension directly in VS Code
1. Open this `vscode-extension/` folder in VS Code.
2. Press `F5` (or go to Run & Debug -> Run Extension).
3. A new "Extension Development Host" window will open with CodeGuard active!
4. Whenever you save a file (`.py`, `.js`, `.sh`, `.sql`), CodeGuard evaluates it in `< 5 ms`.
