"""Offline dependency and untrusted-text checks, with explicit coverage limits.

No registry calls, code execution, or ML inference. DEP-007 remains unavailable
until a reviewed, licensed malicious-package snapshot is bundled.
"""
import ast
import base64
import codecs
import io
import json
import re
import shlex
import tokenize
from time import perf_counter

REASONS = {
    'DEP-004': 'An installation hook performs process execution or network access.',
    'DEP-005': 'An internal-looking dependency is installed with a public extra package index.',
    'DEP-008': 'A dependency install lacks an exact version pin; this is informational by itself.',
    'AIT-002': 'Untrusted text directs an AI reader to disclose protected context or credentials.',
    'AIT-003': 'Untrusted content inserts an active model-role delimiter or role-changing instruction.',
    'AIT-004': 'A tool description inserts instructions unrelated to the tool’s stated operation.',
    'AIT-005': 'Concealed or encoded text contains an instruction to override the AI reader.',
    'AIT-006': 'A safety claim attempts to suppress review next to an executable risk boundary.',
    'AIT-007': 'A workflow comment tells a reviewer bot to approve independently of scan results.',
    'AIT-008': 'A rendered Markdown URL places credential-like data in an outbound query.',
    'AIT-009': 'A supported non-English phrase instructs an AI reader to ignore prior instructions.',
}
SEVERITIES = {'DEP-008': 'info'}
COVERAGE = {
    'DEP-004': 'partial: Python setup cmdclass hooks and JSON npm install hooks',
    'DEP-005': 'partial: explicit internal-name prefixes with public extra index',
    'DEP-007': 'unsupported: no verified malicious-package feed bundled',
    'DEP-008': 'implemented: informational exact-pin check on explicit installs',
    'AIT-002': 'partial: high-precision English imperatives; no trained classifier',
    'AIT-003': 'partial: explicit role tokens and role reassignment',
    'AIT-004': 'partial: explicit tool-use override language',
    'AIT-005': 'partial: bounded base64/hex/rot13 and invisible-character normalization',
    'AIT-006': 'partial: safety claims colocated with known execution calls',
    'AIT-007': 'partial: explicit workflow bot approval overrides',
    'AIT-008': 'partial: Markdown query carrying explicit secret keys or provider tokens; no full taint',
    'AIT-009': 'partial: Spanish, French and Hindi phrase rules; ML is not implemented',
}
ADDRESS = re.compile(r'\b(?:ai|assistant|agent|reviewer|bot|model|llm|tool)\b', re.I)
DISCLOSURE = re.compile(r'\b(?:reveal|print|send|expose|disclose)\b.{0,100}\b(?:system prompt|credentials|api keys?|secrets?|private key)\b', re.I | re.S)
OVERRIDE = re.compile(r'\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|prior|all)\b.{0,25}\binstructions\b|\bapprove\b.{0,100}\bregardless\b|\bskip static analysis\b', re.I | re.S)
ROLE = re.compile(r'<\|(?:im_start|system)\|>|\[INST\]|(?:^|\n)\s*(?:###\s*)?(?:SYSTEM|ASSISTANT):|\byou are now\b.{0,60}\b(?:unrestricted|unfiltered|assistant|agent)\b', re.I)
DOCUMENTATION = re.compile(r'\b(?:example|documentation|describes?|quoted|quotation|detect(?:ing|s)?|prevent(?:ing|s)?|reject(?:ing|s)?|never follow|do not follow)\b', re.I)
INVISIBLE = re.compile('[\u200b-\u200f\u202a-\u202e\u2060-\u206f\U000e0000-\U000e007f]')
ENCODED = re.compile(r'(?:base64\s*:\s*([A-Za-z0-9+/=]{16,4096})|hex\s*:\s*([0-9a-fA-F]{24,4096})|rot13\s*:\s*([^\n]{12,2048}))', re.I)
MARKDOWN_URL = re.compile(r'!?\[[^\]\n]{0,256}\]\((https?://[^\s)]{1,2048})\)', re.I)
SECRET_QUERY = re.compile(r'[?&](?:token|api_key|secret|password|credentials|system_prompt)=([^&#]+)', re.I)
MULTILINGUAL = (
    re.compile(r'\b(?:asistente|agente|ia)\b.{0,60}\bignora\b.{0,25}\binstrucciones (?:anteriores|previas)\b', re.I | re.S),
    re.compile(r'\b(?:assistant|agent|ia)\b.{0,60}\bignore[rz]?\b.{0,25}\binstructions pr[ée]c[ée]dentes\b', re.I | re.S),
    re.compile(r'(?:सहायक|एजेंट|एआई).{0,60}पिछले निर्देशों को अनदेखा', re.S),
)


def _check(deadline):
    if perf_counter() > deadline:
        raise TimeoutError('dependency/text analysis deadline')


def _name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return _name(node.value, aliases) + '.' + node.attr
    return ''


def _value(node, constants):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_value(x, constants) for x in node.elts]
    return None


def _install(command, line, add):
    if isinstance(command, str):
        try:
            tokens = shlex.split(command)
        except ValueError:
            return
    elif isinstance(command, list):
        tokens = command
    else:
        return
    if 'install' not in tokens or not any(isinstance(t, str) and (t in ('pip', 'pip3', 'npm') or t.endswith('/pip')) for t in tokens):
        return
    packages = []
    skip = False
    for token in tokens[tokens.index('install') + 1:]:
        if skip:
            skip = False
            continue
        if token in ('--index-url', '--extra-index-url', '--trusted-host', '-i', '-r', '--requirement'):
            skip = True
        elif isinstance(token, str) and not token.startswith('-'):
            packages.append(token)
    public_extra = '--extra-index-url' in tokens and any(isinstance(t, str) and re.match(r'https?://(?:pypi\.org|pypi\.python\.org)/', t) for t in tokens)
    if public_extra and any(re.match(r'(?:internal|private|corp|company)[_-]', p, re.I) for p in packages):
        add('DEP-005', line)
    unpinned = [p for p in packages if not re.search(r'==[^*]+$|@\d[^*^~]*$', p) and not p.startswith(('http:', 'https:', 'git+', '.', '/'))]
    if unpinned:
        add('DEP-008', line)


def _text(text, line, add, deadline, risky=False, workflow=False, tool=False):
    _check(deadline)
    # Classification is over extracted text only. A short descriptive quotation
    # is exempt; a later independent instruction must still be checked separately.
    text = text[:8192]
    educational = bool(DOCUMENTATION.search(text))
    if not educational:
        disclosure = DISCLOSURE.search(text)
        if disclosure and (ADDRESS.search(text) or re.search(r'system prompt|before answering', text, re.I)):
            add('AIT-002', line)
        if ROLE.search(text):
            add('AIT-003', line)
        if (tool or re.search(r'\b(?:using|use|runs?|calling) this tool\b|\bthis tool (?:runs|is used)\b', text, re.I)) and (disclosure or OVERRIDE.search(text)):
            add('AIT-004', line)
        if workflow and ADDRESS.search(text) and re.search(r'approve.{0,120}regardless|regardless.{0,120}approve', text, re.I | re.S):
            add('AIT-007', line)
        if risky and re.search(r'this code (?:has been|is) (?:audited|approved|safe)|security scan passed|false positive', text, re.I) and re.search(r'\b(?:ignore|skip|do not flag|approve|safe)\b', text, re.I):
            add('AIT-006', line)
        if any(pattern.search(text) for pattern in MULTILINGUAL):
            add('AIT-009', line)
    normalized = INVISIBLE.sub('', text)
    if normalized != text and (OVERRIDE.search(normalized) or DISCLOSURE.search(normalized)) and not educational:
        add('AIT-005', line)
    for match in ENCODED.finditer(text):
        _check(deadline)
        try:
            if match[1]:
                decoded = base64.b64decode(match[1], validate=True).decode('utf-8')
            elif match[2]:
                decoded = bytes.fromhex(match[2]).decode('utf-8')
            else:
                decoded = codecs.decode(match[3], 'rot13')
        except (ValueError, UnicodeError):
            continue
        if not educational and (OVERRIDE.search(decoded) or DISCLOSURE.search(decoded)):
            add('AIT-005', line)
    for match in MARKDOWN_URL.finditer(text):
        query = SECRET_QUERY.search(match[1])
        if query and not re.fullmatch(r'(?:REDACTED|YOUR_[A-Z_]+|%3[Cc].*%3[Ee]|\{[^}]*\})', query[1]):
            add('AIT-008', line)


def inspect(tree, code, add, deadline):
    """Analyze one already-parsed Python AST; caller handles raised deadlines."""
    aliases, constants, calls, classes = {}, {}, [], {}
    texts = []
    nodes = list(ast.walk(tree))
    if len(nodes) > 12000:
        raise TimeoutError('node limit')
    for index, node in enumerate(nodes):
        if index % 64 == 0:
            _check(deadline)
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                aliases[alias.asname or alias.name] = f'{node.module}.{alias.name}'
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = _value(node.value, constants)
        elif isinstance(node, ast.ClassDef):
            classes[node.name] = node
        elif isinstance(node, ast.Call):
            calls.append(node)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            texts.append((node.lineno, node.value, False))
    # Only classes explicitly registered as install hooks are inspected as hooks.
    for call in calls:
        _check(deadline)
        name = _name(call.func, aliases)
        if name in ('os.system', 'os.popen') or name.startswith('subprocess.'):
            if call.args:
                _install(_value(call.args[0], constants), call.lineno, add)
        if name in ('setup', 'setuptools.setup', 'distutils.core.setup'):
            for keyword in call.keywords:
                if keyword.arg == 'cmdclass' and isinstance(keyword.value, ast.Dict):
                    for target in keyword.value.values:
                        cls = classes.get(target.id) if isinstance(target, ast.Name) else None
                        if cls is not None:
                            for operation in ast.walk(cls):
                                if isinstance(operation, ast.Call):
                                    operation_name = _name(operation.func, aliases)
                                    if operation_name.startswith(('subprocess.', 'requests.', 'httpx.', 'urllib.request.')) or operation_name in ('os.system', 'os.popen', 'exec', 'eval'):
                                        add('DEP-004', operation.lineno)
    risky_lines = [n.lineno for n in calls if _name(n.func, aliases) in ('eval', 'exec', 'os.system', 'os.popen', 'pickle.loads')]
    try:
        comments = [(t.start[0], t.string) for t in tokenize.generate_tokens(io.StringIO(code).readline) if t.type == tokenize.COMMENT]
    except (tokenize.TokenError, IndentationError):
        comments = []
    for i, (line, text) in enumerate(comments):
        group = ' '.join(t for n, t in comments[i:i+4] if n <= line+3)
        texts.append((line, group, False))
    for line, text, tool in texts:
        _text(text, line, add, deadline, risky=any(abs(n-line)<=3 for n in risky_lines), tool=tool)


def inspect_text(code, language, add, deadline):
    """Non-Python comments, prose and manifests; never scans JS code as prose."""
    lines = code.splitlines()
    if language in ('javascript', 'unknown'):
        try:
            manifest = json.loads(code)
        except (ValueError, RecursionError):
            manifest = None
        if isinstance(manifest, dict) and isinstance(manifest.get('scripts'), dict):
            for hook in ('preinstall', 'install', 'postinstall'):
                command = manifest['scripts'].get(hook)
                if isinstance(command, str) and command.strip():
                    line = next((i for i, text in enumerate(lines, 1) if '"'+hook+'"' in text), 1)
                    add('DEP-004', line)
    for i, line in enumerate(lines, 1):
        _check(deadline)
        stripped = line.lstrip()
        if language in ('bash', 'yaml') and not stripped.startswith('#'):
            command = stripped
            if language == 'yaml':
                command = command.split('run:', 1)[1] if re.search(r'\brun:', command) else ''
            _install(command, i, add)
        if language in ('markdown', 'yaml', 'unknown') or stripped.startswith(('#', '//', '/*', '*')):
            window = '\n'.join(lines[i-1:i+3]) if language in ('markdown', 'yaml') else line
            _text(window, i, add, deadline, workflow=language=='yaml')
