"""Offline classifiers. No submitted source execution, DNS, or filesystem access."""
import ipaddress
import math
import re
import shlex
from collections import Counter
from urllib.parse import urlsplit

PROVIDER = re.compile(r'''(?<![\w])(?:
    A(?:KIA|SIA)[A-Z0-9]{16}                     # AWS access key id
  | AIza[\w-]{35}                               # Google API key
  | gh[pousr]_[A-Za-z0-9]{36}                   # GitHub classic token
  | github_pat_[A-Za-z0-9_]{60,}                # GitHub fine-grained PAT
  | xox[bpa]-\d{8,14}-\d{8,14}-[A-Za-z0-9]{20,48}  # Slack
  | (?:sk|rk)_live_[A-Za-z0-9]{16,64}           # Stripe
  | sk-ant-[A-Za-z0-9_\-]{20,}                  # Anthropic
  | sk-(?:proj-)?[A-Za-z0-9_\-]{20,}            # OpenAI
  | glpat-[\w-]{20}                             # GitLab
  | npm_[A-Za-z0-9]{36}                         # npm
  | pypi-[A-Za-z0-9_\-]{40,}                    # PyPI
  | hf_[A-Za-z0-9]{30,}                         # Hugging Face
  | SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}  # SendGrid
  | ya29\.[A-Za-z0-9_\-]{20,}                   # Google OAuth
  | SK[0-9a-fA-F]{32}                           # Twilio
)(?![\w])''', re.X)
JWT = re.compile(r'(?<![\w])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')
SECRET_PATH = re.compile(r'(?:\.aws/credentials|\.docker/config\.json|\.kube/config|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.config/gcloud|\.azure/|(?:^|/)\.env(?:$|\.)|/etc/shadow|id_rsa|id_ed25519|\.(?:pem|p12|pfx|kdbx)$|Login Data|wallet\.dat|logins\.json|/proc/(?:self|\d+)/environ)', re.I)
PERSIST_PATH = re.compile(r'(?:/etc/(?:sudoers|cron|systemd|init\.d|ld\.so\.preload|pam\.d)|/var/spool/cron|authorized_keys|sshd_config|\.(?:bashrc|profile|zshrc)|rc\.local|sitecustomize\.py|usercustomize\.py|\.pth$|\.git/hooks/|LaunchAgents/)', re.I)
SECRET_NAME = re.compile(r'key|token|secret|password|credential', re.I)
# Small curated vocabulary, not a complete registry or malicious-package feed.
TOP_PACKAGES = frozenset('requests urllib3 numpy pandas scipy colorama click rich tabulate flask django fastapi pydantic pytest setuptools wheel pip boto3 botocore httpx pyyaml pillow cryptography torch tensorflow opensearch-dashboards-plugin react express lodash'.split())
# Offline snapshot of well-known malicious / typosquatted names (illustrative, not a feed).
MALICIOUS_PACKAGES = frozenset((
    'colourama', 'python3-dateutil', 'jeiilyfish', 'jellyfish', 'reqeusts', 'request',
    'urlib3', 'urllib', 'crypt', 'crypto', 'pycrypto', 'setup-tools', 'setuptools-scm',
    'discordpy', 'python-openssl', 'mysql-connector', 'pandas-dev', 'numpyy', 'tenserflow',
    'beautifulsoup', 'beautifulsoup4', 'djanga', 'flask-sqlalchemy', 'crossenv',
    'django-requests', 'mailfetch', 'openvc', 'opencv-python-headless', 'libpeshka',
    'telegram-python', 'electrum', 'bitcoinlib', 'pynput', 'keylogger',
))


def secret_literal(value, context=''):
    if not isinstance(value, str):
        return False
    if PROVIDER.search(value) or JWT.search(value) or '-----BEGIN PRIVATE KEY-----' in value or '-----BEGIN RSA PRIVATE KEY-----' in value:
        return True
    if re.search(r'\w+://[^\s/:]+:[^\s@]+@[^\s/]+', value) and not re.search(r'localhost|<|\$\{|YOUR_|password@', value):
        return True
    if len(value) < 20 or len(value) > 512 or not SECRET_NAME.search(context):
        return False
    if re.search(r'YOUR_|\$\{|<[^>]+>|xxxx|changeme|example|\s', value, re.I):
        return False
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())
    return entropy >= (3 if re.fullmatch('[0-9a-fA-F]+', value) else 4)


def network_risk(url):
    if not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url if '://' in url else 'http://' + url)
        host = (parsed.hostname or '').lower().rstrip('.')
        if parsed.scheme in ('gopher', 'file', 'dict', 'ldap', 'tftp', 'jar', 'ftp'):
            return 'NET-003'
        if host in ('localhost', 'metadata.google.internal', 'host.docker.internal',
                    'localtest.me', '0.0.0.0', '::', '[::]', '100.100.100.200',
                    'fd00:ec2::254', 'instance-data'):
            return 'NET-001'
        if host.endswith(('.internal', '.local', '.svc.cluster.local', '.nip.io',
                          '.sslip.io', '.ngrok.io', '.ngrok-free.app', '.cloudflared.com')):
            return 'NET-001'
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                if host.isdigit() or host.startswith('0x'):
                    address = ipaddress.ip_address(int(host, 0) if host.startswith('0x') else int(host))
                elif re.fullmatch(r'[0-9xXa-fA-F.]+', host):
                    parts = host.split('.')
                    address = ipaddress.ip_address('.'.join(str(int(p, 16) if p.startswith('0x') else int(p, 8) if p.startswith('0') and len(p)>1 else int(p)) for p in parts))
                else:
                    return None
            except ValueError:
                return None
        if not address.is_global or getattr(address, 'ipv4_mapped', None) and not address.ipv4_mapped.is_global:
            return 'NET-001'
    except ValueError:
        return 'NET-002'
    return None


def distance(a, b):
    previous = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        current = [i]
        for j, y in enumerate(b, 1):
            current.append(min(current[-1]+1, previous[j]+1, previous[j-1]+(x != y)))
        previous = current
    return previous[-1]


def package_risk(package):
    if not isinstance(package, str):
        return False
    if package.startswith(('git+', 'http://', 'https://')):
        return True
    name = re.split(r'==|>=|<=|~=|@|\[', package)[0].lower().replace('_', '-').replace('.', '-')
    if name in MALICIOUS_PACKAGES:
        return True
    if name in TOP_PACKAGES or len(name) < 4:
        return False
    def near(top):
        if abs(len(name)-len(top)) > 1:
            return False
        if distance(name, top) == 1:
            return True
        different = [i for i,(a,b) in enumerate(zip(name,top)) if a!=b]
        return (len(name)==len(top) and len(different)==2
                and different[1]==different[0]+1
                and name[different[0]]==top[different[1]]
                and name[different[1]]==top[different[0]])
    return any(near(top) for top in TOP_PACKAGES)


def command_findings(command):
    """Find behaviors in a known command sink, never in arbitrary code prose."""
    if isinstance(command, (list, tuple)):
        tokens = [str(x) for x in command]
        text = ' '.join(tokens)
    elif isinstance(command, str):
        text = command
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
    else:
        return []
    found = []
    def match(rule, pattern):
        if re.search(pattern, text, re.I):
            found.append(rule)
    match('DES-001', r'\brm\s+[^;\n]*-[\w]*r[\w]*\s+(?:/\s*$|/\*|~|\$|\*)')
    match('DES-002', r'\b(?:mkfs|wipefs|shred)\b|\bdd\b[^\n]*of=/dev/')
    match('DES-005', r'terraform destroy|kubectl delete|git (?:reset --hard|clean -fdx|push --force)|docker system prune')
    match('DES-007', r'history -c|unset HISTFILE|auditctl -e 0|(?:>|truncate[^\n]*)\s*/var/log/')
    match('DES-008', r'ufw disable|setenforce 0|iptables -F|kill -9 -1')
    match('DES-003', r'\bGRANT\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE|EXECUTE)\b')
    match('PER-003', r'\b(?:useradd|chpasswd)\b|usermod.*(?:sudo|wheel)')
    match('PER-004', r'chmod\s+(?:u\+s|4755)|\bsetcap\b')
    match('PER-005', r'--privileged|/var/run/docker.sock|\b(?:nsenter|insmod|pkexec)\b')
    match('PER-007', r'/dev/tcp/|\bnc\s+[^\n]*-e\b|socat\s+[^\n]*exec')
    match('PER-010', r'chmod\s+(?:-R\s+)?777\s+/(?:etc|var|usr|root|bin|sbin)')
    match('PER-002', r'\bcrontab\s+(?!-l\b|-r\b)\S+|systemctl\s+enable\b')
    match('EXF-003', r'\bping\b[^\n]*\s-p\s|\bhttps?://[A-Za-z0-9+/=_-]{40,}\.')
    match('EXF-005', r'\b(?:mysqldump|pg_dump)\b')
    match('DEP-004', r'"postinstall"\s*:')
    match('RES-003', r':\(\)\s*\{\s*:\|:&\s*\}')
    if re.search(r'\bdd\s+[^\n]*if=/dev/zero', text) and not re.search(r'\bcount=\d+', text):
        found.append('RES-005')
    match('RES-005', r'\b(?:yes|cat /dev/zero)\s*>')
    match('RES-007', r'\b(?:xmrig|cpuminer)\b|stratum\+tcp://')
    if re.search(r'\b(?:curl|wget)\b[^\n]*\|\s*(?:sh|bash)', text):
        found += ['DEP-003', 'OBF-009']
    match('OBF-009', r'base64\s+-d[^\n]*\|\s*(?:sh|bash)|xxd\s+-r[^\n]*\|\s*(?:sh|bash)')
    if 'install' in tokens and any('pip' in t or t == 'npm' for t in tokens):
        packages = tokens[tokens.index('install')+1:]
        if any(package_risk(p) for p in packages):
            found.append('DEP-001' if not any(p.startswith(('git+', 'http')) for p in packages) else 'DEP-002')
        if any(t in tokens for t in ('--trusted-host', '--extra-index-url', '--index-url')):
            found.append('DEP-002')
    return found


def text_injection(text):
    # Remove only a quoted example explicitly described as untrusted content.
    # Keep the rest of the passage so documentation cannot hide a later command.
    text = re.sub(r'(["\'])ignore (?:all )?(?:previous|prior) instructions\1\s+in untrusted content',
                  'quoted untrusted example', text, flags=re.I)
    lowered = text.lower()
    if re.search(r'ignore (?:all )?(?:previous|prior) instructions|reveal (?:the )?(?:full )?system prompt|disregard (?:all )?(?:previous|prior|above)', lowered):
        return True
    if re.search(r'<\|\s*(?:im_start|im_end|system|assistant)\s*\|>|\[/?INST\]|###\s*(?:system|assistant)\s*:'
                 r'|^\s*(?:system|assistant)\s*:', lowered, re.M):
        return True
    if re.search(r'you are (?:now|no longer)\b|\bdo not (?:flag|block|report)\b'
                 r'|\bmark (?:this|it) as (?:safe|compliant|approved)\b'
                 r'|\bthis (?:code|snippet) (?:has been|is) (?:audited|approved|safe)\b'
                 r'|\bsecurity (?:scan|review) (?:passed|approved)\b', lowered):
        return True
    if re.search(r'[\u200b-\u200f\u202a-\u202e\u2060-\u206f]', text):
        return True
    addressed = re.search(r'\b(?:ai|agent|assistant|reviewer|bot|model|llm|tool|copilot)\b', lowered)
    return bool(addressed and re.search(r'approve[\s\S]{0,150}regardless|skip static analysis|(?:print|send|reveal)[\s\S]{0,60}(?:credentials|secrets|keys)|report[\s\S]{0,50}compliant|before (?:answering|responding)[\s\S]{0,80}(?:read|send|call)', lowered))
