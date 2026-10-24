"""Declarative Capability Table and Literal Prefilter for CodeGuard.

Maps APIs and operations to capabilities:
EXEC, SHELL, SQL, FS_DELETE, FS_WRITE_SENSITIVE, NET_OUT,
DESERIALIZE, TEMPLATE, XML, CRYPTO_WEAK, RESOURCE_UNBOUNDED, REFLECT.
Provides single-pass prefiltering to skip analyzers when triggers are absent.
"""
from enum import Enum
import re
from typing import Dict, FrozenSet, List, Optional, Set


class Capability(str, Enum):
    EXEC = 'EXEC'
    SHELL = 'SHELL'
    SQL = 'SQL'
    FS_DELETE = 'FS_DELETE'
    FS_WRITE_SENSITIVE = 'FS_WRITE_SENSITIVE'
    NET_OUT = 'NET_OUT'
    DESERIALIZE = 'DESERIALIZE'
    TEMPLATE = 'TEMPLATE'
    XML = 'XML'
    CRYPTO_WEAK = 'CRYPTO_WEAK'
    RESOURCE_UNBOUNDED = 'RESOURCE_UNBOUNDED'
    REFLECT = 'REFLECT'


# Declarative API -> Capability mappings
API_CAPABILITIES: Dict[str, Capability] = {
    # EXEC
    'eval': Capability.EXEC,
    'exec': Capability.EXEC,
    'compile': Capability.EXEC,
    '__import__': Capability.EXEC,
    'importlib.import_module': Capability.EXEC,
    'Function': Capability.EXEC,

    # SHELL
    'os.system': Capability.SHELL,
    'os.popen': Capability.SHELL,
    'subprocess.run': Capability.SHELL,
    'subprocess.Popen': Capability.SHELL,
    'subprocess.call': Capability.SHELL,
    'subprocess.check_output': Capability.SHELL,
    'pty.spawn': Capability.SHELL,
    'execSync': Capability.SHELL,

    # SQL
    'cursor.execute': Capability.SQL,
    'cursor.executemany': Capability.SQL,
    'sqlite3.connect': Capability.SQL,
    'psycopg2.connect': Capability.SQL,
    'MySQLdb.connect': Capability.SQL,

    # FS_DELETE
    'os.remove': Capability.FS_DELETE,
    'os.unlink': Capability.FS_DELETE,
    'shutil.rmtree': Capability.FS_DELETE,
    'Path.unlink': Capability.FS_DELETE,

    # NET_OUT
    'requests.get': Capability.NET_OUT,
    'requests.post': Capability.NET_OUT,
    'httpx.get': Capability.NET_OUT,
    'httpx.post': Capability.NET_OUT,
    'urllib.request.urlopen': Capability.NET_OUT,
    'socket.connect': Capability.NET_OUT,
    'socket.create_connection': Capability.NET_OUT,
    'fetch': Capability.NET_OUT,
    'axios.post': Capability.NET_OUT,

    # DESERIALIZE
    'pickle.loads': Capability.DESERIALIZE,
    'pickle.load': Capability.DESERIALIZE,
    'cPickle.loads': Capability.DESERIALIZE,
    'marshal.loads': Capability.DESERIALIZE,
    'dill.loads': Capability.DESERIALIZE,
    'yaml.load': Capability.DESERIALIZE,
    'torch.load': Capability.DESERIALIZE,

    # TEMPLATE
    'render_template_string': Capability.TEMPLATE,
    'Template': Capability.TEMPLATE,

    # XML
    'xml.etree.ElementTree.parse': Capability.XML,
    'xml.sax.parse': Capability.XML,

    # CRYPTO_WEAK
    'hashlib.md5': Capability.CRYPTO_WEAK,
    'hashlib.sha1': Capability.CRYPTO_WEAK,
    'ssl._create_unverified_context': Capability.CRYPTO_WEAK,

    # REFLECT
    'getattr': Capability.REFLECT,
    'setattr': Capability.REFLECT,
    'globals': Capability.REFLECT,
    '__subclasses__': Capability.REFLECT,
}

# Fast trigger token regex to prefilter entire analyzers
PREFILTER_PATTERNS = {
    Capability.EXEC: re.compile(r'\b(eval|exec|compile|__import__|importlib)\b', re.I),
    Capability.SHELL: re.compile(r'\b(subprocess|os\.system|popen|spawn|bash|sh|execSync)\b', re.I),
    Capability.SQL: re.compile(r'\b(SELECT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|cursor|execute)\b', re.I),
    Capability.FS_DELETE: re.compile(r'\b(rm|rmtree|remove|unlink|wipefs|shred|dd)\b', re.I),
    Capability.NET_OUT: re.compile(r'\b(requests|httpx|urlopen|socket|fetch|axios|ping|curl|wget|http://|https://|gopher://)\b', re.I),
    Capability.DESERIALIZE: re.compile(r'\b(pickle|yaml|marshal|dill|torch\.load|shelve)\b', re.I),
    Capability.CRYPTO_WEAK: re.compile(r'\b(md5|sha1|verify\s*=\s*False|unverified_context)\b', re.I),
    Capability.RESOURCE_UNBOUNDED: re.compile(r'\b(while\s+(?:True|1)|fork|:\|:|range\(10\*\*|bytearray\(10\*\*)\b', re.I),
}


def get_capability(callee: str) -> Optional[Capability]:
    """Resolve an API name to its capability."""
    return API_CAPABILITIES.get(callee)


def scan_prefilter(code: str) -> Set[Capability]:
    """Fast literal prefilter returning capabilities potentially relevant for this code."""
    matched = set()
    for cap, pat in PREFILTER_PATTERNS.items():
        if pat.search(code):
            matched.add(cap)
    return matched
