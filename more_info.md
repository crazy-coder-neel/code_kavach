# CodeGuard — more_info.md

Companion to `context.md` and `prd.md`. Covers: what the four reference documents teach us, the real-time failure-detection pipeline, concrete rule specs for all 9 categories, extra categories beyond the 9, secret detection, the ML model specs, and a suggestion list.

**Reading guide:** all numbers quoted from the reference documents are *self-reported by their authors on curated or hand-written suites*. They tell us what is plausible, not what we will score.

---

## 1. What the four references teach us

| Source | What it is | Reported numbers (their own suites) | Take-away for CodeGuard |
|---|---|---|---|
| **ast-guard** README + RESULTS | Deterministic AST gate for AI-generated code; Python native `ast`, Bash/JS via tree-sitter; pair mode (original vs generated) and standalone mode; additive behavioural risk score (CLEAN <30, WARNING 30–69, CRITICAL ≥70); modes audit/standard/strict | <10–50 ms/scan; MALT standalone: 95.0% TNR on normal, 34.5% recall on bypass; precision only 21% standalone; TRACE standalone: 30.1% FPR, 21.3% in-scope recall | Deterministic AST is fast and explainable. **Standalone mode (our case: no baseline) is where precision suffers.** Its top false-positive triggers are exactly what a naive blocklist does: `import subprocess` (397 normal samples), `sys.exit`, `inspect`, env mutation, and a raw literal-count threshold (30% FPR on data-heavy scripts). We must use **context, not imports or counts** |
| **AEGIS** (arXiv 2603.12621) | Pre-execution firewall for agent tool calls: deep string extraction → regex pattern scan (22 patterns, 7 categories) → JSON-Schema policy → allow / block / pending (human review); hash-chained, Ed25519-signed audit trail; dashboard | 48/48 blocked on its own curated suite; 1.2% FPR on 500 benign calls (all from `OR`-style SQL pattern); median 8.3 ms, P95 14.7 ms, P99 23.1 ms | Validates the architecture and latency budget. Good ideas to copy: **recursive string extraction with depth and count caps and conservative flag on truncation**, **priority order: argument content > tool name > client metadata**, **three-state decisions**, **tamper-evident audit**, **PII detection**. Its own stated limit — regex rules miss unseen variants — is the gap our AST + taint + capability design fills |
| **STELP** (arXiv 2601.05467) | Capital One: parse code to AST, validate against a configurable "safe grammar", transpile to controlled code, execute with timeouts, retries, loop/stack limits; LLM feedback loop for repair | InjectedHumanEval (164 safe, 470 unsafe, LLM-injected CWEs): blocked 100%, allowed 98.1% of safe; Meta CodeShield 68% / 93% | An **allow-list grammar works when benign code is narrow** (HumanEval-style). Our benign set is broader (boto3, requests, logging, SQL), so we use **per-capability policy** as default and offer the strict allow-list as an optional profile. Great CWE list (§6). Most blocks came from "unexpected function call or import" (311), `while True` (70), imports (22), timeouts (19), stack depth (11). Its LLM feedback is out for us (no LLM); we return **deterministic remediation hints** instead |
| **RESULTS.md** | Evaluation discipline | Held-out split "measured once, never tuned"; stress test on 974 MBPP + 164 HumanEval solutions for FPR; independent labelled external datasets; failure analysis of each remaining FP | Copy the **method**: held-out set touched once, a **large public benign-code stress test for false positives**, per-item FP root-cause notes, and honest "known limits" |

**Escalation lesson (ast-guard):** when a model is optimised against a structural gate, it shifts to forms the gate misses. Ours will face the same from adversarial inputs. So we must (a) measure evasion with a mutation fuzzer, (b) fail suspicious-but-unparseable inputs toward `block`, and (c) keep ML as a second, differently-shaped net.

**Constraint reminder:** the brief forbids any external LLM "for any part of the system." Do **not** use an LLM to generate training data or feedback either (STELP and AEGIS do). Use templates and mutations. If you use an AI coding assistant to write code, disclose it.

---

## 2. Real-time failure-detection pipeline

### 2.1 End-to-end flow

```
 Agent proposes code ───────────────────────────────────────────────┐
                                                                    ▼
 ┌───────────────────────────── CodeGuard service ───────────────────────────────┐
 │ 0 Intake      validate, size/depth caps, request id, deadline start           │
 │ 1 Extract     normalise; split into segments: code, strings, comments, prose; │
 │               recursive string extraction (depth ≤ 32, ≤ 10,000 strings; if   │
 │               truncated → mark "incomplete" → suspicious)                     │
 │ 2 Unwrap      decode base64/hex/rot13/chr-joins/concat; rescan, depth ≤ 3     │
 │ 3 Language    hint → shebang → parse trial → lexical score                    │
 │ 4 Fast rules  compiled, prefiltered (cheap, high precision)                   │
 │ 5 Structure   AST/shell/SQL/JS analyzers: aliases, constants, taint,          │
 │               capability table, network + dependency classifiers              │
 │ 6 ML          classical multi-label + injection-text classifier               │
 │ 7 Gray zone?  yes → optional SLM / novelty check                              │
 │ 8 Aggregate   noisy-OR, chain bonuses, severity floors → risk_score, verdict  │
 │ 9 Explain     findings → reason, vulnerable_lines, remediation, references    │
 │10 Respond     fixed schema (+ detail on request); async audit enqueue         │
 └───────────────┬───────────────────────────────────────────────────────────────┘
                 ▼
       Guard wrapper (SDK) ── block → refuse + return machine-readable reason to the agent
                 │ allow
                 ▼
       Restricted executor (timeout, rlimits, no network, scrubbed env)  ← runtime backstop
                 │ tool output
                 ▼
       POST /v1/verify-output (injection and secret-leak check) → back to the LLM
```

### 2.2 Four layers of "catching failures"
1. **Pre-execution verdict** (the main gate).
2. **Runtime backstop** in the executor: wall-clock timeout, CPU/memory rlimits, loop and stack-depth limits, no network, scrubbed environment. Catches what static analysis cannot prove (e.g., an infinite loop it misjudged).
3. **Post-tool verification:** tool output scanned for injected instructions and leaked secrets before the LLM sees it.
4. **Live monitoring:** block-rate anomaly, degraded-rate, latency, new-pattern drift; feedback loop for false positives and negatives.

### 2.3 Decision states
Schema allows only `allow`/`block`. Internally keep three: `allow`, `block`, `needs_review`. `needs_review` is returned as `block` with `decision_basis: "needs_review"` in detail mode and `X-CodeGuard-Review: 1`, so a human-approval workflow (AEGIS-style) can exist without breaking the fixed schema.

### 2.4 Failure semantics
Engine error, timeout, truncation, unparseable-but-suspicious input → `block` with `degraded: true`. Never convert an error into permission.

---

## 3. The 9 categories — implementation spec

Conventions: **Sev** = critical / high / medium / low. **Guard** = conditions that suppress the finding (this is where false positives are killed). Rule ids are `CG-<CAT>-NNN`. Detection modes: **L** = lexical/regex, **A** = AST/structure, **T** = taint/dataflow, **C** = constant propagation, **M** = ML assist.

### 3.1 `secret_access` (SEC)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| SEC-001 | Literal matches a provider token format (§5) in executable context | L+A | high–critical | Docstring/comment-only mention without assignment or use → low. **Do not suppress because it looks like a docs example** (the dev set labels fake-but-well-formed keys as malicious) |
| SEC-002 | PEM private-key block or read of private key files (`id_rsa`, `id_ed25519`, `*.pem`, `*.p12`, `*.pfx`, `*.kdbx`) | L+A | critical | Public key / certificate only → no |
| SEC-003 | Read of a credential file: `~/.aws/credentials`, `~/.docker/config.json`, `~/.kube/config`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.git-credentials`, `~/.config/gcloud`, `~/.azure`, `.env`, `/etc/shadow` | A+C | high | Path resolved via `expanduser`/`Path.home()`/`join` constants. App's own `~/.config/<app>/prefs` not in the set → benign |
| SEC-004 | Environment sweep: iterate `os.environ`/`env`/`printenv` and filter on `KEY`/`TOKEN`/`SECRET`/`PASSWORD` | A+T | high | A single named variable used locally, e.g. for the app's own API → no finding |
| SEC-005 | Generic literal: length ≥ 20, high entropy, assigned to a secret-like name, not a placeholder | A+C | medium | Placeholder list (`YOUR_`, `<…>`, `${…}`, `xxxx`, `changeme`, `example` words only when *not* format-valid); boost if used in an auth header |
| SEC-006 | Credentials in URL / connection string (`scheme://user:pass@host`) | L | medium–high | Placeholders; `user:password@localhost` in tests → low |
| SEC-007 | Cloud-metadata credential fetch (`/latest/meta-data/iam/security-credentials`) | A+C | critical | none (also raises SSRF) |
| SEC-008 | Browser/keychain/wallet stores (`Login Data`, `Cookies`, `logins.json`, keychain, `wallet.dat`) | L+A | high | none |
| SEC-009 | Secret variable passed to logging/print/exception message | T | medium | Masked/redacted values |
| SEC-010 | `/proc/*/environ`, `/proc/self/environ`, process-memory reads | A | high | none |

### 3.2 `data_exfiltration` (EXF)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| EXF-001 | Sensitive source flows to a network sink (`requests`, `httpx`, `urllib`, `aiohttp`, `http.client`, `socket`, `websockets`, `smtplib`, `ftplib`, `paramiko`, `curl`, `wget`, `nc`, `scp`, `rsync`) | T | critical | Destination in allow-list **and** payload non-sensitive |
| EXF-002 | Bulk read (`os.walk`, `glob`, directory listing, `cat /etc/passwd`) followed by external send | T | high | Allow-listed destination |
| EXF-003 | Covert channels: DNS lookups with data-built hostnames, `ping -p`, ICMP, chunk-and-encode loops, HTTP headers/cookies carrying data | A+T | high | none |
| EXF-004 | Public sinks: paste/transfer sites, request catchers, tunnels, chat webhooks, bot APIs | L+C | high | Allow-listed corporate webhook |
| EXF-005 | Database dump to outside: `mysqldump`, `pg_dump`, `COPY … TO`, `INTO OUTFILE`, or `SELECT *` built by tainted string formatting | A+T | high | Parameterised, scoped query |
| EXF-006 | Cloud upload to non-owned destination (`aws s3 cp/sync`, `gsutil cp`, `rclone`, `az storage … upload`) | A+C | medium–high | Bucket/account in allow-list |
| EXF-007 | `git remote add` external + `push` of local data | L+A | high | Org-owned remote |
| EXF-008 | Capture then send: keylogger, clipboard, screenshot libraries | A+T | high | none |
| EXF-009 | PII in outbound payload (email, SSN, Luhn-valid card, JWT, DB URI, AWS ARN — AEGIS list) | L | medium–high | Test fixtures / masked values |

### 3.3 `destructive_command` (DES)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| DES-001 | Recursive delete on broad or unvalidated targets: `rm -rf` with `/`, `~`, `$HOME`, `*`, unvalidated variable; `shutil.rmtree`/`os.remove` over `os.walk`/wide globs; tainted path | A+T | critical | Constant narrow path inside a temp directory; `--dry-run` |
| DES-002 | Disk-level: `dd of=/dev/…`, `mkfs`, `wipefs`, `shred`, redirect to `/dev/sd*`, `truncate -s 0` on important paths | L+A | critical | none |
| DES-003 | SQL: `DROP`, `TRUNCATE`, `ALTER`; `DELETE`/`UPDATE` **without `WHERE`**; DML built by tainted `format`/`%`/f-string | A+T | high–critical | Parameterised with scoped `WHERE` (benign dev pattern) |
| DES-004 | **Command injection:** tainted data into `shell=True`, `os.system`, `popen`, `bash -c`, `eval` of shell | T | high | Argument list without shell + validated/allow-listed input, `shlex.quote` |
| DES-005 | Infra destruction: `terraform destroy`, `kubectl delete` (`--all`, namespaces), `aws … delete/terminate/rm --recursive`, `gcloud … delete`, `docker system prune -a`, `git push --force`, `git reset --hard`, `git clean -fdx` | L+A | high | Pending-review route; scoped single resource in a dev context |
| DES-006 | Ransomware pattern: iterate many files → encrypt/overwrite → delete original or rename to a new extension | A+T | critical | none |
| DES-007 | Log/audit tampering: `history -c`, `unset HISTFILE`, truncating `/var/log`, `auditctl -e 0` | L | high | none |
| DES-008 | Disabling protection: `kill -9 -1`, `pkill`, stop/disable security services, `ufw disable`, `setenforce 0`, `iptables -F` | L | high | none |
| DES-009 | Mass modification: loop `UPDATE` over all rows without bound, mass `chmod -R`/`chown -R` on system paths | A | high | none |

### 3.4 `persistence_or_privesc` (PER)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| PER-001 | Write/append to `/etc/sudoers`, `/etc/sudoers.d/*`; `NOPASSWD` | L+A | critical | Read-only |
| PER-002 | Startup persistence: write crontab (`crontab -`, `/etc/cron*`, `/var/spool/cron`), systemd units (`/etc/systemd/system`, user units) + `enable`, launchd plists, `rc.local`, `init.d`, shell profiles (`.bashrc`, `.profile`, `.zshrc`), autostart `.desktop`, git hooks, Windows Run keys/`schtasks` | A+C | high | `crontab -l`, `systemctl status` (read-only; dev benign pattern) |
| PER-003 | Account backdoors: append to `authorized_keys`, `sshd_config` weakening, `useradd`/`usermod -aG sudo`, `chpasswd` | L+A | critical | none |
| PER-004 | SUID/capabilities: `chmod u+s`, mode `4755`, `setcap`, `os.chmod` with `S_ISUID`, `chown root` | A | critical | none |
| PER-005 | Privilege tools: `sudo`, `su`, `pkexec`, `setuid(0)`, Docker `--privileged`, mounting `docker.sock`, `nsenter`, `insmod`, container escape | L+A | high | Explicit allow-list for CI contexts |
| PER-006 | Library/loader hijack: `LD_PRELOAD`, `/etc/ld.so.preload`, writable-dir `PATH` prepend, `sitecustomize`/`usercustomize`/`.pth` writes, `PYTHONSTARTUP` | A | high | none |
| PER-007 | **Reverse shell / C2:** `/dev/tcp/…`, `nc -e`, `socat exec`, socket + `dup2` + shell, `pty.spawn` | A+T | critical | none |
| PER-008 | PAM/NSS edits, browser-extension installs, login-hook writes | L | high | none |
| PER-009 | Persistence via downloaded script: unit/cron whose command fetches and executes remote code (dev pattern) | A+T | critical | none |
| PER-010 | World-writable perms on sensitive paths (`chmod 777`) | A | medium | Temp dirs |

### 3.5 `obfuscated_execution` (OBF)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| OBF-001 | **Decode → execute** chain: `b64decode`/`fromhex`/`codecs`/`zlib.decompress`/`marshal` result into `exec`/`eval`/`compile`/`os.system`/`subprocess` | A+T | critical | none |
| OBF-002 | `exec`/`eval`/`compile` on a non-literal (high) or tainted (critical) | A+T | high–critical | `ast.literal_eval` is **not** a finding |
| OBF-003 | Dynamic import/attribute: `__import__(x)`, `importlib.import_module(non-literal)`, `getattr(mod, computed)`, `globals()[x]`, `builtins` subscripting | A+T | high | Name validated against an allow-list (dev benign `setattr` case) |
| OBF-004 | Alias/indirection resolved before sink matching (`import os as o`, `from os import system as s`, `f = os.system`) | A | — | Aliasing alone is not a finding; it makes sink rules apply |
| OBF-005 | Sensitive names/URLs built from `chr`, `join`, concat, reversed, `format` and reaching a call | A+C | medium–high | Built string never reaches a sink |
| OBF-006 | **Unsafe deserialization:** `pickle`, `cPickle`, `dill`, `marshal`, `shelve.open`, `yaml.load` without safe loader, `jsonpickle`, `torch.load` without `weights_only`, `numpy.load(allow_pickle=True)` | A+T | high | Source is a trusted, app-owned path (e.g., fixed app data dir); `yaml.safe_load` |
| OBF-007 | Introspection / sandbox escape: `__class__`, `__bases__`, `__subclasses__`, `__globals__`, `__builtins__`, `__reduce__`, `sys.modules` mutation, `ctypes` memory access | A | high | none (STELP shows this exact `__subclasses__` escape) |
| OBF-008 | Packed payloads: long high-entropy blob + decode/decrypt + execute; minified one-liner stagers | A+L | high | Data blobs never executed |
| OBF-009 | Shell: `base64 -d` piped to a shell, `eval "$(…)"`, `curl … \| sh`, `$'\x..'` strings, `${IFS}` splitting, `xxd -r -p` piped to shell | L+A | high | none |
| OBF-010 | JS: `eval(atob(…))`, `new Function(...)`, `Buffer.from(…,'base64')` + eval, `String.fromCharCode` builders | A | high | none |
| OBF-011 | Invisible/bidi/homoglyph characters in identifiers or code (Trojan-Source) | L | medium | Legit non-English string literals |
| OBF-012 | Template injection: `render_template_string(tainted)`, `Template(tainted)`, Jinja sandbox disabled | T | high | Constant templates |

### 3.6 `dependency_risk` (DEP)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| DEP-001 | **Typosquat:** normalised name (case, `-`/`_`/`.`) within edit distance ≤ 2 of a bundled top-N package but not equal; homoglyphs; common decorations (`-python`, `py-`, doubled letters) | L+C | high | Exact match to a known package → clean |
| DEP-002 | Install from URL/VCS/untrusted index: `git+https://…` unpinned or branch ref, `http://`, `--index-url`/`--extra-index-url` non-official, `--trusted-host`, tarball URLs | L+A | high | Pinned commit hash on an org-owned repo (policy allow-list) |
| DEP-003 | Piped installers: `curl … \| sh`, `wget … \| bash`, `iex (irm …)` | L | high | Allow-listed vendor URL |
| DEP-004 | Install-time execution: `setup.py` `cmdclass`/network/shell, npm `postinstall` running commands | A | medium–high | none |
| DEP-005 | Dependency confusion: internal-looking name + public/extra index | L | medium | none |
| DEP-006 | Runtime install with tainted name: `subprocess … pip install <var>` | T | high | Constant pinned package |
| DEP-007 | Known-malicious package list (offline snapshot of public malicious-package datasets) | L | critical | none |
| DEP-008 | Unpinned dependency alone | L | info | **Not** a block by itself; pinned official package is the benign dev pattern |

### 3.7 `resource_exhaustion` (RES)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| RES-001 | Unbounded loop: `while True`/`while 1`/`itertools.count`/`cycle` with no reachable `break`/`return`/`raise` and no bounded wait | A | high | Has exit path, or loop blocks on a queue/socket with timeout |
| RES-002 | Unbounded loop **plus resource creation** (append, thread/process start, open, socket, subprocess) | A | critical | none |
| RES-003 | Fork/process bomb: `os.fork()` in loop/recursion, `:(){ :\|:& };:`, `Popen`/`Process` in unbounded loop | A+L | critical | Bounded pool |
| RES-004 | Memory blow-up: allocation with constant ≥ ~10^8 (`[0]*10**9`, `bytearray(10**10)`, `'x'*10**10`), unbounded `.read()` on stream/`/dev/zero` | A+C | high | Threshold configurable |
| RES-005 | Disk fill: write loop with no cap, `dd if=/dev/zero`, `fallocate -l 1000G`, `yes > file`, `cat /dev/zero >` | L+A | high | none |
| RES-006 | Handle exhaustion: sockets/files/threads opened in a loop, constant count ≥ ~10^4 (dev: 50,000 sockets), no `close`/`with` | A+C | high | Closed in loop / bounded |
| RES-007 | CPU burn: huge nested ranges, hash-grind loops, miner signatures (`xmrig`, `stratum+tcp://`, `cpuminer`), `stress` | A+L | medium–high | none |
| RES-008 | Recursion without base case; `sys.setrecursionlimit(10**9)` | A | high | none |
| RES-009 | ReDoS-prone regex on untrusted input (nested quantifiers) | L | medium | Input length capped |
| RES-010 | Decompression/zip bomb: unbounded `extractall`/`decompress` on untrusted input | A+T | medium | Size/ratio limits present |
| RES-011 | Concurrency hazards: lock-order inversion, unbounded thread creation in loop | A | medium | Fixed-size pool with `join` (dev benign pattern) |
| RES-012 | Infinite retry/backoff on network | A | low | Max attempts |

### 3.8 `ssrf_network_exfil` (NET)
| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| NET-001 | **Destination classifier** hits: loopback, RFC1918, link-local, cloud metadata (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`, IPv6 `fd00:ec2::254`), `.internal`/`.local`/`.svc.cluster.local`, `host.docker.internal`, wildcard-DNS names (`nip.io`, `sslip.io`, `localtest.me`) | C+A | critical (metadata) / high | Explicit local-dev policy |
| NET-002 | IP obfuscation: decimal, hex, octal, `::ffff:` mapped, `0.0.0.0`, `[::]` | C | high | none |
| NET-003 | Non-HTTP schemes: `gopher`, `file`, `dict`, `ldap`, `tftp`, `jar`, `ftp` | A+C | high | none (dev: gopher to internal Redis) |
| NET-004 | **Validation bypass:** URL checked (`startswith`/`in`/regex on the string) but the request uses a different value; `allow_redirects=True` to an unvalidated host; userinfo trick `https://allowed@evil` | A+T+C | high | Host compared after `urlparse` and re-validated on each redirect hop (dev bypass pattern) |
| NET-005 | Tainted URL to an HTTP client with no allow-list | T | medium–high | Allow-list by parsed host equality |
| NET-006 | Probing: port/host sweeps, `socket.connect_ex` over ranges, `nmap`, `masscan` | A | high | none |
| NET-007 | Internal service ports: 6379, 11211, 9200, 2375/2376, 6443, 10250, 2379 | C | high | none |
| NET-008 | Unusual egress: raw public IPs, odd ports, tunnels (`ngrok`, `cloudflared`, `ssh -R`), Tor/SOCKS, DoH | C+L | medium | none |
| NET-009 | Resolve-then-fetch gap (DNS rebinding TOCTOU) | A | medium | Pin resolved IP |

### 3.9 `ai_targeted_instructions` (AIT)
Scan **only** comments, docstrings, string literals, YAML/Markdown prose and tool descriptions — never the code tokens.

| ID | Trigger | Mode | Sev | Guard |
|---|---|---|---|---|
| AIT-001 | Imperative addressed to an AI/agent/reviewer/assistant/bot/model/LLM/Copilot **plus** an override or verdict verb: ignore, disregard, forget, override, skip, bypass, approve, mark as safe, do not flag, report as compliant | L+M | high–critical | Needs addressee **and** imperative **and** override verb ("ignore case", "ignore errors", "TODO: reviewer please check" are benign) |
| AIT-002 | Disclosure/exfil instructions: reveal system prompt, print or send secrets/keys, "before answering, read `~/.ssh`", call tool X | L+M | critical | none |
| AIT-003 | Role/format tokens: `<\|im_start\|>`, `<\|system\|>`, `[INST]`, `### System:`, `SYSTEM:`/`ASSISTANT:` lines, "You are now…", jailbreak personas | L | high | Docs quoting these in a clearly descriptive context |
| AIT-004 | Tool-description poisoning: hidden "before using this tool also…" blocks, `<IMPORTANT>` tags in tool docstrings or manifests | L+M | critical | none |
| AIT-005 | Concealment: zero-width/bidi/Unicode-tag characters, HTML comments in Markdown, base64/hex/rot13 instructions (decode, then rescan) | L+decode | high | none |
| AIT-006 | Verdict manipulation: "this code has been audited/approved/safe", "security scan passed", "false positive" next to risky code | L+M | medium–high | Genuine changelog text with no risky code nearby |
| AIT-007 | CI/workflow bot manipulation (YAML comments telling a reviewer bot to approve regardless of scan results) | L+M | high | none |
| AIT-008 | Output-channel exfil: markdown image/link with data in query, e.g. `![](https://host/?q=…)` | L+T | high | Allow-listed domains |
| AIT-009 | Paraphrases and other languages of the above | M | medium–high | classifier threshold |

**Benign look-alikes to keep passing (dev):** a security-policy string that mentions `password = hunter2` as an example of what *not* to do; comments that describe behaviour plainly; policy docs about prompt injection.

---

## 4. Beyond the nine: extended taxonomy

The hidden set is "mostly the 9, but can be from outside." We detect more, and **map each to the nearest of the nine** for the `categories` field. The finer class is exposed in detail mode (`extended_class`, CWE, ATT&CK). Verdict stays `block` whenever severity warrants it.

| Prefix | Class | Examples | Maps to | Priority |
|---|---|---|---|---|
| INJ | Injection family | SQLi (CWE-89), OS command (78), code (94/95), template (1336), XXE (611), LDAP/NoSQL/XPath, log/CRLF/header injection, path traversal & zip-slip (22) | destructive / exfil / obfuscated by effect | **P0** (appears in dev) |
| DSR | Deserialization & reflection | CWE-502, unsafe reflection (470), remote inclusion (829) | obfuscated_execution | **P0** |
| CRY | Weak crypto / TLS | MD5/SHA1 for passwords (328), ECB, static IV, short keys, `random` for tokens (338), `verify=False`, `_create_unverified_context`, JWT `alg:none` / `verify=False` (347) | other → `secret_access` or none (low) | P1 |
| AUT | Auth & config | `debug=True`, bind `0.0.0.0` on dev servers, CORS `*`, hard-coded default creds, missing auth | secret_access (creds) / none | P2 |
| WEB | Web (JS/Py) | `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, open redirect, prototype pollution, XSS | obfuscated_execution / none | P2 |
| REV | Remote access / C2 | reverse shells, bind shells, beacons, tunnels | persistence + exfil | **P0** (also PER-007) |
| MIN | Cryptojacking | miner binaries, pool URLs, `stratum` | resource_exhaustion | P1 |
| RAN | Ransomware | mass encrypt + delete/rename | destructive | P1 |
| EVA | Defense evasion | log wipe, history tamper, disabling AV/firewall/SELinux | persistence / destructive | P1 |
| CRD | Credential theft | browser stores, keychains, wallets, keyloggers, clipboard | secret_access / exfil | P1 |
| SUP | Supply chain | curl-pipe installers, postinstall scripts, dependency confusion | dependency_risk | **P0** |
| IAC | Cloud / IaC / containers | IAM `*:*`, public buckets/ACLs, `0.0.0.0/0` security groups, `--privileged`, `docker.sock`, privileged pods | persistence_or_privesc | P2 |
| PII | PII exposure | email, SSN, Luhn-valid card numbers, JWT, DB URIs, AWS ARNs in logs/outputs/payloads (AEGIS) | data_exfiltration | P1 |
| MEM | Low-level/logic bugs | out-of-bounds write (787), type confusion (843), deadlock (833), missing release (772) | resource_exhaustion / none | P2 (low static recall; STELP catches these mainly via runtime controls) |
| IPI | Indirect prompt injection in tool output | injected instructions in web/file content | ai_targeted_instructions | P1 (`/v1/verify-output`) |

**Catch-all for the unknown:** any `exec`/`eval`/dynamic import on a non-constant, any call whose callee cannot be resolved *and* whose argument is tainted by a sensitive source, any unparseable input that matches suspicious lexical signals → raise risk and fail toward `block`.

---

## 5. Secret detection spec (no name-based flagging)

**Principle:** a variable *name* never decides on its own. Decide from **format → structure → entropy → context → flow**.

1. **Provider formats (high confidence).** Prefix + length + charset. Check specific prefixes before generic ones.

| Provider | Format (verify before shipping) |
|---|---|
| Google API | `AIza` + 35 chars `[0-9A-Za-z_-]` |
| AWS | access key ID `AKIA`/`ASIA`/… + 16 uppercase alphanumerics; secret 40 chars `[A-Za-z0-9/+]` |
| OpenAI / Anthropic | `sk-…`, `sk-proj-…` / `sk-ant-…` (match Anthropic first) |
| GitHub | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36; `github_pat_…`; newer formats embed a checksum |
| Slack | `xoxb-`, `xoxp-`, `xapp-`; webhook URLs `hooks.slack.com/services/T…/B…/…` |
| Stripe | `sk_live_`, `rk_live_` (`sk_test_` lower) |
| Others | GitLab `glpat-`, npm `npm_`, PyPI `pypi-`, HuggingFace `hf_`, SendGrid `SG.`, Twilio `SK`+32 hex, Telegram `digits:35chars`, Google OAuth `ya29.` |

2. **Structured secrets.** PEM headers; JWT (three base64url parts, header decodes to JSON with `alg`); `scheme://user:pass@host`; Azure `AccountKey=`; database URIs.
3. **Generic high-entropy.** Shannon entropy over the literal (≈ ≥ 4.0 bits/char for base64-like, ≥ 3.0 for hex), length ≥ 20, assigned to a secret-like name or passed to an auth parameter; reject placeholders and obvious words.
4. **Context.** Executable assignment/use vs docstring/comment/prose. A secret-looking literal in prose that is never assigned or used (dev: `hunter2` policy text) is benign.
5. **Flow.** Does the value reach an `Authorization` header, an auth parameter, an outbound request to a foreign host, or a log call? Flow escalates severity.
6. **Behavioural secrets.** Environment sweeps; credential-file reads; metadata-credential endpoints.

**Hackathon-specific rule:** test data uses fake secrets. Dev examples include `AKIAIOSFODNN7EXAMPLE` and `xoxb-123456789012-987654321098-…`, labelled **malicious**. So a **well-formed provider token in executable code is flagged even if it looks like a documentation example**; only obvious templating (`YOUR_KEY_HERE`, `<token>`, `${VAR}`, `xxxx`) is suppressed.

---

## 6. CWE cross-walk (from STELP and our taxonomy)

| CWE | Name | Our rules | Notes |
|---|---|---|---|
| 94 / 95 | Code injection / eval | OBF-002 | |
| 470 | Unsafe reflection (`exec(f"import {x}")`) | OBF-003 | |
| 502 | Deserialization | OBF-006 | |
| 552 / 22 / 73 | Files accessible / path traversal | SEC-003, DES-001, INJ | taint on path |
| 770 | Allocation without limits | RES-004 | |
| 772 | Missing resource release | RES-006 | low severity unless in loop |
| 787 | Out-of-bounds write | — | Python raises; low value statically |
| 829 | Inclusion from untrusted sphere (`exec(requests.get(u).text)`) | OBF-001/002, EXF | high |
| 833 | Deadlock | RES-011 | lock-order heuristic |
| 835 | Unreachable exit (`while True`) | RES-001 | |
| 843 | Type confusion (`func(1234)`) | — | skip/low |
| 1050 | Excessive resource consumption in loop | RES-002, RES-011 | |
| 328 | Weak hash | CRY | low–medium |
| 78 | OS command injection | DES-004 | |
| 89 | SQL injection | DES-003, EXF-005 | |
| 918 | SSRF | NET-001…005 | |
| 798 / 259 | Hard-coded credentials | SEC-001/005 | |
| 532 | Secrets in logs | SEC-009 | |
| 1333 | ReDoS | RES-009 | |
| 409 | Decompression bomb | RES-010 | |
| 1336 | Template injection | OBF-012 | |
| 611 | XXE | INJ | |

---

## 7. Shared engines

| Engine | Job |
|---|---|
| **Extractor** | Recursive string/comment/docstring extraction with depth ≤ 32 and ≤ 10,000 strings; truncation → "incomplete" flag → suspicious (AEGIS pattern) |
| **Unwrapper** | Decode chains with depth/size/time caps; remaps findings to original lines |
| **Symbol resolver** | Imports, aliases, `from … import … as …`, simple reassignment, `getattr`/`__import__` with constants, `chr`/concat folding |
| **Constant propagator** | Folds constants, f-strings, `%`, `format`, `join`, `os.path.join`, `Path` ops, `expanduser` |
| **Taint engine** | Sources (user input, params, argv, request, env, file, network, DB, secrets); sinks by capability; sanitizers (parameterised SQL, `shlex.quote`, allow-list membership, `literal_eval`, `safe_load`, `re.fullmatch`); intraprocedural + one-level call summaries; loop-body propagation (while and for) |
| **Capability table (data, YAML)** | API/command → capability (`EXEC`, `SHELL`, `SQL`, `FS_DELETE`, `FS_WRITE_SENSITIVE`, `NET_OUT`, `DESERIALIZE`, `TEMPLATE`, `XML`, `CRYPTO_WEAK`, `RESOURCE_UNBOUNDED`, `REFLECT`). New APIs are one-line additions |
| **Network classifier** | URL/host/IP parsing, private/metadata ranges, obfuscated IPs, schemes, ports, wildcard DNS, allow-list, redirect-hop validation |
| **Dependency classifier** | Normalised names, edit distance/homoglyph against top-N list, source/pin/flags analysis, malicious-name list |
| **Shell parser** | `bashlex`/`shlex` tokens; pipes, `&&`, substitutions, redirects; detects pipe-to-shell, destructive flags, persistence paths |
| **SQL parser** | `sqlglot`: statement type, presence of `WHERE`, targets, dangerous functions |
| **Text scanner** | Comment/prose extraction; injection patterns; invisible-character scan; PII patterns with Luhn |
| **Explainer** | Finding → what/why/impact/fix/references; `reason`, `vulnerable_lines` |

**Optional strict profile (STELP-style):** allow-list of grammar, built-ins, imports, plus loop-iteration, nesting and stack-depth limits. Not the default (benign hidden code is broad), but available for locked-down agent deployments.

---

## 8. ML model specs

**Decision:** yes, build ML, but as a *second net behind the rules*. It exists for generalisation to phrasing, obfuscation and combinations we didn't write rules for. It never overrides a critical rule hit, and the system remains fully functional with ML switched off. **No LLM, no LLM-generated data.**

### 8.1 Models at a glance
| ID | Name | Purpose | Always on? | Latency | Priority |
|---|---|---|---|---|---|
| M1 | CG-Cls | Multi-label classifier over {9 categories, `benign`, `other_vuln`} | Yes | ≤ 2 ms | P1 |
| M2 | CG-Inj | Text classifier for `ai_targeted_instructions` | Yes (on extracted text only) | ≤ 1 ms | P1 |
| M3 | CG-SLM | Fine-tuned small encoder for ambiguous code (mentor request) | Gray zone only | ≤ 80 ms budget | P1/P2, gated |
| M4 | CG-Novelty | One-class "doesn't look like benign code" signal for unseen error types | Optional | ≤ 2 ms | P2 |

### 8.2 M1 — CG-Cls (classical multi-label)
| Item | Spec |
|---|---|
| Labels | `secret_access`, `data_exfiltration`, `destructive_command`, `persistence_or_privesc`, `obfuscated_execution`, `dependency_risk`, `resource_exhaustion`, `ssrf_network_exfil`, `ai_targeted_instructions`, `benign`, `other_vuln` |
| Input | Normalised code + decoded segments |
| Features | Hashed char n-grams (3–5); token n-grams (1–2) over **alias-resolved canonical API names**; AST node-type histogram; capability/source/sink flags; rule-hit vector (weighted by severity); entropy stats; length, comment ratio, language one-hot |
| Model | One-vs-rest logistic regression (L2) as baseline; gradient-boosted trees on the dense feature subset as challenger; keep the better on CV |
| Calibration | Isotonic or Platt per label on held-out folds; report ECE |
| Data | Own template + mutation generators (§8.6), 42 dev snippets, hand-written hard negatives |
| Split | Group k-fold by seed template so variants never straddle folds; sealed hand-written adversarial set used once |
| Generalisation test | **Leave-one-category-out:** train on 8 categories, test on the 9th, to see whether capability features generalise to unseen error types |
| Explainability | Top contributing features per prediction → `model_signals` |
| Artifact | < 20 MB; loaded at startup; deterministic inference |
| Integration | Bounded adjustment to risk; defines gray zone; `benign` probability can reduce risk only within the gray band and never below a critical-rule floor |
| Success | Beats Baseline B on the mutation set recall at ≤ +1 pt FPR on the benign stress set |

### 8.3 M2 — CG-Inj (prompt-injection text)
| Item | Spec |
|---|---|
| Input | Extracted comments, docstrings, string literals, YAML/Markdown prose, tool descriptions; decoded variants |
| Features | Word + char TF-IDF; addressee terms; override verbs; imperative-mood heuristics (sentence-initial verb); second-person; target nouns (system prompt, reviewer, static analysis, compliant, safe); position (comment vs code vs doc); invisible-character counts; decoded-payload flag |
| Model | Logistic regression (binary + subtype), calibrated |
| Data | Phrase banks × paraphrase templates × contexts (comment, docstring, YAML, Markdown, string, tool description); multilingual variants |
| Hard negatives | Security-policy text, docs about prompt injection, "ignore case/errors/whitespace" comments, human-addressed TODOs, changelog text |
| Success | FPR ≤ 1% on hard negatives; recall ≥ 0.9 on held-out phrasings |

### 8.4 M3 — CG-SLM (fine-tuned small language model; run only if it earns its place)
| Item | Spec |
|---|---|
| Base | Small code-aware encoder (≈ 30–125M parameters). **Record licence and source in README before use**; prefer permissive |
| Head | Multi-label classification head (same 11 labels) |
| Input | ≤ 256–512 tokens; if longer, window around flagged lines plus function headers |
| Training | Fine-tune on the same synthetic + dev data with hard negatives; optionally distil from the rules + M1 ensemble; free GPU for training is fine, inference must be CPU |
| Export | ONNX, int8 dynamic quantisation, ONNX Runtime CPU, 1 intra-op thread per worker |
| Trigger | Aggregated risk in gray band (default 0.35–0.65) or analyzer parse failure, and token budget fits |
| **Adoption gate** | Keep only if held-out F1 improves, FPR does not worsen, and p95 stays within target; otherwise ship M1 and document the experiment |
| Failure modes | Overfits templates; slower than budget; truncation hides payload → mitigate with windowing and rule floors |

### 8.5 M4 — CG-Novelty (optional)
| Item | Spec |
|---|---|
| Idea | Train on **benign** feature vectors only (isolation forest or one-class SVM); score "distance from normal code" |
| Use | Adds a small risk bump and routes to gray zone for code unlike anything benign in training — a hedge for **unseen error types** (AEGIS names outlier detection as future work) |
| Evaluation | Leave-one-category-out; must not raise FPR on the benign stress set by more than a set tolerance |
| Risk | High false positives on unusual-but-benign code → keep the bump small and never use it alone to block |

### 8.6 Training data without any LLM
- **Template generators** per category: vary sources, sinks, constants, idioms, languages, surrounding benign boilerplate.
- **Mutation engine:** renaming, aliasing, string splitting, encoding wrappers, dead code, reordering, formatting, embedding shell inside Python strings, wrapping in functions/classes.
- **Hard-benign generator:** the 12 dev benign patterns varied (parameterised SQL, `literal_eval`, validated `setattr`, `crontab -l`, bounded pools, pinned packages, prose with fake passwords, allow-listed partner API).
- **Public benign corpora** (e.g., HumanEval/MBPP-style solutions; check licences) used **only as a false-positive stress test**, as RESULTS.md does.
- **Sealed adversarial set:** ~40 snippets written by the teammate who did not write the rules; touch once.
- **No verbatim copying** of public attack datasets; reference rule sets for ideas only; disclose any AI coding assistance.

### 8.7 MLOps essentials
Seeds fixed; dataset and model hashes recorded; `training/` scripts reproduce artifacts; model card per model; versions surfaced in responses; shadow-mode evaluation before swapping models; rollback by redeploying the previous image.

---

## 9. Suggestions — what else can be done

**Do first (cheap, high payoff)**
1. Capability table + source/sink taint core; every rule written against capabilities, not API names.
2. Benign look-alike suite wired into CI from hour 1 (precision protection).
3. FPR stress test on a large public benign corpus.
4. Leave-one-category-out and mutation-set evaluation to estimate behaviour on unseen errors.
5. Always return explanations and original-numbered `vulnerable_lines`.

**Differentiators**
6. **Session-aware risk:** optional `session_id` lets the engine remember a sensitive read in step 1 and flag a network send in step 2 (multi-step attacks; AEGIS lists cross-agent cascades as future work).
7. **Machine-readable remediation** for the calling agent (blocked rule id, offending lines, safe-alternative hint) so the agent can self-correct without an LLM in the guard.
8. **Tamper-evident audit:** hash-chained records (SHA-256 over previous hash) with optional signing — cheap to build and impressive.
9. **Policy profiles** per agent type (data analyst, DevOps, web agent): different allow-lists and thresholds, `enforce`/`monitor` modes.
10. **Runtime backstop** in the SDK executor (timeouts, rlimits, no network) so a missed static finding still can't run unbounded.
11. **Post-tool verification** of outputs before they reach the LLM.
12. **Integrations (P2):** MCP server exposing the guard as a tool, SARIF output for CI, framework adapters.
13. **Telemetry with privacy:** metrics only (verdict, categories, rule ids, latency), never raw code by default.

**Avoid**
- Import blocklists (`subprocess`, `os`) as findings — ast-guard's data shows they produce the most false positives.
- Raw counts (literals, ifs) as primary signals on standalone code.
- Name-only secret flags.
- Allow-list-only grammar as the default (fails on broad benign code).
- Any LLM in the path, including for data generation or feedback.
- Quoting accuracy before measuring it.

---

## 10. Immediate next steps
1. Write the capability table and rule YAML skeleton for all 9 categories (§3).
2. Implement extractor, unwrapper, resolver, constant propagator, taint core.
3. Build the dev-set evaluation runner and the benign look-alike suite.
4. Stand up `/v1/guard`, the fail-closed paths and the interception demo.
5. Build generators + mutation engine; train M1 and M2; run leave-one-category-out.
6. Decide on M3 by the adoption gate; decide on M4 only if time remains.

---

## Sources
- ast-guard README and RESULTS.md (provided).
- Yuan, Su, Zhao. *AEGIS: No Tool Call Left Unchecked — A Pre-Execution Firewall and Audit Layer for AI Agents.* arXiv:2603.12621 (provided).
- Shinde et al. *STELP: Secure Transpilation and Execution of LLM-Generated Programs.* arXiv:2601.05467 (provided).
- MITRE ATT&CK; SANS / CWE Top 25; OWASP Top 10 for LLM Applications; MITRE ATLAS (referenced in the dev rationales and AEGIS).
