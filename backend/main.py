"""Fixed-schema HTTP boundary. All submitted source is analyzed statically."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool
from feat_1_scan.analyzer import MAX_BYTES
from feat_1_scan.signals import PROVIDER, text_injection
from feat_2_results.explain import decision_detail
from feat_6_runtime.audit import AuditQueue, verify_chain
from feat_6_runtime.contract import FIELDS, blocked, valid
from feat_6_runtime.runtime import scan, ENGINE_VERSION
from feat_6_runtime.versions import RULES_VERSION, POLICY_VERSION, MODEL_VERSION
from feat_6_runtime.metrics import Metrics
from feat_7_governance import feedback
from feat_7_governance.catalogue import catalogue
from feat_7_governance.report import model_card, policy, rai_report

SCAN_DEADLINE_MS = 25
# JSON escaping can expand each source byte up to six bytes.
MAX_BODY_BYTES = MAX_BYTES * 6 + 1024
MAX_BATCH_BYTES = 4 * 1024 * 1024
BODY_TIMEOUT_SECONDS = 5


@asynccontextmanager
async def lifespan(app):
    app.state.ready = False
    app.state.audit.start()
    try:
        result = await run_in_threadpool(scan, 'value = 1')
        app.state.ready = (valid(result, 1) and result['verdict'] == 'allow'
                           and result.get('analysis_complete') is True)
    except Exception:
        app.state.ready = False
    try:
        yield
    finally:
        app.state.ready = False
        await run_in_threadpool(app.state.audit.close)


app = FastAPI(title='CodeGuard', version=ENGINE_VERSION, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)
app.state.ready = False
app.state.audit = AuditQueue()
app.state.metrics = Metrics()
app.state.latest_live_scan = None


def full_detail(request):
    return (request.query_params.get('detail') == 'full'
            or request.query_params.get('trace') == '1'
            or request.headers.get('X-CodeGuard-Detail') == 'full')


def response_for(request, result, status=200):
    degraded = bool(result.get('degraded') or result.get('analysis_complete') is False)
    if degraded:
        result = {**result, 'verdict': 'block', 'degraded': True}
    payload = {key: result[key] for key in FIELDS}
    if full_detail(request):
        payload = {**result, **decision_detail(result), 'degraded': degraded,
                   'request_id': request.state.request_id, 'engine_version': ENGINE_VERSION,
                   'rules_version': RULES_VERSION, 'policy_version': POLICY_VERSION,
                   'model_version': MODEL_VERSION}
    return JSONResponse(payload, status_code=status, headers={
        'X-CodeGuard-Degraded': '1' if degraded else '0',
        'X-CodeGuard-Cache': result.get('cache_status', 'not-used')})


@app.middleware('http')
async def request_metadata(request, call_next):
    started = perf_counter()
    request.state.request_id = str(uuid4())
    try:
        response = await call_next(request)
    except Exception:
        if request.url.path not in ('/v1/guard', '/v1/guard/batch'):
            raise
        response = response_for(request, blocked('Analysis failed; no execution is authorized.'))
    duration_ms = (perf_counter() - started) * 1000
    if request.url.path in ('/v1/guard', '/v1/guard/batch'):
        app.state.metrics.observe(duration_ms,
            response.headers.get('X-CodeGuard-Degraded') == '1',
            response.headers.get('X-CodeGuard-Cache') == 'hit')
    response.headers.update({'X-Request-Id': request.state.request_id,
        'X-Engine-Version': ENGINE_VERSION, 'X-Rules-Version': RULES_VERSION,
        'X-Policy-Version': POLICY_VERSION, 'X-Model-Version': MODEL_VERSION,
        'X-CodeGuard-Server-Ms': f'{duration_ms:.3f}'})
    # Explicit metadata projection: never store raw code, evidence, or reasons.
    event = {'event': 'http_request', 'request_id': request.state.request_id,
             'timestamp': datetime.now(timezone.utc).isoformat(),
             'route': request.scope.get('route').path if request.scope.get('route') else 'unmatched',
             'status': response.status_code, 'engine_version': ENGINE_VERSION,
             'rules_version': RULES_VERSION, 'policy_version': POLICY_VERSION,
             'decision': getattr(request.state, 'decision', None)}
    try:
        queued = app.state.audit.enqueue(event)
    except Exception:
        queued = False
    response.headers['X-CodeGuard-Audit'] = 'queued' if queued else 'dropped'
    return response


class IntakeError(Exception):
    def __init__(self, message, status):
        self.message, self.status = message, status


async def read_payload(request, limit):
    content_type = request.headers.get('content-type', '')
    if 'multipart/form-data' in content_type:
        try:
            form = await request.form()
            file_obj = form.get('file') or form.get('dataset')
            if file_obj:
                raw = await file_obj.read()
                text = raw.decode('utf-8', errors='replace')
            else:
                raise IntakeError('No file attached in form upload.', 400)
        except IntakeError:
            raise
        except Exception:
            raise IntakeError('Error reading uploaded form file.', 400)
    else:
        try:
            async with asyncio.timeout(BODY_TIMEOUT_SECONDS):
                body = bytearray()
                async for chunk in request.stream():
                    if len(body) + len(chunk) > limit:
                        raise IntakeError('Request exceeds configured size limit.', 413)
                    body.extend(chunk)
                text = body.decode('utf-8')
        except IntakeError:
            raise
        except TimeoutError:
            raise IntakeError('Request intake timed out; analysis unavailable.', 200)
        except (ValueError, UnicodeError, RecursionError):
            raise IntakeError('Invalid JSON or UTF-8 input.', 400)

    text = text.strip()
    if not text:
        raise IntakeError('Empty request payload.', 400)

    # 1. Standard JSON (dict or list)
    try:
        val = json.loads(text, parse_constant=lambda _: None)
        return val
    except Exception:
        pass

    # 2. JSON Lines (JSONL)
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            lines.append(json.loads(line))
        except Exception:
            continue
    if lines:
        return lines

    raise IntakeError('Invalid JSON, JSONL, or file input.', 400)


async def read_json(request, limit):
    try:
        async with asyncio.timeout(BODY_TIMEOUT_SECONDS):
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > limit:
                    raise IntakeError('Request exceeds the configured size limit.', 413)
                body.extend(chunk)
            value = json.loads(body.decode('utf-8'), parse_constant=lambda _: None)
            if not isinstance(value, dict):
                raise IntakeError('Expected a JSON object.', 400)
            return value
    except IntakeError:
        raise
    except TimeoutError:
        raise IntakeError('Request intake timed out; analysis unavailable.', 200)
    except (ValueError, UnicodeError, RecursionError):
        raise IntakeError('Invalid JSON or UTF-8 input.', 400)


def validate_code(code):
    if not isinstance(code, str) or not code.strip():
        raise IntakeError('Provide non-empty source code as a string.', 400)
    try:
        if len(code.encode('utf-8')) > MAX_BYTES:
            raise IntakeError('Source exceeds the 64 KiB limit.', 413)
    except UnicodeError:
        raise IntakeError('Source contains invalid Unicode.', 400)
    return code


def analyze_request(code, session_id=None):
    started = perf_counter()
    try:
        result = scan(code, session_id=session_id)
        if (perf_counter() - started) * 1000 > SCAN_DEADLINE_MS:
            return blocked('Analysis deadline exceeded; no execution is authorized.')
        if not valid(result, len(code.splitlines()) or 1):
            return blocked('Invalid engine response; no execution is authorized.')
        if result.get('analysis_complete') is not True or result.get('degraded'):
            return {**result, 'verdict': 'block', 'degraded': True}
        return result
    except Exception:
        return blocked('Analysis could not complete; no execution is authorized.')


def audit_decision(code, result):
    return {'code_sha256': sha256(code.encode()).hexdigest(), 'code_bytes': len(code.encode()),
            'verdict': result['verdict'], 'risk_score': result['risk_score'],
            'categories': result['categories'], 'degraded': result.get('degraded', False)}


@app.get('/')
@app.get('/health')
@app.get('/healthz')
def health():
    return {'status': 'alive', 'ready': app.state.ready, 'engine_version': ENGINE_VERSION, 'mode': 'local baseline', 'llm_calls': 0}


@app.get('/readyz')
def ready():
    return JSONResponse({'ready': app.state.ready, 'engine_version': ENGINE_VERSION},
                        status_code=200 if app.state.ready else 503)


@app.get('/metrics')
def metrics():
    return PlainTextResponse(app.state.metrics.render() + ''.join(f'codeguard_audit_{key} {value}\n'
        for key, value in app.state.audit.stats().items()), media_type='text/plain; version=0.0.4')


@app.post('/guard')
@app.post('/v1/guard')
async def guard(request: Request):
    try:
        body = await read_json(request, MAX_BODY_BYTES)
        code = validate_code(body.get('code'))
        session_id = body.get('session_id') or request.headers.get('X-CodeGuard-Session-ID')
        if session_id is not None and (not isinstance(session_id, str) or len(session_id) > 128):
            session_id = None
    except IntakeError as error:
        return response_for(request, blocked(error.message), error.status)
    result = await run_in_threadpool(analyze_request, code, session_id)
    request.state.decision = audit_decision(code, result)
    if body.get('source') == 'vscode' or request.headers.get('X-CodeGuard-Source') == 'vscode':
        app.state.latest_live_scan = {
            'active': True,
            'filename': body.get('filename', 'editor.py'),
            'code': code,
            'result': {**result, **decision_detail(result)},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    return response_for(request, result)


@app.get('/v1/live/latest')
def get_latest_live_scan():
    """Returns the most recent scan pushed from VS Code or external IDE."""
    return getattr(app.state, 'latest_live_scan', None) or {'active': False}


@app.post('/batch')
@app.post('/guard/batch')
@app.post('/v1/guard/batch')
async def batch_guard(request: Request):
    try:
        raw_input = await read_payload(request, MAX_BATCH_BYTES)
        if isinstance(raw_input, list):
            items = raw_input
        elif isinstance(raw_input, dict):
            items = raw_input.get('items')
            if items is None:
                items = raw_input.get('snippets', raw_input.get('codes', raw_input.get('dataset', raw_input.get('samples'))))
            if items is None and 'code' in raw_input:
                items = [raw_input]
        else:
            items = None
        if not isinstance(items, list) or not 1 <= len(items) <= 500:
            raise IntakeError('Provide between 1 and 500 batch items.', 400)
    except IntakeError as error:
        return response_for(request, blocked(error.message), error.status)
    results, decisions = [], []
    degraded = False
    for idx, item in enumerate(items):
        item_id = item.get('id') if isinstance(item, dict) else None
        if item_id is None and isinstance(item, dict) and 'code' in item:
            item_id = str(idx)
        elif item_id is None and isinstance(item, str):
            item = {'code': item}
            item_id = str(idx)
        elif not isinstance(item_id, str) or not 1 <= len(item_id) <= 128:
            item_id = None
        try:
            if item_id is None:
                raise IntakeError('Batch item requires a string id of at most 128 characters.', 400)
            code = validate_code(item.get('code'))
            item_session = item.get('session_id') if isinstance(item, dict) else None
            result = await run_in_threadpool(analyze_request, code, item_session)
            decisions.append(audit_decision(code, result))
        except IntakeError as error:
            result = blocked(error.message)
        degraded |= bool(result.get('degraded') or result.get('analysis_complete') is False)
        payload = json.loads(response_for(request, result).body)
        results.append({'id': item_id, **payload})
    request.state.decision = {'batch': decisions}
    return JSONResponse({'results': results}, headers={'X-CodeGuard-Degraded': '1' if degraded else '0'})


@app.post('/v1/guard/file')
@app.post('/v1/evaluate/file')
async def guard_file(request: Request):
    """
    Ingests an entire JSON/JSONL dataset file (via raw body or multipart form-data upload),
    evaluates every code snippet, and returns complete XAI insights, decision cards,
    all 17 pipeline execution steps, vulnerable lines, Noisy-OR traces, ML probabilities,
    and aggregate dataset performance metrics.
    """
    try:
        raw_input = await read_payload(request, MAX_BATCH_BYTES)
        if isinstance(raw_input, list):
            items = raw_input
        elif isinstance(raw_input, dict):
            items = raw_input.get('items')
            if items is None:
                items = raw_input.get('snippets', raw_input.get('codes', raw_input.get('dataset', raw_input.get('samples'))))
            if items is None and 'code' in raw_input:
                items = [raw_input]
        else:
            items = None
        if not isinstance(items, list) or not 1 <= len(items) <= 500:
            raise IntakeError('Provide between 1 and 500 batch items in uploaded dataset.', 400)
    except IntakeError as error:
        return JSONResponse({'error': error.message}, status_code=error.status)

    results = []
    latencies = []
    category_counts = {}
    vulnerable_lines_total = 0
    allow_count = 0
    block_count = 0
    degraded_count = 0
    tp = fp = tn = fn = 0
    has_ground_truth = False

    for idx, item in enumerate(items):
        item_id = item.get('id') if isinstance(item, dict) else str(idx)
        if not isinstance(item_id, str):
            item_id = str(idx)

        label = item.get('label') if isinstance(item, dict) else None
        expected_cat = item.get('category') if isinstance(item, dict) else None

        t0 = perf_counter()
        try:
            code = validate_code(item.get('code') if isinstance(item, dict) else item)
            item_session = item.get('session_id') if isinstance(item, dict) else None
            result = await run_in_threadpool(analyze_request, code, item_session)
        except IntakeError as error:
            result = blocked(error.message)

        elapsed_ms = round((perf_counter() - t0) * 1000, 3)
        latencies.append(elapsed_ms)

        is_degraded = bool(result.get('degraded') or result.get('analysis_complete') is False)
        if is_degraded:
            degraded_count += 1
            result['verdict'] = 'block'
            result['degraded'] = True

        verdict = result.get('verdict', 'block')
        if verdict == 'allow':
            allow_count += 1
        else:
            block_count += 1

        vulnerable_lines_total += len(result.get('vulnerable_lines', []))
        for cat in result.get('categories', []):
            category_counts[cat] = category_counts.get(cat, 0) + 1

        if label is not None:
            has_ground_truth = True
            expected = 'block' if label == 1 else 'allow'
            if expected == 'block' and verdict == 'block':
                tp += 1
            elif expected == 'allow' and verdict == 'block':
                fp += 1
            elif expected == 'allow' and verdict == 'allow':
                tn += 1
            elif expected == 'block' and verdict == 'allow':
                fn += 1

        detailed_item = {
            'id': item_id,
            'verdict': verdict,
            'risk_score': result.get('risk_score', 0.0),
            'categories': result.get('categories', []),
            'code_language': result.get('code_language', 'unknown'),
            'reason': result.get('reason', ''),
            'vulnerable_lines': result.get('vulnerable_lines', []),
            'analysis_complete': result.get('analysis_complete', True),
            'degraded': is_degraded,
            'latency_ms': elapsed_ms,
            'findings': result.get('findings', []),
            'decision_cards': decision_detail(result).get('decision_cards', []),
            'score_trace': result.get('score_trace', {}),
            'runtime_trace': decision_detail(result).get('runtime_trace', []),
            'audit_meta': {
                'code_sha256': sha256(item.get('code', '').encode('utf-8', errors='replace')).hexdigest() if isinstance(item, dict) and 'code' in item else None,
                'code_bytes': len(item.get('code', '').encode('utf-8', errors='replace')) if isinstance(item, dict) and 'code' in item else 0,
            }
        }
        if label is not None:
            detailed_item['ground_truth'] = {'label': label, 'expected': 'block' if label == 1 else 'allow', 'category': expected_cat}

        results.append(detailed_item)

    sorted_lat = sorted(latencies)
    pct = lambda q: sorted_lat[max(0, math.ceil(len(sorted_lat) * q) - 1)] if sorted_lat else 0.0

    summary = {
        'total_samples': len(results),
        'allowed_count': allow_count,
        'blocked_count': block_count,
        'degraded_count': degraded_count,
        'total_vulnerable_lines': vulnerable_lines_total,
        'category_breakdown': category_counts,
        'latencies_ms': {
            'total': round(sum(latencies), 3),
            'avg': round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            'p50': round(pct(0.50), 3),
            'p95': round(pct(0.95), 3),
            'p99': round(pct(0.99), 3),
        }
    }

    if has_ground_truth:
        total_eval = tp + fp + tn + fn
        accuracy = round((tp + tn) / total_eval, 4) if total_eval else 0.0
        precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
        f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
        summary['ground_truth_metrics'] = {
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'fpr': fpr
        }

    return JSONResponse({'summary': summary, 'results': results})


@app.post('/v1/evaluation')
def evaluate_public_set():
    from feat_5_evaluation.evaluate import RUN_LOCK, run_evaluation
    if not RUN_LOCK.acquire(blocking=False):
        raise HTTPException(409, 'An evaluation is already running in this process.')
    try:
        return run_evaluation()
    except (OSError, ValueError, KeyError) as error:
        raise HTTPException(503, 'The bundled evaluation dataset is unavailable or invalid.') from error
    finally:
        RUN_LOCK.release()


@app.get('/v1/rules')
def rules():
    items = catalogue()
    return {'rules_version': RULES_VERSION, 'count': len(items), 'rules': items}


@app.get('/v1/policy')
def get_policy():
    return policy()


@app.get('/v1/audit/verify')
def audit_verify():
    return verify_chain()


@app.get('/v1/rai/report')
def responsible_ai():
    return rai_report(app.state.metrics.snapshot(), app.state.audit.stats())


@app.get('/v1/docs/model-card')
def get_model_card():
    return model_card()


@app.post('/v1/verify-output')
async def verify_output(request: Request):
    """Post-tool checkpoint: scan tool output before it is fed back to an LLM."""
    try:
        body = await read_json(request, MAX_BODY_BYTES)
        text = body.get('output', body.get('code'))
        if not isinstance(text, str) or not text.strip():
            raise IntakeError('Provide non-empty tool output as a string.', 400)
        if len(text.encode('utf-8')) > MAX_BYTES:
            raise IntakeError('Output exceeds the 64 KiB limit.', 413)
    except IntakeError as error:
        return JSONResponse({'verdict': 'block', 'categories': [], 'reason': error.message,
                             'code_language': 'text', 'degraded': True}, status_code=error.status)
    findings = []
    if text_injection(text):
        findings.append({'rule_id': 'CG-AIT-001', 'category': 'ai_targeted_instructions',
                         'line': 1, 'why': 'Tool output contains instructions aimed at an AI reader.'})
    match = PROVIDER.search(text)
    if match:
        line = text[:match.start()].count('\n') + 1
        findings.append({'rule_id': 'CG-SEC-001', 'category': 'secret_access', 'line': line,
                         'why': 'Tool output contains a provider-format credential.'})
    categories = sorted({f['category'] for f in findings})
    payload = {
        'verdict': 'block' if findings else 'allow',
        'categories': categories,
        'code_language': 'text',
        'reason': ('Tool output is unsafe to forward: ' + '; '.join(f['why'] for f in findings))
                  if findings else 'No injected instructions or leaked provider credentials found.',
        'findings': findings,
        'request_id': request.state.request_id,
    }
    return JSONResponse(payload)


@app.post('/v1/feedback')
async def submit_feedback(request: Request):
    try:
        body = await read_json(request, 256 * 1024)
        record = feedback.submit(body.get('request_id'), body.get('kind'),
                                 body.get('note', ''), body.get('code'))
    except IntakeError as error:
        raise HTTPException(error.status, error.message)
    except ValueError as error:
        raise HTTPException(400, str(error))
    return JSONResponse(record, status_code=201)


@app.get('/v1/feedback')
def feedback_summary():
    return feedback.summary()


@app.get('/v1/docs/decisions')
def design_decisions():
    from feat_7_governance.docs import decisions
    return decisions()


@app.get('/v1/demo/intercept')
def latest_intercept_result():
    from feat_7_governance.docs import intercept_result
    return intercept_result()
