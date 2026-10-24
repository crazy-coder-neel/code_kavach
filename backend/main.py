"""Fixed-schema HTTP boundary. All submitted source is analyzed statically."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool
from feat_1_scan.analyzer import MAX_BYTES
from feat_6_runtime.audit import AuditQueue
from feat_6_runtime.contract import FIELDS, blocked, valid
from feat_6_runtime.runtime import scan, ENGINE_VERSION
from feat_6_runtime.versions import RULES_VERSION, POLICY_VERSION, MODEL_VERSION
from feat_6_runtime.metrics import Metrics

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
app.state.ready = False
app.state.audit = AuditQueue()
app.state.metrics = Metrics()


def full_detail(request):
    return (request.query_params.get('detail') == 'full'
            or request.headers.get('X-CodeGuard-Detail') == 'full')


def response_for(request, result, status=200):
    degraded = bool(result.get('degraded') or result.get('analysis_complete') is False)
    if degraded:
        result = {**result, 'verdict': 'block', 'degraded': True}
    payload = {key: result[key] for key in FIELDS}
    if full_detail(request):
        payload = {**result, 'degraded': degraded,
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


def analyze_request(code):
    started = perf_counter()
    try:
        result = scan(code)
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


@app.get('/healthz')
def health():
    return {'status': 'alive', 'engine_version': ENGINE_VERSION, 'mode': 'local baseline', 'llm_calls': 0}


@app.get('/readyz')
def ready():
    return JSONResponse({'ready': app.state.ready, 'engine_version': ENGINE_VERSION},
                        status_code=200 if app.state.ready else 503)


@app.get('/metrics')
def metrics():
    return PlainTextResponse(app.state.metrics.render() + ''.join(f'codeguard_audit_{key} {value}\n'
        for key, value in app.state.audit.stats().items()), media_type='text/plain; version=0.0.4')


@app.post('/v1/guard')
async def guard(request: Request):
    try:
        body = await read_json(request, MAX_BODY_BYTES)
        code = validate_code(body.get('code'))
    except IntakeError as error:
        return response_for(request, blocked(error.message), error.status)
    result = await run_in_threadpool(analyze_request, code)
    request.state.decision = audit_decision(code, result)
    return response_for(request, result)


@app.post('/v1/guard/batch')
async def batch_guard(request: Request):
    try:
        body = await read_json(request, MAX_BATCH_BYTES)
        items = body.get('items')
        if not isinstance(items, list) or not 1 <= len(items) <= 500:
            raise IntakeError('Provide between 1 and 500 batch items.', 400)
    except IntakeError as error:
        return response_for(request, blocked(error.message), error.status)
    results, decisions = [], []
    degraded = False
    for item in items:
        item_id = item.get('id') if isinstance(item, dict) else None
        if not isinstance(item_id, str) or not 1 <= len(item_id) <= 128:
            item_id = None
        try:
            if item_id is None:
                raise IntakeError('Batch item requires a string id of at most 128 characters.', 400)
            code = validate_code(item.get('code'))
            result = await run_in_threadpool(analyze_request, code)
            decisions.append(audit_decision(code, result))
        except IntakeError as error:
            result = blocked(error.message)
        degraded |= bool(result.get('degraded') or result.get('analysis_complete') is False)
        payload = json.loads(response_for(request, result).body)
        results.append({'id': item_id, **payload})
    request.state.decision = {'batch': decisions}
    return JSONResponse({'results': results}, headers={'X-CodeGuard-Degraded': '1' if degraded else '0'})


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
