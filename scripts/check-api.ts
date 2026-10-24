import assert from 'node:assert/strict';
import { normalizeGuardResponse, scanCode } from '../src/lib/api/guard';
import { apiClient } from '../src/lib/api/client';

const allowed = { verdict: 'allow', risk_score: 0, categories: [], code_language: 'python', reason: 'No findings', vulnerable_lines: [], analysis_complete: true, latency_ms: 0, engine_version: 'test' };
assert.equal(normalizeGuardResponse(allowed).verdict, 'ALLOW');
assert.equal(normalizeGuardResponse(allowed).metadata?.duration_ms, 0);
assert.equal(normalizeGuardResponse({ ...allowed, verdict: 'block', analysis_complete: false }).metadata?.parser_status, 'FALLBACK');
for (const invalid of [{}, { ...allowed, verdict: 'unexpected' }, { ...allowed, risk_score: 2 }, { ...allowed, vulnerable_lines: [-1] }]) {
  assert.throws(() => normalizeGuardResponse(invalid));
}
const blocked = normalizeGuardResponse({ ...allowed, verdict: 'block', findings: [{ category: 'secret_access', rule_id: 'CG-SECRET', severity: 'high', lines: [2, 4], title: 'Secret access', why: 'Sensitive source', evidence: 'key = read_secret()', remediation: 'Remove access' }] });
assert.equal(blocked.findings?.[0].line_number, 2);
assert.equal(blocked.findings?.[0].end_line_number, 4);
assert.equal(blocked.findings?.[0].snippet, 'key = read_secret()');
assert.equal(apiClient.getConfig().useMock, false);
globalThis.fetch = async (url, options) => {
  assert.equal(url, '/v1/guard?detail=full');
  assert.deepEqual(JSON.parse(String(options?.body)), { code: 'value = 1' });
  return new Response(JSON.stringify(allowed));
};
assert.equal((await scanCode({ code: 'value = 1', code_language: 'python' })).verdict, 'ALLOW');
globalThis.fetch = async () => new Response('Unavailable', { status: 503 });
await assert.rejects(scanCode({ code: 'value = 1', code_language: 'python' }));
console.log('API mapping, live route, malformed response, and error handling checks passed.');
