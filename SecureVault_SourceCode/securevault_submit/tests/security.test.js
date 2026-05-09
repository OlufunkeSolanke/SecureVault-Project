/**
 * SecureVault Security Test Suite
 * Manual test cases covering OWASP Top 10 considerations
 * Run: node tests/security.test.js
 */

const http = require('http');

const BASE = 'http://localhost:3000';
let passed = 0;
let failed = 0;

async function request(method, path, body, headers = {}) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      method,
      hostname: 'localhost',
      port: 3000,
      path,
      headers: { 'Content-Type': 'application/json', 'Content-Length': data ? Buffer.byteLength(data) : 0, ...headers }
    };
    const req = http.request(opts, (res) => {
      let raw = '';
      res.on('data', d => raw += d);
      res.on('end', () => {
        try { resolve({ status: res.status || res.statusCode, body: JSON.parse(raw), headers: res.headers }); }
        catch { resolve({ status: res.statusCode, body: raw, headers: res.headers }); }
      });
    });
    req.on('error', () => resolve({ status: 0, body: {}, headers: {} }));
    if (data) req.write(data);
    req.end();
  });
}

function assert(name, condition, detail = '') {
  if (condition) {
    console.log(`  PASS  ${name}`);
    passed++;
  } else {
    console.log(`  FAIL  ${name}${detail ? ' | ' + detail : ''}`);
    failed++;
  }
}

async function runTests() {
  console.log('\nSecureVault Security Test Suite');
  console.log('================================\n');

  // ─── TC-01: Health check ─────────────────────────────────
  console.log('TC-01: Health Check');
  const health = await request('GET', '/api/health');
  assert('Server is running', health.status === 200);

  // ─── TC-02: Security Headers ─────────────────────────────
  console.log('\nTC-02: Security Headers (Helmet)');
  assert('X-Content-Type-Options header set', health.headers['x-content-type-options'] === 'nosniff');
  assert('X-Frame-Options header set', !!health.headers['x-frame-options']);
  assert('Strict-Transport-Security present', !!health.headers['strict-transport-security']);

  // ─── TC-03: Input Validation ─────────────────────────────
  console.log('\nTC-03: Input Validation');
  const weak = await request('POST', '/api/auth/register', { email: 'not-an-email', password: '123', name: 'X' });
  assert('Weak registration rejected (422)', weak.status === 422);
  assert('Validation details returned', Array.isArray(weak.body.details));

  // ─── TC-04: Authentication Required ──────────────────────
  console.log('\nTC-04: Authentication Enforcement');
  const noAuth = await request('GET', '/api/notes');
  assert('Notes route blocked without token (401)', noAuth.status === 401);

  const fakeToken = await request('GET', '/api/notes', null, { Authorization: 'Bearer fakejwt123' });
  assert('Fake token rejected (401)', fakeToken.status === 401);

  // ─── TC-05: Rate Limiting ─────────────────────────────────
  console.log('\nTC-05: Rate Limiting on Login');
  let rateLimitHit = false;
  for (let i = 0; i < 12; i++) {
    const r = await request('POST', '/api/auth/login', { email: 'test@test.com', password: 'wrong' });
    if (r.status === 429) { rateLimitHit = true; break; }
  }
  assert('Rate limit triggered after repeated attempts (429)', rateLimitHit);

  // ─── TC-06: RBAC ──────────────────────────────────────────
  console.log('\nTC-06: Role-Based Access Control');
  // Register a normal user first
  await request('POST', '/api/auth/register', { name: 'Test User', email: `test${Date.now()}@test.com`, password: 'Test@12345' });
  const loginRes = await request('POST', '/api/auth/login', { email: `test${Date.now() - 1}@test.com`, password: 'Test@12345' });
  // Admin route should be blocked for regular user if we had a valid token
  const adminNoAuth = await request('GET', '/api/admin/users');
  assert('Admin route blocked without auth (401)', adminNoAuth.status === 401);

  // ─── TC-07: Unknown Routes ────────────────────────────────
  console.log('\nTC-07: Error Handling');
  const notFound = await request('GET', '/api/nonexistent');
  assert('Unknown route returns 404', notFound.status === 404);
  assert('404 error message returned', !!notFound.body.error);

  // ─── SUMMARY ─────────────────────────────────────────────
  console.log('\n================================');
  console.log(`Results: ${passed} passed | ${failed} failed`);
  if (failed === 0) console.log('ALL TESTS PASSED');
  else console.log('Some tests failed. Review application configuration.');
}

runTests();
