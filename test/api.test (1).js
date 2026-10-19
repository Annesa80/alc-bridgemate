process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-that-is-long-enough-for-automated-tests';
process.env.DATABASE_FILE = ':memory:';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const app = require('../src/server');
const { db } = require('../src/db');

async function register(role, phone, name = role) {
  const response = await request(app).post('/api/auth/register').send({
    role, phone, fullName: `${name} User`, password: 'correct-horse-battery-staple', locale: 'ja'
  });
  assert.equal(response.status, 201);
  return response.body;
}

const auth = token => ({ Authorization: `Bearer ${token}` });

test('health endpoint responds', async () => {
  const response = await request(app).get('/api/health');
  assert.equal(response.status, 200);
  assert.equal(response.body.status, 'ok');
});

test('senior, verified helper and consent-based location workflow', async () => {
  const senior = await register('senior', '09000000001', 'Senior');
  const helper = await register('helper', '09000000002', 'Helper');

  db.prepare(`UPDATE helper_profiles SET verification_status='verified',availability=1 WHERE user_id=?`)
    .run(helper.user.id);

  const created = await request(app).post('/api/requests').set(auth(senior.token)).send({
    category: 'ehailing', mode: 'in_person', description: 'Help me book a taxi', priceYen: 1500,
    location: { latitude: 35.6812, longitude: 139.7671 }
  });
  assert.equal(created.status, 201);
  const requestId = created.body.request.id;

  const accepted = await request(app).post(`/api/requests/${requestId}/accept`).set(auth(helper.token));
  assert.equal(accepted.status, 200);

  const deniedLocation = await request(app).put(`/api/requests/${requestId}/location`)
    .set(auth(helper.token)).send({ latitude: 35.68, longitude: 139.76 });
  assert.equal(deniedLocation.status, 403);

  const consent = await request(app).put(`/api/requests/${requestId}/consent/location`)
    .set(auth(senior.token)).send({ granted: true });
  assert.equal(consent.status, 200);

  const location = await request(app).put(`/api/requests/${requestId}/location`)
    .set(auth(helper.token)).send({ latitude: 35.68, longitude: 139.76 });
  assert.equal(location.status, 200);
});

test('job transitions are enforced and completed job can be reviewed once', async () => {
  const senior = await register('senior', '09000000003', 'Second Senior');
  const helper = await register('helper', '09000000004', 'Second Helper');
  db.prepare(`UPDATE helper_profiles SET verification_status='verified',availability=1 WHERE user_id=?`).run(helper.user.id);

  const created = await request(app).post('/api/requests').set(auth(senior.token)).send({
    category: 'other', mode: 'virtual', description: 'Explain a phone setting', priceYen: 900
  });
  const id = created.body.request.id;
  await request(app).post(`/api/requests/${id}/accept`).set(auth(helper.token));

  const invalid = await request(app).patch(`/api/requests/${id}/status`).set(auth(helper.token)).send({ status: 'completed' });
  assert.equal(invalid.status, 409);

  for (const status of ['helping', 'completed']) {
    const response = await request(app).patch(`/api/requests/${id}/status`).set(auth(helper.token)).send({ status });
    assert.equal(response.status, 200);
  }

  const review = await request(app).post(`/api/requests/${id}/review`).set(auth(senior.token)).send({ rating: 5, comment: 'Patient and clear' });
  assert.equal(review.status, 201);
  const duplicate = await request(app).post(`/api/requests/${id}/review`).set(auth(senior.token)).send({ rating: 4 });
  assert.equal(duplicate.status, 409);
});

test.after(() => db.close());
