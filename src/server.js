require('dotenv').config();

const path = require('node:path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { z } = require('zod');
const { db, migrate, transaction } = require('./db');
const { hashPassword, verifyPassword, signToken, authenticate, allowRoles } = require('./auth');

migrate();
const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CLIENT_ORIGIN || true, credentials: false }));
app.use(express.json({ limit: '100kb' }));
app.use(morgan(process.env.NODE_ENV === 'test' ? 'tiny' : 'combined'));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 50 }));

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const now = () => new Date().toISOString();
const getUser = (id) => db.prepare('SELECT id, role, full_name, phone, email, locale, created_at FROM users WHERE id = ?').get(id);
const safeJson = (value, fallback = {}) => { try { return JSON.parse(value); } catch { return fallback; } };

function parse(schema, input) {
  const result = schema.safeParse(input);
  if (!result.success) {
    const error = new Error('Validation failed');
    error.status = 400;
    error.details = result.error.flatten();
    throw error;
  }
  return result.data;
}

function notify(userId, type, title, body, data = {}) {
  db.prepare(`INSERT INTO notifications (user_id,type,title,body,data_json) VALUES (?,?,?,?,?)`)
    .run(userId, type, title, body, JSON.stringify(data));
}

function requestById(id) {
  return db.prepare(`SELECT r.*, s.full_name senior_name, h.full_name helper_name
    FROM service_requests r
    JOIN users s ON s.id=r.senior_id
    LEFT JOIN users h ON h.id=r.helper_id WHERE r.id=?`).get(id);
}

function assertRequestAccess(request, auth) {
  if (!request) { const e = new Error('Request not found'); e.status = 404; throw e; }
  if (auth.role === 'admin' || [request.senior_id, request.requested_by, request.helper_id].includes(Number(auth.sub))) return;
  const link = db.prepare(`SELECT 1 FROM family_links WHERE senior_id=? AND family_id=? AND status='accepted'`)
    .get(request.senior_id, auth.sub);
  if (!link) { const e = new Error('Not permitted to access this request'); e.status = 403; throw e; }
}

app.get('/api/health', (req, res) => res.json({ status: 'ok', service: 'bridgemate-api', time: now() }));

const registerSchema = z.object({
  role: z.enum(['senior', 'helper', 'family']),
  fullName: z.string().trim().min(2).max(100),
  phone: z.string().trim().min(8).max(30),
  email: z.string().email().optional(),
  password: z.string().min(10).max(128),
  locale: z.enum(['ja', 'en', 'zh', 'ms', 'ta']).default('ja')
});

app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const body = parse(registerSchema, req.body);
  try {
    const result = transaction(() => {
      const row = db.prepare(`INSERT INTO users (role,full_name,phone,email,password_hash,locale)
        VALUES (?,?,?,?,?,?)`).run(body.role, body.fullName, body.phone, body.email || null,
          hashPassword(body.password), body.locale);
      if (body.role === 'helper') db.prepare('INSERT INTO helper_profiles (user_id) VALUES (?)').run(row.lastInsertRowid);
      return getUser(row.lastInsertRowid);
    });
    res.status(201).json({ user: result, token: signToken(result) });
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) return res.status(409).json({ error: 'Phone or email already registered' });
    throw error;
  }
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const body = parse(z.object({ phone: z.string().min(8), password: z.string().min(1) }), req.body);
  const user = db.prepare('SELECT * FROM users WHERE phone=?').get(body.phone);
  if (!user || !verifyPassword(body.password, user.password_hash)) return res.status(401).json({ error: 'Invalid phone or password' });
  const publicUser = getUser(user.id);
  res.json({ user: publicUser, token: signToken(publicUser) });
}));

app.get('/api/me', authenticate, (req, res) => {
  const user = getUser(req.auth.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const helperProfile = user.role === 'helper'
    ? db.prepare('SELECT * FROM helper_profiles WHERE user_id=?').get(user.id)
    : null;
  res.json({ user, helperProfile: helperProfile && { ...helperProfile, skills: safeJson(helperProfile.skills_json, []) } });
});

app.patch('/api/me', authenticate, asyncRoute(async (req, res) => {
  const body = parse(z.object({
    fullName: z.string().trim().min(2).max(100).optional(),
    locale: z.enum(['ja', 'en', 'zh', 'ms', 'ta']).optional()
  }).refine(v => Object.keys(v).length > 0), req.body);
  const current = getUser(req.auth.sub);
  db.prepare('UPDATE users SET full_name=?, locale=? WHERE id=?')
    .run(body.fullName || current.full_name, body.locale || current.locale, req.auth.sub);
  res.json({ user: getUser(req.auth.sub) });
}));

app.patch('/api/helpers/me', authenticate, allowRoles('helper'), asyncRoute(async (req, res) => {
  const body = parse(z.object({
    bio: z.string().max(500).optional(),
    skills: z.array(z.enum(['smartphone', 'banking_guidance', 'government_forms', 'delivery', 'health_booking', 'transport'])).max(10).optional(),
    availability: z.boolean().optional(),
    latitude: z.number().gte(-90).lte(90).optional(),
    longitude: z.number().gte(-180).lte(180).optional()
  }), req.body);
  const old = db.prepare('SELECT * FROM helper_profiles WHERE user_id=?').get(req.auth.sub);
  db.prepare(`UPDATE helper_profiles SET bio=?,skills_json=?,availability=?,latitude=?,longitude=?,updated_at=? WHERE user_id=?`)
    .run(body.bio ?? old.bio, JSON.stringify(body.skills ?? safeJson(old.skills_json, [])),
      body.availability === undefined ? old.availability : Number(body.availability),
      body.latitude ?? old.latitude, body.longitude ?? old.longitude, now(), req.auth.sub);
  res.json({ helperProfile: db.prepare('SELECT * FROM helper_profiles WHERE user_id=?').get(req.auth.sub) });
}));

app.post('/api/helpers/verification', authenticate, allowRoles('helper'), asyncRoute(async (req, res) => {
  const body = parse(z.object({
    idDocumentRef: z.string().min(3).max(500), selfieRef: z.string().min(3).max(500),
    addressDocumentRef: z.string().min(3).max(500), employmentStatus: z.string().max(100).optional()
  }), req.body);
  const row = db.prepare(`INSERT INTO verification_submissions
    (helper_id,id_document_ref,selfie_ref,address_document_ref,employment_status) VALUES (?,?,?,?,?)`)
    .run(req.auth.sub, body.idDocumentRef, body.selfieRef, body.addressDocumentRef, body.employmentStatus || null);
  db.prepare(`UPDATE helper_profiles SET verification_status='pending', availability=0 WHERE user_id=?`).run(req.auth.sub);
  res.status(201).json({ id: row.lastInsertRowid, status: 'pending' });
}));

app.get('/api/helpers', authenticate, asyncRoute(async (req, res) => {
  const rows = db.prepare(`SELECT u.id,u.full_name,p.bio,p.skills_json,p.rating,p.completed_jobs,p.latitude,p.longitude
    FROM users u JOIN helper_profiles p ON p.user_id=u.id
    WHERE p.verification_status='verified' AND p.availability=1 ORDER BY p.rating DESC, p.completed_jobs DESC LIMIT 50`).all();
  res.json({ helpers: rows.map(h => ({ ...h, skills: safeJson(h.skills_json, []) })) });
}));

app.post('/api/family-links/invite', authenticate, allowRoles('family', 'helper'), asyncRoute(async (req, res) => {
  const body = parse(z.object({ seniorPhone: z.string().min(8) }), req.body);
  const senior = db.prepare(`SELECT id,full_name FROM users WHERE phone=? AND role='senior'`).get(body.seniorPhone);
  if (!senior) return res.status(404).json({ error: 'Senior not found' });
  try {
    const row = db.prepare(`INSERT INTO family_links (senior_id,family_id) VALUES (?,?)`).run(senior.id, req.auth.sub);
    notify(senior.id, 'family_invite', 'Family invitation', `${getUser(req.auth.sub).full_name} would like to support you.`, { linkId: row.lastInsertRowid });
    res.status(201).json({ id: row.lastInsertRowid, status: 'pending' });
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) return res.status(409).json({ error: 'Invitation already exists' });
    throw error;
  }
}));

app.patch('/api/family-links/:id/respond', authenticate, allowRoles('senior'), asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const body = parse(z.object({ accept: z.boolean(), canViewLocation: z.boolean().default(false), canRequestHelp: z.boolean().default(true) }), req.body);
  const link = db.prepare('SELECT * FROM family_links WHERE id=? AND senior_id=?').get(id, req.auth.sub);
  if (!link) return res.status(404).json({ error: 'Invitation not found' });
  const status = body.accept ? 'accepted' : 'declined';
  db.prepare(`UPDATE family_links SET status=?,can_view_location=?,can_request_help=?,accepted_at=? WHERE id=?`)
    .run(status, Number(body.canViewLocation), Number(body.canRequestHelp), body.accept ? now() : null, id);
  notify(link.family_id, 'family_link', 'Family link updated', `Your invitation was ${status}.`, { linkId: id });
  res.json({ id, status });
}));

app.get('/api/family-links', authenticate, asyncRoute(async (req, res) => {
  const rows = req.auth.role === 'senior'
    ? db.prepare(`SELECT l.*,u.full_name family_name FROM family_links l JOIN users u ON u.id=l.family_id WHERE l.senior_id=?`).all(req.auth.sub)
    : db.prepare(`SELECT l.*,u.full_name senior_name FROM family_links l JOIN users u ON u.id=l.senior_id WHERE l.family_id=?`).all(req.auth.sub);
  res.json({ links: rows });
}));

const requestSchema = z.object({
  seniorId: z.number().int().positive().optional(),
  category: z.enum(['banking', 'government', 'delivery', 'other', 'health', 'ehailing']),
  mode: z.enum(['virtual', 'in_person']),
  description: z.string().trim().min(3).max(1000),
  scheduledFor: z.string().datetime().optional(),
  priceYen: z.number().int().min(0).max(100000),
  location: z.object({ latitude: z.number().gte(-90).lte(90), longitude: z.number().gte(-180).lte(180), addressHint: z.string().max(200).optional() }).optional()
});

app.post('/api/requests', authenticate, allowRoles('senior', 'family', 'helper'), asyncRoute(async (req, res) => {
  const body = parse(requestSchema, req.body);
  const seniorId = req.auth.role === 'senior' ? Number(req.auth.sub) : body.seniorId;
  if (!seniorId) return res.status(400).json({ error: 'seniorId is required when requesting for someone else' });
  if (seniorId !== Number(req.auth.sub)) {
    const link = db.prepare(`SELECT * FROM family_links WHERE senior_id=? AND family_id=? AND status='accepted' AND can_request_help=1`)
      .get(seniorId, req.auth.sub);
    if (!link) return res.status(403).json({ error: 'Senior has not authorised you to request help' });
  }
  const row = db.prepare(`INSERT INTO service_requests
    (senior_id,requested_by,category,mode,description,scheduled_for,price_yen,location_lat,location_lng,address_hint)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(seniorId, req.auth.sub, body.category, body.mode, body.description,
      body.scheduledFor || null, body.priceYen, body.location?.latitude ?? null, body.location?.longitude ?? null, body.location?.addressHint || null);
  db.prepare(`INSERT INTO job_events (request_id,actor_id,event_type) VALUES (?,?,?)`).run(row.lastInsertRowid, req.auth.sub, 'created');
  const helpers = db.prepare(`SELECT user_id FROM helper_profiles WHERE verification_status='verified' AND availability=1 LIMIT 100`).all();
  helpers.forEach(h => notify(h.user_id, 'new_request', 'New help request', body.description, { requestId: row.lastInsertRowid }));
  res.status(201).json({ request: requestById(row.lastInsertRowid) });
}));

app.get('/api/requests', authenticate, asyncRoute(async (req, res) => {
  let rows;
  if (req.auth.role === 'helper') {
    rows = db.prepare(`SELECT * FROM service_requests WHERE status='open' OR helper_id=? ORDER BY created_at DESC LIMIT 100`).all(req.auth.sub);
  } else if (req.auth.role === 'admin') {
    rows = db.prepare('SELECT * FROM service_requests ORDER BY created_at DESC LIMIT 100').all();
  } else {
    rows = db.prepare(`SELECT DISTINCT r.* FROM service_requests r LEFT JOIN family_links f ON f.senior_id=r.senior_id
      WHERE r.senior_id=? OR r.requested_by=? OR (f.family_id=? AND f.status='accepted') ORDER BY r.created_at DESC LIMIT 100`)
      .all(req.auth.sub, req.auth.sub, req.auth.sub);
  }
  res.json({ requests: rows });
}));

app.get('/api/requests/:id', authenticate, asyncRoute(async (req, res) => {
  const request = requestById(req.params.id);
  assertRequestAccess(request, req.auth);
  const events = db.prepare('SELECT * FROM job_events WHERE request_id=? ORDER BY created_at').all(request.id);
  const consents = db.prepare('SELECT * FROM consent_sessions WHERE request_id=?').all(request.id);
  res.json({ request, events, consents });
}));

app.post('/api/requests/:id/accept', authenticate, allowRoles('helper'), asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const profile = db.prepare('SELECT * FROM helper_profiles WHERE user_id=?').get(req.auth.sub);
  if (!profile || profile.verification_status !== 'verified') {
    return res.status(403).json({ error: 'Only verified helpers may accept requests' });
  }
  if (!profile.availability) return res.status(409).json({ error: 'Set your availability before accepting requests' });

  const changed = transaction(() => {
    const result = db.prepare(`UPDATE service_requests SET helper_id=?,status='accepted',updated_at=?
      WHERE id=? AND status='open' AND helper_id IS NULL`).run(req.auth.sub, now(), id);
    if (!result.changes) return false;
    db.prepare(`INSERT INTO job_events (request_id,actor_id,event_type) VALUES (?,?,?)`)
      .run(id, req.auth.sub, 'accepted');
    return true;
  });
  if (!changed) return res.status(409).json({ error: 'Request is unavailable or has already been accepted' });
  const request = requestById(id);
  notify(request.senior_id, 'request_accepted', 'A helper accepted your request', `${request.helper_name} will assist you.`, { requestId: id });
  if (request.requested_by !== request.senior_id) {
    notify(request.requested_by, 'request_accepted', 'A helper accepted the request', `${request.helper_name} will assist ${request.senior_name}.`, { requestId: id });
  }
  res.json({ request });
}));

const jobTransitions = {
  accepted: ['on_the_way', 'arrived', 'helping'],
  on_the_way: ['arrived'],
  arrived: ['helping'],
  helping: ['completed']
};

app.patch('/api/requests/:id/status', authenticate, allowRoles('helper'), asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const body = parse(z.object({ status: z.enum(['on_the_way', 'arrived', 'helping', 'completed']), note: z.string().trim().max(500).optional() }), req.body);
  const request = requestById(id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.helper_id !== Number(req.auth.sub)) return res.status(403).json({ error: 'Only the assigned helper may update this job' });
  if (!(jobTransitions[request.status] || []).includes(body.status)) {
    return res.status(409).json({ error: `Cannot change status from ${request.status} to ${body.status}` });
  }
  transaction(() => {
    db.prepare(`UPDATE service_requests SET status=?,updated_at=?,completed_at=? WHERE id=?`)
      .run(body.status, now(), body.status === 'completed' ? now() : null, id);
    db.prepare(`INSERT INTO job_events (request_id,actor_id,event_type,note) VALUES (?,?,?,?)`)
      .run(id, req.auth.sub, body.status, body.note || null);
    if (body.status === 'completed') {
      db.prepare('UPDATE helper_profiles SET completed_jobs=completed_jobs+1 WHERE user_id=?').run(req.auth.sub);
      db.prepare(`UPDATE consent_sessions SET granted=0,revoked_at=? WHERE request_id=? AND granted=1`).run(now(), id);
    }
  });
  const updated = requestById(id);
  notify(updated.senior_id, 'job_status', 'Assistance status updated', `Status: ${body.status.replaceAll('_', ' ')}`, { requestId: id, status: body.status });
  if (updated.requested_by !== updated.senior_id) {
    notify(updated.requested_by, 'job_status', 'Assistance status updated', `Status: ${body.status.replaceAll('_', ' ')}`, { requestId: id, status: body.status });
  }
  res.json({ request: updated });
}));

app.post('/api/requests/:id/cancel', authenticate, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const body = parse(z.object({ reason: z.string().trim().min(2).max(500) }), req.body);
  const request = requestById(id);
  assertRequestAccess(request, req.auth);
  const actorId = Number(req.auth.sub);
  const canCancel = req.auth.role === 'admin' || actorId === request.senior_id || actorId === request.requested_by || actorId === request.helper_id;
  if (!canCancel) return res.status(403).json({ error: 'Not permitted to cancel this request' });
  if (['completed', 'cancelled'].includes(request.status)) return res.status(409).json({ error: `Request is already ${request.status}` });
  transaction(() => {
    db.prepare(`UPDATE service_requests SET status='cancelled',updated_at=? WHERE id=?`).run(now(), id);
    db.prepare(`INSERT INTO job_events (request_id,actor_id,event_type,note) VALUES (?,?,?,?)`).run(id, actorId, 'cancelled', body.reason);
    db.prepare(`UPDATE consent_sessions SET granted=0,revoked_at=? WHERE request_id=? AND granted=1`).run(now(), id);
  });
  [request.senior_id, request.requested_by, request.helper_id].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i && v !== actorId)
    .forEach(userId => notify(userId, 'request_cancelled', 'Assistance request cancelled', body.reason, { requestId: id }));
  res.json({ request: requestById(id) });
}));

app.post('/api/requests/:id/escalate', authenticate, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const body = parse(z.object({ level: z.enum(['family', 'emergency_contact', 'emergency_services']), reason: z.string().trim().min(3).max(500) }), req.body);
  const request = requestById(id);
  assertRequestAccess(request, req.auth);
  if (['completed', 'cancelled'].includes(request.status)) return res.status(409).json({ error: 'Closed requests cannot be escalated' });
  transaction(() => {
    db.prepare(`UPDATE service_requests SET status='escalated',updated_at=? WHERE id=?`).run(now(), id);
    db.prepare(`INSERT INTO job_events (request_id,actor_id,event_type,note) VALUES (?,?,?,?)`)
      .run(id, req.auth.sub, `escalated_${body.level}`, body.reason);
  });
  const recipients = db.prepare(`SELECT family_id FROM family_links WHERE senior_id=? AND status='accepted' AND can_receive_updates=1`).all(request.senior_id);
  recipients.forEach(({ family_id }) => notify(family_id, 'escalation', 'BridgeMate assistance escalated', body.reason, { requestId: id, level: body.level }));
  res.json({ request: requestById(id), instruction: body.level === 'emergency_services' ? 'Contact local emergency services directly. BridgeMate does not dispatch emergency responders.' : null });
}));

app.put('/api/requests/:id/consent/:type', authenticate, allowRoles('senior'), asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const type = req.params.type;
  const body = parse(z.object({ granted: z.boolean() }), req.body);
  if (!['location', 'screen_share', 'family_updates'].includes(type)) return res.status(400).json({ error: 'Unknown consent type' });
  const request = requestById(id);
  if (!request || request.senior_id !== Number(req.auth.sub)) return res.status(404).json({ error: 'Request not found' });
  if (['completed', 'cancelled'].includes(request.status) && body.granted) return res.status(409).json({ error: 'Consent cannot be granted for a closed request' });
  db.prepare(`INSERT INTO consent_sessions (request_id,senior_id,consent_type,granted,granted_at,revoked_at)
    VALUES (?,?,?,?,?,?) ON CONFLICT(request_id,consent_type) DO UPDATE SET granted=excluded.granted,
    granted_at=excluded.granted_at,revoked_at=excluded.revoked_at`)
    .run(id, req.auth.sub, type, Number(body.granted), body.granted ? now() : null, body.granted ? null : now());
  db.prepare(`INSERT INTO job_events (request_id,actor_id,event_type) VALUES (?,?,?)`)
    .run(id, req.auth.sub, `${type}_${body.granted ? 'granted' : 'revoked'}`);
  res.json({ requestId: id, type, granted: body.granted });
}));

function activeConsent(requestId, type) {
  return db.prepare(`SELECT 1 FROM consent_sessions WHERE request_id=? AND consent_type=? AND granted=1 AND revoked_at IS NULL`).get(requestId, type);
}

app.put('/api/requests/:id/location', authenticate, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const body = parse(z.object({ latitude: z.number().gte(-90).lte(90), longitude: z.number().gte(-180).lte(180) }), req.body);
  const request = requestById(id);
  assertRequestAccess(request, req.auth);
  const actorId = Number(req.auth.sub);
  if (![request.senior_id, request.helper_id].includes(actorId)) return res.status(403).json({ error: 'Only the senior or assigned helper may share a live location' });
  if (!activeConsent(id, 'location')) return res.status(403).json({ error: 'Active senior consent is required for location sharing' });
  if (!['accepted', 'on_the_way', 'arrived', 'helping', 'escalated'].includes(request.status)) return res.status(409).json({ error: 'Location sharing is unavailable for this status' });
  db.prepare(`INSERT INTO live_locations (request_id,user_id,latitude,longitude,captured_at) VALUES (?,?,?,?,?)
    ON CONFLICT(request_id,user_id) DO UPDATE SET latitude=excluded.latitude,longitude=excluded.longitude,captured_at=excluded.captured_at`)
    .run(id, actorId, body.latitude, body.longitude, now());
  res.json({ updated: true });
}));

app.get('/api/requests/:id/locations', authenticate, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const request = requestById(id);
  assertRequestAccess(request, req.auth);
  if (!activeConsent(id, 'location')) return res.status(403).json({ error: 'Location consent is not active' });
  const actorId = Number(req.auth.sub);
  if (req.auth.role !== 'admin' && ![request.senior_id, request.helper_id].includes(actorId)) {
    const link = db.prepare(`SELECT 1 FROM family_links WHERE senior_id=? AND family_id=? AND status='accepted' AND can_view_location=1`).get(request.senior_id, actorId);
    if (!link) return res.status(403).json({ error: 'Senior has not authorised location access' });
  }
  res.json({ locations: db.prepare('SELECT user_id,latitude,longitude,captured_at FROM live_locations WHERE request_id=?').all(id) });
}));

app.post('/api/requests/:id/review', authenticate, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const body = parse(z.object({ rating: z.number().int().min(1).max(5), comment: z.string().trim().max(1000).optional() }), req.body);
  const request = requestById(id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  const actorId = Number(req.auth.sub);
  if (![request.senior_id, request.requested_by].includes(actorId)) return res.status(403).json({ error: 'Only the senior or requester may review this job' });
  if (request.status !== 'completed' || !request.helper_id) return res.status(409).json({ error: 'Only completed jobs can be reviewed' });
  try {
    transaction(() => {
      db.prepare(`INSERT INTO reviews (request_id,reviewer_id,helper_id,rating,comment) VALUES (?,?,?,?,?)`)
        .run(id, actorId, request.helper_id, body.rating, body.comment || null);
      const aggregate = db.prepare('SELECT ROUND(AVG(rating),2) rating FROM reviews WHERE helper_id=?').get(request.helper_id);
      db.prepare('UPDATE helper_profiles SET rating=? WHERE user_id=?').run(aggregate.rating, request.helper_id);
    });
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) return res.status(409).json({ error: 'This request has already been reviewed' });
    throw error;
  }
  notify(request.helper_id, 'review', 'You received a review', `${body.rating} out of 5`, { requestId: id });
  res.status(201).json({ review: db.prepare('SELECT * FROM reviews WHERE request_id=?').get(id) });
}));

const plans = Object.freeze({
  trial: { priceYen: 0, durationDays: 14 },
  monthly: { priceYen: 2400, durationDays: 30 },
  yearly: { priceYen: 26400, durationDays: 365 },
  onetime: { priceYen: 1500, durationDays: null }
});

app.get('/api/plans', (req, res) => res.json({ currency: 'JPY', plans }));

app.post('/api/subscriptions', authenticate, allowRoles('senior', 'family', 'helper'), asyncRoute(async (req, res) => {
  const body = parse(z.object({ seniorId: z.number().int().positive().optional(), plan: z.enum(['trial', 'monthly', 'yearly', 'onetime']), externalPaymentRef: z.string().trim().min(3).max(200).optional() }), req.body);
  const seniorId = req.auth.role === 'senior' ? Number(req.auth.sub) : body.seniorId;
  if (!seniorId) return res.status(400).json({ error: 'seniorId is required' });
  if (seniorId !== Number(req.auth.sub)) {
    const link = db.prepare(`SELECT 1 FROM family_links WHERE senior_id=? AND family_id=? AND status='accepted'`).get(seniorId, req.auth.sub);
    if (!link) return res.status(403).json({ error: 'An accepted family link is required' });
  }
  if (body.plan !== 'trial' && !body.externalPaymentRef) return res.status(400).json({ error: 'A payment-provider reference is required for paid plans' });
  if (body.plan === 'trial') {
    const used = db.prepare(`SELECT 1 FROM subscriptions WHERE senior_id=? AND plan='trial'`).get(seniorId);
    if (used) return res.status(409).json({ error: 'Free trial has already been used' });
  }
  const endsAt = plans[body.plan].durationDays ? new Date(Date.now() + plans[body.plan].durationDays * 86400000).toISOString() : null;
  const row = db.prepare(`INSERT INTO subscriptions (senior_id,payer_id,plan,ends_at,trial_used,external_payment_ref)
    VALUES (?,?,?,?,?,?)`).run(seniorId, req.auth.sub, body.plan, endsAt, Number(body.plan === 'trial'), body.externalPaymentRef || null);
  res.status(201).json({ subscription: db.prepare('SELECT * FROM subscriptions WHERE id=?').get(row.lastInsertRowid) });
}));

app.get('/api/subscriptions', authenticate, asyncRoute(async (req, res) => {
  const rows = req.auth.role === 'admin'
    ? db.prepare('SELECT * FROM subscriptions ORDER BY starts_at DESC').all()
    : db.prepare('SELECT * FROM subscriptions WHERE senior_id=? OR payer_id=? ORDER BY starts_at DESC').all(req.auth.sub, req.auth.sub);
  res.json({ subscriptions: rows });
}));

app.post('/api/subscriptions/:id/cancel', authenticate, asyncRoute(async (req, res) => {
  const subscription = db.prepare('SELECT * FROM subscriptions WHERE id=?').get(req.params.id);
  if (!subscription) return res.status(404).json({ error: 'Subscription not found' });
  if (req.auth.role !== 'admin' && ![subscription.senior_id, subscription.payer_id].includes(Number(req.auth.sub))) {
    return res.status(403).json({ error: 'Not permitted to cancel this subscription' });
  }
  if (subscription.plan === 'onetime') return res.status(409).json({ error: 'One-time sessions are not subscriptions' });
  db.prepare(`UPDATE subscriptions SET status='cancelled' WHERE id=?`).run(subscription.id);
  res.json({ subscription: db.prepare('SELECT * FROM subscriptions WHERE id=?').get(subscription.id) });
}));

app.get('/api/notifications', authenticate, asyncRoute(async (req, res) => {
  const rows = db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(req.auth.sub);
  res.json({ notifications: rows.map(row => ({ ...row, data: safeJson(row.data_json, {}) })) });
}));

app.patch('/api/notifications/:id/read', authenticate, asyncRoute(async (req, res) => {
  const result = db.prepare('UPDATE notifications SET read_at=? WHERE id=? AND user_id=?').run(now(), req.params.id, req.auth.sub);
  if (!result.changes) return res.status(404).json({ error: 'Notification not found' });
  res.json({ read: true });
}));

app.get('/api/admin/verifications', authenticate, allowRoles('admin'), asyncRoute(async (req, res) => {
  res.json({ submissions: db.prepare(`SELECT v.*,u.full_name,u.phone FROM verification_submissions v JOIN users u ON u.id=v.helper_id ORDER BY v.created_at DESC`).all() });
}));

app.patch('/api/admin/verifications/:id', authenticate, allowRoles('admin'), asyncRoute(async (req, res) => {
  const body = parse(z.object({ decision: z.enum(['verified', 'rejected']), note: z.string().trim().max(500).optional() }), req.body);
  const submission = db.prepare(`SELECT * FROM verification_submissions WHERE id=? AND status='pending'`).get(req.params.id);
  if (!submission) return res.status(404).json({ error: 'Pending submission not found' });
  const verifiedUntil = body.decision === 'verified' ? new Date(Date.now() + 183 * 86400000).toISOString() : null;
  transaction(() => {
    db.prepare(`UPDATE verification_submissions SET status=?,reviewed_by=?,review_note=?,reviewed_at=? WHERE id=?`)
      .run(body.decision, req.auth.sub, body.note || null, now(), submission.id);
    db.prepare(`UPDATE helper_profiles SET verification_status=?,verified_until=?,availability=0,updated_at=? WHERE user_id=?`)
      .run(body.decision, verifiedUntil, now(), submission.helper_id);
  });
  notify(submission.helper_id, 'verification', 'Verification reviewed', `Your verification was ${body.decision}.`, { submissionId: submission.id });
  res.json({ id: submission.id, status: body.decision, verifiedUntil });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found' }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

app.use((err, req, res, _next) => {
  if (process.env.NODE_ENV !== 'test') console.error(err);
  res.status(err.status || 500).json({
    error: err.status ? err.message : 'Internal server error',
    ...(err.details ? { details: err.details } : {})
  });
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log(`BridgeMate running on port ${PORT}`));
}

module.exports = app;
