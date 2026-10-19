const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'development-only-secret-change-before-deploying';

if (process.env.NODE_ENV === 'production' && (JWT_SECRET.startsWith('development-only') || JWT_SECRET.length < 32)) {
  throw new Error('JWT_SECRET must be a unique value of at least 32 characters in production');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, storedHash] = String(stored).split(':');
  if (!salt || !storedHash) return false;
  const candidate = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(storedHash, 'hex');
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
}

function authenticate(req, res, next) {
  const raw = req.headers.authorization;
  if (!raw?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.auth = jwt.verify(raw.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function allowRoles(...roles) {
  return (req, res, next) => roles.includes(req.auth.role)
    ? next()
    : res.status(403).json({ error: 'Insufficient permission' });
}

module.exports = { hashPassword, verifyPassword, signToken, authenticate, allowRoles };
