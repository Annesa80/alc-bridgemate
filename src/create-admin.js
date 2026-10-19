require('dotenv').config();

const { db, migrate } = require('./db');
const { hashPassword } = require('./auth');

migrate();

const fullName = process.env.ADMIN_NAME;
const phone = process.env.ADMIN_PHONE;
const email = process.env.ADMIN_EMAIL || null;
const password = process.env.ADMIN_PASSWORD;

if (!fullName || !phone || !password || password.length < 12) {
  console.error('Set ADMIN_NAME, ADMIN_PHONE and ADMIN_PASSWORD (12+ characters) in your environment.');
  process.exitCode = 1;
} else {
  try {
    db.prepare(`INSERT INTO users (role,full_name,phone,email,password_hash,locale)
      VALUES ('admin',?,?,?,?,?)`).run(fullName, phone, email, hashPassword(password), 'ja');
    console.log('Admin account created. Remove ADMIN_PASSWORD from your environment now.');
  } catch (error) {
    console.error(String(error.message).includes('UNIQUE') ? 'That phone or email is already registered.' : 'Could not create admin account.');
    process.exitCode = 1;
  }
}

db.close();
