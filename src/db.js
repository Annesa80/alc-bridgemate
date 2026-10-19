const path = require('node:path');
const Database = require('better-sqlite3');

const databaseFile = process.env.DATABASE_FILE || './data/bridgemate.db';
const db = new Database(databaseFile === ':memory:' ? ':memory:' : path.resolve(process.cwd(), databaseFile));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL CHECK(role IN ('senior','helper','family','admin')),
      full_name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE,
      email TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      locale TEXT NOT NULL DEFAULT 'ja',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS helper_profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      bio TEXT,
      skills_json TEXT NOT NULL DEFAULT '[]',
      availability INTEGER NOT NULL DEFAULT 0,
      verification_status TEXT NOT NULL DEFAULT 'unsubmitted'
        CHECK(verification_status IN ('unsubmitted','pending','verified','rejected','expired')),
      verified_until TEXT,
      rating REAL NOT NULL DEFAULT 0,
      completed_jobs INTEGER NOT NULL DEFAULT 0,
      latitude REAL,
      longitude REAL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS verification_submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      helper_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      id_document_ref TEXT NOT NULL,
      selfie_ref TEXT NOT NULL,
      address_document_ref TEXT NOT NULL,
      employment_status TEXT,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','verified','rejected')),
      reviewed_by INTEGER REFERENCES users(id),
      review_note TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      reviewed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS family_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      senior_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      family_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','accepted','declined','revoked')),
      can_view_location INTEGER NOT NULL DEFAULT 0,
      can_receive_updates INTEGER NOT NULL DEFAULT 1,
      can_request_help INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      accepted_at TEXT,
      UNIQUE(senior_id, family_id)
    );

    CREATE TABLE IF NOT EXISTS service_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      senior_id INTEGER NOT NULL REFERENCES users(id),
      requested_by INTEGER NOT NULL REFERENCES users(id),
      helper_id INTEGER REFERENCES users(id),
      category TEXT NOT NULL CHECK(category IN
        ('banking','government','delivery','other','health','ehailing')),
      mode TEXT NOT NULL CHECK(mode IN ('virtual','in_person')),
      description TEXT NOT NULL,
      scheduled_for TEXT,
      status TEXT NOT NULL DEFAULT 'open' CHECK(status IN
        ('open','matched','accepted','on_the_way','arrived','helping','completed','cancelled','escalated')),
      price_yen INTEGER NOT NULL CHECK(price_yen BETWEEN 0 AND 100000),
      location_lat REAL,
      location_lng REAL,
      address_hint TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS job_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id INTEGER NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
      actor_id INTEGER NOT NULL REFERENCES users(id),
      event_type TEXT NOT NULL,
      note TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS consent_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id INTEGER NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
      senior_id INTEGER NOT NULL REFERENCES users(id),
      consent_type TEXT NOT NULL CHECK(consent_type IN ('location','screen_share','family_updates')),
      granted INTEGER NOT NULL,
      granted_at TEXT,
      revoked_at TEXT,
      UNIQUE(request_id, consent_type)
    );

    CREATE TABLE IF NOT EXISTS live_locations (
      request_id INTEGER NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      latitude REAL NOT NULL,
      longitude REAL NOT NULL,
      captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(request_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id INTEGER NOT NULL UNIQUE REFERENCES service_requests(id) ON DELETE CASCADE,
      reviewer_id INTEGER NOT NULL REFERENCES users(id),
      helper_id INTEGER NOT NULL REFERENCES users(id),
      rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
      comment TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      senior_id INTEGER NOT NULL REFERENCES users(id),
      payer_id INTEGER NOT NULL REFERENCES users(id),
      plan TEXT NOT NULL CHECK(plan IN ('trial','monthly','yearly','onetime')),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled','expired')),
      starts_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ends_at TEXT,
      trial_used INTEGER NOT NULL DEFAULT 0,
      external_payment_ref TEXT
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      data_json TEXT NOT NULL DEFAULT '{}',
      read_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_requests_status ON service_requests(status, created_at);
    CREATE INDEX IF NOT EXISTS idx_requests_helper ON service_requests(helper_id, status);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read_at);
    CREATE INDEX IF NOT EXISTS idx_job_events_request ON job_events(request_id, created_at);
  `);
}

function transaction(fn) {
  return db.transaction(fn)();
}

module.exports = { db, migrate, transaction };
