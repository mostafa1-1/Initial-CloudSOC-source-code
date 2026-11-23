import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createDatabase, resolveDatabaseConfig } from './db';

test('resolveDatabaseConfig honors DATABASE_URL sqlite schemes and DATABASE_PATH', () => {
  const prevUrl = process.env.DATABASE_URL;
  const prevPath = process.env.DATABASE_PATH;

  try {
    process.env.DATABASE_URL = 'sqlite:///./tmp_custom/test.db';
    delete process.env.DATABASE_PATH;
    const sqliteUrlCfg = resolveDatabaseConfig();
    assert.equal(sqliteUrlCfg.sqlitePath, path.resolve(process.cwd(), './tmp_custom/test.db'));
    assert.equal(sqliteUrlCfg.externalDatabaseUrlDetected, false);

    process.env.DATABASE_URL = 'sqlite:///:memory:';
    assert.equal(resolveDatabaseConfig().sqlitePath, ':memory:');

    process.env.DATABASE_URL = 'file:./data/file_url.db';
    assert.equal(resolveDatabaseConfig().sqlitePath, path.resolve(process.cwd(), './data/file_url.db'));

    process.env.DATABASE_URL = 'postgresql://user:pass@db.example:5432/cloudsoc';
    process.env.DATABASE_PATH = './data/pg_fallback.db';
    const pgFallback = resolveDatabaseConfig();
    assert.equal(pgFallback.externalDatabaseUrlDetected, true);
    assert.equal(pgFallback.sqlitePath, path.resolve(process.cwd(), './data/pg_fallback.db'));
  } finally {
    if (prevUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevUrl;
    if (prevPath === undefined) delete process.env.DATABASE_PATH;
    else process.env.DATABASE_PATH = prevPath;
  }
});

test('createDatabase runs versioned schema_migrations and preserves data across restarts', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsoc-mig-'));
  const dbFile = path.join(tmpDir, 'migrations.db');

  try {
    const db1 = createDatabase(dbFile);
    const migrations = db1
      .prepare('SELECT version, name FROM schema_migrations ORDER BY version ASC')
      .all() as Array<{ version: number; name: string }>;
    assert.equal(migrations.length, 4);
    assert.equal(migrations[0].name, '001_initial_schema');
    assert.equal(migrations[1].name, '002_indexes_and_audit_filters');
    assert.equal(migrations[2].name, '003_demo_data_labeling_and_allowlist');
    assert.equal(migrations[3].name, '004_firebase_auth_identity_link');
    const firebaseUidColumn = db1.prepare('PRAGMA table_info(users)').all() as Array<{ name: string }>;
    assert.ok(firebaseUidColumn.some((column) => column.name === 'firebase_uid'));

    const demoEvtCount = (db1.prepare('SELECT COUNT(*) AS c FROM security_events WHERE is_demo = 1').get() as { c: number }).c;
    assert.equal(demoEvtCount >= 14, true);

    db1.prepare("INSERT INTO system_settings (setting_key, setting_value, description) VALUES (?, ?, ?)").run(
      'custom_test_key',
      'persisted_value',
      'Test persistence'
    );
    db1.close();

    // Reopen existing DB: migrations should be idempotent and custom row preserved
    const db2 = createDatabase(dbFile);
    const migrationsAfter = db2
      .prepare('SELECT COUNT(*) AS c FROM schema_migrations')
      .get() as { c: number };
    assert.equal(migrationsAfter.c, 4);
    const persisted = db2
      .prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'custom_test_key'")
      .get() as { setting_value: string } | undefined;
    assert.equal(persisted?.setting_value, 'persisted_value');
    db2.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
