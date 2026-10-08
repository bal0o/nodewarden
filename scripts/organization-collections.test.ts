import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { isValidEncString } from '../src/handlers/ciphers';
import { validateBackupPayloadContents, type BackupPayload } from '../src/services/backup-archive';

const alice = '00000000-0000-4000-8000-0000000000a1';
const bob = '00000000-0000-4000-8000-0000000000b0';
const carol = '00000000-0000-4000-8000-0000000000c0';
const sharedCipherId = '00000000-0000-4000-8000-000000000101';
const carolCipherId = '00000000-0000-4000-8000-000000000102';
const attachmentId = '00000000-0000-4000-8000-000000000201';
const now = '2026-10-04T00:00:00.000Z';
const symmetric = (label: string) => `2.${btoa(label)}|${btoa(`${label}-data`)}|${btoa(`${label}-mac`)}`;
const rsaWrapped = (label: string) => `4.${btoa(label)}`;

function d1Database(sqlite: DatabaseSync): D1Database {
  const prepare = (sql: string) => {
    let values: unknown[] = [];
    const statement = {
      bind(...bound: unknown[]) { values = bound; return statement; },
      async run() {
        const result = sqlite.prepare(sql).run(...(values as never[]));
        return { success: true, meta: { changes: Number(result.changes) } };
      },
      async all() { return { success: true, results: sqlite.prepare(sql).all(...(values as never[])) }; },
      async first() { return sqlite.prepare(sql).get(...(values as never[])) ?? null; },
    };
    return statement;
  };
  return {
    prepare,
    async batch(statements: Array<{ run(): Promise<unknown> }>) {
      sqlite.exec('BEGIN');
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        sqlite.exec('COMMIT');
        return results;
      } catch (error) {
        sqlite.exec('ROLLBACK');
        throw error;
      }
    },
  } as unknown as D1Database;
}

function insertUser(sqlite: DatabaseSync, id: string, email: string): void {
  sqlite.prepare(
    `INSERT INTO users (id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at)
     VALUES (?, ?, ?, 'hash', ?, ?, 'public-key', 0, 600000, 'stamp', ?, ?)`
  ).run(id, email, email.split('@')[0], symmetric(`${id}-key`), symmetric(`${id}-private`), now, now);
}

function personalCipher(id: string, userId: string) {
  return {
    id, userId, organizationId: null, type: 1, name: symmetric(`${id}-name`), notes: null, favorite: false,
    folderId: null, key: null, login: { username: symmetric(`${id}-user`), password: symmetric(`${id}-password`) },
    createdAt: now, updatedAt: now, deletedAt: null,
  };
}

async function fixture(ctx: TestContext) {
  const sqlite = new DatabaseSync(':memory:');
  ctx.after(async () => { await new Promise((resolve) => setImmediate(resolve)); sqlite.close(); });
  const db = d1Database(sqlite);
  await ensureStorageSchema(db);
  insertUser(sqlite, alice, 'alice@example.test');
  insertUser(sqlite, bob, 'bob@example.test');
  insertUser(sqlite, carol, 'carol@example.test');
  ctx.mock.method(StorageService.prototype, 'createAuditLog', async () => {});
  const cachedResponses = new Map<string, Response>();
  (globalThis as any).caches = {
    default: {
      async match(request: Request) { return cachedResponses.get(request.url)?.clone(); },
      async put(request: Request, response: Response) { cachedResponses.set(request.url, response.clone()); },
    },
  };
  ctx.after(() => { delete (globalThis as any).caches; });

  const env: any = {
    DB: db,
    ATTACHMENTS: { delete: async () => {} },
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async () => new Response(null, { status: 204 }) }),
    },
  };
  const storage = new StorageService(db);
  await storage.saveCipher(personalCipher(sharedCipherId, alice) as any);
  await storage.saveCipher(personalCipher(carolCipherId, carol) as any);

  const route = async (userId: string, path: string, method: string, body?: unknown) => {
    const request = new Request(`https://vault.example.test${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const user = await storage.getUserById(userId);
    const response = await handleAuthenticatedRoute(request, env, userId, user as any, path, method);
    assert.ok(response, `${method} ${path} must be handled`);
    return response;
  };
  const json = async (userId: string, path: string, method = 'GET', body?: unknown) => {
    const response = await route(userId, path, method, body);
    assert.ok(response.ok, `${method} ${path} returned ${response.status}: ${await response.clone().text()}`);
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  };
  const syncCipherIds = async (userId: string) => {
    const sync = await json(userId, '/api/sync');
    return sync.ciphers.map((cipher: any) => cipher.id).sort();
  };
  return { sqlite, storage, route, json, syncCipherIds };
}

async function organizationWithSharedItem(f: Awaited<ReturnType<typeof fixture>>, bobGrant: { readOnly: boolean; hidePasswords: boolean }) {
  const organization = await f.json(alice, '/api/organizations', 'POST', {
    name: 'Family',
    key: rsaWrapped('alice-org-key'),
    collectionName: symmetric('Shared'),
    keys: { publicKey: 'org-public-key', encryptedPrivateKey: symmetric('org-private') },
  });
  const [collection] = (await f.json(alice, `/api/organizations/${organization.id}/collections`)).data;
  await f.json(alice, `/api/organizations/${organization.id}/users/invite`, 'POST', { emails: ['bob@example.test'], type: 2 });
  const members = (await f.json(alice, `/api/organizations/${organization.id}/users`)).data;
  const bobMember = members.find((member: any) => member.userId === bob);
  return { organization, collection, bobMember, bobGrant };
}

async function confirmAndShare(f: Awaited<ReturnType<typeof fixture>>, setup: Awaited<ReturnType<typeof organizationWithSharedItem>>) {
  const { organization, collection, bobMember, bobGrant } = setup;
  await f.json(alice, `/api/organizations/${organization.id}/users/${bobMember.id}/confirm`, 'POST', { key: rsaWrapped('bob-org-key') });
  await f.json(alice, `/api/organizations/${organization.id}/collections/${collection.id}`, 'PUT', {
    name: collection.name,
    users: [{ id: bobMember.id, ...bobGrant, manage: false }],
  });
  const original = await f.json(alice, `/api/ciphers/${sharedCipherId}`);
  await f.json(alice, `/api/ciphers/${sharedCipherId}/share`, 'PUT', {
    cipher: { ...original, organizationId: organization.id, key: symmetric('item-key') },
    collectionIds: [collection.id],
  });
}

test('RSA-wrapped membership keys are valid encrypted strings', () => {
  assert.equal(isValidEncString(rsaWrapped('org-key')), true);
  assert.equal(isValidEncString('4.a|b'), false);
});

function backupPayload(db: Partial<BackupPayload['db']>): BackupPayload {
  return {
    manifest: { formatVersion: 1, exportedAt: now, appVersion: 'test', storageKind: null, tableCounts: {}, includes: { attachments: false }, blobSummary: { attachmentFiles: 0, totalBytes: 0, largestObjectBytes: 0 } },
    db: {
      config: [],
      users: [{ id: alice, email: 'alice@example.test' }, { id: bob, email: 'bob@example.test' }],
      domain_settings: [],
      user_revisions: [],
      folders: [],
      ciphers: [],
      attachments: [],
      ...db,
    },
  };
}

const organizationBackupRows = {
  organizations: [{ id: 'org-1', name: 'Family' }],
  organization_users: [{ id: 'member-1', user_id: bob, organization_id: 'org-1' }],
  collections: [{ id: 'collection-1', organization_id: 'org-1' }],
  collection_users: [{ user_id: bob, collection_id: 'collection-1' }],
  cipher_collections: [{ cipher_id: sharedCipherId, collection_id: 'collection-1' }],
  cipher_user_settings: [{ cipher_id: sharedCipherId, user_id: bob, folder_id: null }],
};

test('backups without organization tables still validate', () => {
  assert.doesNotThrow(() => validateBackupPayloadContents(backupPayload({ ciphers: [{ id: carolCipherId, user_id: alice }] }), {}));
});

test('backups validate organization ciphers and their links', () => {
  const organizationCipher = { id: sharedCipherId, user_id: null, organization_id: 'org-1' };
  assert.doesNotThrow(() => validateBackupPayloadContents(backupPayload({ ...organizationBackupRows, ciphers: [organizationCipher] }), {}));
  assert.throws(
    () => validateBackupPayloadContents(backupPayload({ ...organizationBackupRows, ciphers: [{ ...organizationCipher, user_id: alice }] }), {}),
    /invalid cipher row/
  );
  assert.throws(
    () => validateBackupPayloadContents(backupPayload({ ...organizationBackupRows, collections: [], ciphers: [organizationCipher] }), {}),
    /invalid collection access row/
  );
});

test('schema rebuild keeps attachments of existing personal ciphers', async (ctx) => {
  const f = await fixture(ctx);
  f.sqlite.exec(`
    DROP TABLE cipher_user_settings;
    DROP TABLE cipher_collections;
    DROP TABLE attachments;
    DROP TABLE ciphers;
    CREATE TABLE ciphers (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, folder_id TEXT, name TEXT, notes TEXT,
      favorite INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, reprompt INTEGER, key TEXT, created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL, archived_at TEXT, deleted_at TEXT, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE attachments (id TEXT PRIMARY KEY, cipher_id TEXT NOT NULL, file_name TEXT NOT NULL, size INTEGER NOT NULL,
      size_name TEXT NOT NULL, key TEXT, FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE);
  `);
  f.sqlite.prepare("INSERT INTO ciphers (id, user_id, type, data, created_at, updated_at) VALUES (?, ?, 1, '{}', ?, ?)").run(sharedCipherId, alice, now, now);
  f.sqlite.prepare("INSERT INTO attachments (id, cipher_id, file_name, size, size_name) VALUES (?, ?, 'file', 7, '7 B')").run(attachmentId, sharedCipherId);

  await ensureStorageSchema(d1Database(f.sqlite));

  const columns = f.sqlite.prepare('PRAGMA table_info(ciphers)').all().map((column: any) => column.name);
  assert.ok(columns.includes('organization_id'));
  assert.deepEqual(f.sqlite.prepare('SELECT id, cipher_id FROM attachments').all().map((row) => ({ ...row })), [{ id: attachmentId, cipher_id: sharedCipherId }]);
  assert.equal((f.sqlite.prepare('SELECT user_id FROM ciphers WHERE id = ?').get(sharedCipherId) as any).user_id, alice);
});

test('a shared item stays hidden until the member is confirmed and granted a collection', async (ctx) => {
  const f = await fixture(ctx);
  const setup = await organizationWithSharedItem(f, { readOnly: false, hidePasswords: false });
  assert.equal(setup.bobMember.status, 1);
  assert.equal((await f.route(bob, `/api/ciphers/${sharedCipherId}`, 'GET')).status, 404);

  await confirmAndShare(f, setup);

  assert.deepEqual(await f.syncCipherIds(bob), [sharedCipherId]);
  const sync = await f.json(bob, '/api/sync');
  assert.equal(sync.profile.organizations[0].id, setup.organization.id);
  assert.deepEqual(sync.collections.map((collection: any) => collection.id), [setup.collection.id]);
  const shared = sync.ciphers[0];
  assert.equal(shared.organizationId, setup.organization.id);
  assert.equal(shared.userId ?? null, null);
  assert.deepEqual(shared.collectionIds, [setup.collection.id]);
  assert.equal(shared.edit, true);
  assert.equal(shared.viewPassword, true);
});

test('a read-only member cannot change or delete a shared item', async (ctx) => {
  const f = await fixture(ctx);
  await confirmAndShare(f, await organizationWithSharedItem(f, { readOnly: true, hidePasswords: false }));
  const visible = await f.json(bob, `/api/ciphers/${sharedCipherId}`);
  assert.equal(visible.edit, false);

  const update = await f.route(bob, `/api/ciphers/${sharedCipherId}`, 'PUT', { ...visible, name: symmetric('changed') });
  assert.equal(update.status, 403);
  assert.equal((await f.route(bob, `/api/ciphers/${sharedCipherId}`, 'DELETE')).status, 403);
  assert.equal((await f.storage.getCipher(sharedCipherId))?.name, symmetric(`${sharedCipherId}-name`));
});

test('hide passwords keeps the item visible with viewPassword false', async (ctx) => {
  const f = await fixture(ctx);
  await confirmAndShare(f, await organizationWithSharedItem(f, { readOnly: true, hidePasswords: true }));
  const sync = await f.json(bob, '/api/sync');
  assert.equal(sync.ciphers[0].id, sharedCipherId);
  assert.equal(sync.ciphers[0].viewPassword, false);
  assert.equal(sync.ciphers[0].edit, false);
});

test('leaving the organization removes shared items from sync', async (ctx) => {
  const f = await fixture(ctx);
  const setup = await organizationWithSharedItem(f, { readOnly: false, hidePasswords: false });
  await confirmAndShare(f, setup);
  await f.json(bob, `/api/organizations/${setup.organization.id}/leave`, 'POST');

  assert.deepEqual(await f.syncCipherIds(bob), []);
  assert.equal((await f.route(bob, `/api/ciphers/${sharedCipherId}`, 'GET')).status, 404);
  assert.deepEqual((await f.json(bob, '/api/sync')).profile.organizations, []);
  assert.deepEqual(await f.syncCipherIds(alice), [sharedCipherId]);
});

test('a non-member keeps only their personal vault', async (ctx) => {
  const f = await fixture(ctx);
  await confirmAndShare(f, await organizationWithSharedItem(f, { readOnly: false, hidePasswords: false }));

  assert.deepEqual(await f.syncCipherIds(carol), [carolCipherId]);
  assert.equal((await f.route(carol, `/api/ciphers/${sharedCipherId}`, 'GET')).status, 404);
  const sync = await f.json(carol, '/api/sync');
  assert.deepEqual(sync.profile.organizations, []);
  assert.deepEqual(sync.collections, []);
});
