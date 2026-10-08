import { Env, Cipher, Collection, Folder, CipherType } from '../types';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { hasFullAccess, isOwnerOrAdmin, loadOrganizationAccess, writableCollectionIds } from '../services/organization-access';
import { errorResponse, jsonResponse } from '../utils/response';
import { readActingDeviceIdentifier } from '../utils/device';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import {
  isValidEncString,
  normalizeCipherLoginForStorage,
  normalizeCipherSshKeyForCompatibility,
  validateCipherEncryptedFieldsForCompatibility,
} from './ciphers';
import { publishCiphersSync } from './cipher-events';
import { loadOrganizationContext, readJsonBody, type OrganizationContext } from './organizations';

// Bitwarden client import request format
interface CiphersImportRequest {
  ciphers: Array<{
    id?: string | null;
    type: number;
    name?: string | null;
    notes?: string | null;
    favorite?: boolean;
    reprompt?: number;
    sshKey?: any | null;
    bankAccount?: any | null;
    driversLicense?: any | null;
    passport?: any | null;
    key?: string | null;
    login?: {
      uris?: Array<{ uri: string | null; uriChecksum?: string | null; match?: number | null }> | null;
      username?: string | null;
      password?: string | null;
      totp?: string | null;
      autofillOnPageLoad?: boolean | null;
      uri?: string | null;
      passwordRevisionDate?: string | null;
      [key: string]: any;
    } | null;
    card?: {
      cardholderName?: string | null;
      brand?: string | null;
      number?: string | null;
      expMonth?: string | null;
      expYear?: string | null;
      code?: string | null;
    } | null;
    identity?: {
      title?: string | null;
      firstName?: string | null;
      middleName?: string | null;
      lastName?: string | null;
      address1?: string | null;
      address2?: string | null;
      address3?: string | null;
      city?: string | null;
      state?: string | null;
      postalCode?: string | null;
      country?: string | null;
      company?: string | null;
      email?: string | null;
      phone?: string | null;
      ssn?: string | null;
      username?: string | null;
      passportNumber?: string | null;
      licenseNumber?: string | null;
    } | null;
    secureNote?: { type: number } | null;
    fields?: Array<{
      name?: string | null;
      value?: string | null;
      type: number;
      linkedId?: number | null;
    }> | null;
    passwordHistory?: Array<{
      password: string;
      lastUsedDate: string;
    }> | null;
    [key: string]: any;
  }>;
  folders: Array<{
    name: string;
  }>;
  folderRelationships: Array<{
    key: number;   // cipher index
    value: number; // folder index
  }>;
}

function bindNull(v: any): any {
  return v === undefined ? null : v;
}

function readAliasedImportProp<T = unknown>(source: any, aliases: string[]): T | undefined {
  if (!source || typeof source !== 'object') return undefined;
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return source[key] as T;
    }
  }
  return undefined;
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

async function runBatchInChunks(db: D1Database, statements: D1PreparedStatement[], chunkSize: number): Promise<void> {
  for (let i = 0; i < statements.length; i += chunkSize) {
    const chunk = statements.slice(i, i + chunkSize);
    await db.batch(chunk);
  }
}

type ImportedCipher = CiphersImportRequest['ciphers'][number];

interface CipherOwner {
  userId: string | null;
  organizationId: string | null;
}

function buildImportedCipher(c: ImportedCipher, owner: CipherOwner, folderId: string | null, now: string): Cipher {
  const login = readAliasedImportProp<any | null>(c, ['login', 'Login']);
  const card = readAliasedImportProp<any | null>(c, ['card', 'Card']);
  const identity = readAliasedImportProp<any | null>(c, ['identity', 'Identity']);
  const secureNote = readAliasedImportProp<any | null>(c, ['secureNote', 'SecureNote']);
  const sshKey = readAliasedImportProp<any | null>(c, ['sshKey', 'SshKey']);
  const bankAccount = readAliasedImportProp<any | null>(c, ['bankAccount', 'BankAccount']);
  const driversLicense = readAliasedImportProp<any | null>(c, ['driversLicense', 'DriversLicense']);
  const passport = readAliasedImportProp<any | null>(c, ['passport', 'Passport']);
  const fields = readAliasedImportProp<any[] | null>(c, ['fields', 'Fields']);
  const passwordHistory = readAliasedImportProp<any[] | null>(c, ['passwordHistory', 'PasswordHistory']);
  const key = readAliasedImportProp<string | null>(c, ['key', 'Key']);

  const cipher: Cipher = {
    ...c,
    id: generateUUID(),
    userId: owner.userId,
    organizationId: owner.organizationId,
    type: c.type as CipherType,
    folderId: folderId,
    name: c.name ?? 'Untitled',
    notes: c.notes ?? null,
    favorite: owner.organizationId ? false : c.favorite ?? false,
    login: login ? {
      ...login,
      username: login.username ?? null,
      password: login.password ?? null,
      uris: login.uris?.map((u: any) => ({
        ...u,
        uri: u.uri ?? null,
        uriChecksum: u.uriChecksum ?? null,
        match: u.match ?? null,
      })) || null,
      totp: login.totp ?? null,
      autofillOnPageLoad: login.autofillOnPageLoad ?? null,
      fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null,
      uri: login.uri ?? null,
      passwordRevisionDate: login.passwordRevisionDate ?? null,
    } : null,
    card: card ? {
      ...card,
      cardholderName: card.cardholderName ?? null,
      brand: card.brand ?? null,
      number: card.number ?? null,
      expMonth: card.expMonth ?? null,
      expYear: card.expYear ?? null,
      code: card.code ?? null,
    } : null,
    identity: identity ? {
      ...identity,
      title: identity.title ?? null,
      firstName: identity.firstName ?? null,
      middleName: identity.middleName ?? null,
      lastName: identity.lastName ?? null,
      address1: identity.address1 ?? null,
      address2: identity.address2 ?? null,
      address3: identity.address3 ?? null,
      city: identity.city ?? null,
      state: identity.state ?? null,
      postalCode: identity.postalCode ?? null,
      country: identity.country ?? null,
      company: identity.company ?? null,
      email: identity.email ?? null,
      phone: identity.phone ?? null,
      ssn: identity.ssn ?? null,
      username: identity.username ?? null,
      passportNumber: identity.passportNumber ?? null,
      licenseNumber: identity.licenseNumber ?? null,
    } : null,
    secureNote: secureNote ?? null,
    fields: fields?.map((f: any) => ({
      ...f,
      name: f.name ?? null,
      value: f.value ?? null,
      type: f.type,
      linkedId: f.linkedId ?? null,
    })) || null,
    passwordHistory: passwordHistory ?? null,
    reprompt: c.reprompt ?? 0,
    sshKey: normalizeCipherSshKeyForCompatibility(sshKey ?? null),
    bankAccount: bankAccount ?? null,
    driversLicense: driversLicense ?? null,
    passport: passport ?? null,
    key: key ?? null,
    createdAt: now,
    updatedAt: now,
    archivedAt: null,
    deletedAt: null,
  };
  cipher.login = normalizeCipherLoginForStorage(cipher.login);
  return cipher;
}

function insertCipherStatement(db: D1Database, cipher: Cipher): D1PreparedStatement {
  return db
    .prepare(
      'INSERT INTO ciphers(id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(
      cipher.id,
      bindNull(cipher.userId),
      bindNull(cipher.organizationId),
      Number(cipher.type) || 1,
      bindNull(cipher.folderId),
      bindNull(cipher.name),
      bindNull(cipher.notes),
      cipher.favorite ? 1 : 0,
      JSON.stringify(cipher),
      bindNull(cipher.reprompt ?? 0),
      bindNull(cipher.key),
      cipher.createdAt,
      cipher.updatedAt,
      bindNull(cipher.archivedAt),
      bindNull(cipher.deletedAt)
    );
}

// POST /api/ciphers/import - Bitwarden client import endpoint
export async function handleCiphersImport(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const returnCipherMap = url.searchParams.get('returnCipherMap') === '1';

  let importData: CiphersImportRequest;
  try {
    importData = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const folders = Array.isArray(importData.folders) ? importData.folders : [];
  const ciphers = Array.isArray(importData.ciphers) ? importData.ciphers : [];
  const folderRelationships = Array.isArray(importData.folderRelationships) ? importData.folderRelationships : [];

  if (folders.length + ciphers.length > LIMITS.performance.importItemLimit) {
    return errorResponse(`Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();
  const batchChunkSize = LIMITS.performance.bulkMoveChunkSize;

  // Create folders and build index -> id mapping
  const folderIdMap = new Map<number, string>();
  const folderRows: Folder[] = [];
  
  for (let i = 0; i < folders.length; i++) {
    const importedFolder = folders[i] && typeof folders[i] === 'object' ? folders[i] : null;
    const folderId = generateUUID();
    folderIdMap.set(i, folderId);

    const folder: Folder = {
      id: folderId,
      userId: userId,
      name: typeof importedFolder?.name === 'string' && importedFolder.name ? importedFolder.name : 'Folder',
      createdAt: now,
      updatedAt: now,
    };

    folderRows.push(folder);
  }

  if (folderRows.length > 0) {
    const folderStatements = folderRows.map(folder =>
      env.DB
        .prepare(
          'INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ' +
          'ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, name=excluded.name, updated_at=excluded.updated_at'
        )
        .bind(folder.id, folder.userId, folder.name, folder.createdAt, folder.updatedAt)
    );
    await runBatchInChunks(env.DB, folderStatements, batchChunkSize);
  }

  // Build cipher index -> folder id mapping from relationships
  const cipherFolderMap = new Map<number, string>();
  for (const rel of folderRelationships) {
    if (!rel || typeof rel !== 'object') continue;
    const folderId = folderIdMap.get(rel.value);
    if (folderId) {
      cipherFolderMap.set(rel.key, folderId);
    }
  }
  const existingFolderIds = new Set((await storage.getAllFolders(userId)).map((folder) => folder.id));

  // Create ciphers
  const cipherRows: Cipher[] = [];
  const cipherMapRows: Array<{ index: number; sourceId: string | null; id: string }> = [];
  for (let i = 0; i < ciphers.length; i++) {
    const c = ciphers[i] && typeof ciphers[i] === 'object' ? ciphers[i] : {} as CiphersImportRequest['ciphers'][number];
    const importedFolderId = normalizeOptionalId(readAliasedImportProp<string | null>(c, ['folderId', 'FolderId']));
    const folderId = cipherFolderMap.get(i) || (importedFolderId && existingFolderIds.has(importedFolderId) ? importedFolderId : null);
    const sourceIdRaw = String(c?.id ?? '').trim();
    const sourceId = sourceIdRaw || null;
    const cipher = buildImportedCipher(c, { userId, organizationId: null }, folderId, now);
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) {
      return errorResponse(`Cipher ${i + 1}: ${compatibilityError}`, 400);
    }

    cipherRows.push(cipher);
    cipherMapRows.push({ index: i, sourceId, id: cipher.id });
  }

  if (cipherRows.length > 0) {
    await runBatchInChunks(env.DB, cipherRows.map((cipher) => insertCipherStatement(env.DB, cipher)), batchChunkSize);
  }

  // Update revision date
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));

  if (returnCipherMap) {
    return jsonResponse({
      object: 'import-result',
      cipherMap: cipherMapRows,
    });
  }

  return new Response(null, { status: 200 });
}

interface OrganizationImportRequest {
  ciphers?: unknown;
  collections?: unknown;
  collectionRelationships?: unknown;
}

interface ImportedCollection {
  id?: unknown;
  name?: unknown;
  externalId?: unknown;
}

interface ImportCollectionTargets {
  collectionIds: string[];
  newCollections: Collection[];
}

async function resolveImportCollections(
  context: OrganizationContext,
  inputs: readonly ImportedCollection[],
  now: string
): Promise<ImportCollectionTargets | Response> {
  const { actor, organization, store } = context;
  const existingIds = new Set((await store.getCollectionsForOrganizations([organization.id])).map((collection) => collection.id));
  const writable = writableCollectionIds(await loadOrganizationAccess(store, actor.userId), organization.id);
  const targets: ImportCollectionTargets = { collectionIds: [], newCollections: [] };
  for (const input of inputs) {
    const id = normalizeOptionalId(input?.id);
    if (id && existingIds.has(id)) {
      if (!writable.has(id)) return errorResponse('You do not have permission to import into one or more of these collections', 403);
      targets.collectionIds.push(id);
      continue;
    }
    if (!hasFullAccess(actor)) return errorResponse('You do not have permission to create collections', 403);
    if (!isValidEncString(input?.name)) return errorResponse('Collection name must be encrypted', 400);
    const collection: Collection = {
      id: generateUUID(),
      organizationId: organization.id,
      name: input.name.trim(),
      externalId: normalizeOptionalId(input.externalId),
      createdAt: now,
      updatedAt: now,
    };
    targets.newCollections.push(collection);
    targets.collectionIds.push(collection.id);
  }
  return targets;
}

function readCollectionLinks(input: unknown, cipherCount: number, collectionIds: readonly string[]): Map<number, string[]> | Response {
  if (input == null) return new Map();
  if (!Array.isArray(input)) return errorResponse('collectionRelationships must be a list', 400);
  const links = new Map<number, string[]>();
  for (const relation of input) {
    const cipherIndex = Number(relation?.key);
    const collectionId = collectionIds[Number(relation?.value)];
    if (!Number.isInteger(cipherIndex) || cipherIndex < 0 || cipherIndex >= cipherCount || !collectionId) {
      return errorResponse('Invalid collection relationship', 400);
    }
    links.set(cipherIndex, [...(links.get(cipherIndex) ?? []), collectionId]);
  }
  return links;
}

function buildOrganizationCiphers(inputs: readonly unknown[], organizationId: string, now: string): Cipher[] | Response {
  const ciphers: Cipher[] = [];
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i] && typeof inputs[i] === 'object' ? inputs[i] as ImportedCipher : {} as ImportedCipher;
    const cipher = buildImportedCipher(input, { userId: null, organizationId }, null, now);
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) return errorResponse(`Cipher ${i + 1}: ${compatibilityError}`, 400);
    ciphers.push(cipher);
  }
  return ciphers;
}

// POST /api/ciphers/import-organization?organizationId=
export async function handleOrganizationCiphersImport(request: Request, env: Env, userId: string): Promise<Response> {
  const organizationId = new URL(request.url).searchParams.get('organizationId') || '';
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const body = await readJsonBody<OrganizationImportRequest>(request);
  if (body instanceof Response) return body;

  const cipherInputs = Array.isArray(body.ciphers) ? body.ciphers : [];
  const collectionInputs = Array.isArray(body.collections) ? body.collections as ImportedCollection[] : [];
  if (cipherInputs.length + collectionInputs.length > LIMITS.performance.importItemLimit) {
    return errorResponse(`Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();
  const targets = await resolveImportCollections(context, collectionInputs, now);
  if (targets instanceof Response) return targets;
  const links = readCollectionLinks(body.collectionRelationships, cipherInputs.length, targets.collectionIds);
  if (links instanceof Response) return links;
  if (!hasFullAccess(context.actor) && cipherInputs.some((_, index) => !links.has(index))) {
    return errorResponse('Organization items must be in at least one collection', 400);
  }
  const ciphers = buildOrganizationCiphers(cipherInputs, organizationId, now);
  if (ciphers instanceof Response) return ciphers;

  for (const collection of targets.newCollections) await context.store.createCollection(collection, []);
  await runBatchInChunks(env.DB, ciphers.map((cipher) => insertCipherStatement(env.DB, cipher)), LIMITS.performance.bulkMoveChunkSize);
  await context.store.addCipherCollectionLinks(ciphers.flatMap((cipher, index) =>
    (links.get(index) ?? []).map((collectionId) => ({ cipherId: cipher.id, collectionId }))
  ));

  const audience = await context.store.getUserIdsWithCollectionAccess(organizationId, targets.collectionIds);
  await publishCiphersSync(request, env, context.storage, [...new Set([userId, ...audience])]);
  return new Response(null, { status: 200 });
}
