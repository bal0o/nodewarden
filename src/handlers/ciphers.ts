import {
  Env,
  Cipher,
  CipherCard,
  CipherIdentity,
  CipherLogin,
  CipherResponse,
  CipherSecureNote,
  CipherSshKey,
  CipherBankAccount,
  CipherDriversLicense,
  CipherPassport,
  Attachment,
  PasswordHistory,
  CipherUserSettings,
  cipherOwnerOf,
} from '../types';
import { StorageService } from '../services/storage';
import { OrganizationStore } from '../services/organization-store';
import {
  PERSONAL_CIPHER_ACCESS,
  loadOrganizationAccess,
  resolveCiphersForUser,
  writableCollectionIds,
  type CipherAccess,
  type ResolvedCipher,
} from '../services/organization-access';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { deleteAllAttachmentsForCipher, deleteAllAttachmentsForCiphers } from './attachments';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { readNullableFullUpdateField } from './cipher-full-update';
import { cipherAudience, publishCipherEvent, publishCiphersSync, publishVaultSync } from './cipher-events';

// CONTRACT:
// Cipher JSON is the highest-risk Bitwarden compatibility surface. Preserve
// unknown/future client fields by default, then override only server-owned
// fields. Any change to cipher response shape must be checked against /api/sync,
// attachments, import/export, and current official clients.
export interface CipherResponseOptions {
  preserveRepairableUris?: boolean;
  validFolderIds?: ReadonlySet<string>;
  access?: CipherAccess;
}

export function shouldPreserveRepairableCipherUris(request: Request): boolean {
  return request.headers.get('X-NodeWarden-Web') === '1';
}

function cipherResponseOptionsForRequest(request: Request): CipherResponseOptions {
  return { preserveRepairableUris: shouldPreserveRepairableCipherUris(request) };
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

function normalizeResponseFolderId(folderId: unknown, validFolderIds?: ReadonlySet<string>): string | null {
  const normalized = normalizeOptionalId(folderId);
  if (!normalized) return null;
  return validFolderIds && !validFolderIds.has(normalized) ? null : normalized;
}

function getAliasedProp(source: any, aliases: string[]): { present: boolean; value: any } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return { present: true, value: source[key] };
    }
  }
  return { present: false, value: undefined };
}

function readCipherProp<T = unknown>(source: any, aliases: string[]): { present: boolean; value: T | undefined } {
  return getAliasedProp(source, aliases) as { present: boolean; value: T | undefined };
}

function normalizeCipherTimestamp(value: unknown): string | null {
  if (value == null || value === '') return null;
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function readCipherArchivedAt(source: any, fallback: string | null = null): string | null {
  const archived = getAliasedProp(source, ['archivedAt', 'ArchivedAt', 'archivedDate', 'ArchivedDate']);
  return archived.present ? normalizeCipherTimestamp(archived.value) : fallback;
}

function readCipherRevisionDate(source: any): string | null {
  const revision = getAliasedProp(source, ['lastKnownRevisionDate', 'LastKnownRevisionDate']);
  return revision.present ? normalizeCipherTimestamp(revision.value) : null;
}

function isStaleCipherUpdate(existingUpdatedAt: string, clientRevisionDate: string | null): boolean {
  if (!clientRevisionDate) return false;
  const existingTs = Date.parse(existingUpdatedAt);
  const clientTs = Date.parse(clientRevisionDate);
  if (Number.isNaN(existingTs) || Number.isNaN(clientTs)) return false;
  return existingTs > clientTs;
}

function syncCipherComputedAliases(cipher: Cipher): Cipher {
  cipher.archivedDate = cipher.archivedAt ?? null;
  cipher.deletedDate = cipher.deletedAt ?? null;
  return cipher;
}

async function writeCipherAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'cipher',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

export function isValidEncString(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  const dot = trimmed.indexOf('.');
  if (dot <= 0) return false;
  const type = Number(trimmed.slice(0, dot));
  if (!Number.isInteger(type) || type < 0) return false;
  const parts = trimmed.slice(dot + 1).split('|');
  if (parts.some((part) => part.length === 0)) return false;

  // Bitwarden's legacy symmetric EncString variants require IV + data,
  // while the authenticated AES-CBC-HMAC variant requires IV + data + MAC.
  if (type === 0 || type === 1) return parts.length >= 2;
  if (type === 2) return parts.length === 3;
  if (type === 3 || type === 4) return parts.length === 1;
  if (type === 5 || type === 6) return parts.length === 2;

  // Keep newer one-part formats, such as COSE Encrypt0, future-compatible.
  return parts.length >= 1;
}

function optionalEncString(value: unknown): string | null {
  if (value == null || value === '') return null;
  return isValidEncString(value) ? value.trim() : null;
}

function optionalEncStringWithin(value: unknown, maxLength: number): string | null {
  const normalized = optionalEncString(value);
  if (!normalized) return null;
  return normalized.length <= maxLength ? normalized : null;
}

function shouldAcceptCipherKey(value: unknown): boolean {
  return value == null || value === '' || isValidEncString(value);
}

function normalizeCipherKeyForStorage(value: unknown): string | null {
  return optionalEncString(value);
}

function sanitizeEncryptedObject<T extends Record<string, any>>(
  source: T | null | undefined,
  encryptedKeys: readonly string[] | Record<string, number>
): T | null {
  if (!source || typeof source !== 'object') return source ?? null;
  const next: Record<string, any> = { ...source };
  const entries = Array.isArray(encryptedKeys)
    ? encryptedKeys.map((key) => [key, 10000] as const)
    : Object.entries(encryptedKeys);
  for (const [key, maxLength] of entries) {
    if (!Object.prototype.hasOwnProperty.call(next, key)) continue;
    next[key] = optionalEncStringWithin(next[key], maxLength);
  }
  return next as T;
}

const BANK_ACCOUNT_ENCRYPTED_KEYS = [
  'bankName',
  'nameOnAccount',
  'accountType',
  'accountNumber',
  'routingNumber',
  'branchNumber',
  'pin',
  'swiftCode',
  'iban',
  'bankContactPhone',
] as const;

const DRIVERS_LICENSE_ENCRYPTED_KEYS = [
  'firstName',
  'middleName',
  'lastName',
  'dateOfBirth',
  'licenseNumber',
  'issuingCountry',
  'issuingState',
  'issueDate',
  'expirationDate',
  'issuingAuthority',
  'licenseClass',
] as const;

const PASSPORT_ENCRYPTED_KEYS = [
  'surname',
  'givenName',
  'dateOfBirth',
  'sex',
  'birthPlace',
  'nationality',
  'issuingCountry',
  'passportNumber',
  'passportType',
  'nationalIdentificationNumber',
  'issuingAuthority',
  'issueDate',
  'expirationDate',
] as const;

function normalizeCipherForStorage(cipher: Cipher): Cipher {
  cipher.login = normalizeCipherLoginForStorage(cipher.login);
  cipher.sshKey = normalizeCipherSshKeyForCompatibility(cipher.sshKey);
  cipher.folderId = normalizeOptionalId(cipher.folderId);
  const hasArchivedAt = Object.prototype.hasOwnProperty.call(cipher as object, 'archivedAt');
  cipher.archivedAt = hasArchivedAt
    ? normalizeCipherTimestamp(cipher.archivedAt) ?? null
    : normalizeCipherTimestamp(cipher.archivedDate) ?? null;
  return syncCipherComputedAliases(cipher);
}

export function normalizeCipherLoginForStorage(login: any): any {
  if (!login || typeof login !== 'object') return login ?? null;
  return {
    ...login,
    fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null,
  };
}

export function normalizeCipherLoginForCompatibility(
  login: any,
  requiresUriChecksum: boolean = false,
  preserveRepairableUris: boolean = false
): any {
  const normalized = normalizeCipherLoginForStorage(login);
  if (!normalized || typeof normalized !== 'object') return normalized ?? null;
  const next = sanitizeEncryptedObject(normalized, {
    username: 1000,
    password: 5000,
    totp: 1000,
    uri: 10000,
  });
  if (!next) return null;
  next.uris = normalizeCipherLoginUrisForCompatibility(next.uris, {
    requiresUriChecksum,
    preserveRepairableUris,
  });
  next.fido2Credentials = normalizeFido2CredentialsForCompatibility(next.fido2Credentials);
  return next;
}

function normalizeCipherLoginUrisForCompatibility(
  uris: any,
  options: { requiresUriChecksum?: boolean; preserveRepairableUris?: boolean } = {}
): any[] | null {
  if (!Array.isArray(uris) || uris.length === 0) return null;
  const out: any[] = [];

  for (const uri of uris) {
    if (!uri || typeof uri !== 'object') continue;
    const next = sanitizeEncryptedObject(uri, ['uri', 'uriChecksum']);
    if (!next) continue;

    const hasUri = isValidEncString(next.uri);
    const hasChecksum = isValidEncString(next.uriChecksum);
    const hasMatch = next.match != null;

    if (hasUri && String(next.uri).trim().length > 10000) continue;
    if (hasChecksum && String(next.uriChecksum).trim().length > 10000) {
      next.uriChecksum = null;
    }

    if (hasUri && isValidEncString(next.uriChecksum)) {
      out.push(next);
      continue;
    }

    if (hasUri && !hasChecksum) {
      // Official Bitwarden treats UriChecksum as nullable encrypted metadata.
      // Keep the URI intact and let clients that can repair checksums do so.
      out.push({ ...next, uriChecksum: null });
      continue;
    }

    if (hasChecksum || hasMatch) {
      out.push(next);
    }
  }

  return out.length ? out : null;
}

export function validateCipherEncryptedFieldsForCompatibility(cipher: Cipher): string | null {
  if (cipher.name != null && !optionalEncStringWithin(cipher.name, 1000)) return 'Cipher name must be an encrypted string up to 1000 characters.';
  if (cipher.notes != null && !optionalEncStringWithin(cipher.notes, 10000)) return 'Cipher notes must be an encrypted string up to 10000 characters.';

  const login = cipher.login as any;
  if (login && typeof login === 'object') {
    if (login.username != null && !optionalEncStringWithin(login.username, 1000)) return 'Login username must be an encrypted string up to 1000 characters.';
    if (login.password != null && !optionalEncStringWithin(login.password, 5000)) return 'Login password must be an encrypted string up to 5000 characters.';
    if (login.totp != null && !optionalEncStringWithin(login.totp, 1000)) return 'Login TOTP must be an encrypted string up to 1000 characters.';
    if (login.uri != null && !optionalEncStringWithin(login.uri, 10000)) return 'Login URI must be an encrypted string up to 10000 characters.';

    if (Array.isArray(login.uris)) {
      for (const uri of login.uris) {
        if (!uri || typeof uri !== 'object') continue;
        if (uri.uri != null && !optionalEncStringWithin(uri.uri, 10000)) return 'Login URI must be an encrypted string up to 10000 characters.';
        if (uri.uriChecksum != null && !optionalEncStringWithin(uri.uriChecksum, 10000)) return 'Login URI checksum must be an encrypted string up to 10000 characters.';
      }
    }

    // Validate FIDO2 credentials — all encrypted-string fields, both required and optional, must be valid.
    if (Array.isArray(login.fido2Credentials)) {
      const fido2EncryptedKeys = ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable', 'userHandle', 'userName', 'rpName', 'userDisplayName'];
      for (const cred of login.fido2Credentials) {
        if (!cred || typeof cred !== 'object') continue;
        for (const key of fido2EncryptedKeys) {
          if (cred[key] != null && !isValidEncString(cred[key])) return `FIDO2 credential ${key} must be an encrypted string.`;
        }
      }
    }
  }

  // Validate SSH key fields — all three must be encrypted strings.
  const sshKey = cipher.sshKey as any;
  if (sshKey && typeof sshKey === 'object') {
    if (sshKey.privateKey != null && !isValidEncString(sshKey.privateKey)) return 'SSH key private key must be an encrypted string.';
    if (sshKey.publicKey != null && !isValidEncString(sshKey.publicKey)) return 'SSH key public key must be an encrypted string.';
    const fingerprint = sshKey.keyFingerprint ?? sshKey.fingerprint;
    if (fingerprint != null && !isValidEncString(fingerprint)) return 'SSH key fingerprint must be an encrypted string.';
  }

  const typedEncryptedObjects: Array<[string, any, readonly string[]]> = [
    ['Bank account', (cipher as any).bankAccount, BANK_ACCOUNT_ENCRYPTED_KEYS],
    ['Drivers license', (cipher as any).driversLicense, DRIVERS_LICENSE_ENCRYPTED_KEYS],
    ['Passport', (cipher as any).passport, PASSPORT_ENCRYPTED_KEYS],
  ];
  for (const [label, source, keys] of typedEncryptedObjects) {
    if (!source || typeof source !== 'object') continue;
    for (const key of keys) {
      if (source[key] != null && !optionalEncStringWithin(source[key], 10000)) {
        return `${label} ${key} must be an encrypted string.`;
      }
    }
  }

  // Validate password history — each password must be an encrypted string.
  if (Array.isArray(cipher.passwordHistory)) {
    for (const entry of cipher.passwordHistory) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.password != null && !isValidEncString(entry.password)) return 'Password history entry must be an encrypted string.';
    }
  }

  return null;
}

function normalizeFido2CredentialsForCompatibility(credentials: any): any[] | null {
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  const requiredEncryptedKeys = [
    'credentialId',
    'keyType',
    'keyAlgorithm',
    'keyCurve',
    'keyValue',
    'rpId',
    'counter',
    'discoverable',
  ];
  const optionalEncryptedKeys = ['userHandle', 'userName', 'rpName', 'userDisplayName'];
  const out: any[] = [];

  for (const credential of credentials) {
    if (!credential || typeof credential !== 'object') continue;
    const next: Record<string, any> = { ...credential };
    let valid = true;
    for (const key of requiredEncryptedKeys) {
      if (!isValidEncString(next[key])) {
        valid = false;
        break;
      }
      next[key] = String(next[key]).trim();
    }
    if (!valid) continue;
    for (const key of optionalEncryptedKeys) {
      if (Object.prototype.hasOwnProperty.call(next, key)) {
        next[key] = optionalEncString(next[key]);
      }
    }
    out.push(next);
  }

  return out.length ? out : null;
}

// Android 2026.2.0 requires sshKey.keyFingerprint in sync payloads.
// Keep legacy alias "fingerprint" in parallel for older web payloads.
export function normalizeCipherSshKeyForCompatibility(sshKey: any): any {
  if (!sshKey || typeof sshKey !== 'object') return sshKey ?? null;

  const candidate =
    sshKey.keyFingerprint !== undefined && sshKey.keyFingerprint !== null
      ? sshKey.keyFingerprint
      : sshKey.fingerprint;

  const normalizedFingerprint =
    candidate === undefined || candidate === null
      ? ''
      : String(candidate);

  if (
    !isValidEncString(sshKey.privateKey) ||
    !isValidEncString(sshKey.publicKey) ||
    !isValidEncString(normalizedFingerprint)
  ) {
    return null;
  }

  return {
    ...sshKey,
    privateKey: String(sshKey.privateKey).trim(),
    publicKey: String(sshKey.publicKey).trim(),
    keyFingerprint: normalizedFingerprint,
    fingerprint: normalizedFingerprint,
  };
}

function normalizeCipherSecureNoteForCompatibility(secureNote: any): CipherSecureNote | null {
  if (!secureNote || typeof secureNote !== 'object') return null;
  const type = Number(secureNote?.type ?? secureNote?.Type ?? 0);
  return {
    ...secureNote,
    type: Number.isFinite(type) ? type : 0,
  };
}

// Format attachments for API response
export function formatAttachments(attachments: Attachment[]): any[] | null {
  if (attachments.length === 0) return null;
  const formatted = attachments
    .filter((a) => isValidEncString(a.fileName))
    .map(a => ({
      id: a.id,
      fileName: a.fileName.trim(),
      // Bitwarden clients decode attachment size as string in cipher payloads.
      size: String(Number(a.size) || 0),
      sizeName: a.sizeName,
      key: optionalEncString(a.key),
      url: `/api/ciphers/${a.cipherId}/attachment/${a.id}`,  // Android requires non-null url!
      object: 'attachment',
    }));
  return formatted.length ? formatted : null;
}

function formatAttachmentSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

interface IncomingAttachmentMetadata {
  id: string;
  fileName?: unknown;
  key?: unknown;
  fileSize?: unknown;
  hasFileName: boolean;
  hasKey: boolean;
  hasFileSize: boolean;
}

function readIncomingAttachmentMetadataMap(
  value: unknown,
  options: { legacyFileNameMap?: boolean } = {}
): IncomingAttachmentMetadata[] {
  if (!value || typeof value !== 'object') return [];
  const out: IncomingAttachmentMetadata[] = [];

  if (Array.isArray(value)) {
    for (const item of value) {
      if (!item || typeof item !== 'object') continue;
      const row = item as Record<string, unknown>;
      const id = String(row.id ?? row.Id ?? '').trim();
      if (!id) continue;
      const fileName = getAliasedProp(row, ['fileName', 'FileName']);
      const key = getAliasedProp(row, ['key', 'Key']);
      const fileSize = getAliasedProp(row, ['fileSize', 'FileSize', 'size', 'Size']);
      out.push({
        id,
        fileName: fileName.value,
        key: key.value,
        fileSize: fileSize.value,
        hasFileName: fileName.present,
        hasKey: key.present,
        hasFileSize: fileSize.present,
      });
    }
    return out;
  }

  for (const [rawId, rawValue] of Object.entries(value as Record<string, unknown>)) {
    const id = String(rawId || '').trim();
    if (!id) continue;

    if (options.legacyFileNameMap && (typeof rawValue === 'string' || rawValue == null)) {
      out.push({
        id,
        fileName: rawValue,
        key: undefined,
        fileSize: undefined,
        hasFileName: rawValue != null,
        hasKey: false,
        hasFileSize: false,
      });
      continue;
    }

    if (!rawValue || typeof rawValue !== 'object') continue;
    const row = rawValue as Record<string, unknown>;
    const fileName = getAliasedProp(row, ['fileName', 'FileName']);
    const key = getAliasedProp(row, ['key', 'Key']);
    const fileSize = getAliasedProp(row, ['fileSize', 'FileSize', 'size', 'Size']);
    out.push({
      id,
      fileName: fileName.value,
      key: key.value,
      fileSize: fileSize.value,
      hasFileName: fileName.present,
      hasKey: key.present,
      hasFileSize: fileSize.present,
    });
  }

  return out;
}

function readIncomingAttachmentMetadata(source: any): IncomingAttachmentMetadata[] {
  const merged = new Map<string, IncomingAttachmentMetadata>();
  const legacy = getAliasedProp(source, ['attachments', 'Attachments']);
  const current = getAliasedProp(source, ['attachments2', 'Attachments2']);

  if (legacy.present) {
    for (const item of readIncomingAttachmentMetadataMap(legacy.value, { legacyFileNameMap: true })) {
      merged.set(item.id, item);
    }
  }

  if (current.present) {
    for (const item of readIncomingAttachmentMetadataMap(current.value)) {
      const previous = merged.get(item.id);
      merged.set(item.id, {
        id: item.id,
        fileName: item.hasFileName ? item.fileName : previous?.fileName,
        key: item.hasKey ? item.key : previous?.key,
        fileSize: item.hasFileSize ? item.fileSize : previous?.fileSize,
        hasFileName: item.hasFileName || previous?.hasFileName || false,
        hasKey: item.hasKey || previous?.hasKey || false,
        hasFileSize: item.hasFileSize || previous?.hasFileSize || false,
      });
    }
  }

  return [...merged.values()];
}

async function syncIncomingAttachmentMetadata(
  storage: StorageService,
  cipherId: string,
  cipherData: any
): Promise<void> {
  const incoming = readIncomingAttachmentMetadata(cipherData);
  if (!incoming.length) return;

  const currentById = new Map((await storage.getAttachmentsByCipher(cipherId)).map((attachment) => [attachment.id, attachment]));
  for (const item of incoming) {
    const attachment = currentById.get(item.id);
    if (!attachment) continue;

    let changed = false;
    if (item.hasFileName) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName) && fileName !== attachment.fileName) {
        attachment.fileName = fileName;
        changed = true;
      }
    }

    if (item.hasKey) {
      const key = optionalEncString(item.key);
      if (key !== attachment.key) {
        attachment.key = key;
        changed = true;
      }
    }

    if (item.hasFileSize) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0 && size !== Number(attachment.size || 0)) {
        attachment.size = size;
        attachment.sizeName = formatAttachmentSize(size);
        changed = true;
      }
    }

    if (changed) {
      await storage.saveAttachment(attachment);
    }
  }
}

export function applyCipherEmbeddedAttachmentMetadata(cipherData: any, attachments: Attachment[]): Attachment[] {
  const incoming = readIncomingAttachmentMetadata(cipherData);
  if (!incoming.length || !attachments.length) return attachments;

  const incomingById = new Map(incoming.map((item) => [item.id, item]));
  return attachments.map((attachment) => {
    const item = incomingById.get(attachment.id);
    if (!item) return attachment;

    const next: Attachment = { ...attachment };
    if (item.hasFileName) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName)) {
        next.fileName = fileName;
      }
    }
    if (item.hasKey) {
      next.key = optionalEncString(item.key);
    }
    if (item.hasFileSize) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0) {
        next.size = size;
        next.sizeName = formatAttachmentSize(size);
      }
    }
    return next;
  });
}

function normalizeCipherFieldsForCompatibility(fields: any): any[] | null {
  if (!Array.isArray(fields) || fields.length === 0) return null;
  const out = fields
    .map((field: any) => {
      if (!field || typeof field !== 'object') return null;
      return {
        ...field,
        name: optionalEncString(field.name),
        value: optionalEncString(field.value),
        type: Number(field.type) || 0,
        linkedId: field.linkedId ?? null,
      };
    })
    .filter(Boolean);
  return out.length ? out : null;
}

function normalizePasswordHistoryForCompatibility(passwordHistory: any): PasswordHistory[] | null {
  if (!Array.isArray(passwordHistory) || passwordHistory.length === 0) return null;
  const out = passwordHistory
    .filter((entry: any) => entry && typeof entry === 'object' && isValidEncString(entry.password))
    .map((entry: any) => ({
      ...entry,
      password: String(entry.password).trim(),
      lastUsedDate: normalizeCipherTimestamp(entry.lastUsedDate) ?? new Date().toISOString(),
    }));
  return out.length ? out : null;
}

export function isCipherResponseSyncCompatible(cipher: CipherResponse): boolean {
  return isValidEncString(cipher.name);
}

// Convert internal cipher to API response format.
// Uses opaque passthrough: spreads ALL stored fields (including unknown/future ones),
// then overlays server-computed fields. This ensures new Bitwarden client fields
// survive a round-trip without code changes.
export function cipherToResponse(
  cipher: Cipher,
  attachments: Attachment[] = [],
  options: CipherResponseOptions = {}
): CipherResponse {
  // Strip internal-only fields that must not appear in the API response
  const { userId, createdAt, updatedAt, archivedAt, deletedAt, ...passthrough } = cipher;
  const responseCipherKey = optionalEncString(cipher.key);
  const normalizedLogin = normalizeCipherLoginForCompatibility(
    (passthrough as any).login ?? null,
    !!responseCipherKey,
    !!options.preserveRepairableUris
  );
  const normalizedCard = sanitizeEncryptedObject((passthrough as any).card ?? null, {
    cardholderName: 1000,
    brand: 1000,
    number: 1000,
    expMonth: 1000,
    expYear: 1000,
    code: 1000,
  });
  const normalizedIdentity = sanitizeEncryptedObject((passthrough as any).identity ?? null, [
    'title',
    'firstName',
    'middleName',
    'lastName',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
    'company',
    'email',
    'phone',
    'ssn',
    'username',
    'passportNumber',
    'licenseNumber',
  ]);
  const normalizedSshKey = normalizeCipherSshKeyForCompatibility((passthrough as any).sshKey ?? null);
  const normalizedBankAccount = sanitizeEncryptedObject(
    (passthrough as any).bankAccount ?? null,
    BANK_ACCOUNT_ENCRYPTED_KEYS
  );
  const normalizedDriversLicense = sanitizeEncryptedObject(
    (passthrough as any).driversLicense ?? null,
    DRIVERS_LICENSE_ENCRYPTED_KEYS
  );
  const normalizedPassport = sanitizeEncryptedObject(
    (passthrough as any).passport ?? null,
    PASSPORT_ENCRYPTED_KEYS
  );
  const responseType = Number(cipher.type) || 1;
  const normalizedSecureNote = responseType === 2
    ? normalizeCipherSecureNoteForCompatibility((passthrough as any).secureNote ?? null) ?? { type: 0 }
    : null;
  const responseAttachments = applyCipherEmbeddedAttachmentMetadata(cipher, attachments);
  const access = options.access ?? PERSONAL_CIPHER_ACCESS;
  const viewerSettings: CipherUserSettings = access.settings ?? { folderId: cipher.folderId, favorite: !!cipher.favorite };

  return {
    // Pass through ALL stored cipher fields (known + unknown)
    ...passthrough,
    // Server-computed / enforced fields (always override)
    folderId: normalizeResponseFolderId(viewerSettings.folderId, options.validFolderIds),
    favorite: viewerSettings.favorite,
    type: responseType,
    organizationId: cipher.organizationId,
    organizationUseTotp: !!cipher.organizationId,
    creationDate: createdAt,
    revisionDate: updatedAt,
    deletedDate: deletedAt,
    archivedDate: archivedAt ?? null,
    edit: access.edit,
    viewPassword: access.viewPassword,
    permissions: { delete: access.manage, restore: access.manage },
    object: 'cipherDetails',
    collectionIds: access.collectionIds,
    attachments: formatAttachments(responseAttachments),
    name: isValidEncString(cipher.name) ? cipher.name.trim() : cipher.name,
    notes: optionalEncString(cipher.notes),
    login: normalizedLogin,
    card: normalizedCard,
    identity: normalizedIdentity,
    secureNote: normalizedSecureNote,
    fields: normalizeCipherFieldsForCompatibility((passthrough as any).fields),
    passwordHistory: normalizePasswordHistoryForCompatibility((passthrough as any).passwordHistory),
    sshKey: normalizedSshKey,
    bankAccount: responseType === 6 ? normalizedBankAccount : null,
    driversLicense: responseType === 7 ? normalizedDriversLicense : null,
    passport: responseType === 8 ? normalizedPassport : null,
    key: responseCipherKey,
    data: typeof (passthrough as any).data === 'string' ? (passthrough as any).data : null,
    encryptedFor: (passthrough as any).encryptedFor ?? null,
  };
}

export async function resolveCipherForUser(
  env: Env,
  storage: StorageService,
  userId: string,
  id: string
): Promise<ResolvedCipher | null> {
  const cipher = await storage.getCipherForUser(id, userId);
  if (!cipher) return null;
  const [resolved] = await resolveCiphersForUser(new OrganizationStore(env.DB), userId, [cipher]);
  return resolved ?? null;
}

async function resolveCiphersByIds(env: Env, storage: StorageService, userId: string, ids: string[]): Promise<ResolvedCipher[]> {
  const ciphers = await storage.getCiphersByIds(ids, userId);
  return resolveCiphersForUser(new OrganizationStore(env.DB), userId, ciphers);
}

function cipherNotFound(): Response {
  return errorResponse('Cipher not found', 404);
}

function cipherNotEditable(): Response {
  return errorResponse('You do not have permission to edit this item', 403);
}

function cipherNotManageable(): Response {
  return errorResponse('You do not have permission to delete or restore this item', 403);
}

function readCipherPayload(body: any): any {
  // Android client sends PascalCase "Cipher" for organization ciphers
  return body.Cipher || body.cipher || body;
}

export function readCollectionIds(body: any): string[] | null {
  const raw = body?.collectionIds ?? body?.CollectionIds;
  if (!Array.isArray(raw)) return null;
  return Array.from(new Set(raw.map((id: unknown) => String(id || '').trim()).filter(Boolean)));
}

function readOrganizationId(cipherData: any): string | null {
  return normalizeOptionalId(readCipherProp<string | null>(cipherData, ['organizationId', 'OrganizationId']).value);
}

function responseWithAccess(
  request: Request,
  access: CipherAccess,
  validFolderIds?: ReadonlySet<string>
): CipherResponseOptions {
  return { ...cipherResponseOptionsForRequest(request), access, validFolderIds };
}

// GET /api/ciphers
export async function handleGetCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const includeDeleted = url.searchParams.get('deleted') === 'true';
  const pagination = parsePagination(url);

  let filteredCiphers: Cipher[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getCiphersPage(
      userId,
      includeDeleted,
      pagination.limit + 1,
      pagination.offset
    );
    const hasNext = pageRows.length > pagination.limit;
    filteredCiphers = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + filteredCiphers.length) : null;
  } else {
    const ciphers = await storage.getAllCiphers(userId);
    filteredCiphers = includeDeleted
      ? ciphers
      : ciphers.filter(c => !c.deletedAt);
  }

  const resolved = await resolveCiphersForUser(new OrganizationStore(env.DB), userId, filteredCiphers);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(resolved.map(({ cipher }) => cipher.id));
  const validFolderIds = new Set((await storage.getAllFolders(userId)).map((folder) => folder.id));

  // Build responses only for the current page to keep pagination cheap.
  const cipherResponses: CipherResponse[] = resolved.map(({ cipher, access }) =>
    cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], responseWithAccess(request, access, validFolderIds))
  );

  return jsonResponse({
    data: cipherResponses,
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/ciphers/:id
export async function handleGetCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();

  const attachments = await storage.getAttachmentsByCipher(resolved.cipher.id);
  return jsonResponse(cipherToResponse(resolved.cipher, attachments, responseWithAccess(request, resolved.access)));
}

async function verifyFolderOwnership(storage: StorageService, folderId: string | null | undefined, userId: string): Promise<boolean> {
  if (!folderId) return true;
  const folder = await storage.getFolderForUser(folderId, userId);
  return !!folder;
}

function buildNewCipher(cipherData: any, now: string): Cipher | Response {
  const createFolderId = readCipherProp<string | null>(cipherData, ['folderId', 'FolderId']);
  const createKey = readCipherProp<string | null>(cipherData, ['key', 'Key']);
  const createLogin = readCipherProp<CipherLogin | null>(cipherData, ['login', 'Login']);
  const createCard = readCipherProp<CipherCard | null>(cipherData, ['card', 'Card']);
  const createIdentity = readCipherProp<CipherIdentity | null>(cipherData, ['identity', 'Identity']);
  const createSecureNote = readCipherProp<CipherSecureNote | null>(cipherData, ['secureNote', 'SecureNote']);
  const createSshKey = readCipherProp<CipherSshKey | null>(cipherData, ['sshKey', 'SshKey']);
  const createBankAccount = readCipherProp<CipherBankAccount | null>(cipherData, ['bankAccount', 'BankAccount']);
  const createDriversLicense = readCipherProp<CipherDriversLicense | null>(cipherData, ['driversLicense', 'DriversLicense']);
  const createPassport = readCipherProp<CipherPassport | null>(cipherData, ['passport', 'Passport']);
  const createPasswordHistory = readCipherProp<PasswordHistory[] | null>(cipherData, ['passwordHistory', 'PasswordHistory']);

  if (createKey.present && !shouldAcceptCipherKey(createKey.value)) {
    return errorResponse('Cipher key encryption is not supported by this server. Resync the client and try again.', 400);
  }

  // Opaque passthrough: spread ALL client fields to preserve unknown/future ones,
  // then override only server-controlled fields.
  const cipher: Cipher = {
    ...cipherData,
    id: generateUUID(),
    userId: null,
    organizationId: null,
    type: Number(cipherData.type) || 1,
    favorite: !!cipherData.favorite,
    reprompt: cipherData.reprompt || 0,
    createdAt: now,
    updatedAt: now,
    archivedAt: readCipherArchivedAt(cipherData, null),
    deletedAt: null,
  };
  cipher.folderId = createFolderId.present ? normalizeOptionalId(createFolderId.value) : normalizeOptionalId(cipher.folderId);
  cipher.key = normalizeCipherKeyForStorage(createKey.present ? createKey.value : cipher.key);
  cipher.login = createLogin.present ? (createLogin.value ?? null) : (cipher.login ?? null);
  cipher.card = createCard.present ? (createCard.value ?? null) : (cipher.card ?? null);
  cipher.identity = createIdentity.present ? (createIdentity.value ?? null) : (cipher.identity ?? null);
  cipher.secureNote = createSecureNote.present ? (createSecureNote.value ?? null) : (cipher.secureNote ?? null);
  cipher.sshKey = createSshKey.present ? (createSshKey.value ?? null) : (cipher.sshKey ?? null);
  cipher.bankAccount = createBankAccount.present ? (createBankAccount.value ?? null) : ((cipher as any).bankAccount ?? null);
  cipher.driversLicense = createDriversLicense.present ? (createDriversLicense.value ?? null) : ((cipher as any).driversLicense ?? null);
  cipher.passport = createPassport.present ? (createPassport.value ?? null) : ((cipher as any).passport ?? null);
  cipher.passwordHistory = createPasswordHistory.present ? (createPasswordHistory.value ?? null) : (cipher.passwordHistory ?? null);
  const createFields = getAliasedProp(cipherData, ['fields', 'Fields']);
  cipher.fields = createFields.present ? (createFields.value ?? null) : (cipher.fields ?? null);
  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);
  return cipher;
}

async function authorizeOrganizationPlacement(
  env: Env,
  userId: string,
  organizationId: string,
  collectionIds: readonly string[]
): Promise<Response | null> {
  const access = await loadOrganizationAccess(new OrganizationStore(env.DB), userId);
  if (!access.memberships.has(organizationId)) {
    return errorResponse('You are not a confirmed member of this organization', 403);
  }
  if (!collectionIds.length) {
    return errorResponse('Select at least one collection for organization items', 400);
  }
  const writable = writableCollectionIds(access, organizationId);
  if (collectionIds.some((collectionId) => !writable.has(collectionId))) {
    return errorResponse('You do not have permission to add items to one or more of these collections', 403);
  }
  return null;
}

function moveViewerSettingsOffCipher(cipher: Cipher): CipherUserSettings {
  const settings = { folderId: normalizeOptionalId(cipher.folderId), favorite: !!cipher.favorite };
  cipher.folderId = null;
  cipher.favorite = false;
  return settings;
}

async function saveOrganizationCipherPlacement(
  env: Env,
  userId: string,
  cipher: Cipher,
  collectionIds: readonly string[],
  settings: CipherUserSettings
): Promise<void> {
  const store = new OrganizationStore(env.DB);
  await store.setCipherCollections(cipher.id, collectionIds);
  await store.saveCipherUserSettings(cipher.id, userId, settings);
}

async function resolvedResponse(
  request: Request,
  env: Env,
  storage: StorageService,
  userId: string,
  cipher: Cipher,
  status: number = 200
): Promise<Response> {
  const [resolved] = await resolveCiphersForUser(new OrganizationStore(env.DB), userId, [cipher]);
  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(cipherToResponse(cipher, attachments, responseWithAccess(request, resolved?.access ?? PERSONAL_CIPHER_ACCESS)), status);
}

async function createCipher(
  request: Request,
  env: Env,
  userId: string,
  cipherData: any,
  collectionIds: string[] | null
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const built = buildNewCipher(cipherData, new Date().toISOString());
  if (built instanceof Response) return built;
  const cipher = built;

  if (cipher.folderId && !(await verifyFolderOwnership(storage, cipher.folderId, userId))) {
    return errorResponse('Folder not found', 404);
  }

  const organizationId = readOrganizationId(cipherData);
  if (!organizationId) {
    cipher.userId = userId;
    await storage.saveCipher(cipher);
    await publishCipherEvent(request, env, storage, cipher, 'create', [userId]);
    return jsonResponse(cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request)), 200);
  }

  const placementError = await authorizeOrganizationPlacement(env, userId, organizationId, collectionIds ?? []);
  if (placementError) return placementError;
  cipher.organizationId = organizationId;
  const settings = moveViewerSettingsOffCipher(cipher);
  await storage.saveCipher(cipher);
  await saveOrganizationCipherPlacement(env, userId, cipher, collectionIds ?? [], settings);
  await publishCipherEvent(request, env, storage, cipher, 'create');
  return resolvedResponse(request, env, storage, userId, cipher);
}

// POST /api/ciphers, /api/ciphers/create and /api/ciphers/admin
export async function handleCreateCipher(request: Request, env: Env, userId: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  return createCipher(request, env, userId, readCipherPayload(body), readCollectionIds(body));
}

function mergeCipherUpdate(request: Request, existingCipher: Cipher, body: any): Cipher | Response {
  const cipherData = readCipherPayload(body);
  const incomingFolderId = readCipherProp<string | null>(cipherData, ['folderId', 'FolderId']);
  const incomingKey = readCipherProp<string | null>(cipherData, ['key', 'Key']);
  const incomingLogin = readCipherProp<CipherLogin | null>(cipherData, ['login', 'Login']);
  const incomingCard = readCipherProp<CipherCard | null>(cipherData, ['card', 'Card']);
  const incomingIdentity = readCipherProp<CipherIdentity | null>(cipherData, ['identity', 'Identity']);
  const incomingSecureNote = readCipherProp<CipherSecureNote | null>(cipherData, ['secureNote', 'SecureNote']);
  const incomingSshKey = readCipherProp<CipherSshKey | null>(cipherData, ['sshKey', 'SshKey']);
  const incomingBankAccount = readCipherProp<CipherBankAccount | null>(cipherData, ['bankAccount', 'BankAccount']);
  const incomingDriversLicense = readCipherProp<CipherDriversLicense | null>(cipherData, ['driversLicense', 'DriversLicense']);
  const incomingPassport = readCipherProp<CipherPassport | null>(cipherData, ['passport', 'Passport']);
  const incomingPasswordHistory = readCipherProp<PasswordHistory[] | null>(cipherData, ['passwordHistory', 'PasswordHistory']);
  const incomingRevisionDate = readCipherRevisionDate(cipherData);
  const preserveRevisionDate =
    shouldPreserveRepairableCipherUris(request)
    && (body.preserveRevisionDate === true || cipherData.preserveRevisionDate === true);

  if (incomingKey.present && !shouldAcceptCipherKey(incomingKey.value)) {
    return errorResponse('Cipher key encryption is not supported by this server. Resync the client and try again.', 400);
  }

  if (isStaleCipherUpdate(existingCipher.updatedAt, incomingRevisionDate)) {
    return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 400);
  }

  const nextType = Number(cipherData.type) || existingCipher.type;

  // Opaque passthrough: merge existing stored data with ALL incoming client fields.
  // Unknown/future fields from the client are preserved; server-controlled fields are protected.
  const {
    preserveRevisionDate: _preserveRevisionDate,
    PreserveRevisionDate: _pascalPreserveRevisionDate,
    lastKnownRevisionDate: _lastKnownRevisionDate,
    LastKnownRevisionDate: _pascalLastKnownRevisionDate,
    ...cipherDataWithoutFlags
  } = cipherData;
  const cipher: Cipher = {
    ...existingCipher,   // start with all existing stored data (including unknowns)
    ...cipherDataWithoutFlags, // overlay all client data (including new/unknown fields)
    // Server-controlled fields (never from client)
    id: existingCipher.id,
    userId: existingCipher.userId,
    organizationId: existingCipher.organizationId,
    type: nextType,
    favorite: cipherData.favorite ?? existingCipher.favorite,
    reprompt: cipherData.reprompt ?? existingCipher.reprompt,
    createdAt: existingCipher.createdAt,
    updatedAt: preserveRevisionDate ? existingCipher.updatedAt : new Date(Math.max(Date.now(), Date.parse(existingCipher.updatedAt) + 1)).toISOString(),
    archivedAt: readCipherArchivedAt(cipherData, existingCipher.archivedAt ?? null),
    deletedAt: existingCipher.deletedAt,
  };
  if (incomingFolderId.present) {
    cipher.folderId = normalizeOptionalId(incomingFolderId.value);
  }
  if (incomingKey.present) {
    const normalizedIncomingKey = normalizeCipherKeyForStorage(incomingKey.value);
    cipher.key = normalizedIncomingKey || normalizeCipherKeyForStorage(existingCipher.key);
  } else {
    cipher.key = normalizeCipherKeyForStorage(existingCipher.key);
  }
  cipher.login = nextType === 1 ? (incomingLogin.present ? (incomingLogin.value ?? null) : (existingCipher.login ?? null)) : null;
  cipher.secureNote = nextType === 2 ? (incomingSecureNote.present ? (incomingSecureNote.value ?? null) : (existingCipher.secureNote ?? null)) : null;
  cipher.card = nextType === 3 ? (incomingCard.present ? (incomingCard.value ?? null) : (existingCipher.card ?? null)) : null;
  cipher.identity = nextType === 4 ? (incomingIdentity.present ? (incomingIdentity.value ?? null) : (existingCipher.identity ?? null)) : null;
  cipher.sshKey = nextType === 5 ? (incomingSshKey.present ? (incomingSshKey.value ?? null) : (existingCipher.sshKey ?? null)) : null;
  cipher.bankAccount = nextType === 6 ? (incomingBankAccount.present ? (incomingBankAccount.value ?? null) : ((existingCipher as any).bankAccount ?? null)) : null;
  cipher.driversLicense = nextType === 7 ? (incomingDriversLicense.present ? (incomingDriversLicense.value ?? null) : ((existingCipher as any).driversLicense ?? null)) : null;
  cipher.passport = nextType === 8 ? (incomingPassport.present ? (incomingPassport.value ?? null) : ((existingCipher as any).passport ?? null)) : null;
  if (incomingPasswordHistory.present) {
    cipher.passwordHistory = incomingPasswordHistory.value ?? null;
  }

  // Nullable fields use replacement semantics on this full-update endpoint.
  // Some clients omit cleared values, so merge fallback must not resurrect them.
  cipher.notes = readNullableFullUpdateField<string>(cipherData, ['notes', 'Notes']);
  cipher.fields = readNullableFullUpdateField<Cipher['fields']>(cipherData, ['fields', 'Fields']);
  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);
  return cipher;
}

function viewerSettingsAfterUpdate(cipherData: any, merged: Cipher, previous: CipherUserSettings): CipherUserSettings {
  const incomingFolderId = readCipherProp<string | null>(cipherData, ['folderId', 'FolderId']);
  const incomingFavorite = readCipherProp<boolean>(cipherData, ['favorite', 'Favorite']);
  return {
    folderId: incomingFolderId.present ? normalizeOptionalId(merged.folderId) : previous.folderId,
    favorite: incomingFavorite.present ? !!incomingFavorite.value : previous.favorite,
  };
}

function staleCipherResponse(): Response {
  return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 400);
}

// PUT /api/ciphers/:id
export async function handleUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  if (!resolved.access.edit) return cipherNotEditable();
  const existingCipher = resolved.cipher;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const cipherData = readCipherPayload(body);
  const incomingOrganizationId = readOrganizationId(cipherData);
  if (incomingOrganizationId && incomingOrganizationId !== existingCipher.organizationId) {
    return errorResponse('Use the share endpoint to move an item into an organization', 400);
  }

  const merged = mergeCipherUpdate(request, existingCipher, body);
  if (merged instanceof Response) return merged;
  const cipher = merged;

  const viewerSettings = resolved.access.settings
    ? viewerSettingsAfterUpdate(cipherData, cipher, resolved.access.settings)
    : null;
  const viewerFolderId = viewerSettings ? viewerSettings.folderId : cipher.folderId;
  if (viewerFolderId && !(await verifyFolderOwnership(storage, viewerFolderId, userId))) {
    return errorResponse('Folder not found', 404);
  }
  if (viewerSettings) {
    cipher.folderId = null;
    cipher.favorite = false;
  }

  if (!(await storage.updateCipherIfUnchanged(cipher, existingCipher.updatedAt))) {
    return staleCipherResponse();
  }
  // Rejected updates must not modify attachment metadata either.
  await syncIncomingAttachmentMetadata(storage, cipher.id, cipherData);
  if (viewerSettings) {
    await new OrganizationStore(env.DB).saveCipherUserSettings(cipher.id, userId, viewerSettings);
  }
  await publishCipherEvent(request, env, storage, cipher, 'update');
  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments, responseWithAccess(request, { ...resolved.access, settings: viewerSettings }))
  );
}

// PUT/POST /api/ciphers/:id/share
export async function handleShareCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  const existingCipher = resolved.cipher;
  if (existingCipher.organizationId || existingCipher.userId !== userId) {
    return errorResponse('This item already belongs to an organization', 400);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const cipherData = readCipherPayload(body);
  const organizationId = readOrganizationId(cipherData);
  const collectionIds = readCollectionIds(body) ?? [];
  if (!organizationId) return errorResponse('organizationId is required', 400);
  const placementError = await authorizeOrganizationPlacement(env, userId, organizationId, collectionIds);
  if (placementError) return placementError;

  const merged = mergeCipherUpdate(request, existingCipher, body);
  if (merged instanceof Response) return merged;
  const cipher: Cipher = { ...merged, userId: null, organizationId };
  const settings = moveViewerSettingsOffCipher(cipher);
  if (settings.folderId && !(await verifyFolderOwnership(storage, settings.folderId, userId))) {
    return errorResponse('Folder not found', 404);
  }

  if (!(await storage.updateCipherIfUnchanged(cipher, existingCipher.updatedAt, cipherOwnerOf(existingCipher)))) {
    return staleCipherResponse();
  }
  await syncIncomingAttachmentMetadata(storage, cipher.id, cipherData);
  await saveOrganizationCipherPlacement(env, userId, cipher, collectionIds, settings);
  await publishCipherEvent(request, env, storage, cipher, 'update');
  return resolvedResponse(request, env, storage, userId, cipher);
}

async function softDeleteResolvedCipher(
  request: Request,
  env: Env,
  storage: StorageService,
  userId: string,
  resolved: ResolvedCipher
): Promise<Response> {
  const { cipher, access } = resolved;
  cipher.deletedAt = new Date().toISOString();
  cipher.updatedAt = cipher.deletedAt;
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  await publishCipherEvent(request, env, storage, cipher, 'delete');
  await writeCipherAudit(storage, request, userId, 'cipher.delete.soft', {
    id: cipher.id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
  });

  return jsonResponse(cipherToResponse(cipher, [], responseWithAccess(request, access)));
}

async function permanentlyDeleteResolvedCipher(
  request: Request,
  env: Env,
  storage: StorageService,
  userId: string,
  cipher: Cipher,
  auditMetadata: Record<string, unknown> = {}
): Promise<Response> {
  const audience = await cipherAudience(env, [cipher]);
  await deleteAllAttachmentsForCipher(env, cipher.id);
  await storage.deleteCipher(cipher.id);
  await publishCipherEvent(request, env, storage, cipher, 'delete', audience);
  await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent', {
    id: cipher.id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
    ...auditMetadata,
  });
  return new Response(null, { status: 204 });
}

// DELETE /api/ciphers/:id
export async function handleDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  if (!resolved.access.manage) return cipherNotManageable();
  return softDeleteResolvedCipher(request, env, storage, userId, resolved);
}

// DELETE /api/ciphers/:id (compat mode)
// Bitwarden clients may call DELETE on a trashed item to purge it permanently.
// For compatibility:
// - If item is active -> soft delete.
// - If item is already soft-deleted -> hard delete.
export async function handleDeleteCipherCompat(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  if (!resolved.access.manage) return cipherNotManageable();

  if (resolved.cipher.deletedAt) {
    return permanentlyDeleteResolvedCipher(request, env, storage, userId, resolved.cipher, { compat: true });
  }
  return softDeleteResolvedCipher(request, env, storage, userId, resolved);
}

// DELETE /api/ciphers/:id (permanent)
export async function handlePermanentDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  if (!resolved.access.manage) return cipherNotManageable();
  return permanentlyDeleteResolvedCipher(request, env, storage, userId, resolved.cipher);
}

// PUT /api/ciphers/:id/restore
export async function handleRestoreCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  if (!resolved.access.manage) return cipherNotManageable();
  const { cipher, access } = resolved;

  cipher.deletedAt = null;
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  await publishCipherEvent(request, env, storage, cipher, 'update');

  return jsonResponse(cipherToResponse(cipher, [], responseWithAccess(request, access)));
}

// PUT /api/ciphers/:id/partial - Update only favorite/folderId
export async function handlePartialUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  const { cipher, access } = resolved;

  let body: { folderId?: string | null; favorite?: boolean };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const current: CipherUserSettings = access.settings ?? { folderId: cipher.folderId, favorite: cipher.favorite };
  const next: CipherUserSettings = { ...current };
  if (body.folderId !== undefined) {
    next.folderId = normalizeOptionalId(body.folderId);
    if (next.folderId && !(await verifyFolderOwnership(storage, next.folderId, userId))) {
      return errorResponse('Folder not found', 404);
    }
  }
  if (body.favorite !== undefined) {
    next.favorite = !!body.favorite;
  }

  if (access.settings) {
    await new OrganizationStore(env.DB).saveCipherUserSettings(cipher.id, userId, next);
    await publishCipherEvent(request, env, storage, cipher, 'update', [userId]);
    return jsonResponse(cipherToResponse(cipher, [], responseWithAccess(request, { ...access, settings: next })));
  }

  cipher.folderId = next.folderId;
  cipher.favorite = next.favorite;
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  await publishCipherEvent(request, env, storage, cipher, 'update', [userId]);

  return jsonResponse(cipherToResponse(cipher, [], responseWithAccess(request, access)));
}

// POST/PUT /api/ciphers/move - Bulk move to folder
export async function handleBulkMoveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[]; folderId?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const folderId = normalizeOptionalId(body.folderId);
  if (folderId) {
    const folderOk = await verifyFolderOwnership(storage, folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  const resolved = await resolveCiphersByIds(env, storage, userId, body.ids);
  if (!resolved.length) return new Response(null, { status: 204 });
  const personalIds = resolved.filter(({ access }) => !access.settings).map(({ cipher }) => cipher.id);
  const organizationIds = resolved.filter(({ access }) => access.settings).map(({ cipher }) => cipher.id);
  if (personalIds.length) await storage.bulkMovePersonalCiphers(personalIds, folderId, userId);
  if (organizationIds.length) await new OrganizationStore(env.DB).moveCiphersToFolderForUser(userId, organizationIds, folderId);
  await publishVaultSync(request, env, storage, [userId]);

  return new Response(null, { status: 204 });
}

async function buildCipherListResponse(
  request: Request,
  env: Env,
  storage: StorageService,
  userId: string,
  ids: string[]
): Promise<Response> {
  const resolved = await resolveCiphersByIds(env, storage, userId, ids);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(resolved.map(({ cipher }) => cipher.id));

  return jsonResponse({
    data: resolved.map(({ cipher, access }) =>
      cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], responseWithAccess(request, access))
    ),
    object: 'list',
    continuationToken: null,
  });
}

function parseCipherIdList(body: { ids?: unknown }): string[] | null {
  if (!Array.isArray(body.ids)) return null;
  return Array.from(new Set(body.ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

async function setResolvedArchiveState(
  request: Request,
  env: Env,
  storage: StorageService,
  resolved: ResolvedCipher,
  archivedAt: string | null
): Promise<Response> {
  const { cipher, access } = resolved;
  cipher.archivedAt = archivedAt;
  cipher.updatedAt = archivedAt ?? new Date().toISOString();
  normalizeCipherForStorage(cipher);
  await storage.saveCipher(cipher);
  await publishCipherEvent(request, env, storage, cipher, 'update');

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(cipherToResponse(cipher, attachments, responseWithAccess(request, access)));
}

// PUT/POST /api/ciphers/:id/archive
export async function handleArchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  if (!resolved.access.edit) return cipherNotEditable();
  if (resolved.cipher.deletedAt) {
    return errorResponse('Cannot archive a deleted cipher', 400);
  }
  return setResolvedArchiveState(request, env, storage, resolved, new Date().toISOString());
}

// PUT/POST /api/ciphers/:id/unarchive
export async function handleUnarchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, id);
  if (!resolved) return cipherNotFound();
  if (!resolved.access.edit) return cipherNotEditable();
  return setResolvedArchiveState(request, env, storage, resolved, null);
}

type BulkCipherPermission = 'edit' | 'manage';

async function authorizedBulkCiphers(
  env: Env,
  storage: StorageService,
  userId: string,
  ids: string[],
  permission: BulkCipherPermission
): Promise<Cipher[]> {
  const resolved = await resolveCiphersByIds(env, storage, userId, ids);
  return resolved.filter(({ access }) => access[permission]).map(({ cipher }) => cipher);
}

async function readBulkIds(request: Request): Promise<string[] | Response> {
  let body: { ids?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  return parseCipherIdList(body) ?? errorResponse('ids array is required', 400);
}

async function applyBulkCipherChange(
  request: Request,
  env: Env,
  userId: string,
  permission: BulkCipherPermission,
  change: (storage: StorageService, authorizedIds: string[]) => Promise<void>
): Promise<{ storage: StorageService; ids: string[]; changed: Cipher[] } | Response> {
  const ids = await readBulkIds(request);
  if (ids instanceof Response) return ids;
  const storage = new StorageService(env.DB);
  const changed = await authorizedBulkCiphers(env, storage, userId, ids, permission);
  if (changed.length) {
    await change(storage, changed.map((cipher) => cipher.id));
    await publishCiphersSync(request, env, storage, await cipherAudience(env, changed));
  }
  return { storage, ids, changed };
}

// PUT/POST /api/ciphers/archive
export async function handleBulkArchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const result = await applyBulkCipherChange(request, env, userId, 'edit', (storage, ids) => storage.bulkArchiveCiphers(ids));
  if (result instanceof Response) return result;
  return buildCipherListResponse(request, env, result.storage, userId, result.ids);
}

// PUT/POST /api/ciphers/unarchive
export async function handleBulkUnarchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const result = await applyBulkCipherChange(request, env, userId, 'edit', (storage, ids) => storage.bulkUnarchiveCiphers(ids));
  if (result instanceof Response) return result;
  return buildCipherListResponse(request, env, result.storage, userId, result.ids);
}

// POST /api/ciphers/delete - Bulk soft delete
export async function handleBulkDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const result = await applyBulkCipherChange(request, env, userId, 'manage', (storage, ids) => storage.bulkSoftDeleteCiphers(ids));
  if (result instanceof Response) return result;
  if (result.changed.length) {
    await writeCipherAudit(result.storage, request, userId, 'cipher.delete.soft.bulk', {
      count: result.changed.length,
    });
  }
  return new Response(null, { status: 204 });
}

// PUT /api/ciphers/restore (POST retained for older NodeWarden clients)
export async function handleBulkRestoreCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const result = await applyBulkCipherChange(request, env, userId, 'manage', (storage, ids) => storage.bulkRestoreCiphers(ids));
  if (result instanceof Response) return result;
  return buildCipherListResponse(request, env, result.storage, userId, result.changed.map((cipher) => cipher.id));
}

// POST /api/ciphers/delete-permanent - Bulk permanent delete
export async function handleBulkPermanentDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const ids = await readBulkIds(request);
  if (ids instanceof Response) return ids;
  if (!ids.length) return new Response(null, { status: 204 });

  const storage = new StorageService(env.DB);
  const deletable = await authorizedBulkCiphers(env, storage, userId, ids, 'manage');
  if (!deletable.length) return new Response(null, { status: 204 });

  const deletableIds = deletable.map((cipher) => cipher.id);
  const audience = await cipherAudience(env, deletable);
  await deleteAllAttachmentsForCiphers(env, deletableIds);
  await storage.bulkDeleteCiphers(deletableIds);
  await publishCiphersSync(request, env, storage, audience);
  await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent.bulk', {
    count: deletableIds.length,
    requestedCount: ids.length,
  });

  return new Response(null, { status: 204 });
}
