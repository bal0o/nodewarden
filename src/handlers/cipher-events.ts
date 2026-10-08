import type { Cipher, Env } from '../types';
import {
  notifyUserCipherCreate,
  notifyUserCipherDelete,
  notifyUserCipherUpdate,
  notifyUserCiphersSync,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { OrganizationStore } from '../services/organization-store';
import type { StorageService } from '../services/storage';
import { readActingDeviceIdentifier } from '../utils/device';

export type CipherEvent = 'create' | 'update' | 'delete';

const NOTIFY_BY_EVENT = {
  create: notifyUserCipherCreate,
  update: notifyUserCipherUpdate,
  delete: notifyUserCipherDelete,
} as const;

export async function cipherAudience(env: Env, ciphers: readonly Cipher[]): Promise<string[]> {
  const personalOwners = ciphers.flatMap((cipher) => (cipher.userId ? [cipher.userId] : []));
  const organizationCipherIds = ciphers.filter((cipher) => cipher.organizationId).map((cipher) => cipher.id);
  const sharedUsers = organizationCipherIds.length
    ? await new OrganizationStore(env.DB).getUserIdsWithCipherAccess(organizationCipherIds)
    : [];
  return [...new Set([...personalOwners, ...sharedUsers])];
}

export async function publishCipherEvent(
  request: Request,
  env: Env,
  storage: StorageService,
  cipher: Cipher,
  event: CipherEvent,
  audience?: readonly string[]
): Promise<void> {
  const recipients = audience ?? await cipherAudience(env, [cipher]);
  const collectionIds = cipher.organizationId
    ? (await new OrganizationStore(env.DB).getCipherCollectionIds([cipher.id])).get(cipher.id) ?? []
    : null;
  const contextId = readActingDeviceIdentifier(request);
  for (const userId of recipients) {
    const revisionDate = await storage.updateRevisionDate(userId);
    notifyUserVaultSync(env, userId, revisionDate, contextId);
    NOTIFY_BY_EVENT[event](env, {
      userId,
      cipherId: cipher.id,
      revisionDate,
      organizationId: cipher.organizationId,
      collectionIds,
      contextId,
    });
  }
}

export async function publishCiphersSync(
  request: Request,
  env: Env,
  storage: StorageService,
  audience: readonly string[]
): Promise<void> {
  const contextId = readActingDeviceIdentifier(request);
  for (const userId of audience) {
    const revisionDate = await storage.updateRevisionDate(userId);
    notifyUserVaultSync(env, userId, revisionDate, contextId);
    notifyUserCiphersSync(env, userId, revisionDate, contextId);
  }
}

export async function publishVaultSync(
  request: Request,
  env: Env,
  storage: StorageService,
  audience: readonly string[]
): Promise<void> {
  const contextId = readActingDeviceIdentifier(request);
  for (const userId of audience) {
    const revisionDate = await storage.updateRevisionDate(userId);
    notifyUserVaultSync(env, userId, revisionDate, contextId);
  }
}
