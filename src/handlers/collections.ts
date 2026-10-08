import {
  MembershipType,
  type Cipher,
  type Collection,
  type CollectionUser,
  type Env,
} from '../types';
import { StorageService } from '../services/storage';
import { OrganizationStore } from '../services/organization-store';
import {
  effectiveCollectionGrant,
  hasFullAccess,
  isOwnerOrAdmin,
  loadOrganizationAccess,
  resolveCiphersForUser,
  writableCollectionIds,
} from '../services/organization-access';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { cipherToResponse, isValidEncString, readCollectionIds, resolveCipherForUser, shouldPreserveRepairableCipherUris } from './ciphers';
import { cipherAudience, publishCiphersSync, publishVaultSync } from './cipher-events';
import {
  loadOrganizationContext,
  parseCollectionGrants,
  readJsonBody,
  type OrganizationContext,
} from './organizations';
import {
  collectionAccessDetailsResponse,
  collectionDetailsResponse,
  collectionResponse,
  listResponse,
} from './organization-responses';

async function directGrantsFor(context: OrganizationContext) {
  return context.store.getCollectionGrantsForUser(context.actor.userId);
}

function canManageCollection(context: OrganizationContext, directGrants: Awaited<ReturnType<typeof directGrantsFor>>, collectionId: string): boolean {
  return !!effectiveCollectionGrant(context.actor, directGrants.get(collectionId))?.manage;
}

function canCreateCollections(context: OrganizationContext): boolean {
  return isOwnerOrAdmin(context.actor) || context.actor.type === MembershipType.Manager;
}

async function membershipUserResolver(context: OrganizationContext): Promise<(membershipId: string) => string | null> {
  const members = await context.store.getMembersWithUsers(context.organization.id);
  const userByMembership = new Map(members.map((member) => [member.id, member.userId]));
  return (membershipId) => userByMembership.get(membershipId) ?? null;
}

async function parseCollectionUsers(context: OrganizationContext, collectionId: string, input: unknown): Promise<CollectionUser[] | Response> {
  const resolveUser = await membershipUserResolver(context);
  return parseCollectionGrants(input, resolveUser, () => collectionId);
}

// GET /api/organizations/:id/collections
export async function handleListOrganizationCollections(env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const [collections, directGrants] = await Promise.all([
    context.store.getCollectionsForOrganizations([organizationId]),
    directGrantsFor(context),
  ]);
  const visible = collections.filter((collection) => effectiveCollectionGrant(context.actor, directGrants.get(collection.id)));
  return jsonResponse(listResponse(visible.map(collectionResponse)));
}

async function collectionDetailsList(context: OrganizationContext, collections: readonly Collection[]): Promise<Record<string, unknown>[]> {
  const [members, collectionUsers, directGrants] = await Promise.all([
    context.store.getMembersWithUsers(context.organization.id),
    context.store.getCollectionUsersForOrganization(context.organization.id),
    directGrantsFor(context),
  ]);
  return collections.flatMap((collection) => {
    const grant = effectiveCollectionGrant(context.actor, directGrants.get(collection.id));
    if (!grant && !isOwnerOrAdmin(context.actor)) return [];
    const users = grant?.manage || isOwnerOrAdmin(context.actor)
      ? collectionUsers.filter((collectionUser) => collectionUser.collectionId === collection.id)
      : [];
    return [collectionAccessDetailsResponse(collection, grant, members, users)];
  });
}

// GET /api/organizations/:id/collections/details
export async function handleListCollectionDetails(env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const collections = await context.store.getCollectionsForOrganizations([organizationId]);
  return jsonResponse(listResponse(await collectionDetailsList(context, collections)));
}

// GET /api/organizations/:id/collections/:collectionId(/details)
export async function handleGetCollectionDetails(env: Env, userId: string, organizationId: string, collectionId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const collection = await context.store.getCollection(collectionId, organizationId);
  if (!collection) return errorResponse('Collection not found', 404);
  const [details] = await collectionDetailsList(context, [collection]);
  return details ? jsonResponse(details) : errorResponse('Collection not found', 404);
}

// GET /api/organizations/:id/collections/:collectionId/users
export async function handleGetCollectionUsers(env: Env, userId: string, organizationId: string, collectionId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const collection = await context.store.getCollection(collectionId, organizationId);
  if (!collection || !canManageCollection(context, await directGrantsFor(context), collectionId)) {
    return errorResponse('Collection not found', 404);
  }
  const [details] = await collectionDetailsList(context, [collection]);
  return jsonResponse(details?.users ?? []);
}

interface CollectionBody {
  name?: unknown;
  externalId?: unknown;
  users?: unknown;
}

function readCollectionName(body: CollectionBody): string | Response {
  return isValidEncString(body.name) ? body.name.trim() : errorResponse('Collection name must be encrypted', 400);
}

function readExternalId(body: CollectionBody, fallback: string | null): string | null {
  if (body.externalId === undefined) return fallback;
  const value = String(body.externalId ?? '').trim();
  return value || null;
}

async function publishCollectionAccessChange(
  request: Request,
  context: OrganizationContext,
  collectionIds: readonly string[],
  previousAudience: readonly string[] = []
): Promise<void> {
  const currentAudience = await context.store.getUserIdsWithCollectionAccess(context.organization.id, collectionIds);
  await publishVaultSync(request, context.env, context.storage, [...new Set([...previousAudience, ...currentAudience])]);
}

// POST /api/organizations/:id/collections
export async function handleCreateCollection(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  if (!canCreateCollections(context)) return errorResponse('You do not have permission to create collections', 403);
  const body = await readJsonBody<CollectionBody>(request);
  if (body instanceof Response) return body;
  const name = readCollectionName(body);
  if (name instanceof Response) return name;

  const now = new Date().toISOString();
  const collection: Collection = {
    id: generateUUID(),
    organizationId,
    name,
    externalId: readExternalId(body, null),
    createdAt: now,
    updatedAt: now,
  };
  const users = await parseCollectionUsers(context, collection.id, body.users);
  if (users instanceof Response) return users;
  if (!hasFullAccess(context.actor) && !users.some((user) => user.userId === userId)) {
    users.push({ userId, collectionId: collection.id, readOnly: false, hidePasswords: false, manage: true });
  }

  await context.store.createCollection(collection, users);
  await publishCollectionAccessChange(request, context, [collection.id]);
  const [details] = await collectionDetailsList(context, [collection]);
  return jsonResponse(details ?? collectionResponse(collection));
}

// PUT/POST /api/organizations/:id/collections/:collectionId
export async function handleUpdateCollection(request: Request, env: Env, userId: string, organizationId: string, collectionId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const existing = await context.store.getCollection(collectionId, organizationId);
  if (!existing || !canManageCollection(context, await directGrantsFor(context), collectionId)) {
    return errorResponse('Collection not found', 404);
  }
  const body = await readJsonBody<CollectionBody>(request);
  if (body instanceof Response) return body;
  const name = readCollectionName(body);
  if (name instanceof Response) return name;
  const users = body.users === undefined ? null : await parseCollectionUsers(context, collectionId, body.users);
  if (users instanceof Response) return users;

  const previousAudience = await context.store.getUserIdsWithCollectionAccess(organizationId, [collectionId]);
  const collection: Collection = {
    ...existing,
    name,
    externalId: readExternalId(body, existing.externalId),
    updatedAt: new Date().toISOString(),
  };
  await context.store.updateCollection(collection, users);
  await publishCollectionAccessChange(request, context, [collectionId], previousAudience);
  const [details] = await collectionDetailsList(context, [collection]);
  return jsonResponse(details ?? collectionResponse(collection));
}

// PUT /api/organizations/:id/collections/:collectionId/users
export async function handleUpdateCollectionUsers(request: Request, env: Env, userId: string, organizationId: string, collectionId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const existing = await context.store.getCollection(collectionId, organizationId);
  if (!existing || !canManageCollection(context, await directGrantsFor(context), collectionId)) {
    return errorResponse('Collection not found', 404);
  }
  const body = await readJsonBody<unknown>(request);
  if (body instanceof Response) return body;
  const users = await parseCollectionUsers(context, collectionId, body);
  if (users instanceof Response) return users;

  const previousAudience = await context.store.getUserIdsWithCollectionAccess(organizationId, [collectionId]);
  await context.store.updateCollection({ ...existing, updatedAt: new Date().toISOString() }, users);
  await publishCollectionAccessChange(request, context, [collectionId], previousAudience);
  return new Response(null, { status: 200 });
}

async function deleteCollectionsAsActor(request: Request, context: OrganizationContext, collectionIds: readonly string[]): Promise<Response | null> {
  const directGrants = await directGrantsFor(context);
  const collections = await context.store.getCollectionsForOrganizations([context.organization.id]);
  const existingIds = new Set(collections.map((collection) => collection.id));
  const targets = collectionIds.filter((collectionId) => existingIds.has(collectionId));
  if (targets.some((collectionId) => !canManageCollection(context, directGrants, collectionId))) {
    return errorResponse('You do not have permission to delete one or more of these collections', 403);
  }
  const previousAudience = await context.store.getUserIdsWithCollectionAccess(context.organization.id, targets);
  await context.store.deleteCollections(context.organization.id, targets);
  await publishVaultSync(request, context.env, context.storage, previousAudience);
  return null;
}

// DELETE/POST /api/organizations/:id/collections/:collectionId(/delete)
export async function handleDeleteCollection(request: Request, env: Env, userId: string, organizationId: string, collectionId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  if (!(await context.store.getCollection(collectionId, organizationId))) return errorResponse('Collection not found', 404);
  return (await deleteCollectionsAsActor(request, context, [collectionId])) ?? new Response(null, { status: 200 });
}

// DELETE/POST /api/organizations/:id/collections(/delete)
export async function handleBulkDeleteCollections(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const body = await readJsonBody<{ ids?: unknown }>(request);
  if (body instanceof Response) return body;
  if (!Array.isArray(body.ids)) return errorResponse('ids array is required', 400);
  const ids = body.ids.map((id) => String(id || '').trim()).filter(Boolean);
  return (await deleteCollectionsAsActor(request, context, ids)) ?? new Response(null, { status: 200 });
}

function nextCollectionLinks(current: readonly string[], requested: readonly string[], writable: ReadonlySet<string>): string[] {
  const preserved = current.filter((collectionId) => !writable.has(collectionId));
  return [...new Set([...preserved, ...requested])];
}

async function assignCipherCollections(
  env: Env,
  userId: string,
  cipher: Cipher,
  requested: readonly string[]
): Promise<{ previousAudience: string[] } | Response> {
  const organizationId = cipher.organizationId;
  if (!organizationId) return errorResponse('Only organization items can be assigned to collections', 400);
  const store = new OrganizationStore(env.DB);
  const access = await loadOrganizationAccess(store, userId);
  const member = access.memberships.get(organizationId);
  if (!member) return errorResponse('Cipher not found', 404);
  const writable = writableCollectionIds(access, organizationId);
  if (requested.some((collectionId) => !writable.has(collectionId))) {
    return errorResponse('You do not have permission to add items to one or more of these collections', 403);
  }

  const current = (await store.getCipherCollectionIds([cipher.id])).get(cipher.id) ?? [];
  const next = nextCollectionLinks(current, requested, writable);
  if (!next.length && !hasFullAccess(member)) {
    return errorResponse('Organization items must stay in at least one collection', 400);
  }
  const previousAudience = await cipherAudience(env, [cipher]);
  await store.setCipherCollections(cipher.id, next);
  return { previousAudience };
}

type CipherCollectionsResponse = 'cipher' | 'optional';

// PUT/POST /api/ciphers/:id/collections(_v2|-admin)
export async function handleSetCipherCollections(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  responseShape: CipherCollectionsResponse
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const resolved = await resolveCipherForUser(env, storage, userId, cipherId);
  if (!resolved) return errorResponse('Cipher not found', 404);
  if (!resolved.access.edit) return errorResponse('You do not have permission to edit this item', 403);
  const body = await readJsonBody<{ collectionIds?: unknown }>(request);
  if (body instanceof Response) return body;
  const requested = readCollectionIds(body);
  if (!requested) return errorResponse('collectionIds array is required', 400);

  const result = await assignCipherCollections(env, userId, resolved.cipher, requested);
  if (result instanceof Response) return result;
  const currentAudience = await cipherAudience(env, [resolved.cipher]);
  await publishCiphersSync(request, env, storage, [...new Set([...result.previousAudience, ...currentAudience])]);

  const updated = await resolveCipherForUser(env, storage, userId, cipherId);
  const options = { preserveRepairableUris: shouldPreserveRepairableCipherUris(request), access: updated?.access };
  const attachments = updated ? await storage.getAttachmentsByCipher(cipherId) : [];
  const cipherResponse = updated ? cipherToResponse(updated.cipher, attachments, options) : null;
  if (responseShape === 'optional') {
    return jsonResponse({ object: 'optionalCipherDetails', unavailable: !updated, cipher: cipherResponse });
  }
  return cipherResponse ? jsonResponse(cipherResponse) : new Response(null, { status: 200 });
}

interface BulkCollectionsBody {
  organizationId?: unknown;
  cipherIds?: unknown;
  collectionIds?: unknown;
  removeCollections?: unknown;
}

// POST /api/ciphers/bulk-collections
export async function handleBulkCipherCollections(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readJsonBody<BulkCollectionsBody>(request);
  if (body instanceof Response) return body;
  const organizationId = String(body.organizationId || '').trim();
  const cipherIds = readCollectionIds({ collectionIds: body.cipherIds }) ?? [];
  const collectionIds = readCollectionIds(body) ?? [];
  if (!organizationId || !cipherIds.length || !collectionIds.length) {
    return errorResponse('organizationId, cipherIds and collectionIds are required', 400);
  }

  const storage = new StorageService(env.DB);
  const store = new OrganizationStore(env.DB);
  const access = await loadOrganizationAccess(store, userId);
  const writable = writableCollectionIds(access, organizationId);
  if (collectionIds.some((collectionId) => !writable.has(collectionId))) {
    return errorResponse('You do not have permission to change one or more of these collections', 403);
  }
  const resolved = await resolveCiphersForUser(store, userId, await storage.getCiphersByIds(cipherIds, userId));
  const editable = resolved.filter(({ cipher, access: cipherAccess }) => cipher.organizationId === organizationId && cipherAccess.edit);
  if (editable.length !== cipherIds.length) {
    return errorResponse('You do not have permission to edit one or more of these items', 403);
  }

  const ciphers = editable.map(({ cipher }) => cipher);
  const previousAudience = await cipherAudience(env, ciphers);
  if (body.removeCollections === true) await store.removeCiphersFromCollections(cipherIds, collectionIds);
  else await store.addCiphersToCollections(cipherIds, collectionIds);
  const currentAudience = await cipherAudience(env, ciphers);
  await publishCiphersSync(request, env, storage, [...new Set([...previousAudience, ...currentAudience])]);
  return new Response(null, { status: 200 });
}

// GET /api/collections
export async function handleListUserCollections(env: Env, userId: string): Promise<Response> {
  const access = await loadOrganizationAccess(new OrganizationStore(env.DB), userId);
  return jsonResponse(listResponse([...access.collections.values()].map(({ collection, grant }) =>
    collectionDetailsResponse(collection, grant)
  )));
}

// GET /api/ciphers/organization-details(/assigned)?organizationId=
export async function handleOrganizationCipherDetails(request: Request, env: Env, userId: string): Promise<Response> {
  const organizationId = new URL(request.url).searchParams.get('organizationId') || '';
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;

  const ciphers = (await context.storage.getAllCiphers(userId)).filter((cipher) => cipher.organizationId === organizationId);
  const resolved = await resolveCiphersForUser(context.store, userId, ciphers);
  const attachmentsByCipher = await context.storage.getAttachmentsByCipherIds(resolved.map(({ cipher }) => cipher.id));
  const preserveRepairableUris = shouldPreserveRepairableCipherUris(request);
  return jsonResponse(listResponse(resolved.map(({ cipher, access }) => ({
    ...cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], { preserveRepairableUris, access: { ...access, settings: null } }),
    object: 'cipherMiniDetails',
  }))));
}
