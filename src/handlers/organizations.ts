import {
  MembershipStatus,
  MembershipType,
  type Collection,
  type CollectionUser,
  type Env,
  type Organization,
  type OrganizationMember,
} from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { OrganizationStore } from '../services/organization-store';
import { hasFullAccess, isOwnerOrAdmin } from '../services/organization-access';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { deleteAllAttachmentsForCiphers } from './attachments';
import { isValidEncString } from './ciphers';
import { publishVaultSync } from './cipher-events';
import {
  FREE_PLAN,
  listResponse,
  memberResponse,
  organizationResponse,
} from './organization-responses';

export interface OrganizationContext {
  env: Env;
  storage: StorageService;
  store: OrganizationStore;
  organization: Organization;
  actor: OrganizationMember;
}

export type OrganizationRole = 'member' | 'confirmed' | 'manager' | 'admin' | 'owner';

const ROLE_CHECKS: Record<OrganizationRole, (member: OrganizationMember) => boolean> = {
  member: () => true,
  confirmed: (member) => member.status === MembershipStatus.Confirmed,
  manager: (member) => isOwnerOrAdmin(member) || (member.status === MembershipStatus.Confirmed && member.type === MembershipType.Manager),
  admin: isOwnerOrAdmin,
  owner: (member) => member.status === MembershipStatus.Confirmed && member.type === MembershipType.Owner,
};

export async function loadOrganizationContext(
  env: Env,
  userId: string,
  organizationId: string,
  role: OrganizationRole
): Promise<OrganizationContext | Response> {
  const store = new OrganizationStore(env.DB);
  const [organization, actor] = await Promise.all([
    store.getOrganization(organizationId),
    store.getMemberByUser(userId, organizationId),
  ]);
  if (!organization || !actor) return errorResponse('Organization not found', 404);
  if (!ROLE_CHECKS[role](actor)) return errorResponse('You do not have permission to do this in the organization', 403);
  return { env, storage: new StorageService(env.DB), store, organization, actor };
}

export async function readJsonBody<T>(request: Request): Promise<T | Response> {
  try {
    return await request.json() as T;
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
}

interface CollectionGrantInput {
  id?: unknown;
  readOnly?: unknown;
  hidePasswords?: unknown;
  manage?: unknown;
}

export function parseCollectionGrants(
  input: unknown,
  resolveUserId: (id: string) => string | null,
  resolveCollectionId: (id: string) => string | null
): CollectionUser[] | Response {
  if (input == null) return [];
  if (!Array.isArray(input)) return errorResponse('Collection access must be a list', 400);
  const grants = new Map<string, CollectionUser>();
  for (const raw of input as CollectionGrantInput[]) {
    const id = String(raw?.id ?? '').trim();
    const userId = resolveUserId(id);
    const collectionId = resolveCollectionId(id);
    if (!userId || !collectionId) return errorResponse(`Unknown collection access entry: ${id || '(empty)'}`, 400);
    grants.set(`${userId}:${collectionId}`, {
      userId,
      collectionId,
      readOnly: raw.readOnly === true,
      hidePasswords: raw.hidePasswords === true,
      manage: raw.manage === true,
    });
  }
  return [...grants.values()];
}

function parseMembershipType(value: unknown): MembershipType | Response {
  const type = Number(value);
  if (type === MembershipType.Owner || type === MembershipType.Admin || type === MembershipType.User || type === MembershipType.Manager) {
    return type;
  }
  return errorResponse('Custom member roles are not supported by this server', 400);
}

async function memberDetails(context: OrganizationContext, memberId: string, object: 'organizationUserDetails' | 'organizationUserUserDetails') {
  const [members, collectionUsers] = await Promise.all([
    context.store.getMembersWithUsers(context.organization.id),
    context.store.getCollectionUsersForOrganization(context.organization.id),
  ]);
  const member = members.find((candidate) => candidate.id === memberId);
  if (!member) return null;
  return memberResponse(member, collectionUsers.filter((grant) => grant.userId === member.userId), object);
}

interface CreateOrganizationBody {
  name?: string;
  billingEmail?: string;
  key?: string;
  collectionName?: string;
  keys?: { publicKey?: string; encryptedPrivateKey?: string } | null;
}

// POST /api/organizations
export async function handleCreateOrganization(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readJsonBody<CreateOrganizationBody>(request);
  if (body instanceof Response) return body;

  const name = String(body.name || '').trim();
  if (!name) return errorResponse('Organization name is required', 400);
  if (!isValidEncString(body.key)) return errorResponse('Organization key must be encrypted', 400);
  const publicKey = String(body.keys?.publicKey || '').trim() || null;
  const privateKey = body.keys?.encryptedPrivateKey;
  if (privateKey != null && !isValidEncString(privateKey)) return errorResponse('Organization private key must be encrypted', 400);
  if (body.collectionName != null && !isValidEncString(body.collectionName)) {
    return errorResponse('Default collection name must be encrypted', 400);
  }

  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  const now = new Date().toISOString();
  const organization: Organization = {
    id: generateUUID(),
    name,
    billingEmail: String(body.billingEmail || user.email).trim().toLowerCase(),
    publicKey,
    privateKey: privateKey ?? null,
    createdAt: now,
    updatedAt: now,
  };
  const owner: OrganizationMember = {
    id: generateUUID(),
    userId,
    organizationId: organization.id,
    accessAll: true,
    key: body.key,
    status: MembershipStatus.Confirmed,
    type: MembershipType.Owner,
    createdAt: now,
    updatedAt: now,
  };
  const defaultCollection: Collection | null = body.collectionName
    ? { id: generateUUID(), organizationId: organization.id, name: body.collectionName, externalId: null, createdAt: now, updatedAt: now }
    : null;

  await new OrganizationStore(env.DB).createOrganization(organization, owner, defaultCollection);
  await publishVaultSync(request, env, storage, [userId]);
  return jsonResponse(organizationResponse(organization));
}

// GET /api/organizations/:id
export async function handleGetOrganization(env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  return jsonResponse(organizationResponse(context.organization));
}

// PUT/POST /api/organizations/:id
export async function handleUpdateOrganization(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'owner');
  if (context instanceof Response) return context;
  const body = await readJsonBody<{ name?: string; billingEmail?: string }>(request);
  if (body instanceof Response) return body;

  const name = String(body.name ?? context.organization.name).trim();
  if (!name) return errorResponse('Organization name is required', 400);
  const billingEmail = String(body.billingEmail ?? context.organization.billingEmail).trim().toLowerCase();
  await context.store.updateOrganization(organizationId, name, billingEmail);
  await publishVaultSync(request, env, context.storage, await context.store.getMemberUserIds(organizationId));
  return jsonResponse(organizationResponse({ ...context.organization, name, billingEmail }));
}

// DELETE/POST /api/organizations/:id(/delete)
export async function handleDeleteOrganization(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'owner');
  if (context instanceof Response) return context;
  const body = await readJsonBody<{ masterPasswordHash?: string }>(request);
  if (body instanceof Response) return body;

  const user = await context.storage.getUserById(userId);
  const masterPasswordHash = String(body.masterPasswordHash || '').trim();
  if (!user || !masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  if (!(await new AuthService(env).verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email))) {
    return errorResponse('Invalid password', 400);
  }

  const audience = await context.store.getMemberUserIds(organizationId);
  await deleteAllAttachmentsForCiphers(env, await context.store.getOrganizationCipherIds(organizationId));
  await context.store.deleteOrganization(organizationId);
  await publishVaultSync(request, env, context.storage, audience);
  return new Response(null, { status: 200 });
}

async function isLastConfirmedOwner(context: OrganizationContext, member: OrganizationMember): Promise<boolean> {
  if (member.type !== MembershipType.Owner || member.status !== MembershipStatus.Confirmed) return false;
  return (await context.store.countConfirmedOwners(member.organizationId)) <= 1;
}

// POST /api/organizations/:id/leave
export async function handleLeaveOrganization(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'member');
  if (context instanceof Response) return context;
  if (await isLastConfirmedOwner(context, context.actor)) {
    return errorResponse('The last owner cannot leave the organization', 400);
  }
  await context.store.removeMember(context.actor);
  await publishVaultSync(request, env, context.storage, [userId]);
  return new Response(null, { status: 200 });
}

// GET /api/organizations/:id/keys and /public-key
export async function handleGetOrganizationKeys(env: Env, userId: string, organizationId: string, includePrivate: boolean): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'member');
  if (context instanceof Response) return context;
  if (!includePrivate) {
    return jsonResponse({ object: 'organizationPublicKey', publicKey: context.organization.publicKey });
  }
  return jsonResponse({
    object: 'organizationKeys',
    publicKey: context.organization.publicKey,
    privateKey: context.organization.privateKey,
  });
}

// POST /api/organizations/:id/keys
export async function handleSetOrganizationKeys(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  if (context.organization.publicKey && context.organization.privateKey) {
    return errorResponse('Organization keys are already set', 400);
  }
  const body = await readJsonBody<{ publicKey?: string; encryptedPrivateKey?: string }>(request);
  if (body instanceof Response) return body;
  const publicKey = String(body.publicKey || '').trim();
  if (!publicKey || !isValidEncString(body.encryptedPrivateKey)) return errorResponse('publicKey and encryptedPrivateKey are required', 400);

  await context.store.updateOrganizationKeys(organizationId, publicKey, body.encryptedPrivateKey);
  return jsonResponse({ object: 'organizationKeys', publicKey, privateKey: body.encryptedPrivateKey });
}

// GET /api/organizations/:id/users
export async function handleListMembers(env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'manager');
  if (context instanceof Response) return context;
  const [members, collectionUsers] = await Promise.all([
    context.store.getMembersWithUsers(organizationId),
    hasFullAccess(context.actor) ? context.store.getCollectionUsersForOrganization(organizationId) : Promise.resolve([]),
  ]);
  return jsonResponse(listResponse(members.map((member) =>
    memberResponse(member, collectionUsers.filter((grant) => grant.userId === member.userId))
  )));
}

// GET /api/organizations/:id/users/:memberId
export async function handleGetMember(env: Env, userId: string, organizationId: string, memberId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const details = await memberDetails(context, memberId, 'organizationUserDetails');
  return details ? jsonResponse(details) : errorResponse('Member not found', 404);
}

async function collectionResolver(context: OrganizationContext): Promise<(id: string) => string | null> {
  const collections = await context.store.getCollectionsForOrganizations([context.organization.id]);
  const ids = new Set(collections.map((collection) => collection.id));
  return (id) => (ids.has(id) ? id : null);
}

function canAssignType(actor: OrganizationMember, type: MembershipType): boolean {
  return type !== MembershipType.Owner || actor.type === MembershipType.Owner;
}

interface InviteBody {
  emails?: unknown;
  type?: unknown;
  accessAll?: unknown;
  collections?: unknown;
}

// POST /api/organizations/:id/users/invite
export async function handleInviteMembers(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const body = await readJsonBody<InviteBody>(request);
  if (body instanceof Response) return body;

  const type = parseMembershipType(body.type);
  if (type instanceof Response) return type;
  if (!canAssignType(context.actor, type)) return errorResponse('Only owners can invite owners', 403);
  const emails = Array.isArray(body.emails)
    ? Array.from(new Set(body.emails.map((email) => String(email || '').trim().toLowerCase()).filter(Boolean)))
    : [];
  if (!emails.length) return errorResponse('At least one email is required', 400);

  const users = await Promise.all(emails.map((email) => context.storage.getUser(email)));
  const missingIndex = users.findIndex((user) => !user);
  if (missingIndex >= 0) return errorResponse(`User does not exist: ${emails[missingIndex]}`, 400);

  const resolveCollection = await collectionResolver(context);
  const invited: string[] = [];
  for (const user of users) {
    if (!user) continue;
    if (await context.store.getMemberByUser(user.id, organizationId)) {
      return errorResponse(`User is already a member: ${user.email}`, 400);
    }
    const grants = parseCollectionGrants(body.collections, () => user.id, resolveCollection);
    if (grants instanceof Response) return grants;
    const now = new Date().toISOString();
    const member: OrganizationMember = {
      id: generateUUID(),
      userId: user.id,
      organizationId,
      accessAll: body.accessAll === true,
      key: null,
      status: MembershipStatus.Accepted,
      type,
      createdAt: now,
      updatedAt: now,
    };
    await context.store.addMember(member);
    await context.store.updateMemberAccess(member, grants);
    invited.push(user.id);
  }

  await publishVaultSync(request, env, context.storage, invited);
  return new Response(null, { status: 200 });
}

// POST /api/organizations/:id/users/:memberId/reinvite and /accept
export async function handleAcknowledgeInvite(env: Env, userId: string, organizationId: string, memberId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'member');
  if (context instanceof Response) return context;
  const member = await context.store.getMember(memberId, organizationId);
  if (!member) return errorResponse('Member not found', 404);
  if (member.userId !== userId && !isOwnerOrAdmin(context.actor)) {
    return errorResponse('You do not have permission to do this in the organization', 403);
  }
  await context.store.acceptMember(memberId);
  return new Response(null, { status: 200 });
}

async function confirmOne(context: OrganizationContext, memberId: string, key: unknown): Promise<string | null> {
  if (!isValidEncString(key)) return 'Member key must be encrypted';
  const member = await context.store.getMember(memberId, context.organization.id);
  if (!member) return 'Member not found';
  if (member.status !== MembershipStatus.Accepted) return 'Member is not waiting for confirmation';
  if (!canAssignType(context.actor, member.type)) return 'Only owners can confirm owners';
  await context.store.confirmMember(memberId, key);
  return null;
}

// POST /api/organizations/:id/users/:memberId/confirm
export async function handleConfirmMember(request: Request, env: Env, userId: string, organizationId: string, memberId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const body = await readJsonBody<{ key?: unknown }>(request);
  if (body instanceof Response) return body;

  const error = await confirmOne(context, memberId, body.key);
  if (error) return errorResponse(error, 400);
  const member = await context.store.getMember(memberId, organizationId);
  if (member) await publishVaultSync(request, env, context.storage, [member.userId]);
  return new Response(null, { status: 200 });
}

// POST /api/organizations/:id/users/confirm
export async function handleBulkConfirmMembers(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const body = await readJsonBody<{ keys?: Array<{ id?: unknown; key?: unknown }> }>(request);
  if (body instanceof Response) return body;
  if (!Array.isArray(body.keys)) return errorResponse('keys array is required', 400);

  const results: Array<{ object: string; id: string; error: string }> = [];
  const confirmedUsers: string[] = [];
  for (const entry of body.keys) {
    const memberId = String(entry?.id ?? '').trim();
    const error = await confirmOne(context, memberId, entry?.key);
    results.push({ object: 'OrganizationBulkConfirmResponseModel', id: memberId, error: error ?? '' });
    if (error) continue;
    const member = await context.store.getMember(memberId, organizationId);
    if (member) confirmedUsers.push(member.userId);
  }
  await publishVaultSync(request, env, context.storage, confirmedUsers);
  return jsonResponse(listResponse(results));
}

// POST /api/organizations/:id/users/public-keys
export async function handleMemberPublicKeys(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const body = await readJsonBody<{ ids?: unknown }>(request);
  if (body instanceof Response) return body;
  const requested = new Set(Array.isArray(body.ids) ? body.ids.map((id) => String(id || '').trim()) : []);

  const members = await context.store.getMembersWithUsers(organizationId);
  return jsonResponse(listResponse(members
    .filter((member) => requested.has(member.id) && member.publicKey)
    .map((member) => ({
      object: 'organizationUserPublicKeyResponseModel',
      id: member.id,
      userId: member.userId,
      key: member.publicKey,
    }))));
}

interface UpdateMemberBody {
  type?: unknown;
  accessAll?: unknown;
  collections?: unknown;
}

// PUT/POST /api/organizations/:id/users/:memberId
export async function handleUpdateMember(request: Request, env: Env, userId: string, organizationId: string, memberId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const body = await readJsonBody<UpdateMemberBody>(request);
  if (body instanceof Response) return body;

  const member = await context.store.getMember(memberId, organizationId);
  if (!member) return errorResponse('Member not found', 404);
  const type = parseMembershipType(body.type ?? member.type);
  if (type instanceof Response) return type;
  if (!canAssignType(context.actor, type) || !canAssignType(context.actor, member.type)) {
    return errorResponse('Only owners can grant or remove owner rights', 403);
  }
  if (type !== MembershipType.Owner && (await isLastConfirmedOwner(context, member))) {
    return errorResponse('The last owner cannot be demoted', 400);
  }

  const grants = parseCollectionGrants(body.collections, () => member.userId, await collectionResolver(context));
  if (grants instanceof Response) return grants;
  const updated: OrganizationMember = { ...member, type, accessAll: body.accessAll === true };
  await context.store.updateMemberAccess(updated, grants);
  await publishVaultSync(request, env, context.storage, [member.userId]);
  return new Response(null, { status: 200 });
}

async function removeOne(context: OrganizationContext, memberId: string): Promise<{ error: string } | { userId: string }> {
  const member = await context.store.getMember(memberId, context.organization.id);
  if (!member) return { error: 'Member not found' };
  if (!canAssignType(context.actor, member.type)) return { error: 'Only owners can remove owners' };
  if (await isLastConfirmedOwner(context, member)) return { error: 'The last owner cannot be removed' };
  await context.store.removeMember(member);
  return { userId: member.userId };
}

// DELETE/POST /api/organizations/:id/users/:memberId(/delete)
export async function handleRemoveMember(request: Request, env: Env, userId: string, organizationId: string, memberId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const result = await removeOne(context, memberId);
  if ('error' in result) return errorResponse(result.error, 400);
  await publishVaultSync(request, env, context.storage, [result.userId]);
  return new Response(null, { status: 200 });
}

// DELETE /api/organizations/:id/users
export async function handleBulkRemoveMembers(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'admin');
  if (context instanceof Response) return context;
  const body = await readJsonBody<{ ids?: unknown }>(request);
  if (body instanceof Response) return body;
  if (!Array.isArray(body.ids)) return errorResponse('ids array is required', 400);

  const results: Array<{ object: string; id: string; error: string }> = [];
  const removedUsers: string[] = [];
  for (const rawId of body.ids) {
    const memberId = String(rawId || '').trim();
    const result = await removeOne(context, memberId);
    results.push({ object: 'OrganizationBulkConfirmResponseModel', id: memberId, error: 'error' in result ? result.error : '' });
    if ('userId' in result) removedUsers.push(result.userId);
  }
  await publishVaultSync(request, env, context.storage, removedUsers);
  return jsonResponse(listResponse(results));
}

// GET /api/plans
export function handleGetPlans(): Response {
  return jsonResponse(listResponse([FREE_PLAN]));
}

// GET /api/organizations/:id/billing/metadata and /subscription
export async function handleGetBillingStub(env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'confirmed');
  if (context instanceof Response) return context;
  const seats = (await context.store.getMemberUserIds(organizationId)).length;
  return jsonResponse({
    ...organizationResponse(context.organization),
    isEligibleForSelfHost: false,
    isManaged: false,
    isOnSecretsManagerStandalone: false,
    isSubscriptionUnpaid: false,
    hasSubscription: false,
    hasOpenInvoice: false,
    isSubscriptionCanceled: false,
    invoiceDueDate: null,
    invoiceCreatedDate: null,
    subPeriodEndDate: null,
    organizationOccupiedSeats: seats,
    storageName: null,
    storageGb: null,
    subscription: null,
    upcomingInvoice: null,
    expiration: null,
  });
}

// GET /api/organizations/:id/auto-enroll-status
export async function handleAutoEnrollStatus(env: Env, userId: string, organizationId: string): Promise<Response> {
  const context = await loadOrganizationContext(env, userId, organizationId, 'member');
  if (context instanceof Response) return context;
  return jsonResponse({ id: organizationId, resetPasswordEnabled: false });
}
