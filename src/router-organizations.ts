import type { Env } from './types';
import { jsonResponse } from './utils/response';
import {
  handleAcknowledgeInvite,
  handleAutoEnrollStatus,
  handleBulkConfirmMembers,
  handleBulkRemoveMembers,
  handleConfirmMember,
  handleCreateOrganization,
  handleDeleteOrganization,
  handleGetBillingStub,
  handleGetMember,
  handleGetOrganization,
  handleGetOrganizationKeys,
  handleGetPlans,
  handleInviteMembers,
  handleLeaveOrganization,
  handleListMembers,
  handleMemberPublicKeys,
  handleRemoveMember,
  handleSetOrganizationKeys,
  handleUpdateMember,
  handleUpdateOrganization,
} from './handlers/organizations';
import {
  handleBulkCipherCollections,
  handleBulkDeleteCollections,
  handleCreateCollection,
  handleDeleteCollection,
  handleGetCollectionDetails,
  handleGetCollectionUsers,
  handleListCollectionDetails,
  handleListOrganizationCollections,
  handleListUserCollections,
  handleOrganizationCipherDetails,
  handleUpdateCollection,
  handleUpdateCollectionUsers,
} from './handlers/collections';
import { handleCreateCipher } from './handlers/ciphers';
import { listResponse } from './handlers/organization-responses';

const EMPTY_LIST_SUBPATHS = new Set(['/policies', '/groups', '/groups/details']);
const BILLING_SUBPATHS = new Set(['/billing/metadata', '/billing/vnext/metadata', '/subscription']);

function isWrite(method: string): boolean {
  return method === 'PUT' || method === 'POST';
}

async function routeMembers(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  memberPath: string,
  method: string
): Promise<Response | null> {
  if (memberPath === '') {
    if (method === 'GET') return handleListMembers(env, userId, organizationId);
    if (method === 'DELETE') return handleBulkRemoveMembers(request, env, userId, organizationId);
    return null;
  }
  if (memberPath === '/mini-details' && method === 'GET') return handleListMembers(env, userId, organizationId);
  if (memberPath === '/invite' && method === 'POST') return handleInviteMembers(request, env, userId, organizationId);
  if (memberPath === '/confirm' && method === 'POST') return handleBulkConfirmMembers(request, env, userId, organizationId);
  if (memberPath === '/public-keys' && method === 'POST') return handleMemberPublicKeys(request, env, userId, organizationId);

  const match = memberPath.match(/^\/([a-f0-9-]+)(\/[a-z-]+)?$/i);
  if (!match) return null;
  const [, memberId, action = ''] = match;
  if (action === '') {
    if (method === 'GET') return handleGetMember(env, userId, organizationId, memberId);
    if (isWrite(method)) return handleUpdateMember(request, env, userId, organizationId, memberId);
    if (method === 'DELETE') return handleRemoveMember(request, env, userId, organizationId, memberId);
  }
  if (action === '/delete' && method === 'POST') return handleRemoveMember(request, env, userId, organizationId, memberId);
  if (action === '/confirm' && method === 'POST') return handleConfirmMember(request, env, userId, organizationId, memberId);
  if ((action === '/accept' || action === '/reinvite') && method === 'POST') {
    return handleAcknowledgeInvite(env, userId, organizationId, memberId);
  }
  return null;
}

async function routeCollections(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionPath: string,
  method: string
): Promise<Response | null> {
  if (collectionPath === '') {
    if (method === 'GET') return handleListOrganizationCollections(env, userId, organizationId);
    if (method === 'POST') return handleCreateCollection(request, env, userId, organizationId);
    if (method === 'DELETE') return handleBulkDeleteCollections(request, env, userId, organizationId);
    return null;
  }
  if (collectionPath === '/details' && method === 'GET') return handleListCollectionDetails(env, userId, organizationId);
  if (collectionPath === '/delete' && method === 'POST') return handleBulkDeleteCollections(request, env, userId, organizationId);

  const match = collectionPath.match(/^\/([a-f0-9-]+)(\/[a-z-]+)?$/i);
  if (!match) return null;
  const [, collectionId, action = ''] = match;
  if (action === '' || action === '/details') {
    if (method === 'GET') return handleGetCollectionDetails(env, userId, organizationId, collectionId);
  }
  if (action === '') {
    if (isWrite(method)) return handleUpdateCollection(request, env, userId, organizationId, collectionId);
    if (method === 'DELETE') return handleDeleteCollection(request, env, userId, organizationId, collectionId);
  }
  if (action === '/delete' && method === 'POST') return handleDeleteCollection(request, env, userId, organizationId, collectionId);
  if (action === '/users') {
    if (method === 'GET') return handleGetCollectionUsers(env, userId, organizationId, collectionId);
    if (method === 'PUT') return handleUpdateCollectionUsers(request, env, userId, organizationId, collectionId);
  }
  return null;
}

async function routeOrganization(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  subPath: string,
  method: string
): Promise<Response | null> {
  if (subPath === '') {
    if (method === 'GET') return handleGetOrganization(env, userId, organizationId);
    if (isWrite(method)) return handleUpdateOrganization(request, env, userId, organizationId);
    if (method === 'DELETE') return handleDeleteOrganization(request, env, userId, organizationId);
    return null;
  }
  if (subPath === '/delete' && method === 'POST') return handleDeleteOrganization(request, env, userId, organizationId);
  if (subPath === '/leave' && method === 'POST') return handleLeaveOrganization(request, env, userId, organizationId);
  if (subPath === '/keys') {
    if (method === 'GET') return handleGetOrganizationKeys(env, userId, organizationId, true);
    if (method === 'POST') return handleSetOrganizationKeys(request, env, userId, organizationId);
  }
  if (subPath === '/public-key' && method === 'GET') return handleGetOrganizationKeys(env, userId, organizationId, false);
  if (subPath === '/auto-enroll-status' && method === 'GET') return handleAutoEnrollStatus(env, userId, organizationId);
  if (BILLING_SUBPATHS.has(subPath) && method === 'GET') return handleGetBillingStub(env, userId, organizationId);
  if (EMPTY_LIST_SUBPATHS.has(subPath) && method === 'GET') return jsonResponse(listResponse([]));
  if (subPath === '/users' || subPath.startsWith('/users/')) {
    return routeMembers(request, env, userId, organizationId, subPath.slice('/users'.length), method);
  }
  if (subPath === '/collections' || subPath.startsWith('/collections/')) {
    return routeCollections(request, env, userId, organizationId, subPath.slice('/collections'.length), method);
  }
  return null;
}

export async function handleOrganizationRoute(
  request: Request,
  env: Env,
  userId: string,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/plans' && method === 'GET') return handleGetPlans();
  if (path === '/api/organizations' && method === 'POST') return handleCreateOrganization(request, env, userId);
  if (path === '/api/collections' && method === 'GET') return handleListUserCollections(env, userId);
  if (path === '/api/ciphers/admin' && method === 'POST') return handleCreateCipher(request, env, userId);
  if (path === '/api/ciphers/bulk-collections' && method === 'POST') return handleBulkCipherCollections(request, env, userId);
  if ((path === '/api/ciphers/organization-details' || path === '/api/ciphers/organization-details/assigned') && method === 'GET') {
    return handleOrganizationCipherDetails(request, env, userId);
  }

  const organizationMatch = path.match(/^\/api\/organizations\/([^/]+)(\/.*)?$/i);
  if (!organizationMatch) return null;
  return routeOrganization(request, env, userId, organizationMatch[1], organizationMatch[2] || '', method);
}
