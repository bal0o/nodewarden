import { t } from '../i18n';
import type { CollectionAccess, MemberCollectionGrant, MembershipType, OrganizationMember } from '../types';
import { parseCollectionAccess, parseListData, parseOrganizationMember } from './organization-parsers';
import { parseErrorMessage, parseJson, type AuthedFetch } from './shared';

export interface CreateOrganizationPayload {
  name: string;
  billingEmail: string;
  key: string;
  collectionName: string;
  keys: { publicKey: string; encryptedPrivateKey: string };
}

export interface MemberAccessPayload {
  type: MembershipType;
  accessAll: boolean;
  collections: MemberCollectionGrant[];
}

export interface CollectionPayload {
  name: string;
  users: MemberCollectionGrant[];
}

function organizationPath(organizationId: string, suffix = ''): string {
  return `/api/organizations/${encodeURIComponent(organizationId)}${suffix}`;
}

async function sendJson(authedFetch: AuthedFetch, path: string, method: string, body: unknown, failureKey: string): Promise<Response> {
  const resp = await authedFetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t(failureKey)));
  return resp;
}

async function sendEmpty(authedFetch: AuthedFetch, path: string, method: string, failureKey: string): Promise<void> {
  const resp = await authedFetch(path, { method });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t(failureKey)));
}

async function getJson(authedFetch: AuthedFetch, path: string, failureKey: string): Promise<unknown> {
  const resp = await authedFetch(path, { cache: 'no-store' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t(failureKey)));
  return parseJson<unknown>(resp);
}

export async function createOrganization(authedFetch: AuthedFetch, payload: CreateOrganizationPayload): Promise<void> {
  await sendJson(authedFetch, '/api/organizations', 'POST', payload, 'txt_organization_create_failed');
}

export async function leaveOrganization(authedFetch: AuthedFetch, organizationId: string): Promise<void> {
  await sendEmpty(authedFetch, organizationPath(organizationId, '/leave'), 'POST', 'txt_organization_leave_failed');
}

export async function deleteOrganization(authedFetch: AuthedFetch, organizationId: string, masterPasswordHash: string): Promise<void> {
  await sendJson(authedFetch, organizationPath(organizationId), 'DELETE', { masterPasswordHash }, 'txt_organization_delete_failed');
}

export async function listMembers(authedFetch: AuthedFetch, organizationId: string): Promise<OrganizationMember[]> {
  const body = await getJson(authedFetch, organizationPath(organizationId, '/users'), 'txt_organization_members_load_failed');
  return parseListData(body, parseOrganizationMember);
}

export async function inviteMember(authedFetch: AuthedFetch, organizationId: string, email: string, access: MemberAccessPayload): Promise<void> {
  await sendJson(authedFetch, organizationPath(organizationId, '/users/invite'), 'POST', { emails: [email], groups: [], ...access }, 'txt_organization_invite_failed');
}

export async function getMemberPublicKey(authedFetch: AuthedFetch, organizationId: string, memberId: string): Promise<string> {
  const resp = await sendJson(authedFetch, organizationPath(organizationId, '/users/public-keys'), 'POST', { ids: [memberId] }, 'txt_organization_confirm_failed');
  const entries = parseListData(await parseJson<unknown>(resp), (item) => {
    const record = item as { id?: unknown; key?: unknown } | null;
    return record && record.id === memberId && typeof record.key === 'string' ? record.key : null;
  });
  if (!entries[0]) throw new Error(t('txt_organization_member_key_missing'));
  return entries[0];
}

export async function confirmMember(authedFetch: AuthedFetch, organizationId: string, memberId: string, key: string): Promise<void> {
  await sendJson(authedFetch, organizationPath(organizationId, `/users/${encodeURIComponent(memberId)}/confirm`), 'POST', { key }, 'txt_organization_confirm_failed');
}

export async function updateMember(authedFetch: AuthedFetch, organizationId: string, memberId: string, access: MemberAccessPayload): Promise<void> {
  await sendJson(authedFetch, organizationPath(organizationId, `/users/${encodeURIComponent(memberId)}`), 'PUT', { groups: [], ...access }, 'txt_organization_member_update_failed');
}

export async function removeMember(authedFetch: AuthedFetch, organizationId: string, memberId: string): Promise<void> {
  await sendEmpty(authedFetch, organizationPath(organizationId, `/users/${encodeURIComponent(memberId)}`), 'DELETE', 'txt_organization_member_remove_failed');
}

export async function listCollectionAccess(authedFetch: AuthedFetch, organizationId: string): Promise<CollectionAccess[]> {
  const body = await getJson(authedFetch, organizationPath(organizationId, '/collections/details'), 'txt_collections_load_failed');
  return parseListData(body, parseCollectionAccess);
}

export async function createCollection(authedFetch: AuthedFetch, organizationId: string, payload: CollectionPayload): Promise<void> {
  await sendJson(authedFetch, organizationPath(organizationId, '/collections'), 'POST', { groups: [], ...payload }, 'txt_collection_save_failed');
}

export async function updateCollection(authedFetch: AuthedFetch, organizationId: string, collectionId: string, payload: CollectionPayload): Promise<void> {
  await sendJson(authedFetch, organizationPath(organizationId, `/collections/${encodeURIComponent(collectionId)}`), 'PUT', { groups: [], ...payload }, 'txt_collection_save_failed');
}

export async function deleteCollection(authedFetch: AuthedFetch, organizationId: string, collectionId: string): Promise<void> {
  await sendEmpty(authedFetch, organizationPath(organizationId, `/collections/${encodeURIComponent(collectionId)}`), 'DELETE', 'txt_collection_delete_failed');
}

export async function shareCipher(authedFetch: AuthedFetch, cipherId: string, cipher: Record<string, unknown>, collectionIds: string[]): Promise<void> {
  await sendJson(authedFetch, `/api/ciphers/${encodeURIComponent(cipherId)}/share`, 'PUT', { cipher, collectionIds }, 'txt_share_item_failed');
}

export async function setCipherCollections(authedFetch: AuthedFetch, cipherId: string, collectionIds: string[]): Promise<void> {
  await sendJson(authedFetch, `/api/ciphers/${encodeURIComponent(cipherId)}/collections_v2`, 'PUT', { collectionIds }, 'txt_item_collections_save_failed');
}
