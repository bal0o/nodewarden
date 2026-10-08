import {
  MembershipStatus,
  MembershipType,
  type Cipher,
  type CipherUserSettings,
  type Collection,
  type CollectionGrant,
  type OrganizationMember,
} from '../types';
import type { OrganizationStore } from './organization-store';

export interface CipherAccess {
  edit: boolean;
  viewPassword: boolean;
  manage: boolean;
  collectionIds: string[];
  settings: CipherUserSettings | null;
}

export interface VisibleCollection {
  collection: Collection;
  grant: CollectionGrant;
}

export interface OrganizationAccess {
  memberships: Map<string, OrganizationMember>;
  collections: Map<string, VisibleCollection>;
}

export const PERSONAL_CIPHER_ACCESS: CipherAccess = {
  edit: true,
  viewPassword: true,
  manage: true,
  collectionIds: [],
  settings: null,
};

const NO_SETTINGS: CipherUserSettings = { folderId: null, favorite: false };

export function isOwnerOrAdmin(member: OrganizationMember): boolean {
  return member.status === MembershipStatus.Confirmed
    && (member.type === MembershipType.Owner || member.type === MembershipType.Admin);
}

export function hasFullAccess(member: OrganizationMember): boolean {
  return member.status === MembershipStatus.Confirmed && (member.accessAll || isOwnerOrAdmin(member));
}

export function effectiveCollectionGrant(member: OrganizationMember, directGrant: CollectionGrant | undefined): CollectionGrant | null {
  if (member.status !== MembershipStatus.Confirmed) return null;
  if (hasFullAccess(member)) {
    return { readOnly: false, hidePasswords: false, manage: isOwnerOrAdmin(member) || member.type === MembershipType.Manager };
  }
  if (!directGrant) return null;
  const canWriteEverything = !directGrant.readOnly && !directGrant.hidePasswords;
  return {
    readOnly: directGrant.readOnly,
    hidePasswords: directGrant.hidePasswords,
    manage: member.type === MembershipType.Manager && (directGrant.manage || canWriteEverything),
  };
}

export async function loadOrganizationAccess(store: OrganizationStore, userId: string): Promise<OrganizationAccess> {
  const confirmed = await store.getConfirmedMemberships(userId);
  const memberships = new Map(confirmed.map((member) => [member.organizationId, member]));
  const collections = new Map<string, VisibleCollection>();
  if (!memberships.size) return { memberships, collections };

  const [allCollections, directGrants] = await Promise.all([
    store.getCollectionsForOrganizations([...memberships.keys()]),
    store.getCollectionGrantsForUser(userId),
  ]);
  for (const collection of allCollections) {
    const member = memberships.get(collection.organizationId);
    const grant = member ? effectiveCollectionGrant(member, directGrants.get(collection.id)) : null;
    if (grant) collections.set(collection.id, { collection, grant });
  }
  return { memberships, collections };
}

export function cipherAccessFor(
  access: OrganizationAccess,
  cipher: Cipher,
  linkedCollectionIds: readonly string[],
  settings: CipherUserSettings | undefined
): CipherAccess | null {
  if (!cipher.organizationId) return null;
  const member = access.memberships.get(cipher.organizationId);
  if (!member) return null;

  const visibleGrants = linkedCollectionIds
    .map((collectionId) => ({ collectionId, visible: access.collections.get(collectionId) }))
    .filter((entry): entry is { collectionId: string; visible: VisibleCollection } =>
      !!entry.visible && entry.visible.collection.organizationId === cipher.organizationId
    );
  const collectionIds = visibleGrants.map((entry) => entry.collectionId);
  const grants = visibleGrants.map((entry) => entry.visible.grant);
  const viewerSettings = settings ?? NO_SETTINGS;

  if (hasFullAccess(member)) {
    return {
      edit: true,
      viewPassword: true,
      manage: isOwnerOrAdmin(member) || grants.some((grant) => grant.manage),
      collectionIds,
      settings: viewerSettings,
    };
  }
  if (!grants.length) return null;
  return {
    edit: grants.some((grant) => !grant.readOnly),
    viewPassword: grants.some((grant) => !grant.hidePasswords),
    manage: grants.some((grant) => grant.manage),
    collectionIds,
    settings: viewerSettings,
  };
}

export function writableCollectionIds(access: OrganizationAccess, organizationId: string): Set<string> {
  const ids = new Set<string>();
  for (const [collectionId, visible] of access.collections) {
    if (visible.collection.organizationId === organizationId && !visible.grant.readOnly) ids.add(collectionId);
  }
  return ids;
}

export interface ResolvedCipher {
  cipher: Cipher;
  access: CipherAccess;
}

export async function resolveCiphersForUser(
  store: OrganizationStore,
  userId: string,
  ciphers: readonly Cipher[],
  preloadedAccess?: OrganizationAccess
): Promise<ResolvedCipher[]> {
  const organizationCiphers = ciphers.filter((cipher) => cipher.organizationId);
  if (!organizationCiphers.length) {
    return ciphers.filter((cipher) => cipher.userId === userId).map((cipher) => ({ cipher, access: PERSONAL_CIPHER_ACCESS }));
  }

  const organizationCipherIds = organizationCiphers.map((cipher) => cipher.id);
  const [access, links, settings] = await Promise.all([
    preloadedAccess ?? loadOrganizationAccess(store, userId),
    store.getCipherCollectionIds(organizationCipherIds),
    store.getCipherUserSettings(userId, organizationCipherIds),
  ]);
  const resolved: ResolvedCipher[] = [];
  for (const cipher of ciphers) {
    if (cipher.userId === userId) {
      resolved.push({ cipher, access: PERSONAL_CIPHER_ACCESS });
      continue;
    }
    const cipherAccess = cipherAccessFor(access, cipher, links.get(cipher.id) || [], settings.get(cipher.id));
    if (cipherAccess) resolved.push({ cipher, access: cipherAccess });
  }
  return resolved;
}
