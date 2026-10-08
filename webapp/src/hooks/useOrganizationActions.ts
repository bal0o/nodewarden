import { useMemo } from 'preact/hooks';
import { deriveLoginHash } from '@/lib/api/auth';
import {
  confirmMember as confirmMemberRequest,
  createCollection as createCollectionRequest,
  createOrganization as createOrganizationRequest,
  deleteCollection as deleteCollectionRequest,
  deleteOrganization as deleteOrganizationRequest,
  getMemberPublicKey,
  inviteMember as inviteMemberRequest,
  leaveOrganization as leaveOrganizationRequest,
  listCollectionAccess as listCollectionAccessRequest,
  listMembers as listMembersRequest,
  removeMember as removeMemberRequest,
  setCipherCollections as setCipherCollectionsRequest,
  shareCipher as shareCipherRequest,
  updateCollection as updateCollectionRequest,
  updateMember as updateMemberRequest,
  type MemberAccessPayload,
} from '@/lib/api/organizations';
import type { AuthedFetch } from '@/lib/api/shared';
import { buildSharedCipherPayload } from '@/lib/api/vault';
import { t } from '@/lib/i18n';
import {
  createOrganizationKeyMaterial,
  decryptTextWithKey,
  encryptOrganizationKeyForMember,
  encryptTextWithKey,
  sessionWithKey,
  type OrganizationKeys,
  type SymmetricKey,
} from '@/lib/organization-keys';
import type { Cipher, CollectionAccess, MemberCollectionGrant, OrganizationMember, SessionState } from '@/lib/types';

type Notify = (type: 'success' | 'error' | 'warning', text: string) => void;

interface UseOrganizationActionsOptions {
  authedFetch: AuthedFetch;
  session: SessionState | null;
  userPrivateKey: string | null;
  organizationKeys: OrganizationKeys;
  defaultKdfIterations: number;
  onNotify: Notify;
  refreshVault: () => Promise<void>;
}

export interface OrganizationActions {
  createOrganization: (name: string, collectionName: string) => Promise<boolean>;
  leaveOrganization: (organizationId: string) => Promise<boolean>;
  deleteOrganization: (organizationId: string, masterPassword: string) => Promise<boolean>;
  listMembers: (organizationId: string) => Promise<OrganizationMember[] | null>;
  inviteMember: (organizationId: string, email: string, access: MemberAccessPayload) => Promise<boolean>;
  confirmMember: (organizationId: string, memberId: string) => Promise<boolean>;
  updateMember: (organizationId: string, memberId: string, access: MemberAccessPayload) => Promise<boolean>;
  removeMember: (organizationId: string, memberId: string) => Promise<boolean>;
  listCollectionAccess: (organizationId: string) => Promise<CollectionAccess[] | null>;
  createCollection: (organizationId: string, name: string, users: MemberCollectionGrant[]) => Promise<boolean>;
  updateCollection: (organizationId: string, collectionId: string, name: string, users: MemberCollectionGrant[]) => Promise<boolean>;
  deleteCollection: (organizationId: string, collectionId: string) => Promise<boolean>;
  shareCipher: (cipher: Cipher, organizationId: string, collectionIds: string[]) => Promise<boolean>;
  setCipherCollections: (cipherId: string, collectionIds: string[]) => Promise<boolean>;
}

function errorText(error: unknown, fallbackKey: string): string {
  return error instanceof Error && error.message ? error.message : t(fallbackKey);
}

export default function useOrganizationActions(options: UseOrganizationActionsOptions): OrganizationActions {
  const { authedFetch, session, userPrivateKey, organizationKeys, defaultKdfIterations, onNotify, refreshVault } = options;

  return useMemo(() => {
    function requireSession(): SessionState {
      if (!session?.symEncKey || !session.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
      return session;
    }

    function requireOrganizationKey(organizationId: string): SymmetricKey {
      const key = organizationKeys[organizationId];
      if (!key) throw new Error(t('txt_organization_key_unavailable'));
      return key;
    }

    async function mutate(action: () => Promise<void>, successKey: string, failureKey: string): Promise<boolean> {
      try {
        await action();
        await refreshVault();
        onNotify('success', t(successKey));
        return true;
      } catch (error) {
        onNotify('error', errorText(error, failureKey));
        return false;
      }
    }

    async function load<T>(action: () => Promise<T>, failureKey: string): Promise<T | null> {
      try {
        return await action();
      } catch (error) {
        onNotify('error', errorText(error, failureKey));
        return null;
      }
    }

    return {
      createOrganization: (name, collectionName) =>
        mutate(async () => {
          const activeSession = requireSession();
          if (!userPrivateKey) throw new Error(t('txt_organization_account_keys_missing'));
          const material = await createOrganizationKeyMaterial(userPrivateKey, activeSession);
          await createOrganizationRequest(authedFetch, {
            name,
            billingEmail: activeSession.email,
            key: material.encryptedOrganizationKey,
            collectionName: await encryptTextWithKey(collectionName, material.organizationKey),
            keys: { publicKey: material.publicKey, encryptedPrivateKey: material.encryptedPrivateKey },
          });
        }, 'txt_organization_created', 'txt_organization_create_failed'),

      leaveOrganization: (organizationId) =>
        mutate(() => leaveOrganizationRequest(authedFetch, organizationId), 'txt_organization_left', 'txt_organization_leave_failed'),

      deleteOrganization: (organizationId, masterPassword) =>
        mutate(async () => {
          const activeSession = requireSession();
          const derived = await deriveLoginHash(activeSession.email, masterPassword, defaultKdfIterations);
          await deleteOrganizationRequest(authedFetch, organizationId, derived.hash);
        }, 'txt_organization_deleted', 'txt_organization_delete_failed'),

      listMembers: (organizationId) =>
        load(() => listMembersRequest(authedFetch, organizationId), 'txt_organization_members_load_failed'),

      inviteMember: (organizationId, email, access) =>
        mutate(() => inviteMemberRequest(authedFetch, organizationId, email, access), 'txt_organization_member_invited', 'txt_organization_invite_failed'),

      confirmMember: (organizationId, memberId) =>
        mutate(async () => {
          const organizationKey = requireOrganizationKey(organizationId);
          const publicKey = await getMemberPublicKey(authedFetch, organizationId, memberId);
          const key = await encryptOrganizationKeyForMember(organizationKey, publicKey);
          await confirmMemberRequest(authedFetch, organizationId, memberId, key);
        }, 'txt_organization_member_confirmed', 'txt_organization_confirm_failed'),

      updateMember: (organizationId, memberId, access) =>
        mutate(() => updateMemberRequest(authedFetch, organizationId, memberId, access), 'txt_organization_member_updated', 'txt_organization_member_update_failed'),

      removeMember: (organizationId, memberId) =>
        mutate(() => removeMemberRequest(authedFetch, organizationId, memberId), 'txt_organization_member_removed', 'txt_organization_member_remove_failed'),

      listCollectionAccess: (organizationId) =>
        load(async () => {
          const organizationKey = requireOrganizationKey(organizationId);
          const collections = await listCollectionAccessRequest(authedFetch, organizationId);
          return Promise.all(
            collections.map(async (collection) => ({
              ...collection,
              decName: await decryptTextWithKey(collection.name, organizationKey).catch(() => ''),
            }))
          );
        }, 'txt_collections_load_failed'),

      createCollection: (organizationId, name, users) =>
        mutate(async () => {
          const encryptedName = await encryptTextWithKey(name, requireOrganizationKey(organizationId));
          await createCollectionRequest(authedFetch, organizationId, { name: encryptedName, users });
        }, 'txt_collection_saved', 'txt_collection_save_failed'),

      updateCollection: (organizationId, collectionId, name, users) =>
        mutate(async () => {
          const encryptedName = await encryptTextWithKey(name, requireOrganizationKey(organizationId));
          await updateCollectionRequest(authedFetch, organizationId, collectionId, { name: encryptedName, users });
        }, 'txt_collection_saved', 'txt_collection_save_failed'),

      deleteCollection: (organizationId, collectionId) =>
        mutate(() => deleteCollectionRequest(authedFetch, organizationId, collectionId), 'txt_collection_deleted', 'txt_collection_delete_failed'),

      shareCipher: (cipher, organizationId, collectionIds) =>
        mutate(async () => {
          const activeSession = requireSession();
          const organizationSession = sessionWithKey(activeSession, requireOrganizationKey(organizationId));
          const payload = await buildSharedCipherPayload(activeSession, organizationSession, cipher, organizationId);
          await shareCipherRequest(authedFetch, cipher.id, payload, collectionIds);
        }, 'txt_item_shared', 'txt_share_item_failed'),

      setCipherCollections: (cipherId, collectionIds) =>
        mutate(() => setCipherCollectionsRequest(authedFetch, cipherId, collectionIds), 'txt_item_collections_saved', 'txt_item_collections_save_failed'),
    };
  }, [authedFetch, session, userPrivateKey, organizationKeys, defaultKdfIterations, onNotify, refreshVault]);
}
