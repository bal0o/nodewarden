import {
  MembershipType,
  type Collection,
  type CollectionGrant,
  type CollectionUser,
  type Organization,
  type OrganizationMember,
} from '../types';
import type { OrganizationMemberWithUser, OrganizationStore } from '../services/organization-store';

const CUSTOM_PLAN_TYPE = 6;
const ENTERPRISE_PRODUCT_TIER = 3;
const UNLIMITED_STORAGE_GB = 32767;

const FEATURE_FLAGS = {
  use2fa: true,
  useCustomPermissions: false,
  useDirectory: false,
  useEvents: false,
  useGroups: false,
  useTotp: true,
  useScim: false,
  usePolicies: false,
  useApi: false,
  useSso: false,
  useKeyConnector: false,
  useResetPassword: false,
  useSecretsManager: false,
  usePasswordManager: true,
  useActivateAutofillPolicy: false,
  selfHost: true,
  usersGetPremium: true,
} as const;

function memberPermissions(member: OrganizationMember): Record<string, boolean> {
  const isManager = member.type === MembershipType.Manager;
  return {
    accessEventLogs: false,
    accessImportExport: false,
    accessReports: false,
    createNewCollections: isManager,
    editAnyCollection: isManager && member.accessAll,
    deleteAnyCollection: isManager && member.accessAll,
    editAssignedCollections: isManager,
    deleteAssignedCollections: isManager,
    manageGroups: false,
    managePolicies: false,
    manageSso: false,
    manageUsers: false,
    manageResetPassword: false,
    manageScim: false,
  };
}

function hasKeys(organization: Organization): boolean {
  return !!organization.publicKey && !!organization.privateKey;
}

export function organizationResponse(organization: Organization): Record<string, unknown> {
  return {
    ...FEATURE_FLAGS,
    id: organization.id,
    identifier: null,
    name: organization.name,
    seats: null,
    maxAutoscaleSeats: null,
    maxCollections: null,
    maxStorageGb: UNLIMITED_STORAGE_GB,
    hasPublicAndPrivateKeys: hasKeys(organization),
    allowAdminAccessToAllCollectionItems: true,
    limitCollectionCreation: true,
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    businessName: organization.name,
    businessAddress1: null,
    businessAddress2: null,
    businessAddress3: null,
    businessCountry: null,
    businessTaxNumber: null,
    billingEmail: organization.billingEmail,
    planType: CUSTOM_PLAN_TYPE,
    productTierType: ENTERPRISE_PRODUCT_TIER,
    object: 'organization',
  };
}

export function profileOrganizationResponse(member: OrganizationMember, organization: Organization): Record<string, unknown> {
  return {
    ...FEATURE_FLAGS,
    id: organization.id,
    identifier: null,
    name: organization.name,
    seats: null,
    maxAutoscaleSeats: null,
    maxCollections: null,
    maxStorageGb: UNLIMITED_STORAGE_GB,
    hasPublicAndPrivateKeys: hasKeys(organization),
    resetPasswordEnrolled: false,
    ssoBound: false,
    organizationUserId: member.id,
    providerId: null,
    providerName: null,
    providerType: null,
    familySponsorshipFriendlyName: null,
    familySponsorshipAvailable: false,
    familySponsorshipLastSyncDate: null,
    familySponsorshipValidUntil: null,
    familySponsorshipToDelete: null,
    productTierType: ENTERPRISE_PRODUCT_TIER,
    planProductType: ENTERPRISE_PRODUCT_TIER,
    keyConnectorEnabled: false,
    keyConnectorUrl: null,
    accessSecretsManager: false,
    limitCollectionCreation: true,
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    allowAdminAccessToAllCollectionItems: true,
    userIsManagedByOrganization: false,
    userIsClaimedByOrganization: false,
    permissions: memberPermissions(member),
    userId: member.userId,
    key: member.key,
    status: member.status,
    type: member.type,
    enabled: true,
    object: 'profileOrganization',
  };
}

export async function loadProfileOrganizations(store: OrganizationStore, userId: string): Promise<Record<string, unknown>[]> {
  const memberships = await store.getMembershipsWithOrganizations(userId);
  return memberships.map(({ member, organization }) => profileOrganizationResponse(member, organization));
}

function collectionGrantResponse(id: string, grant: CollectionGrant): Record<string, unknown> {
  return { id, readOnly: grant.readOnly, hidePasswords: grant.hidePasswords, manage: grant.manage };
}

export function memberResponse(
  member: OrganizationMemberWithUser,
  collections: readonly CollectionUser[],
  object: 'organizationUserUserDetails' | 'organizationUserDetails' = 'organizationUserUserDetails'
): Record<string, unknown> {
  return {
    id: member.id,
    userId: member.userId,
    organizationId: member.organizationId,
    name: member.name,
    email: member.email,
    externalId: null,
    avatarColor: null,
    groups: [],
    collections: collections.map((grant) => collectionGrantResponse(grant.collectionId, grant)),
    status: member.status,
    type: member.type,
    accessAll: member.accessAll,
    twoFactorEnabled: member.twoFactorEnabled,
    resetPasswordEnrolled: false,
    hasMasterPassword: true,
    permissions: memberPermissions(member),
    ssoBound: false,
    managedByOrganization: false,
    claimedByOrganization: false,
    usesKeyConnector: false,
    accessSecretsManager: false,
    object,
  };
}

export function collectionResponse(collection: Collection): Record<string, unknown> {
  return {
    id: collection.id,
    organizationId: collection.organizationId,
    name: collection.name,
    externalId: collection.externalId,
    type: 0,
    defaultUserCollectionEmail: null,
    object: 'collection',
  };
}

export function collectionDetailsResponse(collection: Collection, grant: CollectionGrant): Record<string, unknown> {
  return {
    ...collectionResponse(collection),
    readOnly: grant.readOnly,
    hidePasswords: grant.hidePasswords,
    manage: grant.manage,
    object: 'collectionDetails',
  };
}

export function collectionAccessDetailsResponse(
  collection: Collection,
  grant: CollectionGrant | null,
  members: readonly OrganizationMember[],
  collectionUsers: readonly CollectionUser[]
): Record<string, unknown> {
  const membershipIdByUser = new Map(members.map((member) => [member.userId, member.id]));
  const users = collectionUsers.flatMap((collectionUser) => {
    const membershipId = membershipIdByUser.get(collectionUser.userId);
    return membershipId ? [collectionGrantResponse(membershipId, collectionUser)] : [];
  });
  return {
    ...collectionResponse(collection),
    assigned: !!grant,
    readOnly: grant?.readOnly ?? false,
    hidePasswords: grant?.hidePasswords ?? false,
    manage: grant?.manage ?? false,
    users,
    groups: [],
    object: 'collectionAccessDetails',
  };
}

export function listResponse(data: unknown[]): Record<string, unknown> {
  return { data, object: 'list', continuationToken: null };
}

export const FREE_PLAN = {
  type: 0,
  productTier: 0,
  name: 'Free',
  nameLocalizationKey: 'planNameFree',
  descriptionLocalizationKey: 'planDescFree',
  isAnnual: false,
  disabled: false,
  legacyYear: null,
  upgradeSortOrder: -1,
  displaySortOrder: -1,
  hasSelfHost: true,
  hasPolicies: false,
  hasGroups: false,
  hasDirectory: false,
  hasEvents: false,
  hasTotp: true,
  has2fa: true,
  hasApi: false,
  hasSso: false,
  hasResetPassword: false,
  usersGetPremium: true,
  trialPeriodDays: null,
  object: 'plan',
  passwordManager: {
    stripePlanId: null,
    stripeSeatPlanId: null,
    stripeProviderPortalSeatPlanId: null,
    basePrice: 0,
    seatPrice: 0,
    providerPortalSeatPrice: 0,
    allowSeatAutoscale: false,
    hasAdditionalSeatsOption: false,
    maxAdditionalSeats: null,
    baseSeats: 2147483647,
    maxSeats: 2147483647,
    maxCollections: null,
    maxProjects: null,
    hasPremiumAccessOption: false,
    hasAdditionalStorageOption: false,
    baseStorageGb: null,
    additionalStoragePricePerGb: 0,
    stripeStoragePlanId: null,
    stripePremiumAccessPlanId: null,
    premiumAccessOptionPrice: 0,
  },
  secretsManager: null,
};
