import {
  MembershipStatus,
  MembershipType,
  type Collection,
  type CollectionAccess,
  type MemberCollectionGrant,
  type OrganizationMember,
  type ProfileOrganization,
} from '../types';

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : null;
}

function readString(record: JsonRecord, key: string): string {
  const value = record[key];
  return typeof value === 'string' ? value : '';
}

function parseMembershipType(value: unknown): MembershipType | null {
  const type = Number(value);
  return Object.values(MembershipType).includes(type) ? type as MembershipType : null;
}

function parseMembershipStatus(value: unknown): MembershipStatus | null {
  const status = Number(value);
  return Object.values(MembershipStatus).includes(status) ? status as MembershipStatus : null;
}

function parseGrant(value: unknown): MemberCollectionGrant | null {
  const record = asRecord(value);
  const id = record ? readString(record, 'id') : '';
  if (!record || !id) return null;
  return {
    id,
    readOnly: record.readOnly === true,
    hidePasswords: record.hidePasswords === true,
    manage: record.manage === true,
  };
}

export function parseItems<T>(value: unknown, parse: (item: unknown) => T | null): T[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const parsed = parse(item);
    return parsed ? [parsed] : [];
  });
}

function parseGrants(value: unknown): MemberCollectionGrant[] {
  return parseItems(value, parseGrant);
}

export function parseProfileOrganization(value: unknown): ProfileOrganization | null {
  const record = asRecord(value);
  if (!record) return null;
  const id = readString(record, 'id');
  const type = parseMembershipType(record.type);
  const status = parseMembershipStatus(record.status);
  if (!id || type === null || status === null) return null;
  return {
    id,
    name: readString(record, 'name'),
    key: readString(record, 'key') || null,
    status,
    type,
  };
}

export function parseCollection(value: unknown): Collection | null {
  const record = asRecord(value);
  if (!record) return null;
  const id = readString(record, 'id');
  const organizationId = readString(record, 'organizationId');
  if (!id || !organizationId) return null;
  return {
    id,
    organizationId,
    name: readString(record, 'name'),
    readOnly: record.readOnly === true,
    hidePasswords: record.hidePasswords === true,
    manage: record.manage === true,
  };
}

export function parseOrganizationMember(value: unknown): OrganizationMember | null {
  const record = asRecord(value);
  if (!record) return null;
  const id = readString(record, 'id');
  const type = parseMembershipType(record.type);
  const status = parseMembershipStatus(record.status);
  if (!id || type === null || status === null) return null;
  return {
    id,
    userId: readString(record, 'userId'),
    name: readString(record, 'name') || null,
    email: readString(record, 'email'),
    status,
    type,
    accessAll: record.accessAll === true,
    collections: parseGrants(record.collections),
  };
}

export function parseCollectionAccess(value: unknown): CollectionAccess | null {
  const record = asRecord(value);
  if (!record) return null;
  const id = readString(record, 'id');
  const organizationId = readString(record, 'organizationId');
  if (!id || !organizationId) return null;
  return {
    id,
    organizationId,
    name: readString(record, 'name'),
    users: parseGrants(record.users),
  };
}

export function parseListData<T>(body: unknown, parse: (item: unknown) => T | null): T[] {
  return parseItems(asRecord(body)?.data, parse);
}
