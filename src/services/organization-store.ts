import {
  MembershipStatus,
  MembershipType,
  type CipherUserSettings,
  type Collection,
  type CollectionGrant,
  type CollectionUser,
  type Organization,
  type OrganizationMember,
} from '../types';

const MAX_IDS_PER_STATEMENT = 90;

export interface OrganizationMemberWithUser extends OrganizationMember {
  email: string;
  name: string | null;
  publicKey: string | null;
  twoFactorEnabled: boolean;
}

export interface MembershipWithOrganization {
  member: OrganizationMember;
  organization: Organization;
}

function chunk<T>(items: readonly T[], size: number = MAX_IDS_PER_STATEMENT): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

function placeholders(items: readonly unknown[]): string {
  return items.map(() => '?').join(',');
}

function uniqueIds(ids: readonly string[]): string[] {
  return Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

function mapOrganization(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email,
    privateKey: row.private_key ?? null,
    publicKey: row.public_key ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapMember(row: any): OrganizationMember {
  return {
    id: row.id,
    userId: row.user_id,
    organizationId: row.organization_id,
    accessAll: !!row.access_all,
    key: row.key ?? null,
    status: Number(row.status) as MembershipStatus,
    type: Number(row.type) as MembershipType,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollection(row: any): Collection {
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollectionUser(row: any): CollectionUser {
  return {
    userId: row.user_id,
    collectionId: row.collection_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  };
}

const MEMBER_COLUMNS = 'ou.id, ou.user_id, ou.organization_id, ou.access_all, ou.key, ou.status, ou.type, ou.created_at, ou.updated_at';
const ORGANIZATION_COLUMNS = 'id, name, billing_email, private_key, public_key, created_at, updated_at';
const COLLECTION_COLUMNS = 'id, organization_id, name, external_id, created_at, updated_at';

export class OrganizationStore {
  constructor(private db: D1Database) {}

  private insertMemberStatement(member: OrganizationMember): D1PreparedStatement {
    return this.db
      .prepare(
        'INSERT INTO organization_users(id, user_id, organization_id, access_all, key, status, type, created_at, updated_at) ' +
        'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(
        member.id, member.userId, member.organizationId, member.accessAll ? 1 : 0, member.key,
        member.status, member.type, member.createdAt, member.updatedAt
      );
  }

  private insertCollectionStatement(collection: Collection): D1PreparedStatement {
    return this.db
      .prepare('INSERT INTO collections(id, organization_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)')
      .bind(collection.id, collection.organizationId, collection.name, collection.externalId, collection.createdAt, collection.updatedAt);
  }

  private insertCollectionUserStatement(collectionUser: CollectionUser): D1PreparedStatement {
    return this.db
      .prepare('INSERT OR REPLACE INTO collection_users(user_id, collection_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?)')
      .bind(
        collectionUser.userId, collectionUser.collectionId,
        collectionUser.readOnly ? 1 : 0, collectionUser.hidePasswords ? 1 : 0, collectionUser.manage ? 1 : 0
      );
  }

  async createOrganization(organization: Organization, owner: OrganizationMember, defaultCollection: Collection | null): Promise<void> {
    await this.db.batch([
      this.db
        .prepare(`INSERT INTO organizations(${ORGANIZATION_COLUMNS}) VALUES(?, ?, ?, ?, ?, ?, ?)`)
        .bind(
          organization.id, organization.name, organization.billingEmail, organization.privateKey,
          organization.publicKey, organization.createdAt, organization.updatedAt
        ),
      this.insertMemberStatement(owner),
      ...(defaultCollection ? [this.insertCollectionStatement(defaultCollection)] : []),
    ]);
  }

  async getOrganization(id: string): Promise<Organization | null> {
    const row = await this.db.prepare(`SELECT ${ORGANIZATION_COLUMNS} FROM organizations WHERE id = ?`).bind(id).first<any>();
    return row ? mapOrganization(row) : null;
  }

  async updateOrganization(id: string, name: string, billingEmail: string): Promise<void> {
    await this.db
      .prepare('UPDATE organizations SET name = ?, billing_email = ?, updated_at = ? WHERE id = ?')
      .bind(name, billingEmail, new Date().toISOString(), id)
      .run();
  }

  async updateOrganizationKeys(id: string, publicKey: string, privateKey: string): Promise<void> {
    await this.db
      .prepare('UPDATE organizations SET public_key = ?, private_key = ?, updated_at = ? WHERE id = ?')
      .bind(publicKey, privateKey, new Date().toISOString(), id)
      .run();
  }

  async deleteOrganization(id: string): Promise<void> {
    const organizationCiphers = 'SELECT id FROM ciphers WHERE organization_id = ?';
    const organizationCollections = 'SELECT id FROM collections WHERE organization_id = ?';
    await this.db.batch([
      this.db.prepare(`DELETE FROM attachments WHERE cipher_id IN (${organizationCiphers})`).bind(id),
      this.db.prepare(`DELETE FROM cipher_user_settings WHERE cipher_id IN (${organizationCiphers})`).bind(id),
      this.db.prepare(`DELETE FROM cipher_collections WHERE collection_id IN (${organizationCollections})`).bind(id),
      this.db.prepare(`DELETE FROM collection_users WHERE collection_id IN (${organizationCollections})`).bind(id),
      this.db.prepare('DELETE FROM ciphers WHERE organization_id = ?').bind(id),
      this.db.prepare('DELETE FROM collections WHERE organization_id = ?').bind(id),
      this.db.prepare('DELETE FROM organization_users WHERE organization_id = ?').bind(id),
      this.db.prepare('DELETE FROM organizations WHERE id = ?').bind(id),
    ]);
  }

  async getMember(memberId: string, organizationId: string): Promise<OrganizationMember | null> {
    const row = await this.db
      .prepare(`SELECT ${MEMBER_COLUMNS} FROM organization_users ou WHERE ou.id = ? AND ou.organization_id = ?`)
      .bind(memberId, organizationId)
      .first<any>();
    return row ? mapMember(row) : null;
  }

  async getMemberByUser(userId: string, organizationId: string): Promise<OrganizationMember | null> {
    const row = await this.db
      .prepare(`SELECT ${MEMBER_COLUMNS} FROM organization_users ou WHERE ou.user_id = ? AND ou.organization_id = ?`)
      .bind(userId, organizationId)
      .first<any>();
    return row ? mapMember(row) : null;
  }

  async getMembersWithUsers(organizationId: string): Promise<OrganizationMemberWithUser[]> {
    const res = await this.db
      .prepare(
        `SELECT ${MEMBER_COLUMNS}, u.email, u.name, u.public_key,
                (u.totp_secret IS NOT NULL OR COALESCE(u.yubikey_key1, u.yubikey_key2, u.yubikey_key3, u.yubikey_key4, u.yubikey_key5) IS NOT NULL)
                  AS two_factor_enabled
         FROM organization_users ou INNER JOIN users u ON u.id = ou.user_id
         WHERE ou.organization_id = ? ORDER BY u.email`
      )
      .bind(organizationId)
      .all<any>();
    return (res.results || []).map((row) => ({
      ...mapMember(row),
      email: row.email,
      name: row.name ?? null,
      publicKey: row.public_key ?? null,
      twoFactorEnabled: !!row.two_factor_enabled,
    }));
  }

  async getMembershipsWithOrganizations(userId: string): Promise<MembershipWithOrganization[]> {
    const res = await this.db
      .prepare(
        `SELECT ${MEMBER_COLUMNS},
                o.id AS org_id, o.name AS org_name, o.billing_email AS org_billing_email, o.private_key AS org_private_key,
                o.public_key AS org_public_key, o.created_at AS org_created_at, o.updated_at AS org_updated_at
         FROM organization_users ou INNER JOIN organizations o ON o.id = ou.organization_id
         WHERE ou.user_id = ? ORDER BY o.name`
      )
      .bind(userId)
      .all<any>();
    return (res.results || []).map((row) => ({
      member: mapMember(row),
      organization: mapOrganization({
        id: row.org_id,
        name: row.org_name,
        billing_email: row.org_billing_email,
        private_key: row.org_private_key,
        public_key: row.org_public_key,
        created_at: row.org_created_at,
        updated_at: row.org_updated_at,
      }),
    }));
  }

  async getConfirmedMemberships(userId: string): Promise<OrganizationMember[]> {
    const res = await this.db
      .prepare(`SELECT ${MEMBER_COLUMNS} FROM organization_users ou WHERE ou.user_id = ? AND ou.status = ?`)
      .bind(userId, MembershipStatus.Confirmed)
      .all<any>();
    return (res.results || []).map(mapMember);
  }

  async countConfirmedOwners(organizationId: string): Promise<number> {
    const row = await this.db
      .prepare('SELECT COUNT(*) AS count FROM organization_users WHERE organization_id = ? AND status = ? AND type = ?')
      .bind(organizationId, MembershipStatus.Confirmed, MembershipType.Owner)
      .first<{ count: number }>();
    return Number(row?.count || 0);
  }

  async addMember(member: OrganizationMember): Promise<void> {
    await this.insertMemberStatement(member).run();
  }

  async confirmMember(memberId: string, key: string): Promise<void> {
    await this.db
      .prepare('UPDATE organization_users SET status = ?, key = ?, updated_at = ? WHERE id = ?')
      .bind(MembershipStatus.Confirmed, key, new Date().toISOString(), memberId)
      .run();
  }

  async acceptMember(memberId: string): Promise<void> {
    await this.db
      .prepare('UPDATE organization_users SET status = ?, updated_at = ? WHERE id = ? AND status = ?')
      .bind(MembershipStatus.Accepted, new Date().toISOString(), memberId, MembershipStatus.Invited)
      .run();
  }

  async updateMemberAccess(member: OrganizationMember, collections: CollectionUser[]): Promise<void> {
    await this.db.batch([
      this.db
        .prepare('UPDATE organization_users SET type = ?, access_all = ?, updated_at = ? WHERE id = ?')
        .bind(member.type, member.accessAll ? 1 : 0, new Date().toISOString(), member.id),
      this.deleteMemberCollectionsStatement(member),
      ...collections.map((collectionUser) => this.insertCollectionUserStatement(collectionUser)),
    ]);
  }

  private deleteMemberCollectionsStatement(member: OrganizationMember): D1PreparedStatement {
    return this.db
      .prepare('DELETE FROM collection_users WHERE user_id = ? AND collection_id IN (SELECT id FROM collections WHERE organization_id = ?)')
      .bind(member.userId, member.organizationId);
  }

  async removeMember(member: OrganizationMember): Promise<void> {
    await this.db.batch([
      this.deleteMemberCollectionsStatement(member),
      this.db
        .prepare('DELETE FROM cipher_user_settings WHERE user_id = ? AND cipher_id IN (SELECT id FROM ciphers WHERE organization_id = ?)')
        .bind(member.userId, member.organizationId),
      this.db.prepare('DELETE FROM organization_users WHERE id = ?').bind(member.id),
    ]);
  }

  async getMemberUserIds(organizationId: string, status: MembershipStatus = MembershipStatus.Confirmed): Promise<string[]> {
    const res = await this.db
      .prepare('SELECT user_id FROM organization_users WHERE organization_id = ? AND status = ?')
      .bind(organizationId, status)
      .all<{ user_id: string }>();
    return (res.results || []).map((row) => row.user_id);
  }

  async getCollection(id: string, organizationId: string): Promise<Collection | null> {
    const row = await this.db
      .prepare(`SELECT ${COLLECTION_COLUMNS} FROM collections WHERE id = ? AND organization_id = ?`)
      .bind(id, organizationId)
      .first<any>();
    return row ? mapCollection(row) : null;
  }

  async getCollectionsForOrganizations(organizationIds: readonly string[]): Promise<Collection[]> {
    const out: Collection[] = [];
    for (const ids of chunk(uniqueIds(organizationIds))) {
      const res = await this.db
        .prepare(`SELECT ${COLLECTION_COLUMNS} FROM collections WHERE organization_id IN (${placeholders(ids)}) ORDER BY name`)
        .bind(...ids)
        .all<any>();
      out.push(...(res.results || []).map(mapCollection));
    }
    return out;
  }

  async createCollection(collection: Collection, users: CollectionUser[]): Promise<void> {
    await this.db.batch([
      this.insertCollectionStatement(collection),
      ...users.map((collectionUser) => this.insertCollectionUserStatement(collectionUser)),
    ]);
  }

  async updateCollection(collection: Collection, users: CollectionUser[] | null): Promise<void> {
    const statements = [
      this.db
        .prepare('UPDATE collections SET name = ?, external_id = ?, updated_at = ? WHERE id = ? AND organization_id = ?')
        .bind(collection.name, collection.externalId, collection.updatedAt, collection.id, collection.organizationId),
    ];
    if (users) {
      statements.push(this.db.prepare('DELETE FROM collection_users WHERE collection_id = ?').bind(collection.id));
      statements.push(...users.map((collectionUser) => this.insertCollectionUserStatement(collectionUser)));
    }
    await this.db.batch(statements);
  }

  async deleteCollections(organizationId: string, collectionIds: readonly string[]): Promise<void> {
    for (const ids of chunk(uniqueIds(collectionIds))) {
      const ownedIds = `SELECT id FROM collections WHERE organization_id = ? AND id IN (${placeholders(ids)})`;
      await this.db.batch([
        this.db.prepare(`DELETE FROM cipher_collections WHERE collection_id IN (${ownedIds})`).bind(organizationId, ...ids),
        this.db.prepare(`DELETE FROM collection_users WHERE collection_id IN (${ownedIds})`).bind(organizationId, ...ids),
        this.db.prepare(`DELETE FROM collections WHERE organization_id = ? AND id IN (${placeholders(ids)})`).bind(organizationId, ...ids),
      ]);
    }
  }

  async getCollectionUsersForOrganization(organizationId: string): Promise<CollectionUser[]> {
    const res = await this.db
      .prepare(
        `SELECT cu.user_id, cu.collection_id, cu.read_only, cu.hide_passwords, cu.manage
         FROM collection_users cu INNER JOIN collections c ON c.id = cu.collection_id
         WHERE c.organization_id = ?`
      )
      .bind(organizationId)
      .all<any>();
    return (res.results || []).map(mapCollectionUser);
  }

  async getCollectionGrantsForUser(userId: string): Promise<Map<string, CollectionGrant>> {
    const res = await this.db
      .prepare('SELECT user_id, collection_id, read_only, hide_passwords, manage FROM collection_users WHERE user_id = ?')
      .bind(userId)
      .all<any>();
    return new Map((res.results || []).map((row) => {
      const { collectionId, readOnly, hidePasswords, manage } = mapCollectionUser(row);
      return [collectionId, { readOnly, hidePasswords, manage }];
    }));
  }

  async getCipherCollectionIds(cipherIds: readonly string[]): Promise<Map<string, string[]>> {
    const grouped = new Map<string, string[]>();
    for (const ids of chunk(uniqueIds(cipherIds))) {
      const res = await this.db
        .prepare(`SELECT cipher_id, collection_id FROM cipher_collections WHERE cipher_id IN (${placeholders(ids)})`)
        .bind(...ids)
        .all<{ cipher_id: string; collection_id: string }>();
      for (const row of res.results || []) {
        const list = grouped.get(row.cipher_id);
        if (list) list.push(row.collection_id);
        else grouped.set(row.cipher_id, [row.collection_id]);
      }
    }
    return grouped;
  }

  async setCipherCollections(cipherId: string, collectionIds: readonly string[]): Promise<void> {
    await this.db.batch([
      this.db.prepare('DELETE FROM cipher_collections WHERE cipher_id = ?').bind(cipherId),
      ...uniqueIds(collectionIds).map((collectionId) =>
        this.db.prepare('INSERT INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?)').bind(cipherId, collectionId)
      ),
    ]);
  }

  async addCiphersToCollections(cipherIds: readonly string[], collectionIds: readonly string[]): Promise<void> {
    const statements = uniqueIds(cipherIds).flatMap((cipherId) =>
      uniqueIds(collectionIds).map((collectionId) =>
        this.db.prepare('INSERT OR IGNORE INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?)').bind(cipherId, collectionId)
      )
    );
    if (statements.length) await this.db.batch(statements);
  }

  async addCipherCollectionLinks(links: ReadonlyArray<{ cipherId: string; collectionId: string }>): Promise<void> {
    for (const linkChunk of chunk(links)) {
      await this.db.batch(linkChunk.map(({ cipherId, collectionId }) =>
        this.db.prepare('INSERT OR IGNORE INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?)').bind(cipherId, collectionId)
      ));
    }
  }

  async removeCiphersFromCollections(cipherIds: readonly string[], collectionIds: readonly string[]): Promise<void> {
    const statements = uniqueIds(cipherIds).flatMap((cipherId) =>
      uniqueIds(collectionIds).map((collectionId) =>
        this.db.prepare('DELETE FROM cipher_collections WHERE cipher_id = ? AND collection_id = ?').bind(cipherId, collectionId)
      )
    );
    if (statements.length) await this.db.batch(statements);
  }

  async getCipherUserSettings(userId: string, cipherIds: readonly string[]): Promise<Map<string, CipherUserSettings>> {
    const settings = new Map<string, CipherUserSettings>();
    for (const ids of chunk(uniqueIds(cipherIds))) {
      const res = await this.db
        .prepare(`SELECT cipher_id, folder_id, favorite FROM cipher_user_settings WHERE user_id = ? AND cipher_id IN (${placeholders(ids)})`)
        .bind(userId, ...ids)
        .all<{ cipher_id: string; folder_id: string | null; favorite: number }>();
      for (const row of res.results || []) {
        settings.set(row.cipher_id, { folderId: row.folder_id ?? null, favorite: !!row.favorite });
      }
    }
    return settings;
  }

  async saveCipherUserSettings(cipherId: string, userId: string, settings: CipherUserSettings): Promise<void> {
    await this.db
      .prepare(
        'INSERT INTO cipher_user_settings(cipher_id, user_id, folder_id, favorite) VALUES(?, ?, ?, ?) ' +
        'ON CONFLICT(cipher_id, user_id) DO UPDATE SET folder_id = excluded.folder_id, favorite = excluded.favorite'
      )
      .bind(cipherId, userId, settings.folderId, settings.favorite ? 1 : 0)
      .run();
  }

  async moveCiphersToFolderForUser(userId: string, cipherIds: readonly string[], folderId: string | null): Promise<void> {
    const statements = uniqueIds(cipherIds).map((cipherId) =>
      this.db
        .prepare(
          'INSERT INTO cipher_user_settings(cipher_id, user_id, folder_id, favorite) VALUES(?, ?, ?, 0) ' +
          'ON CONFLICT(cipher_id, user_id) DO UPDATE SET folder_id = excluded.folder_id'
        )
        .bind(cipherId, userId, folderId)
    );
    if (statements.length) await this.db.batch(statements);
  }

  async getUserIdsWithCipherAccess(cipherIds: readonly string[]): Promise<string[]> {
    const userIds = new Set<string>();
    for (const ids of chunk(uniqueIds(cipherIds), MAX_IDS_PER_STATEMENT / 2)) {
      const list = placeholders(ids);
      const res = await this.db
        .prepare(
          `SELECT ou.user_id FROM ciphers c
           INNER JOIN organization_users ou ON ou.organization_id = c.organization_id
           WHERE c.id IN (${list}) AND ou.status = ${MembershipStatus.Confirmed}
             AND (ou.access_all = 1 OR ou.type IN (${MembershipType.Owner}, ${MembershipType.Admin})
               OR EXISTS (
                 SELECT 1 FROM cipher_collections cc
                 INNER JOIN collection_users cu ON cu.collection_id = cc.collection_id
                 WHERE cc.cipher_id = c.id AND cu.user_id = ou.user_id
               ))
           UNION SELECT user_id FROM ciphers WHERE id IN (${list}) AND user_id IS NOT NULL`
        )
        .bind(...ids, ...ids)
        .all<{ user_id: string }>();
      for (const row of res.results || []) userIds.add(row.user_id);
    }
    return [...userIds];
  }

  async getUserIdsWithCollectionAccess(organizationId: string, collectionIds: readonly string[]): Promise<string[]> {
    const idChunks = chunk(uniqueIds(collectionIds));
    const userIds = new Set<string>();
    for (const ids of idChunks.length ? idChunks : [[]]) {
      const grantedClause = ids.length
        ? `OR EXISTS (SELECT 1 FROM collection_users cu WHERE cu.user_id = ou.user_id AND cu.collection_id IN (${placeholders(ids)}))`
        : '';
      const res = await this.db
        .prepare(
          `SELECT ou.user_id FROM organization_users ou
           WHERE ou.organization_id = ? AND ou.status = ${MembershipStatus.Confirmed}
             AND (ou.access_all = 1 OR ou.type IN (${MembershipType.Owner}, ${MembershipType.Admin}) ${grantedClause})`
        )
        .bind(organizationId, ...ids)
        .all<{ user_id: string }>();
      for (const row of res.results || []) userIds.add(row.user_id);
    }
    return [...userIds];
  }

  async getOrganizationCipherIds(organizationId: string): Promise<string[]> {
    const res = await this.db
      .prepare('SELECT id FROM ciphers WHERE organization_id = ?')
      .bind(organizationId)
      .all<{ id: string }>();
    return (res.results || []).map((row) => row.id);
  }
}
