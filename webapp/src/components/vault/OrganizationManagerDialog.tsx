import { createPortal } from 'preact/compat';
import { useEffect, useState } from 'preact/hooks';
import { Check, Library, LogOut, Pencil, Plus, Trash2, UserPlus, X } from 'lucide-preact';
import ConfirmDialog, { useDialogLifecycle } from '@/components/ConfirmDialog';
import { collectionDisplayName } from '@/components/vault/vault-page-helpers';
import type { OrganizationActions } from '@/hooks/useOrganizationActions';
import { t } from '@/lib/i18n';
import {
  MembershipStatus,
  MembershipType,
  type CollectionAccess,
  type CollectionGrant,
  type MemberCollectionGrant,
  type OrganizationMember,
  type ProfileOrganization,
} from '@/lib/types';

interface OrganizationManagerDialogProps {
  organization: ProfileOrganization | null;
  actions: OrganizationActions;
  onClose: () => void;
}

interface CollectionEditorState {
  collectionId: string | null;
  name: string;
  grants: Record<string, CollectionGrant>;
}

type PendingAction =
  | { kind: 'remove-member'; member: OrganizationMember }
  | { kind: 'delete-collection'; collection: CollectionAccess }
  | { kind: 'leave' }
  | { kind: 'delete-organization' };

const EMPTY_GRANT: CollectionGrant = { readOnly: false, hidePasswords: false, manage: false };

function roleLabel(type: MembershipType): string {
  if (type === MembershipType.Owner) return t('txt_role_owner');
  if (type === MembershipType.Admin) return t('txt_role_admin');
  if (type === MembershipType.Manager) return t('txt_role_manager');
  return t('txt_role_user');
}

function statusLabel(status: MembershipStatus): string {
  if (status === MembershipStatus.Invited) return t('txt_member_status_invited');
  if (status === MembershipStatus.Accepted) return t('txt_member_status_accepted');
  return t('txt_member_status_confirmed');
}

function assignableRoles(isOwner: boolean): MembershipType[] {
  const roles = [MembershipType.User, MembershipType.Manager, MembershipType.Admin];
  return isOwner ? [...roles, MembershipType.Owner] : roles;
}

function memberLabel(member: OrganizationMember): string {
  return member.name ? `${member.name} (${member.email})` : member.email;
}

function editorFor(collection: CollectionAccess | null): CollectionEditorState {
  const grants: Record<string, CollectionGrant> = {};
  for (const user of collection?.users || []) {
    grants[user.id] = { readOnly: user.readOnly, hidePasswords: user.hidePasswords, manage: user.manage };
  }
  return { collectionId: collection?.id ?? null, name: collection ? collectionDisplayName(collection) : '', grants };
}

function grantsToPayload(grants: Record<string, CollectionGrant>): MemberCollectionGrant[] {
  return Object.entries(grants).map(([id, grant]) => ({ id, ...grant }));
}

function RoleSelect(props: { value: MembershipType; roles: MembershipType[]; disabled: boolean; onChange: (type: MembershipType) => void }) {
  return (
    <select
      className="input"
      value={props.value}
      disabled={props.disabled}
      onInput={(e) => props.onChange(Number((e.currentTarget as HTMLSelectElement).value) as MembershipType)}
    >
      {props.roles.map((role) => (
        <option key={role} value={role}>{roleLabel(role)}</option>
      ))}
    </select>
  );
}

function CollectionEditor(props: {
  editor: CollectionEditorState;
  members: OrganizationMember[];
  saving: boolean;
  onChange: (editor: CollectionEditorState) => void;
  onSave: () => void;
  onCancel: () => void;
}) {
  function setGrant(memberId: string, grant: CollectionGrant | null): void {
    const grants = { ...props.editor.grants };
    if (grant) grants[memberId] = grant;
    else delete grants[memberId];
    props.onChange({ ...props.editor, grants });
  }

  function patchGrant(memberId: string, patch: Partial<CollectionGrant>): void {
    setGrant(memberId, { ...(props.editor.grants[memberId] || EMPTY_GRANT), ...patch });
  }

  return (
    <div className="organization-section">
      <label className="field">
        <span>{t('txt_collection_name')}</span>
        <input className="input" value={props.editor.name} onInput={(e) => props.onChange({ ...props.editor, name: (e.currentTarget as HTMLInputElement).value })} />
      </label>
      <table className="organization-table">
        <thead>
          <tr>
            <th>{t('txt_member')}</th>
            <th>{t('txt_access')}</th>
            <th>{t('txt_read_only')}</th>
            <th>{t('txt_hide_passwords')}</th>
            <th>{t('txt_can_manage')}</th>
          </tr>
        </thead>
        <tbody>
          {props.members.map((member) => {
            const grant = props.editor.grants[member.id];
            return (
              <tr key={member.id}>
                <td>{memberLabel(member)}</td>
                <td><input type="checkbox" checked={!!grant} onInput={(e) => setGrant(member.id, (e.currentTarget as HTMLInputElement).checked ? EMPTY_GRANT : null)} /></td>
                <td><input type="checkbox" disabled={!grant} checked={!!grant?.readOnly} onInput={(e) => patchGrant(member.id, { readOnly: (e.currentTarget as HTMLInputElement).checked })} /></td>
                <td><input type="checkbox" disabled={!grant} checked={!!grant?.hidePasswords} onInput={(e) => patchGrant(member.id, { hidePasswords: (e.currentTarget as HTMLInputElement).checked })} /></td>
                <td><input type="checkbox" disabled={!grant} checked={!!grant?.manage} onInput={(e) => patchGrant(member.id, { manage: (e.currentTarget as HTMLInputElement).checked })} /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="actions">
        <button type="button" className="btn btn-primary small" disabled={props.saving || !props.editor.name.trim()} onClick={props.onSave}>
          <Check size={14} className="btn-icon" /> {t('txt_save')}
        </button>
        <button type="button" className="btn btn-secondary small" disabled={props.saving} onClick={props.onCancel}>
          <X size={14} className="btn-icon" /> {t('txt_cancel')}
        </button>
      </div>
    </div>
  );
}

export default function OrganizationManagerDialog(props: OrganizationManagerDialogProps) {
  const organization = props.organization;
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [collections, setCollections] = useState<CollectionAccess[]>([]);
  const [saving, setSaving] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteType, setInviteType] = useState<MembershipType>(MembershipType.User);
  const [editor, setEditor] = useState<CollectionEditorState | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [deletePassword, setDeletePassword] = useState('');

  const isConfirmed = organization?.status === MembershipStatus.Confirmed && !!organization.key;
  const isOwner = isConfirmed && organization?.type === MembershipType.Owner;
  const canManage = isConfirmed && (organization?.type === MembershipType.Owner || organization?.type === MembershipType.Admin);
  const roles = assignableRoles(isOwner);

  useDialogLifecycle(!!organization, pending || saving ? null : props.onClose);

  async function reload(): Promise<void> {
    if (!organization || !canManage) return;
    const [nextMembers, nextCollections] = await Promise.all([
      props.actions.listMembers(organization.id),
      props.actions.listCollectionAccess(organization.id),
    ]);
    setMembers(nextMembers || []);
    setCollections(nextCollections || []);
  }

  useEffect(() => {
    setMembers([]);
    setCollections([]);
    setEditor(null);
    setPending(null);
    setInviteEmail('');
    setInviteType(MembershipType.User);
    setDeletePassword('');
    void reload();
  }, [organization?.id, canManage]);

  async function run(action: () => Promise<boolean>, afterSuccess: () => void | Promise<void> = reload): Promise<void> {
    setSaving(true);
    const succeeded = await action();
    setSaving(false);
    if (succeeded) await afterSuccess();
  }

  if (!organization || typeof document === 'undefined') return null;
  const organizationId = organization.id;

  function invite(): void {
    const email = inviteEmail.trim();
    if (!email) return;
    void run(
      () => props.actions.inviteMember(organizationId, email, { type: inviteType, accessAll: false, collections: [] }),
      async () => {
        setInviteEmail('');
        await reload();
      }
    );
  }

  function changeRole(member: OrganizationMember, type: MembershipType): void {
    void run(() => props.actions.updateMember(organizationId, member.id, { type, accessAll: member.accessAll, collections: member.collections }));
  }

  function saveCollection(): void {
    if (!editor) return;
    const users = grantsToPayload(editor.grants);
    const name = editor.name.trim();
    void run(
      () => editor.collectionId
        ? props.actions.updateCollection(organizationId, editor.collectionId, name, users)
        : props.actions.createCollection(organizationId, name, users),
      async () => {
        setEditor(null);
        await reload();
      }
    );
  }

  function confirmPending(): void {
    if (!pending) return;
    if (pending.kind === 'remove-member') {
      void run(() => props.actions.removeMember(organizationId, pending.member.id), async () => {
        setPending(null);
        await reload();
      });
    } else if (pending.kind === 'delete-collection') {
      void run(() => props.actions.deleteCollection(organizationId, pending.collection.id), async () => {
        setPending(null);
        await reload();
      });
    } else if (pending.kind === 'leave') {
      void run(() => props.actions.leaveOrganization(organizationId), props.onClose);
    } else if (deletePassword) {
      void run(() => props.actions.deleteOrganization(organizationId, deletePassword), props.onClose);
    }
  }

  return createPortal(
    <div className="dialog-mask open" onClick={(event) => event.target === event.currentTarget && !pending && !saving && props.onClose()}>
      <section className="dialog-card organization-dialog open" role="dialog" aria-modal="true" aria-label={organization.name}>
        <div className="organization-dialog-head">
          <h3 className="dialog-title">{organization.name}</h3>
          <button type="button" className="password-history-close" aria-label={t('txt_close')} disabled={saving} onClick={props.onClose}>
            <X size={18} />
          </button>
        </div>

        {!isConfirmed && <div className="detail-sub">{t('txt_organization_pending_message')}</div>}

        {canManage && (
          <>
            <div className="organization-section">
              <div className="organization-section-head">
                <h4>{t('txt_members')}</h4>
              </div>
              <table className="organization-table">
                <tbody>
                  {members.map((member) => (
                    <tr key={member.id}>
                      <td>{memberLabel(member)}</td>
                      <td>{statusLabel(member.status)}</td>
                      <td>
                        <RoleSelect
                          value={member.type}
                          roles={member.type === MembershipType.Owner && !isOwner ? [MembershipType.Owner] : roles}
                          disabled={saving || (member.type === MembershipType.Owner && !isOwner)}
                          onChange={(type) => changeRole(member, type)}
                        />
                      </td>
                      <td>
                        <div className="actions">
                          {member.status === MembershipStatus.Accepted && (
                            <button type="button" className="btn btn-primary small" disabled={saving} onClick={() => void run(() => props.actions.confirmMember(organizationId, member.id))}>
                              <Check size={14} className="btn-icon" /> {t('txt_confirm')}
                            </button>
                          )}
                          <button
                            type="button"
                            className="folder-delete-btn"
                            title={t('txt_remove')}
                            aria-label={t('txt_remove')}
                            disabled={saving}
                            onClick={() => setPending({ kind: 'remove-member', member })}
                          >
                            <X size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="organization-inline-form">
                <input
                  className="input"
                  type="email"
                  placeholder={t('txt_email')}
                  aria-label={t('txt_email')}
                  value={inviteEmail}
                  onInput={(e) => setInviteEmail((e.currentTarget as HTMLInputElement).value)}
                  onKeyDown={(e) => {
                    if (e.key !== 'Enter') return;
                    e.preventDefault();
                    invite();
                  }}
                />
                <RoleSelect value={inviteType} roles={roles} disabled={saving} onChange={setInviteType} />
                <button type="button" className="btn btn-secondary small" disabled={saving || !inviteEmail.trim()} onClick={invite}>
                  <UserPlus size={14} className="btn-icon" /> {t('txt_invite')}
                </button>
              </div>
              <div className="detail-sub">{t('txt_invite_existing_users_only')}</div>
            </div>

            <div className="organization-section">
              <div className="organization-section-head">
                <h4>{t('txt_collections')}</h4>
                {!editor && (
                  <button type="button" className="btn btn-secondary small" disabled={saving} onClick={() => setEditor(editorFor(null))}>
                    <Plus size={14} className="btn-icon" /> {t('txt_new_collection')}
                  </button>
                )}
              </div>
              {editor ? (
                <CollectionEditor
                  editor={editor}
                  members={members}
                  saving={saving}
                  onChange={setEditor}
                  onSave={saveCollection}
                  onCancel={() => setEditor(null)}
                />
              ) : (
                <table className="organization-table">
                  <tbody>
                    {collections.map((collection) => (
                      <tr key={collection.id}>
                        <td>
                          <span className="organization-collection-name">
                            <Library size={14} className="tree-icon" />
                            {collectionDisplayName(collection)}
                          </span>
                        </td>
                        <td>{t('txt_member_count', { count: collection.users.length })}</td>
                        <td>
                          <div className="actions">
                            <button type="button" className="folder-delete-btn folder-edit-btn" title={t('txt_edit')} aria-label={t('txt_edit')} disabled={saving} onClick={() => setEditor(editorFor(collection))}>
                              <Pencil size={12} />
                            </button>
                            <button type="button" className="folder-delete-btn" title={t('txt_delete')} aria-label={t('txt_delete')} disabled={saving} onClick={() => setPending({ kind: 'delete-collection', collection })}>
                              <X size={12} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}

        <div className="actions">
          <button type="button" className="btn btn-secondary" disabled={saving} onClick={() => setPending({ kind: 'leave' })}>
            <LogOut size={14} className="btn-icon" /> {t('txt_leave_organization')}
          </button>
          {isOwner && (
            <button type="button" className="btn btn-danger" disabled={saving} onClick={() => setPending({ kind: 'delete-organization' })}>
              <Trash2 size={14} className="btn-icon" /> {t('txt_delete_organization')}
            </button>
          )}
        </div>
      </section>

      <ConfirmDialog
        open={!!pending}
        title={pendingTitle(pending)}
        message={pendingMessage(pending)}
        danger
        confirmText={t('txt_confirm')}
        cancelText={t('txt_cancel')}
        confirmDisabled={saving || (pending?.kind === 'delete-organization' && !deletePassword)}
        cancelDisabled={saving}
        onConfirm={confirmPending}
        onCancel={() => {
          setPending(null);
          setDeletePassword('');
        }}
      >
        {pending?.kind === 'delete-organization' && (
          <label className="field">
            <span>{t('txt_master_password')}</span>
            <input className="input" type="password" value={deletePassword} onInput={(e) => setDeletePassword((e.currentTarget as HTMLInputElement).value)} />
          </label>
        )}
      </ConfirmDialog>
    </div>,
    document.body
  );
}

function pendingTitle(pending: PendingAction | null): string {
  if (pending?.kind === 'remove-member') return t('txt_remove_member');
  if (pending?.kind === 'delete-collection') return t('txt_delete_collection');
  if (pending?.kind === 'delete-organization') return t('txt_delete_organization');
  return t('txt_leave_organization');
}

function pendingMessage(pending: PendingAction | null): string {
  if (pending?.kind === 'remove-member') return t('txt_remove_member_message', { name: memberLabel(pending.member) });
  if (pending?.kind === 'delete-collection') return t('txt_delete_collection_message', { name: collectionDisplayName(pending.collection) });
  if (pending?.kind === 'delete-organization') return t('txt_delete_organization_message');
  return t('txt_leave_organization_message');
}
