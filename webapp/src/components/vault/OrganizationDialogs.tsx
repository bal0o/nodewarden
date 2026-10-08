import { useEffect, useMemo, useState } from 'preact/hooks';
import ConfirmDialog from '@/components/ConfirmDialog';
import { collectionDisplayName } from '@/components/vault/vault-page-helpers';
import { t } from '@/lib/i18n';
import { MembershipStatus, type Cipher, type Collection, type ProfileOrganization } from '@/lib/types';

function writableCollectionsOf(collections: Collection[], organizationId: string): Collection[] {
  return collections.filter((collection) => collection.organizationId === organizationId && !collection.readOnly);
}

function toggleId(ids: string[], id: string, checked: boolean): string[] {
  return checked ? [...ids, id] : ids.filter((existing) => existing !== id);
}

function CollectionChecklist(props: { collections: Collection[]; selectedIds: string[]; onChange: (ids: string[]) => void }) {
  if (!props.collections.length) return <div className="detail-sub">{t('txt_no_writable_collections')}</div>;
  return (
    <div className="organization-check-list">
      {props.collections.map((collection) => (
        <label key={collection.id} className="check-line">
          <input
            type="checkbox"
            checked={props.selectedIds.includes(collection.id)}
            onInput={(e) => props.onChange(toggleId(props.selectedIds, collection.id, (e.currentTarget as HTMLInputElement).checked))}
          />
          {collectionDisplayName(collection)}
        </label>
      ))}
    </div>
  );
}

export function CreateOrganizationDialog(props: {
  open: boolean;
  onCreate: (name: string, collectionName: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const [name, setName] = useState('');
  const [collectionName, setCollectionName] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!props.open) return;
    setName('');
    setCollectionName(t('txt_default_collection'));
  }, [props.open]);

  async function submit(): Promise<void> {
    if (!name.trim() || !collectionName.trim()) return;
    setSaving(true);
    const created = await props.onCreate(name.trim(), collectionName.trim());
    setSaving(false);
    if (created) props.onClose();
  }

  return (
    <ConfirmDialog
      open={props.open}
      title={t('txt_create_organization')}
      message={t('txt_create_organization_message')}
      confirmText={t('txt_create')}
      cancelText={t('txt_cancel')}
      confirmDisabled={saving || !name.trim() || !collectionName.trim()}
      cancelDisabled={saving}
      onConfirm={() => void submit()}
      onCancel={props.onClose}
    >
      <label className="field">
        <span>{t('txt_organization_name')}</span>
        <input className="input" value={name} onInput={(e) => setName((e.currentTarget as HTMLInputElement).value)} />
      </label>
      <label className="field">
        <span>{t('txt_collection_name')}</span>
        <input className="input" value={collectionName} onInput={(e) => setCollectionName((e.currentTarget as HTMLInputElement).value)} />
      </label>
    </ConfirmDialog>
  );
}

export function shareableOrganizations(organizations: ProfileOrganization[]): ProfileOrganization[] {
  return organizations.filter((organization) => organization.status === MembershipStatus.Confirmed && !!organization.key);
}

export function ShareCipherDialog(props: {
  cipher: Cipher | null;
  organizations: ProfileOrganization[];
  collections: Collection[];
  onShare: (cipher: Cipher, organizationId: string, collectionIds: string[]) => Promise<boolean>;
  onClose: () => void;
}) {
  const organizations = useMemo(() => shareableOrganizations(props.organizations), [props.organizations]);
  const [organizationId, setOrganizationId] = useState('');
  const [collectionIds, setCollectionIds] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const writableCollections = useMemo(() => writableCollectionsOf(props.collections, organizationId), [props.collections, organizationId]);

  useEffect(() => {
    if (!props.cipher) return;
    setOrganizationId(organizations[0]?.id || '');
    setCollectionIds([]);
  }, [props.cipher?.id]);

  async function submit(): Promise<void> {
    if (!props.cipher || !organizationId || !collectionIds.length) return;
    setSaving(true);
    const shared = await props.onShare(props.cipher, organizationId, collectionIds);
    setSaving(false);
    if (shared) props.onClose();
  }

  return (
    <ConfirmDialog
      open={!!props.cipher}
      title={t('txt_share_item')}
      message={t('txt_share_item_message')}
      confirmText={t('txt_share')}
      cancelText={t('txt_cancel')}
      confirmDisabled={saving || !organizationId || !collectionIds.length}
      cancelDisabled={saving}
      onConfirm={() => void submit()}
      onCancel={props.onClose}
    >
      <label className="field">
        <span>{t('txt_organization')}</span>
        <select
          className="input"
          value={organizationId}
          onInput={(e) => {
            setOrganizationId((e.currentTarget as HTMLSelectElement).value);
            setCollectionIds([]);
          }}
        >
          {organizations.map((organization) => (
            <option key={organization.id} value={organization.id}>{organization.name}</option>
          ))}
        </select>
      </label>
      <div className="field">
        <span>{t('txt_collections')}</span>
        <CollectionChecklist collections={writableCollections} selectedIds={collectionIds} onChange={setCollectionIds} />
      </div>
    </ConfirmDialog>
  );
}

export function CipherCollectionsDialog(props: {
  cipher: Cipher | null;
  collections: Collection[];
  onSave: (cipherId: string, collectionIds: string[]) => Promise<boolean>;
  onClose: () => void;
}) {
  const [collectionIds, setCollectionIds] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const writableCollections = useMemo(
    () => writableCollectionsOf(props.collections, props.cipher?.organizationId || ''),
    [props.collections, props.cipher?.organizationId]
  );

  const writableIds = useMemo(() => new Set(writableCollections.map((collection) => collection.id)), [writableCollections]);
  const hasReadOnlyLinks = (props.cipher?.collectionIds || []).some((id) => !writableIds.has(id));
  const canSave = collectionIds.length > 0 || hasReadOnlyLinks;

  useEffect(() => {
    if (!props.cipher) return;
    setCollectionIds((props.cipher.collectionIds || []).filter((id) => writableIds.has(id)));
  }, [props.cipher?.id]);

  async function submit(): Promise<void> {
    if (!props.cipher || !canSave) return;
    setSaving(true);
    const saved = await props.onSave(props.cipher.id, collectionIds);
    setSaving(false);
    if (saved) props.onClose();
  }

  return (
    <ConfirmDialog
      open={!!props.cipher}
      title={t('txt_collections')}
      message={t('txt_item_collections_message')}
      confirmText={t('txt_save')}
      cancelText={t('txt_cancel')}
      confirmDisabled={saving || !canSave}
      cancelDisabled={saving}
      onConfirm={() => void submit()}
      onCancel={props.onClose}
    >
      <CollectionChecklist collections={writableCollections} selectedIds={collectionIds} onChange={setCollectionIds} />
    </ConfirmDialog>
  );
}
