import { useMemo } from 'preact/hooks';
import { Building2, Library, Plus, Settings } from 'lucide-preact';
import { collectionDisplayName, type SidebarFilter } from '@/components/vault/vault-page-helpers';
import { t } from '@/lib/i18n';
import { MembershipStatus, type Collection, type ProfileOrganization } from '@/lib/types';

interface OrganizationSidebarSectionProps {
  organizations: ProfileOrganization[];
  collections: Collection[];
  sidebarFilter: SidebarFilter;
  busy: boolean;
  onChangeFilter: (filter: SidebarFilter) => void;
  onOpenCreateOrganization: () => void;
  onOpenOrganization: (organization: ProfileOrganization) => void;
}

export default function OrganizationSidebarSection(props: OrganizationSidebarSectionProps) {
  const nameCollator = useMemo(() => new Intl.Collator(undefined, { sensitivity: 'base', numeric: true }), []);
  const collectionsByOrganization = useMemo(() => {
    const grouped = new Map<string, Collection[]>();
    for (const collection of props.collections) {
      const list = grouped.get(collection.organizationId) || [];
      list.push(collection);
      grouped.set(collection.organizationId, list);
    }
    for (const list of grouped.values()) {
      list.sort((a, b) => nameCollator.compare(collectionDisplayName(a), collectionDisplayName(b)));
    }
    return grouped;
  }, [props.collections, nameCollator]);
  const sortedOrganizations = useMemo(
    () => [...props.organizations].sort((a, b) => nameCollator.compare(a.name, b.name)),
    [props.organizations, nameCollator]
  );

  return (
    <div className="sidebar-block">
      <div className="sidebar-title-row">
        <div className="sidebar-title">{t('txt_organizations')}</div>
        <div className="folder-title-actions">
          <button
            type="button"
            className="folder-add-btn"
            title={t('txt_create_organization')}
            aria-label={t('txt_create_organization')}
            disabled={props.busy}
            onClick={props.onOpenCreateOrganization}
          >
            <Plus size={14} />
          </button>
        </div>
      </div>
      {sortedOrganizations.map((organization) => (
        <div key={organization.id}>
          <div className="folder-row">
            <button
              type="button"
              className={`tree-btn ${props.sidebarFilter.kind === 'organization' && props.sidebarFilter.organizationId === organization.id ? 'active' : ''}`}
              onClick={() => props.onChangeFilter({ kind: 'organization', organizationId: organization.id })}
            >
              <Building2 size={14} className="tree-icon" />
              <span className="tree-label" title={organization.name}>{organization.name}</span>
              {organization.status !== MembershipStatus.Confirmed && <span className="tree-badge">{t('txt_organization_pending')}</span>}
            </button>
            <button
              type="button"
              className="folder-delete-btn folder-edit-btn"
              title={t('txt_manage_organization')}
              aria-label={t('txt_manage_organization')}
              disabled={props.busy}
              onClick={() => props.onOpenOrganization(organization)}
            >
              <Settings size={12} />
            </button>
          </div>
          {(collectionsByOrganization.get(organization.id) || []).map((collection) => (
            <button
              key={collection.id}
              type="button"
              className={`tree-btn tree-btn-nested ${props.sidebarFilter.kind === 'collection' && props.sidebarFilter.collectionId === collection.id ? 'active' : ''}`}
              onClick={() => props.onChangeFilter({ kind: 'collection', collectionId: collection.id })}
            >
              <Library size={14} className="tree-icon" />
              <span className="tree-label" title={collectionDisplayName(collection)}>{collectionDisplayName(collection)}</span>
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}
