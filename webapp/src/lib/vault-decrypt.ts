import { base64ToBytes, decryptBw, decryptStr } from './crypto';
import { deriveSendKeyParts, looksLikeCipherString } from './app-support';
import type { OrganizationKeys } from './organization-keys';
import type { Cipher, Collection, Folder, Send } from './types';

export interface DecryptVaultCoreArgs {
  folders: Folder[];
  ciphers: Cipher[];
  collections: Collection[];
  organizationKeys: OrganizationKeys;
  symEncKeyB64: string;
  symMacKeyB64: string;
}

export interface DecryptVaultCoreResult {
  folders: Folder[];
  ciphers: Cipher[];
  collections: Collection[];
}

interface KeyBytes {
  enc: Uint8Array;
  mac: Uint8Array;
}

export interface DecryptSendsArgs {
  sends: Send[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  origin: string;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function decryptField(
  value: string | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<string> {
  if (!value || typeof value !== 'string') return '';
  try {
    return await decryptStr(value, enc, mac);
  } catch {
    return looksLikeCipherString(value) ? '' : value;
  }
}

async function decryptCipherField(
  value: string | null | undefined,
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  baseEnc: Uint8Array,
  baseMac: Uint8Array,
  canFallbackToUserKey: boolean
): Promise<string> {
  if (!value || typeof value !== 'string') return '';
  try {
    return await decryptStr(value, itemEnc, itemMac);
  } catch {
    // Try the legacy user-key path for mixed key/field ciphers.
  }
  if (canFallbackToUserKey) {
    try {
      return await decryptStr(value, baseEnc, baseMac);
    } catch {
      // Preserve the old raw fallback for fields that are genuinely unreadable.
    }
  }
  return looksLikeCipherString(value) ? '' : value;
}

async function decryptCipherObjectFields<T extends Record<string, unknown>>(
  source: T | null | undefined,
  fields: readonly string[],
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  baseEnc: Uint8Array,
  baseMac: Uint8Array,
  canFallbackToUserKey: boolean
): Promise<T | null | undefined> {
  if (!source || typeof source !== 'object') return source;
  const next: Record<string, unknown> = { ...source };
  for (const field of fields) {
    const decKey = `dec${field.charAt(0).toUpperCase()}${field.slice(1)}`;
    next[decKey] = await decryptCipherField(
      source[field] as string | null | undefined,
      itemEnc,
      itemMac,
      baseEnc,
      baseMac,
      canFallbackToUserKey
    );
  }
  return next as T;
}

async function decryptFieldWithSource(
  value: string | null | undefined,
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  baseEnc: Uint8Array,
  baseMac: Uint8Array,
  canFallbackToUserKey: boolean
): Promise<{ text: string; source: 'item' | 'user' | 'plain' }> {
  const raw = String(value || '').trim();
  if (!raw) return { text: '', source: 'plain' };
  try {
    return { text: await decryptStr(raw, itemEnc, itemMac), source: 'item' };
  } catch {
    // Try legacy user-key fallback below.
  }
  if (canFallbackToUserKey) {
    try {
      return { text: await decryptStr(raw, baseEnc, baseMac), source: 'user' };
    } catch {
      // Keep plain fallback.
    }
  }
  return { text: looksLikeCipherString(raw) ? '' : raw, source: 'plain' };
}

export async function decryptVaultCore(args: DecryptVaultCoreArgs): Promise<DecryptVaultCoreResult> {
  const personalKey: KeyBytes = { enc: base64ToBytes(args.symEncKeyB64), mac: base64ToBytes(args.symMacKeyB64) };
  const organizationKeys = new Map<string, KeyBytes>(
    Object.entries(args.organizationKeys || {}).map(([organizationId, key]) => [
      organizationId,
      { enc: base64ToBytes(key.encB64), mac: base64ToBytes(key.macB64) },
    ])
  );
  const baseKeyFor = (organizationId: string | null | undefined): KeyBytes | null =>
    organizationId ? organizationKeys.get(organizationId) ?? null : personalKey;

  const folders = await Promise.all(
    args.folders.map(async (folder) => ({
      ...folder,
      decName: await decryptField(folder.name, personalKey.enc, personalKey.mac),
    }))
  );

  const collections = await Promise.all(
    (args.collections || []).map(async (collection) => {
      const organizationKey = baseKeyFor(collection.organizationId);
      return {
        ...collection,
        decName: organizationKey ? await decryptField(collection.name, organizationKey.enc, organizationKey.mac) : '',
      };
    })
  );

  const ciphers = await Promise.all(
    args.ciphers.map(async (cipher) => {
      const baseKey = baseKeyFor(cipher.organizationId);
      if (!baseKey) return { ...cipher, decName: '', decNotes: '' };
      const baseEnc = baseKey.enc;
      const baseMac = baseKey.mac;
      let itemEnc = baseEnc;
      let itemMac = baseMac;
      let usesItemKey = false;
      if (cipher.key) {
        try {
          const itemKey = await decryptBw(cipher.key, baseEnc, baseMac);
          if (itemKey.length >= 64) {
            itemEnc = itemKey.slice(0, 32);
            itemMac = itemKey.slice(32, 64);
            usesItemKey = true;
          }
        } catch {
          // Keep user key fallback.
        }
      }

      const itemUsesBaseKey = sameBytes(itemEnc, baseEnc) && sameBytes(itemMac, baseMac);
      const canFallbackToUserKey = usesItemKey;
      const nextCipher: Cipher = {
        ...cipher,
        decName: await decryptCipherField(cipher.name || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
        decNotes: await decryptCipherField(cipher.notes || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      };

      if (cipher.login) {
        nextCipher.login = {
          ...cipher.login,
          decUsername: await decryptCipherField(cipher.login.username || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decPassword: await decryptCipherField(cipher.login.password || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decTotp: await decryptCipherField(cipher.login.totp || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          uris: await Promise.all(
            (cipher.login.uris || []).map(async (uri) => ({
              ...uri,
              decUri: await decryptCipherField(uri.uri || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
            }))
          ),
        };
      }

      if (Array.isArray(cipher.passwordHistory)) {
        nextCipher.passwordHistory = await Promise.all(
          cipher.passwordHistory.map(async (entry) => ({
            ...entry,
            decPassword: await decryptCipherField(entry?.password || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          }))
        );
      }

      if (cipher.card) {
        nextCipher.card = {
          ...cipher.card,
          decCardholderName: await decryptCipherField(cipher.card.cardholderName || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decNumber: await decryptCipherField(cipher.card.number || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decBrand: await decryptCipherField(cipher.card.brand || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decExpMonth: await decryptCipherField(cipher.card.expMonth || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decExpYear: await decryptCipherField(cipher.card.expYear || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decCode: await decryptCipherField(cipher.card.code || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
        };
      }

      if (cipher.identity) {
        nextCipher.identity = {
          ...cipher.identity,
          decTitle: await decryptCipherField(cipher.identity.title || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decFirstName: await decryptCipherField(cipher.identity.firstName || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decMiddleName: await decryptCipherField(cipher.identity.middleName || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decLastName: await decryptCipherField(cipher.identity.lastName || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decUsername: await decryptCipherField(cipher.identity.username || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decCompany: await decryptCipherField(cipher.identity.company || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decSsn: await decryptCipherField(cipher.identity.ssn || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decPassportNumber: await decryptCipherField(cipher.identity.passportNumber || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decLicenseNumber: await decryptCipherField(cipher.identity.licenseNumber || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decEmail: await decryptCipherField(cipher.identity.email || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decPhone: await decryptCipherField(cipher.identity.phone || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decAddress1: await decryptCipherField(cipher.identity.address1 || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decAddress2: await decryptCipherField(cipher.identity.address2 || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decAddress3: await decryptCipherField(cipher.identity.address3 || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decCity: await decryptCipherField(cipher.identity.city || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decState: await decryptCipherField(cipher.identity.state || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decPostalCode: await decryptCipherField(cipher.identity.postalCode || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decCountry: await decryptCipherField(cipher.identity.country || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
        };
      }

      if (cipher.sshKey) {
        const encryptedFingerprint = cipher.sshKey.keyFingerprint || cipher.sshKey.fingerprint || '';
        nextCipher.sshKey = {
          ...cipher.sshKey,
          decPrivateKey: await decryptCipherField(cipher.sshKey.privateKey || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          decPublicKey: await decryptCipherField(cipher.sshKey.publicKey || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          keyFingerprint: encryptedFingerprint || null,
          fingerprint: encryptedFingerprint || null,
          decFingerprint: await decryptCipherField(encryptedFingerprint, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
        };
      }

      if (cipher.bankAccount) {
        nextCipher.bankAccount = await decryptCipherObjectFields(
          cipher.bankAccount,
          ['bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber', 'branchNumber', 'pin', 'swiftCode', 'iban', 'bankContactPhone'],
          itemEnc,
          itemMac,
          baseEnc,
          baseMac,
          canFallbackToUserKey
        );
      }

      if (cipher.driversLicense) {
        nextCipher.driversLicense = await decryptCipherObjectFields(
          cipher.driversLicense,
          ['firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber', 'issuingCountry', 'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass'],
          itemEnc,
          itemMac,
          baseEnc,
          baseMac,
          canFallbackToUserKey
        );
      }

      if (cipher.passport) {
        nextCipher.passport = await decryptCipherObjectFields(
          cipher.passport,
          ['surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry', 'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority', 'issueDate', 'expirationDate'],
          itemEnc,
          itemMac,
          baseEnc,
          baseMac,
          canFallbackToUserKey
        );
      }

      if (cipher.fields) {
        nextCipher.fields = await Promise.all(
          cipher.fields.map(async (field) => ({
            ...field,
            decName: await decryptCipherField(field.name || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
            decValue: await decryptCipherField(field.value || '', itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
          }))
        );
      }

      if (Array.isArray(cipher.attachments)) {
        nextCipher.attachments = await Promise.all(
          cipher.attachments.map(async (attachment) => {
            const fileNameResult = await decryptFieldWithSource(
              attachment.fileName || '',
              itemEnc,
              itemMac,
              baseEnc,
              baseMac,
              !itemUsesBaseKey
            );
            return {
              ...attachment,
              decFileName: fileNameResult.text,
            };
          })
        );
      }

      return nextCipher;
    })
  );

  return { folders, ciphers, collections };
}

export async function decryptSends(args: DecryptSendsArgs): Promise<Send[]> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);
  return Promise.all(
    args.sends.map(async (send) => {
      const nextSend: Send = { ...send };
      try {
        if (send.key) {
          const sendKeyRaw = await decryptBw(send.key, userEnc, userMac);
          const derived = await deriveSendKeyParts(sendKeyRaw);
          nextSend.decName = await decryptField(send.name || '', derived.enc, derived.mac);
          nextSend.decNotes = await decryptField(send.notes || '', derived.enc, derived.mac);
          nextSend.decText = await decryptField(send.text?.text || '', derived.enc, derived.mac);
          if (send.file?.fileName) {
            const decFileName = await decryptField(send.file.fileName, derived.enc, derived.mac);
            nextSend.file = {
              ...(send.file || {}),
              fileName: decFileName || send.file.fileName,
            };
          }
          nextSend.decShareKey = btoa(String.fromCharCode(...sendKeyRaw))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
          nextSend.shareUrl = `${args.origin}/#/send/${send.accessId}/${nextSend.decShareKey}`;
        } else {
          nextSend.decName = '';
          nextSend.decNotes = '';
          nextSend.decText = '';
        }
      } catch {
        nextSend.decName = 'Decrypt failed';
      }
      return nextSend;
    })
  );
}
