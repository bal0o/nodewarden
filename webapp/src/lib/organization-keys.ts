import { base64ToBytes, bytesToBase64, decryptBw, decryptStr, encryptBw, toBufferSource } from './crypto';
import { t } from './i18n';
import type { Cipher, ProfileOrganization, SessionState } from './types';

const RSA_OAEP_SHA1 = { name: 'RSA-OAEP', hash: 'SHA-1' } as const;
const RSA_OAEP_SHA1_ENC_TYPES = new Set(['4', '6']);

export interface SymmetricKey {
  encB64: string;
  macB64: string;
}

export type OrganizationKeys = Record<string, SymmetricKey>;

export interface OrganizationKeyMaterial {
  organizationKey: SymmetricKey;
  encryptedOrganizationKey: string;
  publicKey: string;
  encryptedPrivateKey: string;
}

function splitSymmetricKey(raw: Uint8Array): SymmetricKey {
  if (raw.length < 64) throw new Error(t('txt_organization_key_unavailable'));
  return { encB64: bytesToBase64(raw.slice(0, 32)), macB64: bytesToBase64(raw.slice(32, 64)) };
}

function joinSymmetricKey(key: SymmetricKey): Uint8Array {
  const raw = new Uint8Array(64);
  raw.set(base64ToBytes(key.encB64), 0);
  raw.set(base64ToBytes(key.macB64), 32);
  return raw;
}

function sessionKey(session: SessionState): SymmetricKey {
  if (!session.symEncKey || !session.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
  return { encB64: session.symEncKey, macB64: session.symMacKey };
}

async function rsaEncrypt(data: Uint8Array, publicKeyB64: string): Promise<string> {
  const publicKey = await crypto.subtle.importKey('spki', toBufferSource(base64ToBytes(publicKeyB64)), RSA_OAEP_SHA1, false, ['encrypt']);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, toBufferSource(data)));
  return `4.${bytesToBase64(encrypted)}`;
}

async function rsaDecrypt(encString: string, privateKey: CryptoKey): Promise<Uint8Array> {
  const dot = encString.indexOf('.');
  const encType = encString.slice(0, dot);
  if (dot <= 0 || !RSA_OAEP_SHA1_ENC_TYPES.has(encType)) throw new Error(t('txt_organization_key_unavailable'));
  const [ciphertext] = encString.slice(dot + 1).split('|');
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, toBufferSource(base64ToBytes(ciphertext))));
}

async function importUserPrivateKey(encryptedPrivateKey: string, session: SessionState): Promise<CryptoKey> {
  const userKey = sessionKey(session);
  const pkcs8 = await decryptBw(encryptedPrivateKey, base64ToBytes(userKey.encB64), base64ToBytes(userKey.macB64));
  return crypto.subtle.importKey('pkcs8', toBufferSource(pkcs8), RSA_OAEP_SHA1, true, ['decrypt']);
}

async function publicKeyOf(privateKey: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RSA-OAEP', ext: true }, RSA_OAEP_SHA1, true, ['encrypt']);
  return bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', publicKey)));
}

export async function decryptOrganizationKeys(
  organizations: readonly ProfileOrganization[],
  encryptedPrivateKey: string | null,
  session: SessionState
): Promise<OrganizationKeys> {
  const keyed = organizations.filter((organization) => !!organization.key);
  if (!keyed.length || !encryptedPrivateKey) return {};
  let privateKey: CryptoKey;
  try {
    privateKey = await importUserPrivateKey(encryptedPrivateKey, session);
  } catch {
    return {};
  }
  const keys: OrganizationKeys = {};
  for (const organization of keyed) {
    try {
      keys[organization.id] = splitSymmetricKey(await rsaDecrypt(organization.key!, privateKey));
    } catch {
      continue;
    }
  }
  return keys;
}

export async function createOrganizationKeyMaterial(encryptedUserPrivateKey: string, session: SessionState): Promise<OrganizationKeyMaterial> {
  const rawOrganizationKey = crypto.getRandomValues(new Uint8Array(64));
  const organizationKey = splitSymmetricKey(rawOrganizationKey);
  const userPublicKey = await publicKeyOf(await importUserPrivateKey(encryptedUserPrivateKey, session));

  const keyPair = await crypto.subtle.generateKey(
    { ...RSA_OAEP_SHA1, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  return {
    organizationKey,
    encryptedOrganizationKey: await rsaEncrypt(rawOrganizationKey, userPublicKey),
    publicKey: bytesToBase64(publicKey),
    encryptedPrivateKey: await encryptBw(privateKey, rawOrganizationKey.slice(0, 32), rawOrganizationKey.slice(32, 64)),
  };
}

export function encryptOrganizationKeyForMember(organizationKey: SymmetricKey, memberPublicKeyB64: string): Promise<string> {
  return rsaEncrypt(joinSymmetricKey(organizationKey), memberPublicKeyB64);
}

export function encryptTextWithKey(text: string, key: SymmetricKey): Promise<string> {
  return encryptBw(new TextEncoder().encode(text), base64ToBytes(key.encB64), base64ToBytes(key.macB64));
}

export function decryptTextWithKey(encrypted: string, key: SymmetricKey): Promise<string> {
  return decryptStr(encrypted, base64ToBytes(key.encB64), base64ToBytes(key.macB64));
}

export function sessionWithKey(session: SessionState, key: SymmetricKey): SessionState {
  return { ...session, symEncKey: key.encB64, symMacKey: key.macB64 };
}

export function cipherBaseKey(session: SessionState, organizationKeys: OrganizationKeys, organizationId: string | null | undefined): SymmetricKey {
  if (!organizationId) return sessionKey(session);
  const key = organizationKeys[organizationId];
  if (!key) throw new Error(t('txt_organization_key_unavailable'));
  return key;
}

export function sessionForCipher(session: SessionState, organizationKeys: OrganizationKeys, cipher: Pick<Cipher, 'organizationId'> | null): SessionState {
  return sessionWithKey(session, cipherBaseKey(session, organizationKeys, cipher?.organizationId));
}
