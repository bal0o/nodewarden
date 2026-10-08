import { Env, Attachment, Cipher } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { buildDirectUploadUrl, getSafeJwtSecret, parseDirectUploadPayload } from '../utils/direct-upload';
import { generateUUID } from '../utils/uuid';
import { sanitizeDownloadContentType } from '../utils/content-type';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
} from '../utils/jwt';
import { applyCipherEmbeddedAttachmentMetadata, cipherToResponse, resolveCipherForUser } from './ciphers';
import { publishCipherEvent } from './cipher-events';
import { LIMITS } from '../config/limits';
import {
  deleteBlobObject,
  getAttachmentObjectKey,
  getBlobObject,
  getBlobStorageMaxBytes,
  putBlobObject,
} from '../services/blob-store';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';

async function touchCipherAndPublish(request: Request, env: Env, storage: StorageService, cipher: Cipher): Promise<void> {
  cipher.updatedAt = new Date().toISOString();
  await storage.saveCipher(cipher);
  await publishCipherEvent(request, env, storage, cipher, 'update');
}

async function findAttachmentOnCipher(storage: StorageService, attachmentId: string, cipherId: string): Promise<Attachment | null> {
  const attachment = await storage.getAttachment(attachmentId);
  return attachment && attachment.cipherId === cipherId ? attachment : null;
}

async function resolveEditableCipher(env: Env, storage: StorageService, userId: string, cipherId: string): Promise<Cipher | Response> {
  const resolved = await resolveCipherForUser(env, storage, userId, cipherId);
  if (!resolved) return errorResponse('Cipher not found', 404);
  if (!resolved.access.edit) return errorResponse('You do not have permission to edit this item', 403);
  return resolved.cipher;
}

function contentDispositionAttachment(fileName: string | null | undefined): string {
  const fallback = 'attachment';
  const value = String(fileName || fallback)
    .replace(/[\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

async function writeAttachmentAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'attachment',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

// Format file size to human readable
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>
): Promise<void> {
  if (items.length === 0) return;
  const limit = Math.max(1, concurrency);
  for (let index = 0; index < items.length; index += limit) {
    await Promise.all(items.slice(index, index + limit).map(worker));
  }
}

async function processAttachmentUpload(
  request: Request,
  env: Env,
  cipher: Cipher,
  attachment: Attachment,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const maxFileSize = getBlobStorageMaxBytes(env, LIMITS.attachment.maxFileSizeBytes);
  const upload = await parseDirectUploadPayload(request, {
    expectedSize: Number(attachment.size) || 0,
    maxFileSize,
    tooLargeMessage: `File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`,
  });
  if (upload instanceof Response) {
    return upload;
  }

  const path = getAttachmentObjectKey(cipherId, attachment.id);
  if (await getBlobObject(env, path)) {
    return errorResponse('Attachment file has already been uploaded', 409);
  }

  try {
    await putBlobObject(env, path, upload.body, {
      size: upload.size,
      contentType: upload.contentType,
      customMetadata: {
        cipherId,
        attachmentId: attachment.id,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('KV object too large')) {
      return errorResponse(`File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`, 413);
    }
    return errorResponse('Attachment storage is not configured', 500);
  }

  if (upload.size !== attachment.size) {
    attachment.size = upload.size;
    attachment.sizeName = formatSize(upload.size);
    await storage.saveAttachment(attachment);
  }

  await touchCipherAndPublish(request, env, storage, cipher);

  return new Response(null, { status: 201 });
}

// POST /api/ciphers/{cipherId}/attachment/v2
// Creates attachment metadata and returns upload URL
export async function handleCreateAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await resolveEditableCipher(env, storage, userId, cipherId);
  if (cipher instanceof Response) return cipher;

  let body: {
    fileName?: string;
    key?: string;
    fileSize?: number;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.fileName || !body.key) {
    return errorResponse('fileName and key are required', 400);
  }

  const fileSize = body.fileSize || 0;
  const attachmentId = generateUUID();

  // Create attachment metadata
  const attachment: Attachment = {
    id: attachmentId,
    cipherId: cipherId,
    fileName: body.fileName,
    size: fileSize,
    sizeName: formatSize(fileSize),
    key: body.key,
  };

  await storage.saveAttachment(attachment);
  await touchCipherAndPublish(request, env, storage, cipher);

  const updated = await resolveCipherForUser(env, storage, userId, cipherId);
  if (!updated) return errorResponse('Cipher not found', 404);
  const attachments = await storage.getAttachmentsByCipher(cipherId);
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }
  const uploadToken = await createAttachmentUploadToken(userId, cipherId, attachmentId, jwtSecret);

  return jsonResponse({
    object: 'attachment-fileUpload',
    attachmentId: attachmentId,
    url: buildDirectUploadUrl(request, `/api/ciphers/${cipherId}/attachment/${attachmentId}`, uploadToken),
    fileUploadType: 1,
    cipherResponse: cipherToResponse(updated.cipher, attachments, { access: updated.access }),
  });
}

// POST /api/ciphers/{cipherId}/attachment/{attachmentId}
// Upload attachment file content
export async function handleUploadAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await resolveEditableCipher(env, storage, userId, cipherId);
  if (cipher instanceof Response) return cipher;

  const attachment = await findAttachmentOnCipher(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, cipher, attachment, cipherId);
}

export async function handlePublicUploadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifyAttachmentUploadToken(token, jwtSecret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);
  const cipher = await resolveEditableCipher(env, storage, claims.userId, cipherId);
  if (cipher instanceof Response) return cipher;

  const attachment = await findAttachmentOnCipher(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, cipher, attachment, cipherId);
}

// GET /api/ciphers/{cipherId}/attachment/{attachmentId}
// Get attachment download info
export async function handleGetAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const resolved = await resolveCipherForUser(env, storage, userId, cipherId);
  if (!resolved) {
    return errorResponse('Cipher not found', 404);
  }
  const cipher = resolved.cipher;

  const attachment = await findAttachmentOnCipher(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }
  const responseAttachment = applyCipherEmbeddedAttachmentMetadata(cipher, [attachment])[0] || attachment;

  // Generate short-lived download token
  const token = await createFileDownloadToken(cipherId, attachmentId, env.JWT_SECRET);
  
  // Generate download URL with token
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/attachments/${cipherId}/${attachmentId}?token=${token}`;

  return jsonResponse({
    object: 'attachment',
    id: responseAttachment.id,
    url: downloadUrl,
    fileName: responseAttachment.fileName,
    key: responseAttachment.key,
    size: String(Number(responseAttachment.size) || 0),
    sizeName: responseAttachment.sizeName,
  });
}

// PUT /api/ciphers/{cipherId}/attachment/{attachmentId}/metadata
// 修正旧附件的加密元数据，供官方客户端按当前 Bitwarden 契约解密。
export async function handleUpdateAttachmentMetadata(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await resolveEditableCipher(env, storage, userId, cipherId);
  if (cipher instanceof Response) return cipher;

  const attachment = await findAttachmentOnCipher(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  let body: { fileName?: string | null; key?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!Object.prototype.hasOwnProperty.call(body, 'fileName') && !Object.prototype.hasOwnProperty.call(body, 'key')) {
    return errorResponse('No metadata fields supplied', 400);
  }

  if (Object.prototype.hasOwnProperty.call(body, 'fileName')) {
    const fileName = String(body.fileName || '').trim();
    if (!fileName) return errorResponse('fileName is required', 400);
    attachment.fileName = fileName;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'key')) {
    const key = body.key == null ? null : String(body.key || '').trim();
    attachment.key = key || null;
  }

  await storage.saveAttachment(attachment);
  await touchCipherAndPublish(request, env, storage, cipher);

  return jsonResponse({
    object: 'attachment',
    id: attachment.id,
    fileName: attachment.fileName,
    key: attachment.key,
    size: String(Number(attachment.size) || 0),
    sizeName: attachment.sizeName,
  });
}

// GET /api/attachments/{cipherId}/{attachmentId}?token=xxx
// Public download endpoint (uses token for auth instead of header)
export async function handlePublicDownloadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const secret = getSafeJwtSecret(env);
  if (!secret) return errorResponse('Server configuration error', 500);

  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return errorResponse('Token required', 401);
  }

  // Verify token
  const claims = await verifyFileDownloadToken(token, secret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }

  // Verify token matches request
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  const firstUse = await storage.consumeAttachmentDownloadToken(claims.jti, claims.exp);
  if (!firstUse) {
    return errorResponse('Invalid or expired token', 401);
  }

  const object = await getBlobObject(env, path);
  if (!object) {
    return errorResponse('Attachment file not found', 404);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': sanitizeDownloadContentType(object.contentType),
      'Content-Length': String(object.size),
      'Content-Disposition': contentDispositionAttachment(attachment.fileName),
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}
// Delete attachment
export async function handleDeleteAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await resolveEditableCipher(env, storage, userId, cipherId);
  if (cipher instanceof Response) return cipher;

  const attachment = await findAttachmentOnCipher(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  await deleteBlobObject(env, path);
  await storage.deleteAttachment(attachmentId);
  await touchCipherAndPublish(request, env, storage, cipher);
  await writeAttachmentAudit(storage, request, userId, 'attachment.delete', {
    id: attachmentId,
    cipherId,
    size: attachment.size,
  });

  const updated = await resolveCipherForUser(env, storage, userId, cipherId);
  if (!updated) return errorResponse('Cipher not found', 404);
  const attachments = await storage.getAttachmentsByCipher(cipherId);
  const cipherResponse = cipherToResponse(updated.cipher, attachments, { access: updated.access });

  return jsonResponse({
    Cipher: cipherResponse,
    cipher: cipherResponse,
    Object: 'deleteAttachment',
    object: 'deleteAttachment',
  });
}

// Delete all attachments for a cipher (used when deleting cipher)
export async function deleteAllAttachmentsForCipher(
  env: Env,
  cipherId: string
): Promise<void> {
  await deleteAllAttachmentsForCiphers(env, [cipherId]);
}

export async function deleteAllAttachmentsForCiphers(
  env: Env,
  cipherIds: string[]
): Promise<void> {
  const storage = new StorageService(env.DB);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(cipherIds);
  const attachments = Array.from(attachmentsByCipher.entries()).flatMap(([ownedCipherId, items]) =>
    items.map((attachment) => ({ attachment, cipherId: ownedCipherId }))
  );
  if (!attachments.length) return;

  await runWithConcurrency(attachments, LIMITS.performance.attachmentDeleteConcurrency, async ({ attachment, cipherId }) => {
    const path = getAttachmentObjectKey(cipherId, attachment.id);
    await deleteBlobObject(env, path);
  });

  await storage.bulkDeleteAttachmentsByIds(attachments.map(({ attachment }) => attachment.id));
}
