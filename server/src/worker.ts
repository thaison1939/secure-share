/**
 * Cloudflare Worker for Secure Share API
 * Handles file upload/download with strict privacy guarantees
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Redis } from '@upstash/redis/cloudflare';

// Cloudflare Worker environment bindings interface
interface Bindings {
    R2_BUCKET: R2Bucket;
    UPSTASH_REDIS_REST_URL: string;
    UPSTASH_REDIS_REST_TOKEN: string;
    UPLOAD_AUTH_SECRET: string;
    MAX_FILE_SIZE_BYTES: number;
    MAX_DOWNLOAD_LIMIT: number;
    RATE_LIMIT_REQUESTS_PER_MINUTE: number;
    [key: string]: any;
    // Add CRON_SECRET if you implement token-based access for /api/cleanup
    // CRON_SECRET?: string;
}

// Hono context type
type HonoContext = {
    Bindings: Bindings;
};

const app = new Hono<HonoContext>();

// CORS middleware - allowing specific origins in production is recommended
app.use('*', cors({
    origin: '*', // CONSIDER: Restrict this to your frontend domain(s) in production
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Original-Filename', 'X-Remaining-Downloads', 'X-Password-Hash-Base64', 'X-Nonce-Base64', 'X-Pwhash-Salt-Base64'],
    // Expose custom headers so the client can read them
    exposeHeaders: ['X-Original-Filename', 'X-Remaining-Downloads', 'X-Password-Hash-Base64', 'X-Nonce-Base64', 'X-Pwhash-Salt-Base64'],
}));

// Initialize Redis client
function getRedisClient(env: Bindings): Redis {
    // Ensure both URL and Token are present
    if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) {
        throw new Error('Missing UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN environment variables.');
    }
    return new Redis({
        url: env.UPSTASH_REDIS_REST_URL,
        token: env.UPSTASH_REDIS_REST_TOKEN,
    });
}

// Rate limiting helper
async function checkRateLimit(redis: Redis, clientIP: string, limit: number): Promise<boolean> {
    try {
        const key = `rate_limit:${clientIP}`;
        const current = await redis.incr(key);

        if (current === 1) {
            await redis.expire(key, 60); // 1 minute window
        }

        return current <= limit;
    } catch (error) {
        console.error('Rate limit check failed (Redis error):', error);
        // CONSIDER: In a production system, you might want to fail-closed on Redis errors
        // to prevent abuse if the rate limit system is down. For now, failing-open.
        return true; // Allow on error to avoid blocking legitimate users
    }
}

// Password brute-force protection functions
// These should use specific keys for each file and IP to prevent cross-file attacks.
const PASSWORD_ATTEMPT_LIMIT = 5; // Max password attempts per IP per file
const PASSWORD_ATTEMPT_WINDOW_SECONDS = 15 * 60; // 15 minutes window

async function checkPasswordAttempts(redis: Redis, clientIP: string, uuid: string): Promise<boolean> {
    try {
        const key = `pwd_attempts:${clientIP}:${uuid}`;
        const attempts = await redis.get(key);
        const currentAttempts = attempts ? parseInt(attempts as string) : 0;

        return currentAttempts < PASSWORD_ATTEMPT_LIMIT;
    } catch (error) {
        console.error('Password attempt check failed (Redis error):', error);
        // Fail-open for Redis error in password attempt check
        return true;
    }
}

async function recordPasswordAttempt(redis: Redis, clientIP: string, uuid: string): Promise<void> {
    try {
        const key = `pwd_attempts:${clientIP}:${uuid}`;
        const current = await redis.incr(key);

        if (current === 1) {
            await redis.expire(key, PASSWORD_ATTEMPT_WINDOW_SECONDS); // Set TTL for the first attempt
        }
    } catch (error) {
        console.error('Failed to record password attempt (Redis error):', error);
    }
}

// Validate UUID format
function isValidUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

// Health check endpoint
app.get('/api/health', (c) => {
    return c.json({
        status: 'healthy',
        timestamp: Date.now(),
        environment: 'production' // Assuming this is deployed in production, adjust as needed
    });
});

// File upload endpoint
app.post('/api/upload', async (c) => {
    try {
        const env = c.env;
        const redis = getRedisClient(env);

        // Get client IP for rate limiting
        const clientIP = c.req.header('CF-Connecting-IP') || // Cloudflare specific header
                         c.req.header('X-Forwarded-For')?.split(',')[0].trim() || // Standard proxy header
                         c.req.header('X-Real-IP') || // Common proxy header
                         'unknown';

        console.log(`Upload request from IP: ${clientIP}`);

        // Check general rate limit
        const rateLimitOk = await checkRateLimit(redis, clientIP, env.RATE_LIMIT_REQUESTS_PER_MINUTE);
        if (!rateLimitOk) {
            console.log(`Rate limit exceeded for IP: ${clientIP}`);
            return c.json({ success: false, error: 'Rate limit exceeded' }, 429);
        }

        // Verify upload auth secret
        const authHeader = c.req.header('Authorization');
        const expectedAuth = `Bearer ${env.UPLOAD_AUTH_SECRET}`;

        if (!authHeader || authHeader !== expectedAuth) {
            console.warn('Unauthorized upload attempt: Mismatched Authorization header');
            return c.json({ success: false, error: 'Unauthorized' }, 401);
        }

        // Parse form data
        const formData = await c.req.formData();
        const file = formData.get('file') as File; // The encrypted data blob
        const uuid = formData.get('uuid') as string;
        const originalFilename = formData.get('originalFilename') as string;
        // Parse numbers safely
        const downloadLimit = parseInt(formData.get('downloadLimit') as string, 10);
        const fileSize = parseInt(formData.get('fileSize') as string, 10);

        // ✅ FIXED: Extract ALL password fields including new pwhashSaltBase64
        const passwordHashBase64 = formData.get('passwordHashBase64') as string;
        const nonceBase64 = formData.get('nonceBase64') as string;
        const pwhashSaltBase64 = formData.get('pwhashSaltBase64') as string; // ✅ NEW FIELD

        console.log(`Upload request - UUID: ${uuid}, Filename: ${originalFilename}, Size: ${fileSize}, Downloads: ${downloadLimit}, HasPassword: ${!!passwordHashBase64}`);

        // ✅ UPDATED: Validate ALL required fields including pwhashSaltBase64
        if (!file || !uuid || !originalFilename || isNaN(downloadLimit) || isNaN(fileSize) || !passwordHashBase64 || !nonceBase64 || !pwhashSaltBase64) {
            console.warn('Missing or invalid required fields in upload request.');
            return c.json({ 
                success: false, 
                error: 'Missing or invalid required fields (file, uuid, originalFilename, downloadLimit, fileSize, passwordHashBase64, nonceBase64, pwhashSaltBase64)' 
            }, 400);
        }

        // Validate UUID format
        if (!isValidUUID(uuid)) {
            console.warn(`Invalid UUID format received: ${uuid}`);
            return c.json({ success: false, error: 'Invalid UUID format' }, 400);
        }

        // Validate file size against worker's binding (which should be MAX_FILE_SIZE_BYTES)
        if (file.size > env.MAX_FILE_SIZE_BYTES) {
            console.warn(`File size (${file.size} bytes) exceeds limit (${env.MAX_FILE_SIZE_BYTES} bytes) for UUID: ${uuid}`);
            return c.json({
                success: false,
                error: `File too large. Maximum size: ${Math.round(env.MAX_FILE_SIZE_BYTES / (1024 * 1024))}MB`
            }, 413);
        }

        // Validate download limit against worker's binding
        if (downloadLimit < 1 || downloadLimit > env.MAX_DOWNLOAD_LIMIT) {
            console.warn(`Invalid download limit (${downloadLimit}) for UUID: ${uuid}`);
            return c.json({
                success: false,
                error: `Invalid download limit. Must be between 1 and ${env.MAX_DOWNLOAD_LIMIT}`
            }, 400);
        }

        // Check if UUID already exists (prevent overwrites and race conditions)
        const existingMetadata = await redis.get(`file:${uuid}`);
        if (existingMetadata) {
            console.warn(`File ID already exists: ${uuid}. Preventing overwrite.`);
            return c.json({ success: false, error: 'File ID already exists' }, 409);
        }

        // Store encrypted file in R2
        const fileBuffer = await file.arrayBuffer();
        console.log(`Attempting to store file in R2 with UUID: ${uuid}, Size: ${fileBuffer.byteLength} bytes`);

        await env.R2_BUCKET.put(uuid, fileBuffer, {
            httpMetadata: {
                contentType: file.type || 'application/octet-stream',
                cacheControl: 'no-cache, no-store, must-revalidate',
            },
            customMetadata: {
                originalFilename,
                uploadTime: Date.now().toString(),
                fileSize: fileSize.toString(), // Store original plaintext size
            },
        });
        console.log(`File successfully stored in R2: ${uuid}`);

        // Store metadata with new field names
        const metadata = {
            uuid,
            originalFilename,
            fileSize, // Original plaintext size
            downloadLimit,
            uploadTime: Date.now(),
            expiresAt: Date.now() + (60 * 60 * 1000), // 1 hour in milliseconds
            passwordHashBase64,
            nonceBase64,
            pwhashSaltBase64,
            hasPassword: true,
        };

        // Use pipeline for atomic operations for metadata and download counter
        const pipeline = redis.pipeline();
        pipeline.setex(`file:${uuid}`, 3600, JSON.stringify(metadata)); // 1 hour TTL
        pipeline.setex(`downloads:${uuid}`, 3600, '0'); // Initial downloads counter, 1 hour TTL
        await pipeline.exec();
        console.log(`Metadata and download counter set in Redis for UUID: ${uuid}`);

        return c.json({
            success: true,
            uuid,
            message: 'File uploaded successfully',
        }, 200);

    } catch (error) {
        console.error('Upload error:', error instanceof Error ? error.message : error);
        return c.json({
            success: false,
            error: 'Upload failed - internal server error'
        }, 500);
    }
});

// File download endpoint - READ ONLY (no counter increment)
app.get('/api/download/:uuid', async (c) => {
    try {
        const env = c.env;
        const redis = getRedisClient(env);
        const uuid = c.req.param('uuid');

        // Get client IP for rate limiting
        const clientIP = c.req.header('CF-Connecting-IP') || 
                         c.req.header('X-Forwarded-For')?.split(',')[0].trim() || 
                         c.req.header('X-Real-IP') || 
                         'unknown';

        console.log(`Download request from IP: ${clientIP}, UUID: ${uuid}`);

        // Validate UUID format
        if (!isValidUUID(uuid)) {
            console.warn(`Invalid UUID format: ${uuid}`);
            return c.json({ success: false, error: 'Invalid file ID format' }, 400);
        }

        // Get file metadata from Redis
        const metadataString = await redis.get(`file:${uuid}`);
        if (!metadataString) {
            console.warn(`File not found or expired: ${uuid}`);
            return c.json({ success: false, error: 'File not found or expired' }, 404);
        }

        // Parse metadata correctly
        let metadata;
        try {
            if (typeof metadataString === 'string') {
                metadata = JSON.parse(metadataString);
            } else {
                metadata = metadataString;
            }
        } catch (parseError) {
            console.error(`Failed to parse metadata for UUID: ${uuid}`, parseError);
            return c.json({ success: false, error: 'File metadata corrupted' }, 500);
        }

        // Validate required fields exist
        if (!metadata.passwordHashBase64 || !metadata.nonceBase64 || !metadata.pwhashSaltBase64) {
            console.error(`Missing required fields in metadata for UUID: ${uuid}`, {
                hasPasswordHash: !!metadata.passwordHashBase64,
                hasNonce: !!metadata.nonceBase64,
                hasPwhashSalt: !!metadata.pwhashSaltBase64
            });
            return c.json({ success: false, error: 'File metadata incomplete' }, 500);
        }

        // Check if file has expired
        if (metadata.expiresAt && Date.now() > metadata.expiresAt) {
            console.warn(`File expired: ${uuid}, expired at: ${new Date(metadata.expiresAt)}`);
            // Clean up expired file
            await redis.del(`file:${uuid}`);
            await redis.del(`downloads:${uuid}`);
            await env.R2_BUCKET.delete(uuid);
            return c.json({ success: false, error: 'File expired' }, 410);
        }

        // Get current download count from separate Redis key (read-only)
        const currentDownloads = await redis.get(`downloads:${uuid}`) || '0';
        const remainingDownloads = metadata.downloadLimit - parseInt(String(currentDownloads));

        // Check if already at limit (read-only check)
        if (parseInt(String(currentDownloads)) >= metadata.downloadLimit) {
            console.warn(`Download limit exceeded for file: ${uuid} (${currentDownloads}/${metadata.downloadLimit})`);
            return c.json({ success: false, error: 'Download limit exceeded' }, 403);
        }

        // Download file from R2
        const fileObject = await env.R2_BUCKET.get(uuid);
        if (!fileObject) {
            console.error(`File not found in R2: ${uuid}`);
            return c.json({ success: false, error: 'File not found in storage' }, 404);
        }

        console.log(`File download successful: ${uuid}, remaining downloads: ${remainingDownloads}`);

        return new Response(fileObject.body, {
            headers: {
                'Content-Type': fileObject.httpMetadata?.contentType || 'application/octet-stream',
                'Content-Disposition': `attachment; filename="${encodeURIComponent(metadata.originalFilename || 'downloaded-file')}"`,
                'X-Original-Filename': encodeURIComponent(metadata.originalFilename || 'downloaded-file'),
                'X-Remaining-Downloads': remainingDownloads.toString(),
                'X-Password-Hash-Base64': metadata.passwordHashBase64,
                'X-Nonce-Base64': metadata.nonceBase64,
                'X-Pwhash-Salt-Base64': metadata.pwhashSaltBase64,
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Access-Control-Expose-Headers': 'X-Original-Filename, X-Remaining-Downloads, X-Password-Hash-Base64, X-Nonce-Base64, X-Pwhash-Salt-Base64',
            },
        });

    } catch (error) {
        console.error('Download error:', error);
        return c.json({ success: false, error: 'Download failed - internal server error' }, 500);
   }
});

// POST /api/download/:uuid/increment - Track download attempts
app.post('/api/download/:uuid/increment', async (c) => {
    try {
        const env = c.env;
        const redis = getRedisClient(env);
        const uuid = c.req.param('uuid');

        // Get client IP for logging
        const clientIP = c.req.header('CF-Connecting-IP') || 
                         c.req.header('X-Forwarded-For')?.split(',')[0].trim() || 
                         c.req.header('X-Real-IP') || 
                         'unknown';

        console.log(`Download increment request from IP: ${clientIP}, UUID: ${uuid}`);

        // Verify auth secret
        const authHeader = c.req.header('Authorization');
        const expectedAuth = `Bearer ${env.UPLOAD_AUTH_SECRET}`;

        if (!authHeader || authHeader !== expectedAuth) {
            console.warn('Unauthorized increment attempt');
            return c.json({ success: false, error: 'Unauthorized' }, 401);
        }

        // Validate UUID format
        if (!isValidUUID(uuid)) {
            console.warn(`Invalid UUID format: ${uuid}`);
            return c.json({ success: false, error: 'Invalid file ID format' }, 400);
        }

        // Get file metadata from Redis
        const metadataString = await redis.get(`file:${uuid}`);
        if (!metadataString) {
            console.warn(`File not found or expired: ${uuid}`);
            return c.json({ 
                success: false, 
                error: 'File not found or expired',
                fileDeleted: true 
            }, 404);
        }

        // Parse metadata
        let metadata;
        try {
            metadata = typeof metadataString === 'string' ? JSON.parse(metadataString) : metadataString;
        } catch (parseError) {
            console.error(`Failed to parse metadata for UUID: ${uuid}`, parseError);
            return c.json({ success: false, error: 'File metadata corrupted' }, 500);
        }

        // Check if file has expired
        if (metadata.expiresAt && Date.now() > metadata.expiresAt) {
            console.warn(`File expired: ${uuid}`);
            await Promise.all([
                redis.del(`file:${uuid}`),
                redis.del(`downloads:${uuid}`),
                env.R2_BUCKET.delete(uuid)
            ]);
            return c.json({ 
                success: false, 
                error: 'File expired', 
                fileDeleted: true 
            }, 410);
        }

        // Use Redis INCR for atomic increment
        const downloadCounterKey = `downloads:${uuid}`;
        const currentDownloads = await redis.incr(downloadCounterKey);

        const downloadLimit = metadata.downloadLimit;
        const remainingDownloads = downloadLimit - currentDownloads;

        console.log(`Incremented download count for ${uuid}: ${currentDownloads}/${downloadLimit}`);

        // Check if limit reached - delete file immediately
        if (currentDownloads >= downloadLimit) {
            console.log(`Download limit reached for ${uuid}. Deleting file from R2 and Redis.`);
            
            // Delete from both R2 and Redis
            await Promise.all([
                redis.del(`file:${uuid}`),
                redis.del(downloadCounterKey),
                env.R2_BUCKET.delete(uuid)
            ]);

            // Log the deletion
            console.log(`File ${uuid} auto-deleted due to download limit.`);

            return c.json({ 
                success: true,
                downloads: currentDownloads,
                downloadLimit: downloadLimit,
                remainingDownloads: 0,
                fileDeleted: true,
                message: 'Download limit reached. File has been deleted.'
            });
        }

        return c.json({
            success: true,
            downloads: currentDownloads,
            downloadLimit: downloadLimit,
            remainingDownloads: remainingDownloads,
            fileDeleted: false
        });

    } catch (error) {
        console.error('Download increment error:', error);
        return c.json({ success: false, error: 'Increment failed - internal server error' }, 500);
    }
});

// Cleanup endpoint (for testing/manual trigger, consider removing or securing in production)
app.get('/api/cleanup', async (c) => {
    try {
        console.log('Manual cleanup triggered...');
        await handleCleanup(c.env);

        return c.json({
            success: true,
            message: 'Manual cleanup initiated. Check logs for details.',
            timestamp: Date.now()
        }, 200);
    } catch (error) {
        console.error('Manual cleanup endpoint error:', error);
        return c.json({ success: false, error: 'Manual cleanup failed' }, 500);
    }
});

// Handle scheduled events (cron jobs) and main fetch handler
export default {
    fetch: app.fetch,
    async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext): Promise<void> {
        console.log(`Scheduled cleanup triggered at ${new Date(event.scheduledTime).toISOString()}`);
        ctx.waitUntil(handleCleanup(env));
    },
};

/**
 * Performs scheduled cleanup: identifies and deletes R2 objects corresponding
 * to expired Redis metadata entries.
 */
async function handleCleanup(env: Bindings): Promise<void> {
    const redis = getRedisClient(env);
    console.log('Running scheduled cleanup logic...');

    try {
        let cursor = 0;
        const scanBatchSize = 100;
        let totalKeysScanned = 0;
        let totalR2Deleted = 0;
        let totalRedisDownloadsDeleted = 0;

        do {
            const [nextCursorStr, keys] = await redis.scan(cursor, { match: 'file:*', count: scanBatchSize });
            cursor = parseInt(nextCursorStr, 10);
            totalKeysScanned += keys.length;

            console.log(`Cleanup scan: cursor=${cursor}, found ${keys.length} keys in this batch.`);

            for (const key of keys) {
                const uuid = key.substring(5); // Extract UUID from "file:UUID"
                const metadataJson = await redis.get(key);

                if (!metadataJson) {
                    // Metadata has expired in Redis, so delete corresponding R2 object and download counter
                    console.log(`Cleanup: Metadata for UUID ${uuid} expired in Redis. Deleting from R2 and downloads counter.`);
                    await env.R2_BUCKET.delete(uuid);
                    totalR2Deleted++;
                    await redis.del(`downloads:${uuid}`);
                    totalRedisDownloadsDeleted++;
                }
            }
        } while (cursor !== 0);

        console.log(`Scheduled cleanup finished. Scanned ${totalKeysScanned} file keys.`);
        console.log(`Deleted ${totalR2Deleted} R2 objects.`);
        console.log(`Deleted ${totalRedisDownloadsDeleted} Redis downloads counters.`);

    } catch (error) {
        console.error('Scheduled cleanup experienced an error:', error instanceof Error ? error.message : error);
    }
}