/**
 * Cloudflare Worker for Secure Share API
 * Handles file upload/download with strict privacy guarantees
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Redis } from '@upstash/redis/cloudflare';

// Cloudflare Worker environment bindings interface
interface Bindings {
    SECURE_SHARE_BUCKET: R2Bucket;
    UPSTASH_REDIS_REST_URL: string;
    UPSTASH_REDIS_REST_TOKEN: string;
    UPLOAD_AUTH_SECRET: string;
    MAX_FILE_SIZE_BYTES: number;
    MAX_CLICK_LIMIT: number;
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
    allowHeaders: ['Content-Type', 'Authorization', 'X-Original-Filename', 'X-Remaining-Clicks', 'X-Password-Hash-Base64', 'X-Nonce-Base64', 'X-Pwhash-Salt-Base64'],
    // Expose custom headers so the client can read them
    exposeHeaders: ['X-Original-Filename', 'X-Remaining-Clicks', 'X-Password-Hash-Base64', 'X-Nonce-Base64', 'X-Pwhash-Salt-Base64'],
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
        const clickLimit = parseInt(formData.get('clickLimit') as string, 10);
        const fileSize = parseInt(formData.get('fileSize') as string, 10);

        // ✅ FIXED: Extract ALL password fields including new pwhashSaltBase64
        const passwordHashBase64 = formData.get('passwordHashBase64') as string;
        const nonceBase64 = formData.get('nonceBase64') as string;
        const pwhashSaltBase64 = formData.get('pwhashSaltBase64') as string; // ✅ NEW FIELD

        console.log(`Upload request - UUID: ${uuid}, Filename: ${originalFilename}, Size: ${fileSize}, Clicks: ${clickLimit}, HasPassword: ${!!passwordHashBase64}`);

        // ✅ UPDATED: Validate ALL required fields including pwhashSaltBase64
        if (!file || !uuid || !originalFilename || isNaN(clickLimit) || isNaN(fileSize) || !passwordHashBase64 || !nonceBase64 || !pwhashSaltBase64) {
            console.warn('Missing or invalid required fields in upload request.');
            return c.json({ 
                success: false, 
                error: 'Missing or invalid required fields (file, uuid, originalFilename, clickLimit, fileSize, passwordHashBase64, nonceBase64, pwhashSaltBase64)' 
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

        // Validate click limit against worker's binding (which should be MAX_CLICK_LIMIT)
        if (clickLimit < 1 || clickLimit > env.MAX_CLICK_LIMIT) {
            console.warn(`Invalid click limit (${clickLimit}) for UUID: ${uuid}`);
            return c.json({
                success: false,
                error: `Invalid click limit. Must be between 1 and ${env.MAX_CLICK_LIMIT}`
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

        await env.SECURE_SHARE_BUCKET.put(uuid, fileBuffer, {
            // R2 automatically infers content type for some types, but specifying is good.
            httpMetadata: {
                contentType: file.type || 'application/octet-stream', // Use original file type if available, fallback
                cacheControl: 'no-cache, no-store, must-revalidate',
            },
            customMetadata: {
                originalFilename,
                uploadTime: Date.now().toString(),
                fileSize: fileSize.toString(), // Store original plaintext size
            },
        });
        console.log(`File successfully stored in R2: ${uuid}`);

        // ✅ UPDATED: Store metadata with pwhashSaltBase64
        const metadata = {
            uuid,
            originalFilename,
            fileSize, // Original plaintext size
            clickLimit,
            clicksUsed: 0,
            uploadTime: Date.now(),
            expiresAt: Date.now() + (60 * 60 * 1000), // 1 hour in milliseconds
            // ✅ UPDATED: All password protection fields
            passwordHashBase64,
            nonceBase64,
            pwhashSaltBase64, // ✅ NEW FIELD
            hasPassword: true,
        };

        // Use pipeline for atomic operations for metadata and click counter
        const pipeline = redis.pipeline();
        pipeline.setex(`file:${uuid}`, 3600, JSON.stringify(metadata)); // 1 hour TTL
        pipeline.setex(`clicks:${uuid}`, 3600, '0'); // Initial clicks, also with 1 hour TTL
        await pipeline.exec();
        console.log(`Metadata and click counter set in Redis for UUID: ${uuid}`);

        return c.json({
            success: true,
            uuid,
            message: 'File uploaded successfully',
        }, 200); // Explicitly return 200 OK

    } catch (error) {
        console.error('Upload error:', error instanceof Error ? error.message : error);
        // Provide more specific error messages if possible, but avoid leaking internal details.
        return c.json({
            success: false,
            error: 'Upload failed - internal server error'
        }, 500);
    }
});

// File download endpoint
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

        // Validate UUID format early
        if (!isValidUUID(uuid)) {
            console.warn(`Invalid UUID format for download: ${uuid}`);
            return c.json({ success: false, error: 'Invalid file ID format' }, 400);
        }

        // ✅ FIXED: Check password brute-force attempts first (before general rate limit for this specific path)
        const passwordAttemptsOk = await checkPasswordAttempts(redis, clientIP, uuid);
        if (!passwordAttemptsOk) {
            console.warn(`Password attempts limit exceeded for IP: ${clientIP}, UUID: ${uuid}`);
            return c.json({ success: false, error: `Too many password attempts for this file. Please try again in ${PASSWORD_ATTEMPT_WINDOW_SECONDS / 60} minutes.` }, 429);
        }

        // Check general rate limit
        const rateLimitOk = await checkRateLimit(redis, clientIP, env.RATE_LIMIT_REQUESTS_PER_MINUTE);
        if (!rateLimitOk) {
            console.warn(`General rate limit exceeded for IP: ${clientIP}`);
            return c.json({ success: false, error: 'Rate limit exceeded (general)' }, 429);
        }

        // Check if file metadata exists (Redis TTL check is implicit here)
        const metadataStr = await redis.get(`file:${uuid}`);
        if (!metadataStr) {
            console.log(`File metadata not found or expired for UUID: ${uuid}`);
            return c.json({ success: false, error: 'File not found or has expired' }, 404);
        }

        const metadata = JSON.parse(metadataStr as string);
        console.log(`File metadata found for UUID: ${uuid}. Clicks used: ${metadata.clicksUsed}/${metadata.clickLimit}`);

        // Atomic increment of click counter (pre-decrement in original description implies `decr` for limit,
        // but `incr` is more common for counting usage. I'll stick to `incr` for 'clicksUsed' and check against `clickLimit`.)
        const clicksUsed = await redis.incr(`clicks:${uuid}`);

        // Check click limit after incrementing (if it goes over, it's blocked)
        if (clicksUsed > metadata.clickLimit) {
            // Decrement it back if limit exceeded to reflect actual usage.
            // This rollback ensures the counter accurately reflects state for future attempts.
            await redis.decr(`clicks:${uuid}`);
            console.warn(`Download limit exceeded for UUID: ${uuid}. Clicks: ${clicksUsed}/${metadata.clickLimit}`);
            return c.json({ success: false, error: `Download limit exceeded (max ${metadata.clickLimit} downloads)` }, 403);
        }

        // Record password attempt *before* serving the file (this attempt counts towards brute force)
        // This is done after file existence check and general rate limits, but before R2 retrieval.
        await recordPasswordAttempt(redis, clientIP, uuid);

        // Get encrypted file from R2
        const fileObject = await env.SECURE_SHARE_BUCKET.get(uuid);
        if (!fileObject) {
            // This should ideally not happen if metadata exists, but good for robustness
            console.error(`File object not found in R2 for UUID: ${uuid}, despite metadata existing.`);
            return c.json({ success: false, error: 'File not found in storage' }, 404);
        }

        // Calculate remaining clicks for response header
        const remainingClicks = Math.max(0, metadata.clickLimit - clicksUsed);

        console.log(`File download preparation successful for UUID: ${uuid}. Remaining clicks: ${remainingClicks}`);

        // ✅ UPDATED: Stream the encrypted file back to client with password metadata in headers
        return new Response(fileObject.body, {
            headers: {
                'Content-Type': fileObject.httpMetadata?.contentType || 'application/octet-stream',
                'Content-Disposition': `attachment; filename="${encodeURIComponent(metadata.originalFilename || 'downloaded-file')}"`,
                'X-Original-Filename': encodeURIComponent(metadata.originalFilename || 'downloaded-file'),
                'X-Remaining-Clicks': remainingClicks.toString(),
                // ✅ UPDATED: Include ALL password fields in headers
                'X-Password-Hash-Base64': metadata.passwordHashBase64,
                'X-Nonce-Base64': metadata.nonceBase64,
                'X-Pwhash-Salt-Base64': metadata.pwhashSaltBase64, // ✅ NEW HEADER
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                // ✅ UPDATED: Expose new header to client
                'Access-Control-Expose-Headers': 'X-Original-Filename, X-Remaining-Clicks, X-Password-Hash-Base64, X-Nonce-Base64, X-Pwhash-Salt-Base64',
            },
        });

    } catch (error) {
        console.error('Download error:', error instanceof Error ? error.message : error);
        return c.json({
            success: false,
            error: 'Download failed - internal server error'
        }, 500);
    }
});

// Cleanup endpoint (for testing/manual trigger, consider removing or securing in production)
app.get('/api/cleanup', async (c) => {
    try {
        // CONSIDER: Add authentication for this endpoint (e.g., check a CRON_SECRET header)
        // if (c.req.header('X-Cron-Secret') !== c.env.CRON_SECRET) {
        //     return c.json({ success: false, error: 'Unauthorized' }, 401);
        // }

        console.log('Manual cleanup triggered...');
        // Execute the cleanup logic immediately
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
        // Ensure the cleanup task does not extend past the CPU time limit
        ctx.waitUntil(handleCleanup(env));
    },
};

/**
 * Performs scheduled cleanup: identifies and deletes R2 objects corresponding
 * to expired Redis metadata entries.
 * This acts as a redundancy to Redis TTL and R2 lifecycle policies.
 */
async function handleCleanup(env: Bindings): Promise<void> {
    const redis = getRedisClient(env); // Re-initialize to ensure it's fresh for the scheduled event
    console.log('Running scheduled cleanup logic...');

    try {
        let cursor = 0;
        const scanBatchSize = 100; // Process keys in batches
        let totalKeysScanned = 0;
        let totalR2Deleted = 0;
        let totalRedisClicksDeleted = 0;

        do {
            // Use SCAN command to iterate over keys in Redis
            // We scan for all `file:*` keys. Redis `get` will tell us if it's expired.
            // Using `COUNT` for batch size.
            const [nextCursorStr, keys] = await redis.scan(cursor, { match: 'file:*', count: scanBatchSize });
            cursor = parseInt(nextCursorStr, 10);
            totalKeysScanned += keys.length;

            console.log(`Cleanup scan: cursor=${cursor}, found ${keys.length} keys in this batch.`);

            for (const key of keys) {
                const uuid = key.substring(5); // Extract UUID from "file:UUID"
                // Attempt to get the metadata. If it's expired (TTL of -2), get will return null in Upstash.
                const metadataJson = await redis.get(key);

                if (!metadataJson) {
                    // Metadata has expired in Redis, so delete corresponding R2 object and click counter
                    console.log(`Cleanup: Metadata for UUID ${uuid} expired in Redis. Deleting from R2 and clicks counter.`);
                    await env.SECURE_SHARE_BUCKET.delete(uuid);
                    totalR2Deleted++;
                    await redis.del(`clicks:${uuid}`);
                    totalRedisClicksDeleted++;
                } else {
                    // Metadata still exists, meaning its TTL hasn't expired. Nothing to do here.
                    // console.log(`Cleanup: Metadata for UUID ${uuid} still exists in Redis. Skipping R2 delete.`);
                }
            }
        } while (cursor !== 0);

        console.log(`Scheduled cleanup finished. Scanned ${totalKeysScanned} file keys.`);
        console.log(`Deleted ${totalR2Deleted} R2 objects.`);
        console.log(`Deleted ${totalRedisClicksDeleted} Redis clicks counters.`);

    } catch (error) {
        console.error('Scheduled cleanup experienced an error:', error instanceof Error ? error.message : error);
    }
}

