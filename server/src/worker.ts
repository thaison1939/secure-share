/**
 * Cloudflare Worker for Secure Share API
 * Handles file upload/download with strict privacy guarantees
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { csrf } from 'hono/csrf';
import { secureHeaders } from 'hono/secure-headers';
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
}

// Hono context type
type HonoContext = {
    Bindings: Bindings;
};

const app = new Hono<HonoContext>();

// Security headers middleware
app.use('*', secureHeaders({
    contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
    },
    crossOriginEmbedderPolicy: false, // Disable for file downloads
}));

// CSRF protection with proper configuration
app.use('/api/upload', csrf({
    origin: ['https://secured-share.org', 'https://www.secured-share.org', 'http://localhost:3000'],
}));

// CORS middleware with strict origin control
app.use('*', cors({
    origin: (origin) => {
        const allowedOrigins = [
            'https://secured-share.org',
            'https://www.secured-share.org',
            'http://localhost:3000', // For development
        ];
        return allowedOrigins.includes(origin) ? origin : null;
    },
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-Original-Filename', 
        'X-Remaining-Downloads', 
        'X-Password-Hash-Base64', 
        'X-Nonce-Base64', 
        'X-Pwhash-Salt-Base64',
        'X-Client-Auth'
    ],
    exposeHeaders: [
        'X-Original-Filename', 
        'X-Remaining-Downloads', 
        'X-Password-Hash-Base64', 
        'X-Nonce-Base64', 
        'X-Pwhash-Salt-Base64'
    ],
    credentials: true,
}));

// Initialize Redis client
function getRedisClient(env: Bindings): Redis {
    if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) {
        throw new Error('Missing Redis configuration');
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
            await redis.expire(key, 60);
        }

        return current <= limit;
    } catch (error) {
        return true;
    }
}

// Password brute-force protection functions
const PASSWORD_ATTEMPT_LIMIT = 5;
const PASSWORD_ATTEMPT_WINDOW_SECONDS = 15 * 60;

async function checkPasswordAttempts(redis: Redis, clientIP: string, uuid: string): Promise<boolean> {
    try {
        const key = `pwd_attempts:${clientIP}:${uuid}`;
        const attempts = await redis.get(key);
        const currentAttempts = attempts ? parseInt(attempts as string) : 0;

        return currentAttempts < PASSWORD_ATTEMPT_LIMIT;
    } catch (error) {
        return true;
    }
}

async function recordPasswordAttempt(redis: Redis, clientIP: string, uuid: string): Promise<void> {
    try {
        const key = `pwd_attempts:${clientIP}:${uuid}`;
        const current = await redis.incr(key);

        if (current === 1) {
            await redis.expire(key, PASSWORD_ATTEMPT_WINDOW_SECONDS);
        }
    } catch (error) {
        // Silent fail
    }
}

// Validate UUID format
function isValidUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

// Content-Type validation helper
function validateContentType(contentType: string | undefined): boolean {
    if (!contentType) {
        return false;
    }
    
    const allowedTypes = [
        'multipart/form-data',
        'application/json',
        'application/octet-stream'
    ];
    
    return allowedTypes.some(type => contentType.includes(type));
}

// Health check endpoint
app.get('/api/health', (c) => {
    return c.json({
        status: 'healthy',
        timestamp: Date.now(),
        environment: 'production'
    });
});

// File upload endpoint with enhanced security
app.post('/api/upload', async (c) => {
    try {
        const env = c.env;
        const redis = getRedisClient(env);

        // Validate Content-Type header
        const contentType = c.req.header('Content-Type');
        if (!validateContentType(contentType)) {
            return c.json({ 
                success: false, 
                error: 'Invalid Content-Type header' 
            }, 400);
        }

        // Get client IP for rate limiting
        const clientIP = c.req.header('CF-Connecting-IP') || 
                         c.req.header('X-Forwarded-For')?.split(',')[0].trim() || 
                         c.req.header('X-Real-IP') || 
                         'unknown';

        // Check general rate limit
        const rateLimitOk = await checkRateLimit(redis, clientIP, env.RATE_LIMIT_REQUESTS_PER_MINUTE);
        if (!rateLimitOk) {
            return c.json({ success: false, error: 'Rate limit exceeded' }, 429);
        }

        // Verify upload auth secret
        const authHeader = c.req.header('Authorization');
        const expectedAuth = `Bearer ${env.UPLOAD_AUTH_SECRET}`;

        if (!authHeader || authHeader !== expectedAuth) {
            return c.json({ success: false, error: 'Unauthorized' }, 401);
        }

        // Parse form data
        const formData = await c.req.formData();
        const file = formData.get('file') as File;
        const uuid = formData.get('uuid') as string;
        const originalFilename = formData.get('originalFilename') as string;
        const downloadLimit = parseInt(formData.get('downloadLimit') as string, 10);
        const fileSize = parseInt(formData.get('fileSize') as string, 10);

        const passwordHashBase64 = formData.get('passwordHashBase64') as string;
        const nonceBase64 = formData.get('nonceBase64') as string;
        const pwhashSaltBase64 = formData.get('pwhashSaltBase64') as string;

        // Validate ALL required fields
        if (!file || !uuid || !originalFilename || isNaN(downloadLimit) || isNaN(fileSize) || !passwordHashBase64 || !nonceBase64 || !pwhashSaltBase64) {
            return c.json({ 
                success: false, 
                error: 'Missing or invalid required fields' 
            }, 400);
        }

        // Validate UUID format
        if (!isValidUUID(uuid)) {
            return c.json({ success: false, error: 'Invalid UUID format' }, 400);
        }

        // Validate file size
        if (file.size > env.MAX_FILE_SIZE_BYTES) {
            return c.json({
                success: false,
                error: `File too large. Maximum size: ${Math.round(env.MAX_FILE_SIZE_BYTES / (1024 * 1024))}MB`
            }, 413);
        }

        // Validate download limit
        if (downloadLimit < 1 || downloadLimit > env.MAX_DOWNLOAD_LIMIT) {
            return c.json({
                success: false,
                error: `Invalid download limit. Must be between 1 and ${env.MAX_DOWNLOAD_LIMIT}`
            }, 400);
        }

        // Check if UUID already exists
        const existingMetadata = await redis.get(`file:${uuid}`);
        if (existingMetadata) {
            return c.json({ success: false, error: 'File ID already exists' }, 409);
        }

        // Store encrypted file in R2
        const fileBuffer = await file.arrayBuffer();

        await env.R2_BUCKET.put(uuid, fileBuffer, {
            httpMetadata: {
                contentType: file.type || 'application/octet-stream',
                cacheControl: 'no-cache, no-store, must-revalidate',
            },
            customMetadata: {
                originalFilename,
                uploadTime: Date.now().toString(),
                fileSize: fileSize.toString(),
            },
        });

        // Store metadata
        const metadata = {
            uuid,
            originalFilename,
            fileSize,
            downloadLimit,
            uploadTime: Date.now(),
            expiresAt: Date.now() + (60 * 60 * 1000),
            passwordHashBase64,
            nonceBase64,
            pwhashSaltBase64,
            hasPassword: true,
        };

        // Use pipeline for atomic operations
        const pipeline = redis.pipeline();
        pipeline.setex(`file:${uuid}`, 3600, JSON.stringify(metadata));
        pipeline.setex(`downloads:${uuid}`, 3600, '0');
        await pipeline.exec();

        return c.json({
            success: true,
            uuid,
            message: 'File uploaded successfully',
        }, 200);

    } catch (error) {
        return c.json({
            success: false,
            error: 'Upload failed - internal server error'
        }, 500);
    }
});

// File download endpoint - READ ONLY
app.get('/api/download/:uuid', async (c) => {
    try {
        const env = c.env;
        const redis = getRedisClient(env);
        const uuid = c.req.param('uuid');

        // Get client IP
        const clientIP = c.req.header('CF-Connecting-IP') || 
                         c.req.header('X-Forwarded-For')?.split(',')[0].trim() || 
                         c.req.header('X-Real-IP') || 
                         'unknown';

        // Validate UUID format
        if (!isValidUUID(uuid)) {
            return c.json({ success: false, error: 'Invalid file ID format' }, 400);
        }

        // Get file metadata from Redis
        const metadataString = await redis.get(`file:${uuid}`);
        if (!metadataString) {
            return c.json({ success: false, error: 'File not found or expired' }, 404);
        }

        // Parse metadata
        let metadata;
        try {
            if (typeof metadataString === 'string') {
                metadata = JSON.parse(metadataString);
            } else {
                metadata = metadataString;
            }
        } catch (parseError) {
            return c.json({ success: false, error: 'File metadata corrupted' }, 500);
        }

        // Validate required fields exist
        if (!metadata.passwordHashBase64 || !metadata.nonceBase64 || !metadata.pwhashSaltBase64) {
            return c.json({ success: false, error: 'File metadata incomplete' }, 500);
        }

        // Check if file has expired
        if (metadata.expiresAt && Date.now() > metadata.expiresAt) {
            await redis.del(`file:${uuid}`);
            await redis.del(`downloads:${uuid}`);
            await env.R2_BUCKET.delete(uuid);
            return c.json({ success: false, error: 'File expired' }, 410);
        }

        // Get current download count from separate Redis key
        const currentDownloads = await redis.get(`downloads:${uuid}`) || '0';
        const remainingDownloads = metadata.downloadLimit - parseInt(String(currentDownloads));

        // Check if already at limit
        if (parseInt(String(currentDownloads)) >= metadata.downloadLimit) {
            return c.json({ success: false, error: 'Download limit exceeded' }, 403);
        }

        // Download file from R2
        const fileObject = await env.R2_BUCKET.get(uuid);
        if (!fileObject) {
            return c.json({ success: false, error: 'File not found in storage' }, 404);
        }

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
        return c.json({ success: false, error: 'Download failed - internal server error' }, 500);
   }
});

// POST /api/download/:uuid/increment - Track download attempts
app.post('/api/download/:uuid/increment', async (c) => {
    try {
        const env = c.env;
        const redis = getRedisClient(env);
        const uuid = c.req.param('uuid');

        // Get client IP
        const clientIP = c.req.header('CF-Connecting-IP') || 
                         c.req.header('X-Forwarded-For')?.split(',')[0].trim() || 
                         c.req.header('X-Real-IP') || 
                         'unknown';

        // Verify auth secret
        const authHeader = c.req.header('Authorization');
        const expectedAuth = `Bearer ${env.UPLOAD_AUTH_SECRET}`;

        if (!authHeader || authHeader !== expectedAuth) {
            return c.json({ success: false, error: 'Unauthorized' }, 401);
        }

        // Validate UUID format
        if (!isValidUUID(uuid)) {
            return c.json({ success: false, error: 'Invalid file ID format' }, 400);
        }

        // Get file metadata from Redis
        const metadataString = await redis.get(`file:${uuid}`);
        if (!metadataString) {
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
            return c.json({ success: false, error: 'File metadata corrupted' }, 500);
        }

        // Check if file has expired
        if (metadata.expiresAt && Date.now() > metadata.expiresAt) {
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

        // Check if limit reached - delete file immediately
        if (currentDownloads >= downloadLimit) {
            await Promise.all([
                redis.del(`file:${uuid}`),
                redis.del(downloadCounterKey),
                env.R2_BUCKET.delete(uuid)
            ]);

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
        return c.json({ success: false, error: 'Increment failed - internal server error' }, 500);
    }
});

// Cleanup endpoint
app.get('/api/cleanup', async (c) => {
    try {
        await handleCleanup(c.env);

        return c.json({
            success: true,
            message: 'Manual cleanup initiated',
            timestamp: Date.now()
        }, 200);
    } catch (error) {
        return c.json({ success: false, error: 'Manual cleanup failed' }, 500);
    }
});

// Handle scheduled events and main fetch handler
export default {
    fetch: app.fetch,
    async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext): Promise<void> {
        ctx.waitUntil(handleCleanup(env));
    },
};

/**
 * Cleanup function
 */
async function handleCleanup(env: Bindings): Promise<void> {
    const redis = getRedisClient(env);

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

            for (const key of keys) {
                const uuid = key.substring(5);
                const metadataJson = await redis.get(key);

                if (!metadataJson) {
                    await env.R2_BUCKET.delete(uuid);
                    totalR2Deleted++;
                    await redis.del(`downloads:${uuid}`);
                    totalRedisDownloadsDeleted++;
                }
            }
        } while (cursor !== 0);

    } catch (error) {
        // Silent fail in production
    }
}