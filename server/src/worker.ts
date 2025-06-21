/**
 * Cloudflare Worker for Secure Share API
 * Handles file upload/download with strict privacy guarantees
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Redis } from '@upstash/redis/cloudflare';

// Environment bindings interface
interface Env {
  SECURE_SHARE_BUCKET: R2Bucket;
  UPSTASH_REDIS_REST_URL: string;
  UPSTASH_REDIS_REST_TOKEN: string;
  UPLOAD_AUTH_SECRET: string;
  MAX_FILE_SIZE_BYTES: number;
  MAX_CLICK_LIMIT: number;
  RATE_LIMIT_REQUESTS_PER_MINUTE: number;
  [key: string]: any; // Allow additional bindings
}

const app = new Hono<{ Bindings: Env }>();

// CORS middleware - allowing all origins for development
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// Initialize Redis client
function getRedisClient(env: Env): Redis {
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
    console.error('Rate limit check failed:', error);
    return true; // Allow on error to avoid blocking legitimate users
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
    environment: c.env.name || 'development'
  });
});

// File upload endpoint
app.post('/api/upload', async (c) => {
  try {
    const env = c.env;
    const redis = getRedisClient(env);
    
    // Get client IP for rate limiting
    const clientIP = c.req.header('CF-Connecting-IP') || 
                     c.req.header('X-Forwarded-For') || 
                     c.req.header('X-Real-IP') || 
                     'unknown';
    
    console.log(`Upload request from IP: ${clientIP}`);
    
    // Check rate limit
    const rateLimitOk = await checkRateLimit(redis, clientIP, env.RATE_LIMIT_REQUESTS_PER_MINUTE);
    if (!rateLimitOk) {
      console.log(`Rate limit exceeded for IP: ${clientIP}`);
      return c.json({ success: false, error: 'Rate limit exceeded' }, 429);
    }

    // Verify upload auth secret
    const authHeader = c.req.header('Authorization');
    const expectedAuth = `Bearer ${env.UPLOAD_AUTH_SECRET}`;
    
    if (!authHeader || authHeader !== expectedAuth) {
      console.log('Unauthorized upload attempt');
      return c.json({ success: false, error: 'Unauthorized' }, 401);
    }

    // Parse form data
    const formData = await c.req.formData();
    const file = formData.get('file') as File;
    const uuid = formData.get('uuid') as string;
    const originalFilename = formData.get('originalFilename') as string;
    const clickLimit = parseInt(formData.get('clickLimit') as string);
    const fileSize = parseInt(formData.get('fileSize') as string);

    console.log(`Upload request - UUID: ${uuid}, Filename: ${originalFilename}, Size: ${fileSize}, Clicks: ${clickLimit}`);

    // Validate required fields
    if (!file || !uuid || !originalFilename || !clickLimit) {
      return c.json({ success: false, error: 'Missing required fields' }, 400);
    }

    // Validate UUID format
    if (!isValidUUID(uuid)) {
      return c.json({ success: false, error: 'Invalid UUID format' }, 400);
    }

    // Validate file size
    if (file.size > env.MAX_FILE_SIZE_BYTES) {
      return c.json({ 
        success: false, 
        error: `File too large. Maximum size: ${Math.round(env.MAX_FILE_SIZE_BYTES / 1024 / 1024)}MB` 
      }, 413);
    }

    // Validate click limit
    if (clickLimit < 1 || clickLimit > env.MAX_CLICK_LIMIT) {
      return c.json({ 
        success: false, 
        error: `Invalid click limit. Must be between 1 and ${env.MAX_CLICK_LIMIT}` 
      }, 400);
    }

    // Check if UUID already exists (prevent overwrites)
    const existingMetadata = await redis.get(`file:${uuid}`);
    if (existingMetadata) {
      return c.json({ success: false, error: 'File ID already exists' }, 409);
    }

    // Store encrypted file in R2
    const fileBuffer = await file.arrayBuffer();
    console.log(`Storing file in R2 with UUID: ${uuid}, Size: ${fileBuffer.byteLength} bytes`);
    
    await env.SECURE_SHARE_BUCKET.put(uuid, fileBuffer, {
      httpMetadata: {
        contentType: 'application/octet-stream',
        cacheControl: 'no-cache, no-store, must-revalidate',
      },
      customMetadata: {
        originalFilename,
        uploadTime: Date.now().toString(),
        fileSize: fileSize.toString(),
      },
    });

    // Store metadata in Redis with 1-hour TTL (3600 seconds)
    const metadata = {
      uuid,
      originalFilename,
      fileSize,
      clickLimit,
      clicksUsed: 0,
      uploadTime: Date.now(),
      expiresAt: Date.now() + (60 * 60 * 1000), // 1 hour
    };

    // Use pipeline for atomic operations
    const pipeline = redis.pipeline();
    pipeline.setex(`file:${uuid}`, 3600, JSON.stringify(metadata));
    pipeline.setex(`clicks:${uuid}`, 3600, '0');
    await pipeline.exec();

    console.log(`File uploaded successfully - UUID: ${uuid}`);

    return c.json({
      success: true,
      uuid,
      message: 'File uploaded successfully',
    });

  } catch (error) {
    console.error('Upload error:', error);
    return c.json({ 
      success: false, 
      error: 'Upload failed - server error' 
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
                     c.req.header('X-Forwarded-For') || 
                     c.req.header('X-Real-IP') || 
                     'unknown';
    
    console.log(`Download request from IP: ${clientIP}, UUID: ${uuid}`);

    // Check rate limit
    const rateLimitOk = await checkRateLimit(redis, clientIP, env.RATE_LIMIT_REQUESTS_PER_MINUTE);
    if (!rateLimitOk) {
      console.log(`Rate limit exceeded for IP: ${clientIP}`);
      return c.json({ success: false, error: 'Rate limit exceeded' }, 429);
    }

    // Validate UUID format
    if (!isValidUUID(uuid)) {
      return c.json({ success: false, error: 'Invalid UUID' }, 400);
    }

    // Check if file metadata exists (TTL check)
    const metadataStr = await redis.get(`file:${uuid}`);
    if (!metadataStr) {
      console.log(`File not found or expired: ${uuid}`);
      return c.json({ success: false, error: 'File not found or expired' }, 404);
    }

    const metadata = JSON.parse(metadataStr as string);
    console.log(`File found - UUID: ${uuid}, Clicks used: ${metadata.clicksUsed}/${metadata.clickLimit}`);

    // Atomic increment of click counter
    const clicksUsed = await redis.incr(`clicks:${uuid}`);
    
    // Check click limit
    if (clicksUsed > metadata.clickLimit) {
      console.log(`Download limit exceeded for UUID: ${uuid}, Clicks: ${clicksUsed}/${metadata.clickLimit}`);
      return c.json({ success: false, error: 'Download limit exceeded' }, 403);
    }

    // Get encrypted file from R2
    const fileObject = await env.SECURE_SHARE_BUCKET.get(uuid);
    if (!fileObject) {
      console.log(`File not found in R2 storage: ${uuid}`);
      return c.json({ success: false, error: 'File not found in storage' }, 404);
    }

    // Calculate remaining clicks
    const remainingClicks = Math.max(0, metadata.clickLimit - clicksUsed);
    
    console.log(`File download successful - UUID: ${uuid}, Remaining clicks: ${remainingClicks}`);

    // Stream the encrypted file back to client
    return new Response(fileObject.body, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="encrypted-file"`,
        'X-Original-Filename': metadata.originalFilename,
        'X-Remaining-Clicks': remainingClicks.toString(),
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Access-Control-Expose-Headers': 'X-Original-Filename, X-Remaining-Clicks',
      },
    });

  } catch (error) {
    console.error('Download error:', error);
    return c.json({ 
      success: false, 
      error: 'Download failed - server error' 
    }, 500);
  }
});

// Cleanup endpoint (for testing)
app.get('/api/cleanup', async (c) => {
  try {
    const env = c.env;
    const redis = getRedisClient(env);

    console.log('Manual cleanup triggered...');
    
    // In a real implementation, you'd scan for expired keys
    // For now, just return success
    return c.json({ 
      success: true, 
      message: 'Cleanup completed',
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    return c.json({ success: false, error: 'Cleanup failed' }, 500);
  }
});

// Handle scheduled events (cron jobs)
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log('Scheduled cleanup starting...');
    ctx.waitUntil(handleCleanup(env));
  },
};

async function handleCleanup(env: Env): Promise<void> {
  try {
    const redis = getRedisClient(env);
    console.log('Running detailed cleanup...');
    
    let cursor = '0';
    let deletedCount = 0;
    
    do {
      // Scan for all file metadata keys
      const result = await redis.scan(cursor, { match: 'file:*', count: 100 });
      cursor = result[0]; // Update cursor for next iteration
      const keys = result[1]; // Keys found in this scan batch

      for (const key of keys) {
        const ttl = await redis.ttl(key); // Get TTL of the metadata key
        const uuid = key.replace('file:', '');

        // If TTL is -2, the key (metadata) has expired and no longer exists in Redis.
        // This is our primary indicator for R2 cleanup.
        if (ttl === -2) {
          console.log(`Cleanup: Redis metadata for ${uuid} expired. Deleting R2 object.`);
          try {
            await env.SECURE_SHARE_BUCKET.delete(uuid);
            // Also explicitly delete the associated clicks key, just in case it lingered
            await redis.del(`clicks:${uuid}`);
            deletedCount++;
          } catch (deleteError) {
            console.error(`Cleanup: Failed to delete R2 object ${uuid}:`, deleteError);
          }
        } else if (ttl === -1) {
          // Key exists but has no TTL. This shouldn't happen with `setex`, but good to log.
          console.warn(`Cleanup: Metadata for ${uuid} found but no TTL. Consider manual intervention.`);
        } else {
          // Key exists and has a TTL. It's not expired yet.
          console.log(`Cleanup: UUID ${uuid} still active (TTL: ${ttl}s). Skipping R2 cleanup.`);
        }
      }
    } while (cursor !== '0'); // Continue scanning until cursor returns '0'

    console.log(`Detailed cleanup completed. Total R2 objects deleted: ${deletedCount}`);
  } catch (error) {
    console.error('Detailed cleanup failed:', error);
  }
}
