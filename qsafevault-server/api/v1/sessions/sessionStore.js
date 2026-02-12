/**
 * Session Store for WebRTC Sessions
 * 
 * Uses Upstash Redis (KV) for cross-instance persistence when available,
 * falls back to in-memory storage for local development/testing.
 * 
 * This enables horizontal scaling for 100s of concurrent users.
 */

const { randomUUID } = require('crypto');
const crypto = require('crypto');

const SESS_TTL_SEC = 180;
const SESS_TTL_MS = SESS_TTL_SEC * 1000;

function now() { return Date.now(); }

// ==================== Storage Backend ====================

// Check if Upstash Redis (KV) is available via env vars
const USE_KV_STORAGE = !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);

// In-memory fallback for local development/testing
const memoryStore = new Map();
const memoryPinIndex = new Map();

// Lazy-load Upstash Redis to avoid errors when not available
let redisClient = null;
function getRedisClient() {
  if (!redisClient && USE_KV_STORAGE) {
    const { Redis } = require('@upstash/redis');
    redisClient = new Redis({
      url: process.env.KV_REST_API_URL,
      token: process.env.KV_REST_API_TOKEN,
    });
  }
  return redisClient;
}

// Key prefix for namespacing
const KEY_PREFIX = 'qsv-webrtc-sessions:';

/**
 * Generate a cryptographic hash for key derivation
 * This makes keys unpredictable
 */
function deriveSecureKey(...parts) {
  const combined = parts.join(':');
  return crypto.createHash('sha256').update(combined).digest('base64url').slice(0, 32);
}

// Generate a safe storage key from session parameters
function storageKey(prefix, ...parts) {
  const secureHash = deriveSecureKey(prefix, ...parts);
  return `${KEY_PREFIX}${prefix}:${secureHash}`;
}

// ==================== Storage Operations ====================

// Parse Redis data (handles both auto-parsed objects and JSON strings)
function parseRedisData(data) {
  if (!data) return null;
  return typeof data === 'string' ? JSON.parse(data) : data;
}

// Read data from storage (returns null if not found or expired)
async function readStorage(key) {
  if (USE_KV_STORAGE) {
    try {
      const redis = getRedisClient();
      const data = await redis.get(key);
      if (!data) return null;
      
      const parsed = parseRedisData(data);
      
      // Check if expired (belt-and-suspenders with Redis TTL)
      if (parsed.expires && parsed.expires < now()) {
        await redis.del(key);
        return null;
      }
      
      return parsed;
    } catch (e) {
      return null;
    }
  } else {
    // In-memory fallback
    const data = memoryStore.get(key);
    if (!data) return null;
    
    if (data.expires && data.expires < now()) {
      memoryStore.delete(key);
      return null;
    }
    
    return data;
  }
}

// Write data to storage with TTL
async function writeStorage(key, data) {
  if (USE_KV_STORAGE) {
    const redis = getRedisClient();
    const ttlMs = data.expires ? data.expires - now() : SESS_TTL_MS;
    if (ttlMs <= 0) return; // Skip writing already-expired data
    const ttlSec = Math.ceil(ttlMs / 1000);
    await redis.set(key, JSON.stringify(data), { ex: ttlSec });
  } else {
    memoryStore.set(key, data);
  }
}

// Delete data from storage
async function deleteStorage(key) {
  if (USE_KV_STORAGE) {
    try {
      const redis = getRedisClient();
      await redis.del(key);
    } catch (e) {
      // Ignore deletion errors
    }
  } else {
    memoryStore.delete(key);
  }
}

// ==================== Session Management ====================

async function createSession(pin) {
  const sessionId = randomUUID();
  const created = now();
  const expires = created + SESS_TTL_MS;
  
  const sessionData = {
    sessionId,
    pin: pin || null,
    created,
    expires,
    offer: null,
    answer: null,
  };
  
  // Store session by sessionId
  const sessionKey = storageKey('session', sessionId);
  await writeStorage(sessionKey, sessionData);
  
  // If pin provided, create pin -> sessionId mapping
  if (pin) {
    const pinKey = storageKey('pin', pin);
    await writeStorage(pinKey, {
      sessionId,
      expires,
    });
  }
  
  return { sessionId, ttlSec: SESS_TTL_SEC };
}

async function getSessionIdByPin(pin) {
  const pinKey = storageKey('pin', pin);
  const pinData = await readStorage(pinKey);
  
  if (!pinData) {
    return { error: 'pin_not_found' };
  }
  
  if (pinData.expires < now()) {
    await deleteStorage(pinKey);
    return { error: 'session_expired' };
  }
  
  // Verify session still exists
  const sessionKey = storageKey('session', pinData.sessionId);
  const sess = await readStorage(sessionKey);
  
  if (!sess || sess.expires < now()) {
    await deleteStorage(pinKey);
    if (sess) await deleteStorage(sessionKey);
    return { error: 'session_expired' };
  }
  
  return { sessionId: pinData.sessionId };
}

async function getSession(sessionId) {
  const sessionKey = storageKey('session', sessionId);
  const sess = await readStorage(sessionKey);
  
  if (!sess) return null;
  
  if (sess.expires < now()) {
    await deleteStorage(sessionKey);
    if (sess.pin) {
      const pinKey = storageKey('pin', sess.pin);
      await deleteStorage(pinKey);
    }
    return null;
  }
  
  return sess;
}

async function saveSession(sessionId, data) {
  const sessionKey = storageKey('session', sessionId);
  const sess = await readStorage(sessionKey);
  
  if (!sess) return false;
  if (sess.expires < now()) {
    await deleteStorage(sessionKey);
    return false;
  }
  
  // Merge data and save
  const updatedSession = { ...sess, ...data };
  await writeStorage(sessionKey, updatedSession);
  return true;
}

async function deleteSession(sessionId) {
  const sessionKey = storageKey('session', sessionId);
  const sess = await readStorage(sessionKey);
  
  if (sess && sess.pin) {
    const pinKey = storageKey('pin', sess.pin);
    await deleteStorage(pinKey);
  }
  
  await deleteStorage(sessionKey);
}

async function purgeExpired() {
  if (USE_KV_STORAGE) {
    // Redis handles TTL-based expiration automatically.
    // This is a no-op for KV storage since we set TTLs on write.
  } else {
    const cutoff = now();
    for (const [key, data] of memoryStore.entries()) {
      if (data.expires && data.expires < cutoff) {
        memoryStore.delete(key);
      }
    }
  }
}

module.exports = {
  createSession,
  getSessionIdByPin,
  getSession,
  saveSession,
  deleteSession,
  purgeExpired,
  SESS_TTL_SEC,
  USE_KV_STORAGE,
};
