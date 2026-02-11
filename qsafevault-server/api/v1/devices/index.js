/**
 * Device Registry for Enterprise Edition
 * 
 * Uses Upstash Redis (KV) for cross-instance persistence when available,
 * falls back to in-memory storage for local development/testing.
 * 
 * ENTERPRISE ONLY: This endpoint requires Enterprise mode.
 */

const crypto = require('crypto');

// ==================== Storage Backend ====================

const USE_KV_STORAGE = !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);

// In-memory fallback for local development/testing
const memoryStore = new Map();

// Lazy-load Upstash Redis
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

const KEY_PREFIX = 'qsv-devices:';

function deriveSecureKey(...parts) {
  const combined = parts.join(':');
  return crypto.createHash('sha256').update(combined).digest('base64url').slice(0, 32);
}

function storageKey(userId) {
  const secureHash = deriveSecureKey('devices', userId);
  return `${KEY_PREFIX}${secureHash}`;
}

function now() { return Date.now(); }

// ==================== Storage Operations ====================

// Parse Redis data (handles both auto-parsed objects and JSON strings)
function parseRedisData(data) {
  if (!data) return null;
  return typeof data === 'string' ? JSON.parse(data) : data;
}

async function readStorage(key) {
  if (USE_KV_STORAGE) {
    try {
      const redis = getRedisClient();
      const data = await redis.get(key);
      if (!data) return null;
      return parseRedisData(data);
    } catch (e) {
      return null;
    }
  } else {
    return memoryStore.get(key) || null;
  }
}

async function writeStorage(key, data) {
  if (USE_KV_STORAGE) {
    const redis = getRedisClient();
    // Device registrations have a max TTL of 24 hours
    await redis.set(key, JSON.stringify(data), { ex: 86400 });
  } else {
    memoryStore.set(key, data);
  }
}

// ==================== Validation ====================

function validateOnion(onion) {
  return typeof onion === 'string' && /^[a-z2-7]{16,56}\.onion$/.test(onion);
}

// ==================== Device Management ====================

async function getDevices(userId) {
  const key = storageKey(userId);
  const data = await readStorage(key);
  if (!data || !data.devices) return [];
  
  // Filter expired devices
  const nowVal = now();
  return data.devices.filter(d => !d.expires || d.expires > nowVal);
}

async function saveDevices(userId, devices) {
  const key = storageKey(userId);
  await writeStorage(key, { devices, updated: now() });
}

// ==================== HTTP Handlers ====================

async function registerDevice(req, res) {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.end();
    return;
  }
  
  try {
    // Validate req.body exists (Express should have parsed it)
    if (!req.body || typeof req.body !== 'object') {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'invalid_json' }));
      return;
    }
    
    const input = req.body;
    
    const { userId, deviceId, onion, port, ttlSec } = input;
    if (!userId || !deviceId || !validateOnion(onion)) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'invalid_input' }));
      return;
    }
    
    const expires = ttlSec 
      ? now() + Math.min(86400, Math.max(30, ttlSec)) * 1000 
      : now() + 180 * 1000;
    
    const entry = { deviceId, onion, port, expires };
    
    // Get existing devices and filter expired
    const devices = await getDevices(userId);
    
    // Update or add device
    const idx = devices.findIndex(d => d.deviceId === deviceId);
    if (idx >= 0) {
      devices[idx] = entry;
    } else {
      devices.push(entry);
    }
    
    await saveDevices(userId, devices);
    
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ status: 'ok' }));
  } catch (e) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'server_error' }));
  }
}

module.exports = { registerDevice, getDevices };
