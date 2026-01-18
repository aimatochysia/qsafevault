const metaFileName = 'pwdb.meta.json';
const baseEncryptedName = 'pwdb.enc';
const backupSuffix = '.bak';
const derivedKeyFileName = 'derived.key';
const verifierLabel = 'q-safe-verifier';
const keyWrapLabel = 'qsv-keywrap-v1';
const fastSigLabel = 'qsv-fastparams-sig-v1';
const entryNonceLabel = 'qsv-entry-nonce-v1';
const int fastKdfSaltLen = 32;

// FIPS-compliant PBKDF2-HMAC-SHA256 constants (NIST SP 800-132)
const int minPbkdf2Iterations = 10000;     // FIPS minimum
const int fastPbkdf2Iterations = 100000;   // Fast unlock (~100ms)
const int slowPbkdf2Iterations = 600000;   // Slow unlock (~1s)
const int slowTargetMs = 1000;
const int fastTargetMs = 100;

// Legacy Argon2id constants (deprecated, for compatibility only)
const int fastMemoryKb = 131072;
const int fastIterations = 1;
const int fastParallelism = 2;
const int slowKdfIterations = 3;
const int slowKdfMemoryKb = 262144;
const int slowKdfParallelism = 2;
const int minIterations = 1;
const int minMemoryKb = 16384;
const int minParallelism = 1;
