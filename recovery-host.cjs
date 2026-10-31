const REQUIRED_RECOVERY_SETTINGS = [
  'RECOVERY_DATABASE_URL',
  'OTP_PEPPER',
  'LOOKUP_PEPPER',
  'RECOVERY_SECRET_PEPPER',
  'SESSION_PEPPER',
  'CONTACT_DATA_KEY',
];

function hasRecoveryConfiguration(env = process.env) {
  const complete = REQUIRED_RECOVERY_SETTINGS.every(name => typeof env[name] === 'string' && env[name].length > 0);
  return complete && (!env.DATABASE_URL || !sameDatabasePrincipal(env.DATABASE_URL, env.RECOVERY_DATABASE_URL));
}

function sameDatabasePrincipal(legacyUrl, recoveryUrl) {
  if (legacyUrl === recoveryUrl) return true;
  try {
    return new URL(legacyUrl).username === new URL(recoveryUrl).username;
  } catch {
    return false;
  }
}

async function mountRecoveryApi(app, { env = process.env, importer, logger = console } = {}) {
  const unavailable = (_req, res) => res.status(503).json({
    error: { code: 'RECOVERY_API_UNAVAILABLE', message: 'Recovery API is not configured.' }
  });
  if (!hasRecoveryConfiguration(env)) {
    logger.warn('[recovery] API disabled: required configuration is missing');
    app.use('/v1', unavailable);
    return false;
  }
  try {
    const loaded = await (importer || (() => import('./staging-backend/src/app.js')))();
    if (!loaded || !loaded.app) throw new Error('recovery app export missing');
    app.use(loaded.app);
    return true;
  } catch {
    logger.error('[recovery] API disabled: configuration or initialization failed');
    app.use('/v1', unavailable);
    return false;
  }
}

module.exports = { hasRecoveryConfiguration, mountRecoveryApi };
