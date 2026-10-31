import { app } from './app.js';
import { config } from './config.js';
import { pool } from './db/pool.js';

const server = app.listen(config.PORT, () => console.log(`CORVON API listening on port ${config.PORT}`));
const retentionJob = setInterval(async () => {
  try {
    await pool.query("DELETE FROM location_reports WHERE received_at < now()-($1 * interval '1 day')", [config.LOCATION_RETENTION_DAYS]);
    await pool.query("UPDATE recovery_requests SET status='expired' WHERE status='active' AND expires_at<=now()");
    await pool.query("DELETE FROM otp_challenges WHERE expires_at < now()-interval '1 day'");
    await pool.query("DELETE FROM recovery_challenges WHERE expires_at < now()-interval '1 day'");
    await pool.query("DELETE FROM registrations WHERE expires_at < now()-interval '1 day' AND secret_issued_at IS NULL");
    await pool.query('DELETE FROM rate_limit_buckets WHERE reset_at < now()');
  } catch { /* Never log sensitive database/provider data. Operational monitoring should alert on job health. */ }
}, 60 * 60 * 1000);
retentionJob.unref();
async function shutdown() { server.close(async () => { await pool.end(); process.exit(0); }); }
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
