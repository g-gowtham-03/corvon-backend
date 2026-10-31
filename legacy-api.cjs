const express = require('express');
const crypto = require('node:crypto');

function createLegacyRouter(pool, logger = console) {
  const router = express.Router();

  router.post('/register', async (req, res) => {
    const { phoneNumber, emergencyContact, credentialHash, fcmToken } = req.body || {};
    if (!phoneNumber || !emergencyContact || !credentialHash) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
      await pool.query(`
        INSERT INTO devices (phone_number, emergency_contact, credential_hash, fcm_token)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (phone_number) DO UPDATE
          SET emergency_contact = $2,
              credential_hash = $3,
              fcm_token = $4,
              registered_at = NOW()
      `, [phoneNumber, emergencyContact, credentialHash, fcmToken || '']);
      logger.info('[legacy] device registered');
      return res.status(200).json({ success: true, message: 'Device registered' });
    } catch {
      logger.error('[legacy] registration failed');
      return res.status(500).json({ error: 'Registration failed' });
    }
  });

  router.post('/recover', async (req, res) => {
    const { phoneNumber, credential } = req.body || {};
    if (!phoneNumber || !credential) {
      return res.status(400).json({ error: 'Phone number and credential required' });
    }
    try {
      const result = await pool.query('SELECT * FROM devices WHERE phone_number = $1', [phoneNumber]);
      if (!result.rows.length) return res.status(404).json({ error: 'Device not registered' });
      const device = result.rows[0];
      if (device.locked_until && new Date(device.locked_until) > new Date()) {
        const remaining = Math.ceil((new Date(device.locked_until) - new Date()) / 60000);
        return res.status(429).json({ error: `Account locked. Try again in ${remaining} minute(s).` });
      }
      const submittedHash = crypto.createHash('sha256').update(credential + phoneNumber).digest('hex');
      if (submittedHash !== device.credential_hash) {
        const newFailCount = (device.fail_count || 0) + 1;
        const lockedUntil = newFailCount >= 3 ? new Date(Date.now() + 24 * 60 * 60 * 1000) : null;
        await pool.query('UPDATE devices SET fail_count = $1, locked_until = $2 WHERE phone_number = $3',
          [newFailCount >= 3 ? 0 : newFailCount, lockedUntil, phoneNumber]);
        if (lockedUntil) logger.warn('[legacy] recovery account temporarily locked');
        return res.status(401).json({ error: 'Invalid credential' });
      }
      await pool.query('UPDATE devices SET fail_count = 0, locked_until = NULL WHERE phone_number = $1', [phoneNumber]);
      await pool.query('DELETE FROM location_reports WHERE phone_number = $1', [phoneNumber]);
      await pool.query(`
        INSERT INTO pending_commands (phone_number, has_command)
        VALUES ($1, TRUE)
        ON CONFLICT (phone_number) DO UPDATE SET has_command = TRUE, created_at = NOW()
      `, [phoneNumber]);
      logger.info('[legacy] recovery command dispatched');
      return res.status(200).json({ success: true, message: 'Recovery command dispatched.' });
    } catch {
      logger.error('[legacy] recovery request failed');
      return res.status(500).json({ error: 'Recovery failed' });
    }
  });

  router.get('/checkCommand', async (req, res) => {
    const { phoneNumber } = req.query;
    if (!phoneNumber) return res.status(400).json({ error: 'Phone number required' });
    try {
      const result = await pool.query('SELECT has_command FROM pending_commands WHERE phone_number = $1', [phoneNumber]);
      const hasCommand = result.rows.length > 0 && result.rows[0].has_command;
      if (hasCommand) await pool.query('UPDATE pending_commands SET has_command = FALSE WHERE phone_number = $1', [phoneNumber]);
      return res.status(200).json({ hasCommand });
    } catch {
      logger.error('[legacy] command check failed');
      return res.status(500).json({ error: 'Command check failed' });
    }
  });

  router.post('/locationReport', async (req, res) => {
    const { phoneNumber, latitude, longitude, accuracy, timestamp } = req.body || {};
    if (!phoneNumber || !latitude || !longitude) return res.status(400).json({ error: 'Missing location data' });
    try {
      const deviceResult = await pool.query('SELECT * FROM devices WHERE phone_number = $1', [phoneNumber]);
      if (!deviceResult.rows.length) return res.status(404).json({ error: 'Device not found' });
      await pool.query(`
        INSERT INTO location_reports (phone_number, latitude, longitude, accuracy, timestamp)
        VALUES ($1, $2, $3, $4, $5)
      `, [phoneNumber, latitude, longitude, accuracy, timestamp]);
      logger.info('[legacy] location received');
      return res.status(200).json({ success: true });
    } catch {
      logger.error('[legacy] location report failed');
      return res.status(500).json({ error: 'Failed to process location' });
    }
  });

  router.get('/relayLocation', async (req, res) => {
    const { phone, lat, lng } = req.query;
    if (!phone || !lat || !lng) {
      return res.status(400).send('<html><body style="font-family:sans-serif;text-align:center;padding:40px;"><h2>❌ Invalid link</h2><p>Missing required information.</p></body></html>');
    }
    try {
      await pool.query(`
        INSERT INTO location_reports (phone_number, latitude, longitude, accuracy, timestamp, source)
        VALUES ($1, $2, $3, NULL, $4, 'sms-fallback-relay')
      `, [phone, parseFloat(lat), parseFloat(lng), new Date().toISOString()]);
      return res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a1628;color:white;"><h2>✅ Location shared with owner</h2><p>The device owner can now see this location on their recovery portal.</p><p style="color:#8899aa;">Lat: ${lat}, Lng: ${lng}</p><p style="margin-top:30px;color:#e8a020;font-size:14px;">You can close this page now.</p></body></html>`);
    } catch {
      logger.error('[legacy] location relay failed');
      return res.status(500).send('<html><body style="font-family:sans-serif;text-align:center;padding:40px;"><h2>❌ Error storing location</h2></body></html>');
    }
  });

  router.get('/status', async (req, res) => {
    res.set('Access-Control-Allow-Origin', '*');
    const { phoneNumber } = req.query;
    if (!phoneNumber) return res.status(400).json({ error: 'Phone number required' });
    try {
      const result = await pool.query(`
        SELECT * FROM location_reports
        WHERE phone_number = $1
        ORDER BY received_at DESC
        LIMIT 1
      `, [phoneNumber]);
      if (!result.rows.length) return res.status(200).json({ status: 'PENDING', location: null });
      const latest = result.rows[0];
      return res.status(200).json({ status: 'LOCATION_RECEIVED', location: {
        latitude: latest.latitude,
        longitude: latest.longitude,
        accuracy: latest.accuracy,
        timestamp: latest.timestamp,
      } });
    } catch {
      logger.error('[legacy] status check failed');
      return res.status(500).json({ error: 'Status check failed' });
    }
  });

  router.get('/devices', async (_req, res) => {
    try {
      const result = await pool.query('SELECT phone_number FROM devices');
      return res.status(200).json({ devices: result.rows.map(row => row.phone_number) });
    } catch {
      return res.status(500).json({ error: 'Failed to fetch devices' });
    }
  });

  return router;
}

module.exports = { createLegacyRouter };
