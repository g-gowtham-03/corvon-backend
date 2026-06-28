const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

// ── PostgreSQL connection ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Create tables on startup ──
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      phone_number TEXT PRIMARY KEY,
      emergency_contact TEXT NOT NULL,
      credential_hash TEXT NOT NULL,
      fcm_token TEXT DEFAULT '',
      registered_at TIMESTAMPTZ DEFAULT NOW(),
      fail_count INTEGER DEFAULT 0,
      locked_until TIMESTAMPTZ NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS location_reports (
      id SERIAL PRIMARY KEY,
      phone_number TEXT NOT NULL,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      accuracy DOUBLE PRECISION,
      timestamp TEXT,
      received_at TIMESTAMPTZ DEFAULT NOW(),
      source TEXT DEFAULT 'direct'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pending_commands (
      phone_number TEXT PRIMARY KEY,
      has_command BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("✅ Database tables ready");
}

initDB().catch(console.error);

// ─────────────────────────────────────────────────────────
// POST /register
// ─────────────────────────────────────────────────────────
app.post("/register", async (req, res) => {
  const { phoneNumber, emergencyContact, credentialHash, fcmToken } = req.body;

  if (!phoneNumber || !emergencyContact || !credentialHash) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    await pool.query(`
      INSERT INTO devices (phone_number, emergency_contact, credential_hash, fcm_token)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (phone_number) DO UPDATE
        SET emergency_contact = $2,
            credential_hash   = $3,
            fcm_token         = $4,
            registered_at     = NOW()
    `, [phoneNumber, emergencyContact, credentialHash, fcmToken || ""]);

    console.log(`✅ Device registered: ${phoneNumber}`);
    return res.status(200).json({ success: true, message: "Device registered" });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ error: "Registration failed" });
  }
});

// ─────────────────────────────────────────────────────────
// POST /recover
// ─────────────────────────────────────────────────────────
app.post("/recover", async (req, res) => {
  const { phoneNumber, credential } = req.body;

  if (!phoneNumber || !credential) {
    return res.status(400).json({ error: "Phone number and credential required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM devices WHERE phone_number = $1", [phoneNumber]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Device not registered" });
    }

    const device = result.rows[0];

    // Lockout check
    if (device.locked_until && new Date(device.locked_until) > new Date()) {
      const remaining = Math.ceil((new Date(device.locked_until) - new Date()) / 60000);
      return res.status(429).json({
        error: `Account locked. Try again in ${remaining} minute(s).`,
      });
    }

    // Validate credential
    const submittedHash = crypto
      .createHash("sha256")
      .update(credential + phoneNumber)
      .digest("hex");

    if (submittedHash !== device.credential_hash) {
      const newFailCount = (device.fail_count || 0) + 1;
      let lockedUntil = null;

      if (newFailCount >= 3) {
        lockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000);
        console.log(`🔒 Account locked: ${phoneNumber}`);
      }

      await pool.query(
        "UPDATE devices SET fail_count = $1, locked_until = $2 WHERE phone_number = $3",
        [newFailCount >= 3 ? 0 : newFailCount, lockedUntil, phoneNumber]
      );

      console.log(`❌ Wrong credential for ${phoneNumber} (attempt ${newFailCount})`);
      return res.status(401).json({ error: "Invalid credential" });
    }

    // Valid — reset fail count
    await pool.query(
      "UPDATE devices SET fail_count = 0, locked_until = NULL WHERE phone_number = $1",
      [phoneNumber]
    );

    // Clear previous location reports
    await pool.query(
      "DELETE FROM location_reports WHERE phone_number = $1", [phoneNumber]
    );

    // Set pending command
    await pool.query(`
      INSERT INTO pending_commands (phone_number, has_command)
      VALUES ($1, TRUE)
      ON CONFLICT (phone_number) DO UPDATE SET has_command = TRUE, created_at = NOW()
    `, [phoneNumber]);

    console.log(`🚨 RECOVERY TRIGGERED for ${phoneNumber}`);
    return res.status(200).json({
      success: true,
      message: "Recovery command dispatched.",
    });
  } catch (err) {
    console.error("Recovery error:", err);
    return res.status(500).json({ error: "Recovery failed" });
  }
});

// ─────────────────────────────────────────────────────────
// GET /checkCommand
// ─────────────────────────────────────────────────────────
app.get("/checkCommand", async (req, res) => {
  const { phoneNumber } = req.query;
  if (!phoneNumber) return res.status(400).json({ error: "Phone number required" });

  try {
    const result = await pool.query(
      "SELECT has_command FROM pending_commands WHERE phone_number = $1", [phoneNumber]
    );

    const hasCommand = result.rows.length > 0 && result.rows[0].has_command;

    if (hasCommand) {
      await pool.query(
        "UPDATE pending_commands SET has_command = FALSE WHERE phone_number = $1",
        [phoneNumber]
      );
      console.log(`📲 Recovery command delivered to: ${phoneNumber}`);
    }

    return res.status(200).json({ hasCommand });
  } catch (err) {
    console.error("CheckCommand error:", err);
    return res.status(500).json({ error: "Command check failed" });
  }
});

// ─────────────────────────────────────────────────────────
// POST /locationReport
// ─────────────────────────────────────────────────────────
app.post("/locationReport", async (req, res) => {
  const { phoneNumber, latitude, longitude, accuracy, timestamp } = req.body;

  if (!phoneNumber || !latitude || !longitude) {
    return res.status(400).json({ error: "Missing location data" });
  }

  try {
    const deviceResult = await pool.query(
      "SELECT * FROM devices WHERE phone_number = $1", [phoneNumber]
    );

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({ error: "Device not found" });
    }

    await pool.query(`
      INSERT INTO location_reports (phone_number, latitude, longitude, accuracy, timestamp)
      VALUES ($1, $2, $3, $4, $5)
    `, [phoneNumber, latitude, longitude, accuracy, timestamp]);

    const mapsLink = `https://maps.google.com/?q=${latitude},${longitude}`;
    console.log(`📍 Location received for ${phoneNumber}: ${latitude}, ${longitude}`);
    console.log(`🗺️  Map link: ${mapsLink}`);

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("Location report error:", err);
    return res.status(500).json({ error: "Failed to process location" });
  }
});

// ─────────────────────────────────────────────────────────
// GET /relayLocation
// ─────────────────────────────────────────────────────────
app.get("/relayLocation", async (req, res) => {
  const { phone, lat, lng } = req.query;

  if (!phone || !lat || !lng) {
    return res.status(400).send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:40px;">
        <h2>❌ Invalid link</h2>
        <p>Missing required information.</p>
      </body></html>
    `);
  }

  try {
    await pool.query(`
      INSERT INTO location_reports (phone_number, latitude, longitude, accuracy, timestamp, source)
      VALUES ($1, $2, $3, NULL, $4, 'sms-fallback-relay')
    `, [phone, parseFloat(lat), parseFloat(lng), new Date().toISOString()]);

    console.log(`📨 Location relayed via SMS fallback for ${phone}: ${lat}, ${lng}`);

    return res.send(`
      <html>
      <body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a1628;color:white;">
        <h2>✅ Location shared with owner</h2>
        <p>The device owner can now see this location on their recovery portal.</p>
        <p style="color:#8899aa;">Lat: ${lat}, Lng: ${lng}</p>
        <p style="margin-top:30px;color:#e8a020;font-size:14px;">You can close this page now.</p>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("Relay error:", err);
    return res.status(500).send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:40px;">
        <h2>❌ Error storing location</h2>
      </body></html>
    `);
  }
});

// ─────────────────────────────────────────────────────────
// GET /status
// ─────────────────────────────────────────────────────────
app.get("/status", async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  const { phoneNumber } = req.query;

  if (!phoneNumber) {
    return res.status(400).json({ error: "Phone number required" });
  }

  try {
    const result = await pool.query(`
      SELECT * FROM location_reports
      WHERE phone_number = $1
      ORDER BY received_at DESC
      LIMIT 1
    `, [phoneNumber]);

    if (result.rows.length === 0) {
      return res.status(200).json({ status: "PENDING", location: null });
    }

    const latest = result.rows[0];
    return res.status(200).json({
      status: "LOCATION_RECEIVED",
      location: {
        latitude: latest.latitude,
        longitude: latest.longitude,
        accuracy: latest.accuracy,
        timestamp: latest.timestamp,
      },
    });
  } catch (err) {
    console.error("Status error:", err);
    return res.status(500).json({ error: "Status check failed" });
  }
});

// ─────────────────────────────────────────────────────────
// GET /devices
// ─────────────────────────────────────────────────────────
app.get("/devices", async (req, res) => {
  try {
    const result = await pool.query("SELECT phone_number FROM devices");
    return res.status(200).json({ devices: result.rows.map(r => r.phone_number) });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch devices" });
  }
});

// ─────────────────────────────────────────────────────────
// Start server
// ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("===========================================");
  console.log("  CORVON Backend Server — PostgreSQL MODE");
  console.log("===========================================");
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`\n📋 Available endpoints:`);
  console.log(`   POST /register`);
  console.log(`   POST /recover`);
  console.log(`   GET  /checkCommand?phoneNumber=xxx`);
  console.log(`   POST /locationReport`);
  console.log(`   GET  /relayLocation?phone=xxx&lat=xxx&lng=xxx`);
  console.log(`   GET  /status?phoneNumber=xxx`);
  console.log(`\n⏳ Waiting for connections...`);
});
