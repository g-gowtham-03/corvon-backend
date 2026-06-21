const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// ── In-memory storage ──
const devices = {};
const locationReports = {};
const notifications = [];
const pendingCommands = {};  // NEW: tracks pending recovery commands

// ─────────────────────────────────────────────────────────
// POST /register
// ─────────────────────────────────────────────────────────
app.post("/register", (req, res) => {
  const { phoneNumber, emergencyContact, credentialHash, fcmToken } = req.body;

  if (!phoneNumber || !emergencyContact || !credentialHash) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  devices[phoneNumber] = {
    phoneNumber,
    emergencyContact,
    credentialHash,
    fcmToken: fcmToken || "",
    registeredAt: new Date().toISOString(),
    failCount: 0,
    lockedUntil: null,
  };

  console.log(`✅ Device registered: ${phoneNumber}`);
  return res.status(200).json({ success: true, message: "Device registered" });
});

// ─────────────────────────────────────────────────────────
// POST /recover
// ─────────────────────────────────────────────────────────
app.post("/recover", (req, res) => {
  const { phoneNumber, credential } = req.body;

  if (!phoneNumber || !credential) {
    return res.status(400).json({ error: "Phone number and credential required" });
  }

  const device = devices[phoneNumber];
  if (!device) {
    return res.status(404).json({ error: "Device not registered" });
  }

  // Lockout check
  if (device.lockedUntil && new Date(device.lockedUntil) > new Date()) {
    const remaining = Math.ceil((new Date(device.lockedUntil) - new Date()) / 60000);
    return res.status(429).json({
      error: `Account locked. Try again in ${remaining} minute(s).`,
    });
  }

  // Validate credential
  const submittedHash = crypto
    .createHash("sha256")
    .update(credential + phoneNumber)
    .digest("hex");

  if (submittedHash !== device.credentialHash) {
    device.failCount = (device.failCount || 0) + 1;
    console.log(`❌ Wrong credential for ${phoneNumber} (attempt ${device.failCount})`);

    if (device.failCount >= 3) {
      device.lockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      device.failCount = 0;
      console.log(`🔒 Account locked: ${phoneNumber}`);
    }

    return res.status(401).json({ error: "Invalid credential" });
  }

  // Valid
  device.failCount = 0;
  device.lockedUntil = null;

  console.log(`🚨 RECOVERY TRIGGERED for ${phoneNumber}`);
  console.log(`📡 Sending recovery command to device...`);

  // Clear previous location and set pending command
  locationReports[phoneNumber] = null;
  pendingCommands[phoneNumber] = true;  // NEW

  return res.status(200).json({
    success: true,
    message: "Recovery command dispatched.",
  });
});

// ─────────────────────────────────────────────────────────
// GET /checkCommand  (NEW — polled by Android app)
// ─────────────────────────────────────────────────────────
app.get("/checkCommand", (req, res) => {
  const { phoneNumber } = req.query;
  if (!phoneNumber) return res.status(400).json({ error: "Phone number required" });

  const hasCommand = pendingCommands[phoneNumber] === true;
  if (hasCommand) {
    pendingCommands[phoneNumber] = false;
    console.log(`📲 Recovery command delivered to: ${phoneNumber}`);
  }
  return res.status(200).json({ hasCommand });
});

// ─────────────────────────────────────────────────────────
// POST /locationReport
// ─────────────────────────────────────────────────────────
app.post("/locationReport", (req, res) => {
  const { phoneNumber, latitude, longitude, accuracy, timestamp } = req.body;

  if (!phoneNumber || !latitude || !longitude) {
    return res.status(400).json({ error: "Missing location data" });
  }

  const device = devices[phoneNumber];
  if (!device) {
    return res.status(404).json({ error: "Device not found" });
  }

  locationReports[phoneNumber] = {
    latitude,
    longitude,
    accuracy,
    timestamp,
    receivedAt: new Date().toISOString(),
  };

  const mapsLink = `https://maps.google.com/?q=${latitude},${longitude}`;

  const notification = {
    to: device.emergencyContact,
    message: `CORVON ALERT: Device located! View location: ${mapsLink}`,
    sentAt: new Date().toISOString(),
  };
  notifications.push(notification);

  console.log(`📍 Location received for ${phoneNumber}: ${latitude}, ${longitude}`);
  console.log(`📱 SMS to ${device.emergencyContact}: ${notification.message}`);
  console.log(`🗺️  Map link: ${mapsLink}`);

  return res.status(200).json({ success: true });
});

// ─────────────────────────────────────────────────────────
// GET /relayLocation  (SMS FALLBACK — called when emergency
// contact taps the link inside the fallback SMS, since the
// lost phone had no internet to report directly)
// ─────────────────────────────────────────────────────────
app.get("/relayLocation", (req, res) => {
  const { phone, lat, lng } = req.query;

  if (!phone || !lat || !lng) {
    return res.status(400).send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:40px;">
        <h2>❌ Invalid link</h2>
        <p>Missing required information.</p>
      </body></html>
    `);
  }

  const device = devices[phone];
  if (!device) {
    return res.status(404).send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:40px;">
        <h2>❌ Device not found</h2>
      </body></html>
    `);
  }

  locationReports[phone] = {
    latitude: parseFloat(lat),
    longitude: parseFloat(lng),
    accuracy: null,
    timestamp: new Date().toISOString(),
    receivedAt: new Date().toISOString(),
    source: "sms-fallback-relay",
  };

  console.log(`📨 Location relayed via SMS fallback for ${phone}: ${lat}, ${lng}`);

  return res.send(`
    <html>
    <body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a1628;color:white;">
      <h2>✅ Location shared with owner</h2>
      <p>The device owner can now see this location on their recovery portal.</p>
      <p style="color:#8899aa;">Lat: ${lat}, Lng: ${lng}</p>
    </body>
    </html>
  `);
});

// ─────────────────────────────────────────────────────────
// GET /status
// ─────────────────────────────────────────────────────────
app.get("/status", (req, res) => {
  const { phoneNumber } = req.query;

  if (!phoneNumber) {
    return res.status(400).json({ error: "Phone number required" });
  }

  const location = locationReports[phoneNumber];

  if (!location) {
    return res.status(200).json({ status: "PENDING", location: null });
  }

  return res.status(200).json({
    status: "LOCATION_RECEIVED",
    location,
  });
});

// ─────────────────────────────────────────────────────────
// GET /devices
// ─────────────────────────────────────────────────────────
app.get("/devices", (req, res) => {
  return res.status(200).json({ devices: Object.keys(devices) });
});

// ─────────────────────────────────────────────────────────
// Start server
// ─────────────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("===========================================");
  console.log("  CORVON Backend Server — LOCAL MODE");
  console.log("===========================================");
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`✅ Also accessible on your local network`);
  console.log(`\n📋 Available endpoints:`);
  console.log(`   POST http://localhost:${PORT}/register`);
  console.log(`   POST http://localhost:${PORT}/recover`);
  console.log(`   GET  http://localhost:${PORT}/checkCommand?phoneNumber=xxx`);
  console.log(`   POST http://localhost:${PORT}/locationReport`);
  console.log(`   GET  http://localhost:${PORT}/status?phoneNumber=xxx`);
  console.log(`\n⏳ Waiting for connections...`);
});
