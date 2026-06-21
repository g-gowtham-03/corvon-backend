const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

// ─────────────────────────────────────────────────────────
// POST /register
// Called by Android app during first-time setup
// Body: { phoneNumber, emergencyContact, credentialHash, fcmToken }
// ─────────────────────────────────────────────────────────
exports.register = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const { phoneNumber, emergencyContact, credentialHash, fcmToken } = req.body;

  if (!phoneNumber || !emergencyContact || !credentialHash || !fcmToken) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    await db.collection("devices").doc(phoneNumber).set({
      phoneNumber,
      emergencyContact,
      credentialHash,   // SHA-256(credential + salt) — computed on device
      fcmToken,
      registeredAt: admin.firestore.FieldValue.serverTimestamp(),
      attemptCount: 0,
      lockedUntil: null,
    });

    return res.status(200).json({ success: true, message: "Device registered" });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ error: "Registration failed" });
  }
});

// ─────────────────────────────────────────────────────────
// POST /updateToken
// Called when FCM token refreshes on device
// Body: { phoneNumber, fcmToken }
// ─────────────────────────────────────────────────────────
exports.updateToken = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const { phoneNumber, fcmToken } = req.body;
  if (!phoneNumber || !fcmToken) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    await db.collection("devices").doc(phoneNumber).update({ fcmToken });
    return res.status(200).json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Token update failed" });
  }
});

// ─────────────────────────────────────────────────────────
// POST /recover
// Called by Recovery Portal when owner submits credential
// Body: { phoneNumber, credential }
// ─────────────────────────────────────────────────────────
exports.recover = functions.https.onRequest(async (req, res) => {
  // Allow CORS from portal
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).send("");
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const { phoneNumber, credential } = req.body;

  if (!phoneNumber || !credential) {
    return res.status(400).json({ error: "Phone number and credential required" });
  }

  try {
    const docRef = db.collection("devices").doc(phoneNumber);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "Device not registered" });
    }

    const device = doc.data();

    // ── Lockout check ──────────────────────────────────
    if (device.lockedUntil && device.lockedUntil.toDate() > new Date()) {
      const remaining = Math.ceil(
        (device.lockedUntil.toDate() - new Date()) / 60000
      );
      return res.status(429).json({
        error: `Account locked. Try again in ${remaining} minute(s).`,
      });
    }

    // ── Rate limit: max 5 attempts per hour ────────────
    const now = new Date();
    const oneHourAgo = new Date(now - 3600000);
    const recentAttempts = (device.recentAttempts || []).filter(
      (t) => t.toDate() > oneHourAgo
    );
    if (recentAttempts.length >= 5) {
      return res.status(429).json({
        error: "Too many attempts. Please wait before trying again.",
      });
    }

    // ── Credential validation ──────────────────────────
    // Hash the submitted credential with the stored salt (phone number as salt for demo)
    const submittedHash = crypto
      .createHash("sha256")
      .update(credential + phoneNumber)
      .digest("hex");

    const isValid = submittedHash === device.credentialHash;

    // Log the attempt
    const attemptRecord = {
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      success: isValid,
      requestedAt: now.toISOString(),
    };

    if (!isValid) {
      const newFailCount = (device.failCount || 0) + 1;
      const updateData = {
        failCount: newFailCount,
        recentAttempts: [
          ...(device.recentAttempts || []).slice(-9),
          admin.firestore.Timestamp.now(),
        ],
      };

      // Lock after 3 consecutive failures for 24 hours
      if (newFailCount >= 3) {
        updateData.lockedUntil = admin.firestore.Timestamp.fromDate(
          new Date(now.getTime() + 24 * 60 * 60 * 1000)
        );
        updateData.failCount = 0;
        // Notify emergency contact of lockout
        await notifyEmergencyContact(
          device.emergencyContact,
          phoneNumber,
          "LOCKOUT",
          null
        );
      }

      await docRef.update(updateData);
      return res.status(401).json({ error: "Invalid credential" });
    }

    // ── Valid credential — dispatch recovery command ───
    await docRef.update({
      failCount: 0,
      recentAttempts: [],
      lastRecoveryAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Build signed recovery command
    const recoveryCommand = {
      type: "EMERGENCY_RECOVERY",
      phoneNumber,
      credentialHash: device.credentialHash,
      issuedAt: now.toISOString(),
      signature: crypto
        .createHash("sha256")
        .update(device.credentialHash + now.toISOString())
        .digest("hex"),
    };

    // Dispatch via FCM (Channel 1)
    const message = {
      token: device.fcmToken,
      data: {
        type: "EMERGENCY_RECOVERY",
        payload: JSON.stringify(recoveryCommand),
      },
      android: {
        priority: "high",
        ttl: 3600000, // 1 hour TTL for queue fallback
      },
    };

    await admin.messaging().send(message);

    // Store in queue for polling fallback (Channel 2)
    await db.collection("recoveryQueue").add({
      phoneNumber,
      command: recoveryCommand,
      deliveredAt: admin.firestore.FieldValue.serverTimestamp(),
      consumed: false,
    });

    return res.status(200).json({
      success: true,
      message: "Recovery command dispatched. Location will be sent to your emergency contact.",
    });
  } catch (err) {
    console.error("Recovery error:", err);
    return res.status(500).json({ error: "Recovery dispatch failed" });
  }
});

// ─────────────────────────────────────────────────────────
// POST /locationReport
// Called by Android app when location is obtained
// Body: { phoneNumber, latitude, longitude, accuracy, timestamp }
// ─────────────────────────────────────────────────────────
exports.locationReport = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const { phoneNumber, latitude, longitude, accuracy, timestamp } = req.body;

  if (!phoneNumber || !latitude || !longitude) {
    return res.status(400).json({ error: "Missing location data" });
  }

  try {
    const doc = await db.collection("devices").doc(phoneNumber).get();
    if (!doc.exists) return res.status(404).json({ error: "Device not found" });

    const device = doc.data();

    // Store location report
    await db.collection("locationReports").add({
      phoneNumber,
      latitude,
      longitude,
      accuracy,
      timestamp,
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Notify emergency contact
    await notifyEmergencyContact(
      device.emergencyContact,
      phoneNumber,
      "LOCATION",
      { latitude, longitude }
    );

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("Location report error:", err);
    return res.status(500).json({ error: "Failed to process location" });
  }
});

// ─────────────────────────────────────────────────────────
// GET /status?phoneNumber=xxx
// Polled by Recovery Portal to show real-time status
// ─────────────────────────────────────────────────────────
exports.status = functions.https.onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  if (req.method !== "GET") return res.status(405).send("Method Not Allowed");

  const { phoneNumber } = req.query;
  if (!phoneNumber) return res.status(400).json({ error: "Phone number required" });

  try {
    const snapshot = await db
      .collection("locationReports")
      .where("phoneNumber", "==", phoneNumber)
      .orderBy("receivedAt", "desc")
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(200).json({ status: "PENDING", location: null });
    }

    const latest = snapshot.docs[0].data();
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
    return res.status(500).json({ error: "Status check failed" });
  }
});

// ─────────────────────────────────────────────────────────
// Helper: notify emergency contact (logs for demo — real
// implementation would use Twilio SMS or Firebase Extensions)
// ─────────────────────────────────────────────────────────
async function notifyEmergencyContact(contactNumber, ownerNumber, type, location) {
  const logEntry = {
    contactNumber,
    ownerNumber,
    type,
    location,
    sentAt: admin.firestore.FieldValue.serverTimestamp(),
  };

  if (type === "LOCATION" && location) {
    logEntry.mapLink = `https://maps.google.com/?q=${location.latitude},${location.longitude}`;
    logEntry.message = `CORVON ALERT: Device belonging to ${ownerNumber} has been located. View location: ${logEntry.mapLink}`;
  } else if (type === "LOCKOUT") {
    logEntry.message = `CORVON ALERT: Multiple failed recovery attempts on device ${ownerNumber}. Account temporarily locked.`;
  }

  // In production: call Twilio API or similar to send SMS
  // For demo: log to Firestore and show in portal
  await db.collection("notifications").add(logEntry);
  console.log("Notification queued:", logEntry.message);
}
