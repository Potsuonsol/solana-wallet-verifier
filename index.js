require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bs58 = require("bs58");
const nacl = require("tweetnacl");
const admin = require("firebase-admin");

const app = express();
app.use(cors());
app.use(express.json());
 

const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const users = db.collection("users");


// ✅ Verify signature and save user info
app.post("/verify", async (req, res) => {
  const { publicKey, message, signature, data } = req.body;

  if (!publicKey || !message || !signature) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = bs58.decode(signature);
    const publicKeyBytes = bs58.decode(publicKey);

    const isValid = nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      publicKeyBytes
    );

    if (!isValid) {
      console.warn("❌ Invalid signature from:", publicKey);
      return res.json({ verified: false });
    }

    console.log("✅ Signature verified for:", publicKey);

    await users.doc(publicKey).set(
      {
        publicKey,
        message,
        lastVerified: new Date().toISOString(),
        ...(data || {})
      },
      { merge: true }
    );

    res.json({ verified: true });
  } catch (e) {
    console.error("❌ Verification error:", e);
    res.status(500).json({ error: "Verification failed", details: e.message });
  }
});

// ✅ Save items
app.post("/save", async (req, res) => {
  const { publicKey, items } = req.body;

  if (!publicKey || !items) {
    return res.status(400).json({ error: "Missing publicKey or items" });
  }

  try {
    await users.doc(publicKey).set(
      {
        items,
        lastUpdated: new Date().toISOString()
      },
      { merge: true }
    );
    res.json({ success: true });
  } catch (e) {
    console.error("❌ Save error:", e);
    res.status(500).json({ error: "Save failed", details: e.message });
  }
});

// ✅ Load items
app.post("/load", async (req, res) => {
  const { publicKey } = req.body;

  if (!publicKey) {
    return res.status(400).json({ error: "Missing publicKey" });
  }

  try {
    const doc = await users.doc(publicKey).get();
    if (!doc.exists) {
      return res.json({ items: [] });
    }
    const user = doc.data();
    res.json({
      publicKey: user.publicKey,
      items: user.items || []
    });
  } catch (e) {
    console.error("❌ Load error:", e);
    res.status(500).json({ error: "Load failed", details: e.message });
  }
});

// ✅ Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Wallet verifier running on port ${PORT}`)
);
