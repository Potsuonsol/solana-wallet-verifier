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
  const { publicKey, ...data } = req.body;

  if (!publicKey) {
    return res.status(400).json({ error: "Missing publicKey" });
  }

  try {
    await users.doc(publicKey).set(
      {
        ...data,
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

app.post("/save-item", async (req, res) => {
  const { publicKey, item } = req.body;

  if (!publicKey || !item || !item.objectId) {
    return res.status(400).json({ error: "Missing publicKey or item.objectId" });
  }

  try {
    const userRef = users.doc(publicKey);
    const doc = await userRef.get();

    let updatedItems = [];

    if (doc.exists) {
      const data = doc.data();
      updatedItems = data.items || [];

      const existingIndex = updatedItems.findIndex(i => i.objectId === item.objectId);
      if (existingIndex !== -1) {
        updatedItems[existingIndex] = item;
      } else {
        updatedItems.push(item);
      }
    } else {
      updatedItems.push(item);
    }

    await userRef.set({ items: updatedItems }, { merge: true });

    res.json({ success: true });
  } catch (e) {
    console.error("❌ Save item error:", e);
    res.status(500).json({ error: "Save item failed", details: e.message });
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
      return res.json({}); // Return empty payload
    }

    res.json(doc.data()); // Return all saved fields
  } catch (e) {
    console.error("❌ Load error:", e);
    res.status(500).json({ error: "Load failed", details: e.message });
  }
});

app.post("/delete", async (req, res) => {
  const { publicKey, objectId } = req.body;

  if (!publicKey || !objectId) {
    return res.status(400).json({ error: "Missing publicKey or objectId" });
  }

  try {
    const userRef = users.doc(publicKey);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    const userData = doc.data();
    const existingItems = userData.items || [];

    const updatedItems = existingItems.filter(item => item.objectId !== objectId);

    await userRef.update({ items: updatedItems });

    res.json({ success: true });
  } catch (e) {
    console.error("❌ Delete item error:", e);
    res.status(500).json({ error: "Delete item failed", details: e.message });
  }
});


// Node.js Express route
app.get("/users", async (req, res) => {
    const usersSnapshot = await db.collection("users").get();
    const addresses = usersSnapshot.docs.map(doc => doc.id); // assuming publicKey is doc ID
    res.json(addresses);
});

// ✅ Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Wallet verifier running on port ${PORT}`)
);
