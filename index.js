require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bs58 = require("bs58");
const nacl = require("tweetnacl");
const { MongoClient } = require("mongodb");

const app = express();
app.use(cors());
app.use(express.json());

const client = new MongoClient(process.env.MONGODB_URI);

// Start everything after DB is connected
async function startServer() {
  try {
    await client.connect();
    const db = client.db("Potsu");
    const users = db.collection("verified_users");
    console.log("✅ Connected to MongoDB");

    // Routes
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

        await users.updateOne(
          { publicKey },
          {
            $set: {
              publicKey,
              message,
              lastVerified: new Date(),
              ...(data || {})
            }
          },
          { upsert: true }
        );

        res.json({ verified: true });
      } catch (e) {
        console.error("❌ Verification error:", e);
        res.status(500).json({ error: "Verification failed", details: e.message });
      }
    });

    app.post("/save", async (req, res) => {
      const { publicKey, items } = req.body;

      if (!publicKey || !items) {
        return res.status(400).json({ error: "Missing publicKey or items" });
      }

      try {
        await users.updateOne(
          { publicKey },
          {
            $set: {
              items,
              lastUpdated: new Date()
            }
          },
          { upsert: true }
        );
        res.json({ success: true });
      } catch (e) {
        console.error("❌ Save error:", e);
        res.status(500).json({ error: "Save failed", details: e.message });
      }
    });

    app.post("/load", async (req, res) => {
      const { publicKey } = req.body;

      if (!publicKey) {
        return res.status(400).json({ error: "Missing publicKey" });
      }

      try {
        const user = await users.findOne({ publicKey });
        if (!user) {
          return res.json({ items: [] }); // No data yet
        }
        res.json({
          publicKey: user.publicKey,
          items: user.items || []
        });
      } catch (e) {
        console.error("❌ Load error:", e);
        res.status(500).json({ error: "Load failed", details: e.message });
      }
    });

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`✅ Wallet verifier running on port ${PORT}`);
    });

  } catch (err) {
    console.error("❌ Failed to connect to MongoDB:", err);
    process.exit(1); // Stop server if DB doesn't connect
  }
}

startServer();
