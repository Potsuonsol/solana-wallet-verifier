require("dotenv").config();
const { MongoClient } = require("mongodb");
const express = require("express");
const cors = require("cors");
const bs58 = require("bs58");
const nacl = require("tweetnacl");

const app = express();
app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function main() {
  await client.connect();
  console.log("✅ Connected to MongoDB");

  const db = client.db("potsu_db"); // you can name this anything
  const users = db.collection("verified_users"); // or 'accounts', 'players', etc.

  app.post("/verify", async (req, res) => {
    const { publicKey, message, signature } = req.body;

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

      if (isValid) {
        console.log("✅ Signature verified for:", publicKey);

        // Store user in MongoDB
        await users.updateOne(
          { publicKey: publicKey },
          {
            $set: {
              publicKey: publicKey,
              lastVerified: new Date(),
              message,
            },
          },
          { upsert: true }
        );

        res.json({ verified: true });
      } else {
        console.warn("❌ Invalid signature from:", publicKey);
        res.json({ verified: false });
      }
    } catch (e) {
      console.error("❌ Verification error:", e);
      res.status(500).json({ error: "Verification failed", details: e.message });
    }
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () =>
    console.log(`✅ Wallet verifier running on port ${PORT}`)
  );
}

main().catch(console.error);
