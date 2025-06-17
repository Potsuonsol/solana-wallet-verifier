require("dotenv").config();
const { MongoClient } = require("mongodb");
const express = require("express");
const cors = require("cors");
const bs58 = require("bs58");
const nacl = require("tweetnacl");

// MongoDB connection
const client = new MongoClient(process.env.MONGODB_URI);
let db, users;

client.connect().then(() => {
  db = client.db("potsu_metaverse"); // You can name this whatever you want
  users = db.collection("verified_users");
  console.log("✅ Connected to MongoDB");
});

const app = express();
app.use(cors());
app.use(express.json());

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

    if (!isValid) {
      console.warn("❌ Invalid signature from:", publicKey);
      return res.json({ verified: false });
    }

    console.log("✅ Signature verified for:", publicKey);

    // Create or update the user in MongoDB
    const result = await users.updateOne(
      { publicKey },
      {
        $setOnInsert: {
          items: [],
          base: {},
        },
        $set: {
          publicKey,
          lastVerified: new Date(),
          message,
        },
      },
      { upsert: true }
    );

    res.json({ verified: true });
  } catch (e) {
    console.error("❌ Verification error:", e);
    res.status(500).json({ error: "Verification failed", details: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Wallet verifier running on port ${PORT}`)
);
