require("dotenv").config(); 
const express = require("express");
const cors = require("cors");
const bs58 = require("bs58");
const nacl = require("tweetnacl"); 

const app = express();
app.use(cors());
app.use(express.json());
//const uri = 'mongodb+srv://potsuonsolana:eRiDS8E5YlNYXDIl@potsumetaverse.ggqxjlx.mongodb.net/?retryWrites=true&w=majority&appName=PotsuMetaverse';
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://potsuonsolana:eRiDS8E5YlNYXDIl@potsumetaverse.ggqxjlx.mongodb.net/?retryWrites=true&w=majority&appName=PotsuMetaverse";
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);


// Verify signature and save user info
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

    // Store flexible data (items, base, etc.) from Unity
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

// Save items
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

// Load items
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

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Wallet verifier running on port ${PORT}`)
);
