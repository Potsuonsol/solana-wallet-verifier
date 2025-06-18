require("dotenv").config();

// 2. Import necessary modules
const express = require("express");
const cors = require("cors");
const bs58 = require("bs58"); // Will be used for Solana data
const nacl = require("tweetnacl"); // Will be used for signature verification
const { MongoClient, ServerApiVersion } = require("mongodb"); // Import ServerApiVersion for new clients

// 3. Initialize Express app
const app = express();
app.use(cors()); // Enable CORS for all origins (adjust for production)
app.use(express.json()); // Enable parsing of JSON request bodies

// 4. MongoDB setup
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI is not defined in the .env file!");
  process.exit(1); // Exit the process if essential config is missing
}

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db; // Use a more descriptive name for the collection variable

// 5. Connect to MongoDB and set up the collection
async function connectToMongo() {
  try {
    await client.connect();
    db = client.db("Potsu"); // Connect to your specific database 
    console.log("✅ Connected to MongoDB");

    // Optional: Create an index if needed for better performance, e.g., on publicKey
    // This is good practice if you'll be querying by publicKey often
    // await usersCollection.createIndex({ publicKey: 1 }, { unique: true });
    // console.log("✅ Index on publicKey created.");

  } catch (err) {
    console.error("❌ Failed to connect to MongoDB:", err);
    // In a production app, you might want more sophisticated error handling
    // like retrying connection or logging to a monitoring system.
    process.exit(1); // Exit if database connection fails at startup
  }
}

// Call the connection function
connectToMongo();

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
