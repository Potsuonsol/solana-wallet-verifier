const express = require("express");
const cors = require("cors");
const bs58 = require("bs58");
const nacl = require("tweetnacl");

const app = express();
app.use(cors());
app.use(express.json());

app.post("/verify", (req, res) => {
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
            return res.json({ success: true, userId: publicKey });
        } else {
            return res.status(401).json({ success: false, error: "Invalid signature" });
        }
    } catch (e) {
        res.status(500).json({ error: "Verification failed", details: e.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Wallet verifier running on port ${PORT}`));
