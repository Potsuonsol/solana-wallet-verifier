# Solana Wallet Verifier

Simple Node.js API to verify Solana wallet signatures.

## POST /verify

**Body:**
```json
{
  "publicKey": "base58string",
  "message": "string",
  "signature": "base58string"
}
