const assert = require('node:assert');

const {
  createDiffieHellman,
} = require('node:crypto');

// Generate Alice's keys...
const alice = createDiffieHellman(256);
const aliceKey = alice.generateKeys();

// Generate Bob's keys...
const bob = createDiffieHellman(alice.getPrime(), alice.getGenerator());
const bobKey = bob.generateKeys();

// Exchange and generate the secret...
const aliceSecret = alice.computeSecret(bobKey);
const bobSecret = bob.computeSecret(aliceKey);

// OK
assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));

const crypto = require("crypto");

const algorithm = "aes-256-cbc"; 

// generate 16 bytes of random data
const initVector = crypto.randomBytes(16);

// protected data
const message = "This is a secret message";

console.log(aliceSecret.toString('hex').length);
console.log(aliceSecret.byteLength);




// the cipher function
const cipher = crypto.createCipheriv(algorithm, aliceSecret, initVector);

// encrypt the message
// input encoding
// output encoding
let encryptedData = cipher.update(message, "utf-8", "hex");
encryptedData += cipher.final("hex");
console.log("Encrypted message: " + encryptedData);

const decipher = crypto.createDecipheriv(algorithm, aliceSecret, initVector);

let decryptedData = decipher.update(encryptedData, "hex", "utf-8");

decryptedData += decipher.final("utf8");

console.log("Decrypted message: " + decryptedData);