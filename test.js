//part 1: making DiffieHellman keys
const assert = require('node:assert');

const {
  createDiffieHellman,
} = require('node:crypto');

// Generate Alice's keys... I chose to do a 256 sized key because that's the size needed for aes 256 enc. 
// BUT, if you want to create a large key then sha 256 it, that would work as well.
const alice = createDiffieHellman(256);
const aliceKey = alice.generateKeys();

// Generate Bob's keys...
const bob = createDiffieHellman(alice.getPrime(), alice.getGenerator());
const bobKey = bob.generateKeys();

// Exchange and generate the secret...
const aliceSecret = alice.computeSecret(bobKey);
const bobSecret = bob.computeSecret(aliceKey);

// OK, this shows that they are the same key! congrats, we did it
assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));


// Part 2: using the key to encrypt something.
const crypto = require("crypto");

const algorithm = "aes-256-cbc"; 

// generate 16 bytes of random data
const initVector = crypto.randomBytes(16);

// protected data
const message = "testing attention please";

//This is the information I copied over to the other scripts to create the same encrypted string
console.log("initVector: " + initVector.toString('hex'))
console.log("secret in hex: " + aliceSecret.toString('hex'));

// the cipher function
const cipher = crypto.createCipheriv(algorithm, aliceSecret, initVector);

// encrypt the message
// input encoding
// output encoding
let encryptedData = cipher.update(message, "utf-8", "hex");
encryptedData += cipher.final("hex");
console.log("Encrypted message: " + encryptedData);


//Part 3: Decrypting that message
const decipher = crypto.createDecipheriv(algorithm, aliceSecret, initVector);

let decryptedData = decipher.update(encryptedData, "hex", "utf-8");

decryptedData += decipher.final("utf8");

console.log("Decrypted message: " + decryptedData);