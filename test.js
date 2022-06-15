const crypto = require("crypto");

// // The `generateKeyPairSync` method accepts two arguments:
// // 1. The type ok keys we want, which in this case is "rsa"
// // 2. An object with the properties of the key
// const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
//   // The standard secure default length for RSA keys is 2048 bits
//   modulusLength: 2048,
// });
// // This is the data we want to encrypt
// const data = "my secret data";

// const encryptedData = crypto.publicEncrypt(
//   {
//     key: publicKey,
//     padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
//     oaepHash: "sha256",
//   },
//   // We convert the data string to a buffer using `Buffer.from`
//   Buffer.from(data)
// );

// // The encrypted data is in the form of bytes, so we print it in base64 format
// // so that it's displayed in a more readable form
// console.log("encypted data: ", encryptedData.toString("base64"));

const fs = require('fs');
privateKey = fs.readFileSync('/Users/ian/Desktop/keys/privateKey.pem', {encoding:'utf8'})

let encryptedData = fs.readFileSync('/Users/ian/Desktop/encrypted_data', null)

console.log(privateKey)

// console.log(fr.readAsBinaryString("/Users/ian/Desktop/keys/publicKey.pem"));


const decryptedData = crypto.privateDecrypt(
    {
      key: privateKey,
      // In order to decrypt the data, we need to specify the
      // same hashing function and padding scheme that we used to
      // encrypt the data in the previous step
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      // padding: crypto.constants.RSA_PKCS1_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encryptedData, 'base64')
  );
  
  // The decrypted data is of the Buffer type, which we can convert to a
  // string to reveal the original data
  console.log("decrypted data: ", decryptedData.toString());