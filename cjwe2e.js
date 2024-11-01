var forge = require('node-forge');

var rsa = forge.pki.rsa;
let rsaKeyPair = null


export function generateKeyPair() {
    rsaKeyPair = rsa.generateKeyPair({bits: 2048, e: 0x10001});
    // rsa.generateKeyPair({ bits: 2048, workers: 2 }, function (err, keypair) {
    //     // keypair.privateKey, keypair.publicKey
    //     rsaKeyPair = keypair

    //     console.log("Private key: ", keypair.privateKey)
    //     var nHex = keypair.publicKey.n.toString(16);

    //     console.log("Public key: ", nHex)
    //     let utf8Encode = new TextEncoder()
    //     console.log("Public key Len: ", utf8Encode.encode(nHex).length)

    // });
}

export function rsaEncrypt(plainData) {
    // encrypt data with a public key using RSAES-OAEP/SHA-256
    var encrypted = rsaKeyPair.publicKey.encrypt(plainData, 'RSA-OAEP', {
        md: forge.md.sha512.create(),
        mgf1: {
            md: forge.md.sha1.create()
        }
    });
    return encrypted

}

export function getPublicKey() {
    // encrypt data with a public key using RSAES-OAEP/SHA-256
    var nHex = rsaKeyPair.publicKey.n.toString(16);
    return nHex

}


export function rsaDecrypt(encryptedTxt) {
    // decrypt data with a private key using RSAES-OAEP/SHA-256/MGF1-SHA-1
    // compatible with Java's RSA/ECB/OAEPWithSHA-256AndMGF1Padding
    var decrypted = rsaKeyPair.privateKey.decrypt(encryptedTxt, 'RSA-OAEP', {
        md: forge.md.sha512.create(),
        mgf1: {
            md: forge.md.sha1.create()
        }
    });
    return decrypted;
}




