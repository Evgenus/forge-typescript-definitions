/// <reference path="./forge.d.ts" />

function testAES(someBytes: string) {
    // generate a random key and IV
    // Note: a key size of 16 bytes will use AES-128, 24 => AES-192, 32 => AES-256
    var key = forge.random.getBytesSync(16);
    var iv = forge.random.getBytesSync(16);

    /* alternatively, generate a password-based 16-byte key
    var salt = forge.random.getBytesSync(128);
    var key = forge.pkcs5.pbkdf2('password', salt, numIterations, 16);
    */

    // encrypt some bytes using CBC mode
    // (other modes include: CFB, OFB, CTR, and GCM)
    var cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(someBytes));
    cipher.finish();
    var encrypted = cipher.output;
    // outputs encrypted hex
    console.log(encrypted.toHex());

    // decrypt some bytes using CBC mode
    // (other modes include: CFB, OFB, CTR, and GCM)
    var decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({ iv: iv });
    decipher.update(encrypted);
    decipher.finish();
    // outputs decrypted hex
    console.log(decipher.output.toHex());

    // Encryption using byte buffer key
    var bbKey: forge.util.ByteBuffer;
    var cipher = forge.cipher.createCipher('AES-CBC', bbKey);
    var cipher = forge.cipher.createDecipher('AES-CBC', bbKey);

    // encrypt some bytes using GCM mode
    var cipher = forge.cipher.createCipher('AES-GCM', key);
    cipher.start({
        iv: iv, // should be a 12-byte binary-encoded string or byte buffer
        additionalData: 'binary-encoded string', // optional
        tagLength: 128 // optional, defaults to 128 bits
    });
    cipher.update(forge.util.createBuffer(someBytes));
    cipher.finish();
    var encrypted = cipher.output;
    var tag = (<forge.cipher.modes.GCM>cipher.mode).tag;
    // outputs encrypted hex
    console.log(encrypted.toHex());
    // outputs authentication tag
    console.log(tag.toHex());

    // decrypt some bytes using GCM mode
    var decipher = forge.cipher.createDecipher('AES-GCM', key);
    decipher.start({
        iv: iv,
        additionalData: 'binary-encoded string', // optional
        tagLength: 128, // optional, defaults to 128 bits
        tag: tag // authentication tag from encryption
    });
    decipher.update(encrypted);
    var pass = decipher.finish();
    // pass is false if there was a failure (eg: authentication tag didn't match)
    if (pass) {
        // outputs decrypted hex
        console.log(decipher.output.toHex());
    }
}

function testRC2(someBytes: string) {
    // generate a random key and IV
    var key = forge.random.getBytesSync(16);
    var iv = forge.random.getBytesSync(8);

    // encrypt some bytes
    var cipher = forge.rc2.createEncryptionCipher(key);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(someBytes));
    cipher.finish();
    var encrypted = cipher.output;
    // outputs encrypted hex
    console.log(encrypted.toHex());

    // decrypt some bytes
    var cipher = forge.rc2.createDecryptionCipher(key);
    cipher.start(iv);
    cipher.update(encrypted);
    cipher.finish();
    // outputs decrypted hex
    console.log(cipher.output.toHex());
}

function testRSA() {
    var rsa = forge.pki.rsa;

    // generate an RSA key pair synchronously
    var keypair = rsa.generateKeyPair({ bits: 2048, e: 0x10001 });

    // generate an RSA key pair asynchronously (uses web workers if available)
    // use workers: -1 to run a fast core estimator to optimize # of workers
    rsa.generateKeyPair({ bits: 2048, workers: 2 }, function (err, keypair) {
        // keypair.privateKey, keypair.publicKey
    });

    // generate an RSA key pair in steps that attempt to run for a specified period
    // of time on the main JS thread
    var state = rsa.createKeyPairGenerationState(2048, 0x10001);
    var step = function () {
        // run for 100 ms
        if (!rsa.stepKeyPairGenerationState(state, 100)) {
            setTimeout(step, 1);
        }
        else {
            // done, turn off progress indicator, use state.keys
        }
    };
    // turn on progress indicator, schedule generation to run
    setTimeout(step);

    var privateKey = keypair.privateKey;
    var publicKey = keypair.publicKey;

    // sign data with a private key and output DigestInfo DER-encoded bytes
    // (defaults to RSASSA PKCS#1 v1.5)
    var md = forge.md.sha1.create();
    md.update('sign this', 'utf8');
    var signature = privateKey.sign(md);

    // verify data with a public key
    // (defaults to RSASSA PKCS#1 v1.5)
    var verified = publicKey.verify(md.digest().bytes(), signature);

    // sign data using RSASSA-PSS where PSS uses a SHA-1 hash, a SHA-1 based
    // masking function MGF1, and a 20 byte salt
    var md = forge.md.sha1.create();
    md.update('sign this', 'utf8');
    var pss = forge.pss.create({
        md: forge.md.sha1.create(),
        mgf: forge.mgf.mgf1.create(forge.md.sha1.create()),
        saltLength: 20
        // optionally pass 'prng' with a custom PRNG implementation
        // optionalls pass 'salt' with a forge.util.ByteBuffer w/custom salt
    });
    var signature = privateKey.sign(md, pss);

    // verify RSASSA-PSS signature
    var pss = forge.pss.create({
        md: forge.md.sha1.create(),
        mgf: forge.mgf.mgf1.create(forge.md.sha1.create()),
        saltLength: 20
        // optionally pass 'prng' with a custom PRNG implementation
    });
    var md = forge.md.sha1.create();
    md.update('sign this', 'utf8');
    publicKey.verify(md.digest().getBytes(), signature, pss);

    var bytes = "bytes";

    // encrypt data with a public key (defaults to RSAES PKCS#1 v1.5)
    var encrypted = publicKey.encrypt(bytes);

    // decrypt data with a private key (defaults to RSAES PKCS#1 v1.5)
    var decrypted = privateKey.decrypt(encrypted);

    // encrypt data with a public key using RSAES PKCS#1 v1.5
    var encrypted = publicKey.encrypt(bytes, 'RSAES-PKCS1-V1_5');

    // decrypt data with a private key using RSAES PKCS#1 v1.5
    var decrypted = privateKey.decrypt(encrypted, 'RSAES-PKCS1-V1_5');

    // encrypt data with a public key using RSAES-OAEP
    var encrypted = publicKey.encrypt(bytes, 'RSA-OAEP');

    // decrypt data with a private key using RSAES-OAEP
    var decrypted = privateKey.decrypt(encrypted, 'RSA-OAEP');

    // encrypt data with a public key using RSAES-OAEP/SHA-256
    var encrypted = publicKey.encrypt(bytes, 'RSA-OAEP', {
        md: forge.md.sha256.create()
    });

    // decrypt data with a private key using RSAES-OAEP/SHA-256
    var decrypted = privateKey.decrypt(encrypted, 'RSA-OAEP', {
        md: forge.md.sha256.create()
    });

    // encrypt data with a public key using RSAES-OAEP/SHA-256/MGF1-SHA-1
    // compatible with Java's RSA/ECB/OAEPWithSHA-256AndMGF1Padding
    var encrypted = publicKey.encrypt(bytes, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
            md: forge.md.sha1.create()
        }
    });

    // decrypt data with a private key using RSAES-OAEP/SHA-256/MGF1-SHA-1
    // compatible with Java's RSA/ECB/OAEPWithSHA-256AndMGF1Padding
    var decrypted = privateKey.decrypt(encrypted, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
            md: forge.md.sha1.create()
        }
    });
}

function test_RSA_KEM() {
    // generate an RSA key pair asynchronously (uses web workers if available)
    // use workers: -1 to run a fast core estimator to optimize # of workers
    forge.rsa.generateKeyPair({bits: 2048, workers: -1}, function(err, keypair) {
      // keypair.privateKey, keypair.publicKey
    });


}

function testSSH() {
    // encodes (and optionally encrypts) a private RSA key as a Putty PPK file
    forge.ssh.privateKeyToPutty(privateKey, "passphrase", "comment");

    // encodes a public RSA key as an OpenSSH file
    forge.ssh.publicKeyToOpenSSH(publicKey, "comment");

    // encodes a private RSA key as an OpenSSH file
    forge.ssh.privateKeyToOpenSSH(privateKey, "passphrase");

    // gets the SSH public key fingerprint in a byte buffer
    forge.ssh.getPublicKeyFingerprint(publicKey);

    // gets a hex-encoded, colon-delimited SSH public key fingerprint
    forge.ssh.getPublicKeyFingerprint(publicKey, {encoding: 'hex', delimiter: ':'});
}
