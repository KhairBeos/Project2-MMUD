"use strict";

/** ******* Imports ********/
const crypto = require("node:crypto");
const { subtle } = require("node:crypto").webcrypto;
const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr,
} = require("./lib");

/** ******* Implementation ********/

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = {}; // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    // Tạo cặp khóa ElGamal (EG) cho client này [cite: 71]
    const egKeyPair = await generateEG();

    // Lưu trữ toàn bộ cặp khóa (cả public và private) vào đối tượng client
    // Khóa bí mật (egKeyPair.sec) sẽ cần thiết cho việc tính toán computeDH sau này
    this.EGKeyPair = egKeyPair;
    this.username = username;

    // Tạo đối tượng chứng chỉ
    const certificate = {
      username: username, // Chứng chỉ phải chứa username [cite: 72]
      publicKey: egKeyPair.pub, //... và khóa công khai ElGamal [cite: 71, 37]
    };

    // Lưu lại chứng chỉ của chính mình
    this.certificate = certificate;

    // Trả về đối tượng chứng chỉ để gửi cho Certificate Authority (CA)
    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: ArrayBuffer
   *
   * Return Type: void
   */
  async receiveCertificate(certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate);
    throw "not implemented!";
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, ArrayBuffer]
   */
  async sendMessage(name, plaintext) {
    // Lấy chứng chỉ người nhận
    const receiverCert = this.certs[name];
    if (!receiverCert) {
      throw new Error(`No certificate for user: ${name}`);
    }
    // Tạo ephemeral key cho tin nhắn
    const ephemeralKeyPair = await generateEG();
    const sharedSecret = await computeDH(
      ephemeralKeyPair.sec,
      receiverCert.publicKey
    );
    const aesKey = await HMACtoAESKey(sharedSecret, "ratchet-str");
    const receiverIV = genRandomSalt(12);
    const certString = JSON.stringify(receiverCert);
    const ciphertext = await encryptWithGCM(
      aesKey,
      plaintext,
      receiverIV,
      certString
    );
    const govEphemeralKeyPair = await generateEG();
    const govSharedSecret = await computeDH(
      govEphemeralKeyPair.sec,
      this.govPublicKey
    );
    const govAESKey = await HMACtoAESKey(govSharedSecret, govEncryptionDataStr);

    const ivGov = genRandomSalt(12);

    const aesKeyBuffer = await crypto.subtle.exportKey("raw", aesKey);

    const cGov = await encryptWithGCM(
      govAESKey, // Khóa AES của chính phủ
      aesKeyBuffer, // MÃ HÓA CHÍNH AES KEY
      ivGov,
      certString
    );
    const header = {
      receiverIV: receiverIV,
      ephemeralPub: ephemeralKeyPair.pub,
      vGov: govEphemeralKeyPair.pub,
      cGov: cGov,
      ivGov: ivGov,
      nonce: genRandomSalt(16), //chống replay attack
    };

    return [header, ciphertext];
  }

  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
   *
   * Return Type: string
   */
  async receiveMessage(name, [header, ciphertext]) {
    // Kiểm tra replay attack
    const nonceKey = `${name}:${header.nonce}`;
    if (this.conns[nonceKey]) {
      throw new Error("Replay attack detected!");
    }
    // Lấy chứng chỉ người gửi
    const senderCert = this.certs[name];
    if (!senderCert) {
      throw new Error(`No certificate for sender: ${name}`);
    }
    const sharedSecret = await computeDH(
      this.EGKeyPair.sec, // Khóa bí mật của mình
      header.ephemeralPub // Khóa công khai tạm của người gửi
    );
    const aesKey = await HMACtoAESKey(sharedSecret, "ratchet-str");
    const certString = JSON.stringify(senderCert);
    const plaintextBuffer = await decryptWithGCM(
      aesKey,
      ciphertext,
      header.receiverIV,
      certString
    );
    const plaintext = bufferToString(plaintextBuffer);

    //  Lưu nonce để chống replay
    this.conns[nonceKey] = true;
    return plaintext;
  }
}

module.exports = {
  MessengerClient,
};
