const CryptoJS = require('./CryptoJS');
const RSAEncryptor = require('./RSAEncryptor');

function generateRandomIntString(length, random = Math.random) {
    let randomString = '';
    while (length--) {
        randomString += Math.floor(random() * 10);
    }
    return randomString;
};

class TPEncryptor {
    constructor(
        rsaModulus,
        rsaExponent,
        sequence,
        username,
        password,
        random = Math.random,
    ) {
        this.random = random;

        this.rsa = new RSAEncryptor(rsaModulus, rsaExponent, random);
        this.sequence = sequence;
        this.hash = CryptoJS.MD5(username + password).toString();

        this.aesKey = generateRandomIntString(16);
        this.aesIv = generateRandomIntString(16);
        this.aesKeyWords = CryptoJS.enc.Utf8.parse(this.aesKey);
        this.aesConfig = {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
            iv: CryptoJS.enc.Utf8.parse(this.aesIv),
        };
    }

    getSignature(text, withAES) {
        const data = (withAES ? `k=${this.aesKey}&i=${this.aesIv}&` : '') + `h=${this.hash}&s=${text}`;

        let signature = '';
        for (let i = 0; i < data.length; i += 53) {
            signature += this.rsa.encrypt(data.substring(i, i + 53));
        }

        return signature;
    }

    encryptData(text, withAES) {
        const encryptedText = CryptoJS.AES.encrypt(text, this.aesKeyWords, this.aesConfig).toString();
        const sign = this.getSignature(this.sequence + encryptedText.length, withAES);
        const data = encryptedText;
        return { sign, data };
    }

    decryptData(data) {
        return CryptoJS.AES.decrypt(data, this.aesKeyWords, this.aesConfig).toString(CryptoJS.enc.Utf8);
    }

    generateRandomIntString(length) {
        let randomString = '';
        while (length--) {
            randomString += Math.floor(this.random() * 10);
        }
        return randomString;
    }
}

module.exports = TPEncryptor;
