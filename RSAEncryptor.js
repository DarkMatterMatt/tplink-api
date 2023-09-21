function bitLength(bigint) {
    return bigint.toString(2).length
}

function arrayToBigInt(arr) {
    let result = 0n;
    for (let i = 0; i < arr.length; i++) {
        result = (result << 8n) | BigInt(arr[i]);
    }
    return result;
}

class Montgomery {
    constructor(modulus) {
        const modLen = bitLength(modulus);

        this.mod = modulus;
        this.modLen = modLen;
        this.k = Montgomery.#calculateK(modulus);
        this.r = 1n << BigInt(modLen + 16);
        this.rInv = Montgomery.#calculateRInv(modulus, modLen);
    }

    static #calculateK(modulus) {
        let k = 0n;
        while (modulus % 2n === 0n) {
            k++;
            modulus >>= 1n;
        }
        return k;
    }

    static #calculateRInv(modulus, modulusBitLength) {
        let rInv = 1n;
        for (let i = modulusBitLength; i > 0; i--) {
            rInv = rInv * rInv % modulus;
        }
        return modulus - rInv;
    }

    exp(x, y) {
        let a = 1n;

        while (y > 0n) {
            if (y % 2n === 1n) {
                a = this.#mul(a, x, this.mod, this.modLen);
            }
            x = this.#mul(x, x, this.mod, this.modLen);
            y >>= 1n;
        }

        return a;
    }

    #mul(a, b, modulus, modulusBitLength) {
        let result = 0n;
        for (let i = 0n; i < modulusBitLength; i++) {
            if ((a & 1n) === 1n) {
                result = (result + b) % modulus;
            }
            a >>= 1n;
            b <<= 1n;
            if (b >= modulus) {
                b = (b - modulus) % modulus;
            }
        }
        return result;
    }
}

class RSAEncryptor {
    constructor(modulus, exponent, random = Math.random) {
        this.random = random;
        this.modulus = BigInt('0x' + modulus);
        this.encryptedLength = modulus.length;
        this.exponent = BigInt('0x' + exponent);
        this.montgomery = new Montgomery(this.modulus);
    }

    encrypt(str) {
        let bufIdx = (bitLength(this.modulus) + 7) >> 3;
        if (bufIdx < str.length + 11) {
            throw new Error(`String is too long, received length ${str.length}`);
        }

        const encodedBytes = [];
        for (let i = str.length - 1; i >= 0 && bufIdx > 2; i--) {
            const charCode = str.charCodeAt(i);
            if (charCode < 128) {
                encodedBytes[--bufIdx] = charCode;
            } else if (charCode < 2048) {
                encodedBytes[--bufIdx] = charCode & 63 | 128;
                encodedBytes[--bufIdx] = (charCode >> 6) & 63 | 128;
            } else {
                encodedBytes[--bufIdx] = charCode & 63 | 128;
                encodedBytes[--bufIdx] = (charCode >> 6) & 63 | 128;
                encodedBytes[--bufIdx] = (charCode >> 12) | 224;
            }
        }
        encodedBytes[--bufIdx] = 0;
        while (bufIdx > 2) {
            encodedBytes[--bufIdx] = Math.floor(this.random() * 255) + 1;
        }
        encodedBytes[--bufIdx] = 2;
        encodedBytes[--bufIdx] = 0;

        const encrypted = this.montgomery.exp(arrayToBigInt(encodedBytes), this.exponent);

        return encrypted.toString(16).padStart(this.encryptedLength, '0');
    }
}

module.exports = RSAEncryptor;
