const RSAEncryptor = require('./RSAEncryptor');
const TPEncryptor = require('./TPEncryptor');

const assert = (bool, data) => {
    if (!bool) {
        console.warn(data || bool);
        throw new Error('Assertion failed.');
    }
}

const DEFAULT_API_BASE = 'http://tplinkwifi.net/cgi-bin';

class TPSession {
    #password;
    #apiBase;
    #random;
    #encryptor;
    #stok;
    #sysauth;

    constructor(password, apiBase = DEFAULT_API_BASE, random = Math.random) {
        assert(password);
        this.#password = password;
        this.#apiBase = apiBase;
        this.#random = random;
    }

    async login() {
        const [encryptedPassword, encryptor] = await Promise.all([
            this.#getEncryptedPassword(),
            this.#getEncryptor(),
        ]);
        this.#encryptor = encryptor;

        const login = await this.#queryAuth({
            path: '/login?form=login',
            body: `password=${encryptedPassword}&operation=login`,
            isLogin: true,
        });
        assert(typeof login === 'object' && typeof login.stok === 'string', login);
        this.#stok = login.stok;
    }

    async statusAll() {
        const status = await this.#queryAuth({ path: '/admin/status?form=all' });
        assert(typeof status === 'object' && Array.isArray(status.access_devices_wireless_host), status);
        return status;
    }

    async #getEncryptedPassword() {
        const keys = await this.#query({ path: '/login?form=keys' });
        assert(
            typeof keys === 'object'
            && Array.isArray(keys.password)
            && keys.password.length === 2,
            keys
        );
        const [modulus, exponent] = keys.password;

        return new RSAEncryptor(modulus, exponent, this.random).encrypt(this.#password);
    }

    async #getEncryptor() {
        const auth = await this.#query({ path: '/login?form=auth' });
        assert(
            typeof auth === 'object'
            && Array.isArray(auth.key)
            && auth.key.length === 2
            && typeof auth.seq === 'number',
            auth
        );
        const { key: [modulus, exponent], seq } = auth;
        return new TPEncryptor(modulus, exponent, seq, 'admin', this.#password, this.#random);
    }

    async #query({
        path,
        body = 'operation=read',
    }) {
        const res = await fetch(`${this.#apiBase}/luci/;stok=${path}`, {
            method: 'POST',
            body,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        const text = await res.text();
        try {
            const json = JSON.parse(text);
            assert(json.success, json);
            return json.data;
        } catch (err) {
            console.warn('Failed querying API', JSON.stringify(text));
            throw err;
        }
    };

    async #queryAuth({
        path,
        body = 'operation=read',
        isLogin = false,
    }) {
        assert(body);
        assert(isLogin || this.#stok, [isLogin, this.#stok]);
        assert(isLogin || this.#sysauth, [isLogin, this.#stok]);
        assert(this.#encryptor);

        const { data, sign } = this.#encryptor.encryptData(body, isLogin);
        const res = await fetch(`${this.#apiBase}/luci/;stok=${this.#stok || ''}${path}`, {
            method: 'POST',
            body: `sign=${encodeURIComponent(sign)}&data=${encodeURIComponent(data)}`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': this.#sysauth && `sysauth=${this.#sysauth}`,
            },
        });

        const text = await res.text();
        try {
            const json = JSON.parse(this.#encryptor.decryptData(JSON.parse(text).data));
            assert(json.success, json);

            if (isLogin) {
                const setCookiesArr = res.headers.get('Set-Cookie').split(';');
                const setCookies = new Map(setCookiesArr.map(kv => kv.split('=', 2)));
                this.#sysauth = setCookies.get('sysauth');
            }

            return json.data;
        } catch (err) {
            console.warn('Failed querying API', JSON.stringify(text));
            throw err;
        }
    };
}

module.exports = TPSession;
