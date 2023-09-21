const TPSession = require('./TPSession');

(async () => {
    const session = new TPSession('example_password');
    await session.login();
    const status = await session.statusAll();
    console.log(status);
})();

