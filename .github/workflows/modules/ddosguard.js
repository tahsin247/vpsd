const logger = require('../helpers/logger');
const random = require('../helpers/random');

async function randomMover(browser) {
    await browser.mouse.move([random.randomInt(100, 600), random.randomInt(100, 600)]);
}

async function randomClicker(browser) {
    await browser.mouse.click([random.randomInt(100, 600), random.randomInt(100, 600)], 'left');
}

async function solver(browser, pid, proxies) {
    logger.log(`[browser@${pid.pid}] Detected protection: DDoS-Guard`)

    await randomMover(browser);
    await randomClicker(browser);

    var i = 0;
    while (await browser.title() === 'DDoS-Guard') {
        if (i > 10) {
            logger.log(`[proxy@${pid.pid}] Proxy error: ${proxy}`)

            await browser.close();

            const proxy1 = proxies[Math.floor(Math.random() * proxies.length)];
            run(proxy1);
            return;
        }

        await randomMover(browser);
        await randomClicker(browser);
        await browser.sleep(2000);

        i++;
    }
}


module.exports = {
    solver: solver
}