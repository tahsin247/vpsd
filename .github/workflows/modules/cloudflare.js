const logger = require('../helpers/logger');
const random = require('../helpers/random');

const COORDS_EVALUATE = `const element = document.querySelector("#turnstile-wrapper");

const rect = element.getBoundingClientRect();
const x = rect.left + window.scrollX;
const y = rect.top + window.scrollY;

const a = x.toString();
const b = y.toString();

('' + x.toString() + ' ' + y.toString() + '').toString();`


async function clicker(browser, coordinates) {
    const offsets = [
        [85, 65],
        [85, 25],
        [85, 65],
        [33, 33],
        [40, 30],
        [25, 50],
        [40, 65],
        [60, 50],
        [10, 30],
        [80, 25],
        [15, 25],
    ];

    for (const offset of offsets) {
        const newCordX = Number(coordinates[0]) + offset[0];
        const newCordY = Number(coordinates[1]) + offset[1];
        await browser.mouse.move([newCordX, newCordY]);
        await browser.mouse.click([newCordX, newCordY], 'left');
    }
}


async function randomMover(browser) {
    await browser.mouse.move([random.randomInt(100, 600), random.randomInt(100, 600)]);
}


async function randomClicker(browser) {
    await browser.mouse.click([random.randomInt(100, 600), random.randomInt(100, 600)], 'left');
}


async function solver(browser, pid, proxies) {
    const captchaSelector = await browser.locator("#turnstile-wrapper");

    await randomMover(browser);
    await randomClicker(browser);

    if (captchaSelector) {
        logger.log(`[browser@${pid.pid}] Detected protection: Cloudflare (Captcha)`)

        await randomMover(browser);
        await randomClicker(browser);

        await browser.sleep(3000);

        const uCoords = await browser.evaluate(COORDS_EVALUATE);

        const fCoords = uCoords.split(' ');

        var i = 0;
        while (await browser.title() === 'Just a moment...') {
            if (i > 5) {
                logger.log(`[proxy@${pid.pid}] Proxy error: ${proxy}`)

                await browser.close();

                const proxy1 = proxies[Math.floor(Math.random() * proxies.length)];
                run(proxy1);
                return;
            }

            await randomMover(browser);
            await randomClicker(browser);

            await clicker(browser, fCoords)

            await browser.sleep(15000)
            i++;
        }

    } else {
        await randomMover(browser);
        await randomClicker(browser);

        await browser.sleep(5000);

        await randomMover(browser);
        await randomClicker(browser);

        if (captchaSelector) {
            logger.log(`[browser@${pid.pid}] Detected protection: Cloudflare (Captcha)`)

            await randomMover(browser);
            await randomClicker(browser);

            await browser.sleep(3000);

            const uCoords = await browser.evaluate(COORDS_EVALUATE);

            const fCoords = uCoords.split(' ');

            var i = 0;
            while (await browser.title() === 'Just a moment...') {
                if (i > 5) {
                    logger.log(`[proxy@${pid.pid}] Proxy error: ${proxy}`)

                    await browser.close();

                    const proxy1 = proxies[Math.floor(Math.random() * proxies.length)];
                    run(proxy1);
                    return;
                }

                await randomMover(browser);
                await randomClicker(browser);

                await clicker(browser, fCoords)

                await browser.sleep(15000)
                i++;
            }

        } else {
            logger.log(`[browser@${pid.pid}] Detected protection: Cloudflare (JS)`)
            await browser.sleep(15000);
        }
    }
}


module.exports = {
    solver: solver
}