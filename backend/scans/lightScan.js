const axios = require('axios');
const { spawn } = require('child_process');

async function runLightScan(url) {
    const results = [];

    // Check Security Headers
    try {
        const response = await axios.get(url);
        const headers = response.headers;

        const checks = [
            { header: 'content-security-policy', name: 'Content Security Policy' },
            { header: 'x-frame-options', name: 'Clickjacking Protection' },
            { header: 'strict-transport-security', name: 'HSTS' },
            { header: 'x-content-type-options', name: 'MIME Sniffing Protection' },
        ];

        checks.forEach(({ header, name }) => {
            results.push({
                vulnerability: name,
                severity: headers[header] ? 'Low' : 'Medium',
                evidence: headers[header] || 'Missing',
                tool: 'HeaderChecker',
            });
        });
    } catch (e) {
        results.push({
            vulnerability: 'Header Fetch Failed',
            severity: 'High',
            evidence: e.message,
            tool: 'HeaderChecker',
        });
    }

    const hostname = new URL(url).hostname;

    // Use spawn instead of exec to run nmap
    await new Promise((resolve) => {
        const nmap = spawn('C:\\Program Files (x86)\\Nmap\\nmap.exe', ['-F', hostname]);

        // Capture output
        nmap.stdout.on('data', (data) => {
            results.push({
                vulnerability: 'Open Ports',
                severity: 'Info',
                evidence: data.toString(),
                tool: 'Nmap',
            });
        });

        // Capture errors
        nmap.stderr.on('data', (data) => {
            results.push({
                vulnerability: 'Nmap Error',
                severity: 'Low',
                evidence: data.toString(),
                tool: 'Nmap',
            });
        });

        // Resolve the promise once nmap finishes
        nmap.on('close', (code) => {
            if (code !== 0) {
                console.error(`Nmap process exited with code ${code}`);
            }
            resolve(); // Continue after nmap finishes
        });
    });

    return results;
}

module.exports = { runLightScan };
