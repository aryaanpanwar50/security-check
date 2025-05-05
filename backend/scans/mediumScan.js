const {runLightScan} = require('./lightScan');
const {exec} = require('child_process');
const dns = require('dns').promises
const whois = require('whois-json');
const axios = require('axios');
const tls = require('tls');

async function runMediumScan(url) {
    const results = await runLightScan(url); // Start with light scan results
    const hostname = new URL(url).hostname;

    // WHOIS Lookup
    try{
        const whoisData = await whois(hostname);
        results.push({
            vulnerability: 'WHOIS Information',
            severity: 'Info',
            evidence: JSON.stringify(whoisData, null, 2),
            tool: 'WHOIS Lookup',
        });
    } catch(e){
        results.push({
            vulnerability: 'WHOIS Lookup Failed',
            severity: 'Low',
            evidence: e.message,
            tool: 'WHOIS',
        });
    }

    //DNS Records

    try{
        const records = await dns.resolveAny(hostname);
        results.push({
            vulnerability: 'DNS Records',
            severity: 'Info',
            evidence: JSON.stringify(records, null, 2),
            tool: 'DNS Lookup',
        });
        
    }catch(err){
        results.push({
            vulnerability: 'DNS Resolution Failed',
            severity: 'Low',
            evidence: err.message,
            tool: 'DNS Resolver', 
        });
    }

    //Check HTTP Methods

    try{
        const res = await axios.options(url);
        results.push({
            vulnerability:'HTTP Methods Enabled',
            severity:'Medium',
            evidence:res.headers.allow || 'Not specified',
            tool: 'HTTP Options',
        })
    }catch(err){
        results.push({
            vulnerability: 'HTTP Methods Check Failed',
            severity: 'Low',
            evidence: err.message,
            tool: 'HTTP Options',
        });
    }

    //SSL Certificate Check

    try{
        const certInfo = await new Promise((resolve, reject) => {
            const socket = tls.connect(443,hostname,{servername:hostname},()=>{
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve(cert);
            })
            socket.on('error',reject)
        })

        results.push({
            vulnerability: 'SSL Certificate',
            severity: 'Info',
            evidence: JSON.stringify(certInfo, null, 2),
            tool: 'SSL Checker',
        });
    }catch(err){
        results.push({
            vulnerability:'SSL Certificate Check Failed',
            severity: 'Low',
            evidence: err.message,
            tool: 'SSL Checker',
        })
    }

    return results
}

module.exports = {runMediumScan}