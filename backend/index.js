require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const {runLightScan} = require('./scans/lightScan.js');
const {runMediumScan} = require('./scans/mediumScan.js');
const axios = require('axios');

const app = express();

const corsOptions = {
    origin: ['https://security-check-xi.vercel.app', 'http://localhost:5173'],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    preflightContinue: false,
    optionsSuccessStatus: 204,
    allowedHeaders: ['Content-Type', 'Accept']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight

app.use(bodyParser.json());

app.post('/api/scan/light', async (req, res) => {
  const { url } = req.body;

  if (!url || !/^https?:\/\/.+/.test(url)) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  try {
    // Validate URL is reachable
    try {
      await axios.head(url, { timeout: 5000 });
    } catch (err) {
      return res.status(400).json({
        error: 'Unable to reach the URL. Please verify the website is accessible.'
      });
    }

    const report = await runLightScan(url);
    res.json({ success: true, report });
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({
      error: 'Scan failed: ' + (err.message || 'Unknown error')
    });
  }
});

app.post('/api/scan/medium', async (req, res) => {
    const { url } = req.body;
    if(!url || !/^https?:\/\/.+/.test(url)) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }
    try{
        await axios.head(url,{timeout: 5000});

        const report = await runMediumScan(url);
        let summary = null

        try{
            summary = await simplifyReport(report);
        } catch(err){
            summary = "Couldn't simplify the report. Please check the technical output."
        }

        res.json({success:true,report,summary});
    } catch(err){
        res.status(500).json({error:err.message})
    }
})

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error'
    });
});

app.listen(5000, () => console.log('Server running on http://localhost:5000'));