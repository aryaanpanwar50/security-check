require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const {runLightScan} = require('./scans/lightScan.js');
const {runMediumScan} = require('./scans/mediumScan.js');
const axios = require('axios');

const app = express();

app.use(cors({
  origin: 'https://security-check-xi.vercel.app',
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept']
}));

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

app.listen(5000, () => console.log('Server running on http://localhost:5000'));