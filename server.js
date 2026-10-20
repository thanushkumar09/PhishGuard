const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Main Dynamic Active Production Endpoints Verification API Control Validation
app.post('/api/v1/predict-url', (req, res) => {
    const targetUrl = req.body.url;
    
    if (!targetUrl) {
        return res.status(400).json({ status: "error", message: "URL is required parameters." });
    }

    // Trigger internal analytics calculations using existing framework machine components safely
    execFile('python', ['ml_score.py', targetUrl], (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ status: "error", debug: error.message });
        }
        try {
            const resultsPayloadOutputData = JSON.parse(stdout);
            return res.json({
                status: "success",
                url: targetUrl,
                data: resultsPayloadOutputData
            });
        } catch (e) {
            return res.json({
                status: "success",
                url: targetUrl,
                verdict: stdout.trim()
            });
        }
    });
});

app.listen(PORT, () => {
    console.log(`Backend server engine routing parameters runtime running cleanly on endpoint: http://localhost:${PORT}`);
});
