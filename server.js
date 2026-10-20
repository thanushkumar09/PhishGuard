const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { execFile } = require('child_process');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// 🗄️ Step 3.1: Initialize MongoDB Remote/Local Connection Pipeline System Configurations
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/phishguard_logs';
mongoose.connect(MONGO_URI)
  .then(() => console.log('Database pipeline storage engine connected cleanly.'))
  .catch(err => console.error('Database terminal connection failure logs:', err));

// 📝 Step 3.2: Create Global Relational Analytical Logs Schema Models Layout Settings Setup
const ScanLogSchema = new mongoose.Schema({
    urlAnalyzed: { type: String, required: true },
    securityVerdict: { type: String, required: true },
    scannedAt: { type: Date, default: Date.now }
});
const ScanLog = mongoose.model('ScanLog', ScanLogSchema);

// ⚡ Active Prediction Engine Input Payload Operations Endpoint
app.post('/api/v1/predict-url', (req, res) => {
    const targetUrl = req.body.url;
    if (!targetUrl) {
        return res.status(400).json({ status: "error", message: "URL payload parameter missing configurations check." });
    }

    execFile('python', ['ml_score.py', targetUrl], async (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ status: "error", debug: error.message });
        }
        
        const finalVerdict = stdout.trim();

        // 💾 Step 3.3: Persist Analytical Output Payload Inside Verified Database Arrays Mappings Setup
        try {
            const auditLogEntry = new ScanLog({
                urlAnalyzed: targetUrl,
                securityVerdict: finalVerdict
            });
            await auditLogEntry.save();
            
            return res.json({
                status: "success",
                url: targetUrl,
                verdict: finalVerdict,
                databaseRecordSaved: true
            });
        } catch (dbError) {
            return res.status(500).json({ status: "error", message: "Failed to persist database log indices." });
        }
    });
});

// 🔎 New Historical Audit Verification Logs Access Interface Module Endpoint Setup
app.get('/api/v1/history/logs', async (req, res) => {
    try {
        const historicalRecords = await ScanLog.find().sort({ scannedAt: -1 }).limit(100);
        return res.json({ status: "success", count: historicalRecords.length, data: historicalRecords });
    } catch (err) {
        return res.status(500).json({ status: "error", message: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Enterprise system core analytics routing parameters running cleanly on endpoint: http://localhost:${PORT}`);
});
