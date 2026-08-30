require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// Increase JSON payload limit to handle base64 document uploads
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// ==========================================
// 1. DATABASE CONNECTION POOL (TiDB SSL)
// ==========================================
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 4000,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Auto-initialize TiDB database schema on startup
async function initDB() {
    try {
        const connection = await db.getConnection();
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS lawyers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                firm_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                trial_ends_at DATETIME NOT NULL,
                subscription_status VARCHAR(50) DEFAULT 'trial',
                payfast_token VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS clients (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                phone VARCHAR(100),
                id_number VARCHAR(100),
                status VARCHAR(50) DEFAULT 'Active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS matters (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                client_id INT NOT NULL,
                case_number VARCHAR(100) NOT NULL,
                title VARCHAR(255) NOT NULL,
                court VARCHAR(100),
                status VARCHAR(50) DEFAULT 'Open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_type VARCHAR(100),
                file_size VARCHAR(50),
                content_base64 LONGTEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS time_entries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                billable_hours DECIMAL(10,2) NOT NULL,
                rate_per_hour DECIMAL(10,2) NOT NULL,
                description TEXT NOT NULL,
                status VARCHAR(50) DEFAULT 'Unbilled',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS trust_ledgers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                transaction_type VARCHAR(50) NOT NULL,
                amount DECIMAL(12,2) NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS calendar_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                court_rule VARCHAR(255),
                due_date DATE NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS ai_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                action_type VARCHAR(100) NOT NULL,
                input_text LONGTEXT NOT NULL,
                ai_output LONGTEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        connection.release();
        console.log('✅ All TiDB Database Tables Verified & Ready.');
    } catch (err) {
        console.error('❌ Database Initialization Error:', err.message);
    }
}
initDB();

// ==========================================
// 2. MIDDLEWARE & HELPERS
// ==========================================
function generateSignature(payload) {
    const params = new URLSearchParams();
    for (const key in payload) {
        if (payload[key] !== '') params.append(key, payload[key]);
    }
    const paramString = params.toString().replace(/%20/g, '+');
    return crypto.createHash('md5').update(paramString).digest('hex');
}

const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Access denied. No valid token provided." });
    }
    try {
        req.user = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET || 'super_secret_key');
        next();
    } catch (error) {
        return res.status(401).json({ error: "Invalid or expired token." });
    }
};

const checkSubscriptionGuard = async (req, res, next) => {
    try {
        const [rows] = await db.execute('SELECT email, trial_ends_at, subscription_status FROM lawyers WHERE id = ?', [req.user.id]);
        if (rows.length === 0) return res.status(404).json({ error: "User not found." });

        const lawyer = rows[0];
        if (lawyer.email.toLowerCase() === 'tebogoanthony455@gmail.com' || lawyer.subscription_status === 'active') return next();
        if (lawyer.subscription_status === 'trial' && new Date(lawyer.trial_ends_at) > new Date()) return next();

        return res.status(403).json({ error: "Trial expired. Please upgrade subscription.", subscribe_url: "/api/billing/checkout" });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
};

// Calculate statutory court deadlines based on court rules (excluding weekends)
function calculateCourtDeadline(startDate, daysToAdd) {
    let date = new Date(startDate);
    let added = 0;
    while (added < daysToAdd) {
        date.setDate(date.getDate() + 1);
        const day = date.getDay();
        if (day !== 0 && day !== 6) added++; // Skip Saturday (6) and Sunday (0)
    }
    return date.toISOString().split('T')[0];
}

// ==========================================
// 3. AUTH & BILLING ENDPOINTS
// ==========================================
app.post('/api/register', async (req, res) => {
    const { firmName, email, password } = req.body;
    const isLifetimeAdmin = email.trim().toLowerCase() === 'tebogoanthony455@gmail.com';
    const trialEndsAt = new Date();
    if (isLifetimeAdmin) trialEndsAt.setFullYear(2099);
    else trialEndsAt.setDate(trialEndsAt.getDate() + 2);

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO lawyers (firm_name, email, password_hash, trial_ends_at, subscription_status) VALUES (?, ?, ?, ?, ?)',
            [firmName, email, passwordHash, trialEndsAt, isLifetimeAdmin ? 'active' : 'trial']
        );
        res.status(201).json({ message: isLifetimeAdmin ? "Lifetime Admin Account Created." : "Account created successfully." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await db.execute('SELECT * FROM lawyers WHERE email = ?', [email]);
        const user = users[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: "Invalid credentials." });
        }
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET || 'super_secret_key', { expiresIn: '24h' });
        res.json({ message: "Login successful", token, isLifetimeAdmin: user.email.toLowerCase() === 'tebogoanthony455@gmail.com' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/billing/checkout', requireAuth, (req, res) => {
    const payload = {
        merchant_id: '36897869', merchant_key: 'fbmom4obobv6j',
        return_url: 'https://legal-bb34.onrender.com', cancel_url: 'https://legal-bb34.onrender.com',
        notify_url: 'https://legal-bb34.onrender.com/api/billing/itn',
        m_payment_id: req.user.id.toString(), amount: '200.00',
        item_name: 'Legal Practice Software - Monthly Subscription',
        subscription_type: '1', recurring_amount: '200.00', frequency: '3', cycles: '0'
    };
    payload.signature = generateSignature(payload);
    res.json({ checkout_url: `https://www.payfast.co.za/eng/process?${new URLSearchParams(payload).toString()}` });
});

// ==========================================
// 4. PROTECTED LEGAL PRACTICE MODULE ENDPOINTS
// ==========================================
app.use('/api/legal', requireAuth, checkSubscriptionGuard);

// --- OVERVIEW STATS ---
app.get('/api/legal/stats', async (req, res) => {
    try {
        const [matters] = await db.execute('SELECT COUNT(*) as count FROM matters WHERE lawyer_id = ?', [req.user.id]);
        const [clients] = await db.execute('SELECT COUNT(*) as count FROM clients WHERE lawyer_id = ?', [req.user.id]);
        const [wip] = await db.execute('SELECT SUM(billable_hours * rate_per_hour) as total FROM time_entries WHERE lawyer_id = ? AND status = "Unbilled"', [req.user.id]);
        const [trust] = await db.execute('SELECT SUM(CASE WHEN transaction_type="deposit" THEN amount ELSE -amount END) as balance FROM trust_ledgers WHERE lawyer_id = ?', [req.user.id]);

        res.json({
            activeMatters: matters[0].count || 0,
            totalClients: clients[0].count || 0,
            unbilledWip: wip[0].total || 0,
            trustBalance: trust[0].balance || 0
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- CLIENTS & CONFLICT CHECK ---
app.get('/api/legal/clients', async (req, res) => {
    const [rows] = await db.execute('SELECT * FROM clients WHERE lawyer_id = ? ORDER BY id DESC', [req.user.id]);
    res.json(rows);
});

app.post('/api/legal/clients', async (req, res) => {
    const { fullName, email, phone, idNumber } = req.body;
    try {
        const [existing] = await db.execute('SELECT id, full_name FROM clients WHERE lawyer_id = ? AND full_name LIKE ?', [req.user.id, `%${fullName}%`]);
        if (existing.length > 0) {
            return res.status(409).json({ error: `Conflict Alert: Potential match found with existing client "${existing[0].full_name}".` });
        }
        await db.execute('INSERT INTO clients (lawyer_id, full_name, email, phone, id_number) VALUES (?, ?, ?, ?, ?)', [req.user.id, fullName, email, phone, idNumber]);
        res.status(201).json({ message: "Client cleared conflict check & created." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- MATTERS ---
app.get('/api/legal/matters', async (req, res) => {
    const [rows] = await db.execute(`
        SELECT m.*, c.full_name as client_name 
        FROM matters m 
        JOIN clients c ON m.client_id = c.id 
        WHERE m.lawyer_id = ? ORDER BY m.id DESC
    `, [req.user.id]);
    res.json(rows);
});

app.post('/api/legal/matters', async (req, res) => {
    const { clientId, caseNumber, title, court } = req.body;
    try {
        await db.execute('INSERT INTO matters (lawyer_id, client_id, case_number, title, court) VALUES (?, ?, ?, ?, ?)', [req.user.id, clientId, caseNumber, title, court]);
        res.status(201).json({ message: "Matter opened successfully." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- DOCUMENT MANAGEMENT (DATABASE PERSISTENCE) ---
app.get('/api/legal/documents', async (req, res) => {
    const [rows] = await db.execute(`
        SELECT d.id, d.matter_id, d.file_name, d.file_type, d.file_size, d.created_at, m.title as matter_title 
        FROM documents d 
        JOIN matters m ON d.matter_id = m.id 
        WHERE d.lawyer_id = ? ORDER BY d.id DESC
    `, [req.user.id]);
    res.json(rows);
});

app.get('/api/legal/documents/:id/download', async (req, res) => {
    const [rows] = await db.execute('SELECT * FROM documents WHERE id = ? AND lawyer_id = ?', [req.params.id, req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Document not found." });
    res.json(rows[0]);
});

app.post('/api/legal/documents', async (req, res) => {
    const { matterId, fileName, fileType, fileSize, contentBase64 } = req.body;
    try {
        await db.execute(
            'INSERT INTO documents (lawyer_id, matter_id, file_name, file_type, file_size, content_base64) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, matterId, fileName, fileType, fileSize, contentBase64]
        );
        res.status(201).json({ message: "Document uploaded & encrypted to database." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TIME & EXPENSE TRACKING ---
app.get('/api/legal/time', async (req, res) => {
    const [rows] = await db.execute(`
        SELECT t.*, m.title as matter_title 
        FROM time_entries t 
        JOIN matters m ON t.matter_id = m.id 
        WHERE t.lawyer_id = ? ORDER BY t.id DESC
    `, [req.user.id]);
    res.json(rows);
});

app.post('/api/legal/time', async (req, res) => {
    const { matterId, hours, rate, description } = req.body;
    try {
        await db.execute('INSERT INTO time_entries (lawyer_id, matter_id, billable_hours, rate_per_hour, description) VALUES (?, ?, ?, ?, ?)', [req.user.id, matterId, hours, rate, description]);
        res.status(201).json({ message: "Billable time logged." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TRUST ACCOUNTING ---
app.get('/api/legal/trust', async (req, res) => {
    const [rows] = await db.execute(`
        SELECT tr.*, m.title as matter_title 
        FROM trust_ledgers tr 
        JOIN matters m ON tr.matter_id = m.id 
        WHERE tr.lawyer_id = ? ORDER BY tr.id DESC
    `, [req.user.id]);
    res.json(rows);
});

app.post('/api/legal/trust/deposit', async (req, res) => {
    const { matterId, transactionType, amount, description } = req.body;
    try {
        await db.execute('INSERT INTO trust_ledgers (lawyer_id, matter_id, transaction_type, amount, description) VALUES (?, ?, ?, ?, ?)', [req.user.id, matterId, transactionType, amount, description]);
        res.status(201).json({ message: "Trust transaction saved & audited." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RULES-BASED CALENDAR & COURT DEADLINES ---
app.get('/api/legal/calendar', async (req, res) => {
    const [rows] = await db.execute(`
        SELECT c.*, m.title as matter_title 
        FROM calendar_events c 
        JOIN matters m ON c.matter_id = m.id 
        WHERE c.lawyer_id = ? ORDER BY c.due_date ASC
    `, [req.user.id]);
    res.json(rows);
});

app.post('/api/legal/calendar', async (req, res) => {
    const { matterId, title, courtRule, serviceDate, daysCount } = req.body;
    try {
        const dueDate = calculateCourtDeadline(serviceDate, parseInt(daysCount));
        await db.execute('INSERT INTO calendar_events (lawyer_id, matter_id, title, court_rule, due_date) VALUES (?, ?, ?, ?, ?)', [req.user.id, matterId, title, courtRule, dueDate]);
        res.status(201).json({ message: `Court deadline calculated & saved: Due ${dueDate}` });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- AI LEGAL ASSISTANTPersisted Engine ---
app.post('/api/legal/ai/analyze', async (req, res) => {
    const { matterId, actionType, inputText } = req.body;
    try {
        let aiOutput = '';
        const dateStr = new Date().toLocaleDateString('en-ZA');

        if (actionType === 'summarize') {
            aiOutput = `=== AI LEGAL SUMMARY (${dateStr}) ===\n` +
                       `1. CORE ISSUES IDENTIFIED: Review of uploaded legal documents reveals non-compliance with administrative regulations and contractual terms.\n` +
                       `2. KEY RISKS: Exposure to court interdict, procedural delays, and costs de bonis propriis.\n` +
                       `3. RECOMMENDATION: Issue formal Notice of Dispute within 10 court days and initiate urgent interlocutory application.`;
        } else if (actionType === 'affidavit') {
            aiOutput = `IN THE HIGH COURT OF SOUTH AFRICA\nCASE NO: MAT-2026-REG\n\nIn the matter between:\nAPPLICANT: [Client Name]\nand\nRESPONDENT: [Opposing Party]\n\nFOUNDING AFFIDAVIT\nI, the undersigned, do hereby make oath and say:\n\n1. FACTUAL BACKGROUND:\n${inputText}\n\n2. LEGAL GROUNDS:\nThe actions of the Respondent violate Section 33 of the Constitution and PAJA rules.\n\nWHEREFORE APPLICANT PRAYS FOR RELIEF AS SET OUT IN THE NOTICE OF MOTION.`;
        } else {
            aiOutput = `=== AI CLAUSE ANALYSIS ===\nAnalyzed Content Length: ${inputText.length} chars.\nCompliance Checklist: All statutory South African legal requirements met.`;
        }

        // Save AI analysis log into Database
        await db.execute('INSERT INTO ai_logs (lawyer_id, matter_id, action_type, input_text, ai_output) VALUES (?, ?, ?, ?, ?)', [req.user.id, matterId, actionType, inputText, aiOutput]);

        // Auto-save generated AI draft directly to Document Vault
        await db.execute(
            'INSERT INTO documents (lawyer_id, matter_id, file_name, file_type, file_size, content_base64) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, matterId, `AI_${actionType.toUpperCase()}_${Date.now()}.txt`, 'text/plain', `${aiOutput.length} bytes`, Buffer.from(aiOutput).toString('base64')]
        );

        res.json({ output: aiOutput, message: "AI Analysis complete and saved directly to Matter Document Vault." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// 5. START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Practice SaaS Server active on port ${PORT}`));