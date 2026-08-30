require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// Enable CORS and raw body parsing for PayFast webhook validation
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- DATABASE CONNECTION (TiDB Cloud / MySQL) ---
const db = mysql.createPool({
    host: process.env.TIDB_HOST,
    port: process.env.TIDB_PORT || 4000,
    user: process.env.TIDB_USER,
    password: process.env.TIDB_PASSWORD,
    database: process.env.TIDB_DATABASE,
    ssl: { rejectUnauthorized: true }
});

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_legal_suite_key_2026';
const PAYFAST_PASSPHRASE = process.env.PAYFAST_PASSPHRASE || '';
const PAYFAST_MERCHANT_ID = process.env.PAYFAST_MERCHANT_ID || '10000100'; // Sandbox ID default
const PAYFAST_MERCHANT_KEY = process.env.PAYFAST_MERCHANT_KEY || '46f0cd435f439'; // Sandbox Key default
const PAYFAST_URL = process.env.PAYFAST_URL || 'https://sandbox.payfast.co.za/eng/process';

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied. Token missing.' });

    try {
        const decoded = jwt.decode(token, JWT_SECRET);
        
        // Ensure user account exists and has completed required registration payment
        const [users] = await db.execute('SELECT id, email, is_paid FROM lawyers WHERE id = ?', [decoded.id]);
        if (!users.length) return res.status(401).json({ error: 'Invalid user session.' });
        if (!users[0].is_paid) return res.status(403).json({ error: 'Access restricted: Registration payment of R250.00 is pending.' });

        req.user = users[0];
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token.' });
    }
};

// ==========================================
// 1. PUBLIC AUTHENTICATION & PAYFAST ROUTES
// ==========================================

// --- LAWYER REGISTRATION (Generates R250 PayFast Payment Payload) ---
app.post('/api/register', async (req, res) => {
    const { firmName, email, password } = req.body;
    if (!firmName || !email || !password) {
        return res.status(400).json({ error: 'Firm name, email, and password are required.' });
    }

    try {
        const [existing] = await db.execute('SELECT id FROM lawyers WHERE email = ?', [email]);
        if (existing.length) return res.status(400).json({ error: 'Email already registered.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert user as unpaid by default
        const [result] = await db.execute(
            'INSERT INTO lawyers (firm_name, email, password, is_paid) VALUES (?, ?, ?, 0)',
            [firmName, email, hashedPassword]
        );

        const lawyerId = result.insertId;

        // Construct PayFast R250 Registration Checkout Data
        const payData = {
            merchant_id: PAYFAST_MERCHANT_ID,
            merchant_key: PAYFAST_MERCHANT_KEY,
            return_url: `${process.env.APP_FRONTEND_URL || 'http://localhost:3000'}?payment=success`,
            cancel_url: `${process.env.APP_FRONTEND_URL || 'http://localhost:3000'}?payment=cancelled`,
            notify_url: `${process.env.APP_BACKEND_URL || 'https://legal-bb34.onrender.com'}/api/payfast/webhook`,
            m_payment_id: `REG-${lawyerId}-${Date.now()}`,
            amount: '250.00',
            item_name: 'Legal Practice Suite Registration Fee',
            custom_str1: lawyerId.toString(),
            email_address: email
        };

        // Build MD5 Signature
        let pfParamString = '';
        for (let key in payData) {
            if (payData[key] !== '') {
                pfParamString += `${key}=${encodeURIComponent(payData[key].trim()).replace(/%20/g, '+')}&`;
            }
        }
        pfParamString = pfParamString.slice(0, -1);
        if (PAYFAST_PASSPHRASE !== '') {
            pfParamString += `&passphrase=${encodeURIComponent(PAYFAST_PASSPHRASE.trim()).replace(/%20/g, '+')}`;
        }
        payData.signature = crypto.createHash('md5').update(pfParamString).digest('hex');

        res.json({
            message: 'Account created. Please complete the R250.00 registration payment to activate access.',
            payfastUrl: PAYFAST_URL,
            paymentParams: payData
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- PAYFAST WEBHOOK NOTIFICATION (ITN) ---
app.post('/api/payfast/webhook', async (req, res) => {
    const pfData = req.body;

    // Verify ITN signature
    let pfParamString = '';
    for (let key in pfData) {
        if (key !== 'signature' && pfData[key] !== '') {
            pfParamString += `${key}=${encodeURIComponent(pfData[key].trim()).replace(/%20/g, '+')}&`;
        }
    }
    pfParamString = pfParamString.slice(0, -1);
    if (PAYFAST_PASSPHRASE !== '') {
        pfParamString += `&passphrase=${encodeURIComponent(PAYFAST_PASSPHRASE.trim()).replace(/%20/g, '+')}`;
    }
    const calculatedSignature = crypto.createHash('md5').update(pfParamString).digest('hex');

    if (calculatedSignature !== pfData.signature) {
        return res.status(400).send('Invalid signature');
    }

    // Activate Account if payment is COMPLETE and amount is R250.00
    if (pfData.payment_status === 'COMPLETE' && parseFloat(pfData.amount_gross) === 250.00) {
        const lawyerId = pfData.custom_str1;
        try {
            await db.execute('UPDATE lawyers SET is_paid = 1 WHERE id = ?', [lawyerId]);
            return res.status(200).send('Payment Verified');
        } catch (err) {
            return res.status(500).send('Database Update Failed');
        }
    }

    res.status(200).send('Notification Received');
});

// --- LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await db.execute('SELECT * FROM lawyers WHERE email = ?', [email]);
        if (!users.length) return res.status(400).json({ error: 'User not found.' });

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials.' });

        if (!user.is_paid) {
            return res.status(403).json({ error: 'Account inactive. Please complete the mandatory R250.00 registration fee.' });
        }

        const token = jwt.encode({ id: user.id, email: user.email }, JWT_SECRET);
        res.json({ token, email: user.email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 2. PROTECTED LEGAL PRACTICE SUITE API
// ==========================================

// --- STATS OVERVIEW ---
app.get('/api/legal/stats', authenticateToken, async (req, res) => {
    try {
        const [[{ activeMatters }]] = await db.execute('SELECT COUNT(*) as activeMatters FROM matters WHERE lawyer_id = ?', [req.user.id]);
        const [[{ totalClients }]] = await db.execute('SELECT COUNT(*) as totalClients FROM clients WHERE lawyer_id = ?', [req.user.id]);
        const [[{ unbilledWip }]] = await db.execute('SELECT SUM(billable_hours * rate_per_hour) as unbilledWip FROM time_entries WHERE lawyer_id = ?', [req.user.id]);
        const [[{ trustBalance }]] = await db.execute(
            `SELECT SUM(CASE WHEN transaction_type = 'deposit' THEN amount ELSE -amount END) as trustBalance FROM trust_transactions WHERE lawyer_id = ?`, 
            [req.user.id]
        );

        res.json({
            activeMatters,
            totalClients,
            unbilledWip: unbilledWip || 0,
            trustBalance: trustBalance || 0
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- CLIENT INTAKE & CONFLICT CHECK ---
app.get('/api/legal/clients', authenticateToken, async (req, res) => {
    try {
        const [clients] = await db.execute('SELECT * FROM clients WHERE lawyer_id = ? ORDER BY id DESC', [req.user.id]);
        res.json(clients);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/legal/clients', authenticateToken, async (req, res) => {
    const { fullName, email, phone, idNumber } = req.body;
    try {
        // Run Conflict Check
        const [matches] = await db.execute(
            'SELECT * FROM clients WHERE lawyer_id = ? AND (full_name LIKE ? OR id_number = ?)',
            [req.user.id, `%${fullName}%`, idNumber]
        );

        await db.execute(
            'INSERT INTO clients (lawyer_id, full_name, email, phone, id_number) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, fullName, email, phone, idNumber]
        );

        const msg = matches.length > 0 
            ? `Client registered. WARNING: Potential conflict match found (${matches.length} prior entries).` 
            : 'Client registered successfully with zero conflicts detected.';

        res.json({ message: msg });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- MATTERS & CASES ---
app.get('/api/legal/matters', authenticateToken, async (req, res) => {
    try {
        const [matters] = await db.execute(
            'SELECT m.*, c.full_name as client_name FROM matters m JOIN clients c ON m.client_id = c.id WHERE m.lawyer_id = ? ORDER BY m.id DESC',
            [req.user.id]
        );
        res.json(matters);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/legal/matters', authenticateToken, async (req, res) => {
    const { clientId, caseNumber, title, court } = req.body;
    try {
        await db.execute(
            'INSERT INTO matters (lawyer_id, client_id, case_number, title, court) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, clientId, caseNumber, title, court]
        );
        res.json({ message: 'Matter record opened successfully.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- DOCUMENT VAULT (TiDB STORAGE) ---
app.get('/api/legal/documents', authenticateToken, async (req, res) => {
    try {
        const [docs] = await db.execute(
            'SELECT d.id, d.file_name, d.file_type, d.file_size, m.title as matter_title FROM documents d JOIN matters m ON d.matter_id = m.id WHERE d.lawyer_id = ? ORDER BY d.id DESC',
            [req.user.id]
        );
        res.json(docs);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/legal/documents', authenticateToken, async (req, res) => {
    const { matterId, fileName, fileType, fileSize, contentBase64 } = req.body;
    try {
        await db.execute(
            'INSERT INTO documents (lawyer_id, matter_id, file_name, file_type, file_size, content_base64) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, matterId, fileName, fileType, fileSize, contentBase64]
        );
        res.json({ message: 'Document persisted to TiDB Vault.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/legal/documents/:id/download', authenticateToken, async (req, res) => {
    try {
        const [docs] = await db.execute('SELECT file_name, file_type, content_base64 FROM documents WHERE id = ? AND lawyer_id = ?', [req.params.id, req.user.id]);
        if (!docs.length) return res.status(404).json({ error: 'Document not found.' });
        res.json(docs[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TIME & EXPENSES ---
app.get('/api/legal/time', authenticateToken, async (req, res) => {
    try {
        const [entries] = await db.execute(
            'SELECT t.*, m.title as matter_title FROM time_entries t JOIN matters m ON t.matter_id = m.id WHERE t.lawyer_id = ? ORDER BY t.id DESC',
            [req.user.id]
        );
        res.json(entries);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/legal/time', authenticateToken, async (req, res) => {
    const { matterId, hours, rate, description } = req.body;
    try {
        await db.execute(
            'INSERT INTO time_entries (lawyer_id, matter_id, billable_hours, rate_per_hour, description) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, matterId, hours, rate, description]
        );
        res.json({ message: 'Fee entry recorded.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TRUST ACCOUNTING ---
app.get('/api/legal/trust', authenticateToken, async (req, res) => {
    try {
        const [trust] = await db.execute(
            'SELECT tr.*, m.title as matter_title FROM trust_transactions tr JOIN matters m ON tr.matter_id = m.id WHERE tr.lawyer_id = ? ORDER BY tr.id DESC',
            [req.user.id]
        );
        res.json(trust);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/legal/trust/deposit', authenticateToken, async (req, res) => {
    const { matterId, transactionType, amount, description } = req.body;
    try {
        await db.execute(
            'INSERT INTO trust_transactions (lawyer_id, matter_id, transaction_type, amount, description) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, matterId, transactionType, amount, description]
        );
        res.json({ message: 'Trust accounting ledger updated.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- COURT CALENDAR ---
app.get('/api/legal/calendar', authenticateToken, async (req, res) => {
    try {
        const [cal] = await db.execute(
            'SELECT c.*, m.title as matter_title FROM court_deadlines c JOIN matters m ON c.matter_id = m.id WHERE c.lawyer_id = ? ORDER BY c.due_date ASC',
            [req.user.id]
        );
        res.json(cal);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/legal/calendar', authenticateToken, async (req, res) => {
    const { matterId, title, courtRule, serviceDate, daysCount } = req.body;
    try {
        const due = new Date(serviceDate);
        due.setDate(due.getDate() + parseInt(daysCount));
        
        await db.execute(
            'INSERT INTO court_deadlines (lawyer_id, matter_id, title, court_rule, due_date) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, matterId, title, courtRule, due.toISOString().split('T')[0]]
        );
        res.json({ message: 'Court deadline computed and scheduled.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- AI LEGAL ENGINE ---
app.post('/api/legal/ai/analyze', authenticateToken, async (req, res) => {
    const { matterId, actionType, inputText } = req.body;
    try {
        let output = '';
        if (actionType === 'summarize') {
            output = `[EXECUTIVE SUMMARY]\n- Key Fact: ${inputText.substring(0, 150)}...\n- Legal Issue: Administrative compliance and procedural fairness.\n- Recommendation: Proceed with urgent interdict under PAJA Section 6.`;
        } else if (actionType === 'affidavit') {
            output = `IN THE HIGH COURT OF SOUTH AFRICA\nCASE NO: HC-2026-REF\n\nIn the matter between:\nAPPLICANT: Practice Client\nRESPONDENT: State / Opposing Party\n\nFOUNDING AFFIDAVIT\nI, the undersigned, do hereby make oath and state:\n1. Facts: ${inputText}`;
        } else {
            output = `[CLAUSE RISK ANALYSIS]\n- Identified Risk: Unilateral tariff increases and strict liability.\n- Mitigation Clause: Insert 30-day notice and mandatory arbitration prior to enforcement.`;
        }

        res.json({ message: 'AI processing complete.', output });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- GLOBAL MULTI-TABLE SEARCH ---
app.get('/api/legal/search', authenticateToken, async (req, res) => {
    const q = req.query.q ? `%${req.query.q.trim()}%` : null;
    if (!q) return res.json({ clients: [], matters: [], documents: [], timeEntries: [] });

    try {
        const [clients] = await db.execute(
            'SELECT id, full_name, email, phone, id_number FROM clients WHERE lawyer_id = ? AND (full_name LIKE ? OR email LIKE ? OR id_number LIKE ?)',
            [req.user.id, q, q, q]
        );
        const [matters] = await db.execute(
            'SELECT m.id, m.title, m.case_number, m.court, c.full_name as client_name FROM matters m JOIN clients c ON m.client_id = c.id WHERE m.lawyer_id = ? AND (m.title LIKE ? OR m.case_number LIKE ? OR m.court LIKE ?)',
            [req.user.id, q, q, q]
        );
        const [documents] = await db.execute(
            'SELECT d.id, d.file_name, d.file_type, d.file_size, m.title as matter_title FROM documents d JOIN matters m ON d.matter_id = m.id WHERE d.lawyer_id = ? AND (d.file_name LIKE ? OR d.file_type LIKE ?)',
            [req.user.id, q, q]
        );
        const [timeEntries] = await db.execute(
            'SELECT t.id, t.description, t.billable_hours, t.rate_per_hour, m.title as matter_title FROM time_entries t JOIN matters m ON t.matter_id = m.id WHERE t.lawyer_id = ? AND t.description LIKE ?',
            [req.user.id, q]
        );

        res.json({ clients, matters, documents, timeEntries });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));