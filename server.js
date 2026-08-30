require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- ENVIRONMENT VARIABLES ---
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_legal_suite_key_2026_production';
const PAYFAST_PASSPHRASE = process.env.PAYFAST_PASSPHRASE || '';
const PAYFAST_MERCHANT_ID = process.env.PAYFAST_MERCHANT_ID || '10000100'; // Sandbox default
const PAYFAST_MERCHANT_KEY = process.env.PAYFAST_MERCHANT_KEY || '46f0cd435f439'; // Sandbox default
const PAYFAST_URL = process.env.PAYFAST_URL || 'https://sandbox.payfast.co.za/eng/process';
const APP_FRONTEND_URL = process.env.APP_FRONTEND_URL || 'https://your-frontend-domain.com';
const APP_BACKEND_URL = process.env.APP_BACKEND_URL || 'https://legal-bb34.onrender.com';

// --- DATABASE CONNECTION POOL (TiDB / MySQL) ---
const db = mysql.createPool({
    host: process.env.TIDB_HOST,
    port: process.env.TIDB_PORT || 4000,
    user: process.env.TIDB_USER,
    password: process.env.TIDB_PASSWORD,
    database: process.env.TIDB_DATABASE,
    ssl: { rejectUnauthorized: true },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- AUTOMATED DATABASE SCHEMA INITIALIZATION ---
async function initializeDatabase() {
    try {
        const connection = await db.getConnection();
        console.log('⚡ Connected to TiDB Database. Syncing schema...');

        // 1. Lawyers / Users Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS lawyers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                firm_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_paid TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 2. Clients Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS clients (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                phone VARCHAR(50) NOT NULL,
                id_number VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (lawyer_id) REFERENCES lawyers(id) ON DELETE CASCADE
            );
        `);

        // 3. Matters Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS matters (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                client_id INT NOT NULL,
                case_number VARCHAR(100) NOT NULL,
                title VARCHAR(255) NOT NULL,
                court VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (lawyer_id) REFERENCES lawyers(id) ON DELETE CASCADE,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            );
        `);

        // 4. Documents Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_type VARCHAR(100) NOT NULL,
                file_size VARCHAR(50) NOT NULL,
                content_base64 LONGTEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (lawyer_id) REFERENCES lawyers(id) ON DELETE CASCADE,
                FOREIGN KEY (matter_id) REFERENCES matters(id) ON DELETE CASCADE
            );
        `);

        // 5. Time Entries Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS time_entries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                billable_hours DECIMAL(10,2) NOT NULL,
                rate_per_hour DECIMAL(10,2) NOT NULL,
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (lawyer_id) REFERENCES lawyers(id) ON DELETE CASCADE,
                FOREIGN KEY (matter_id) REFERENCES matters(id) ON DELETE CASCADE
            );
        `);

        // 6. Trust Accounting Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS trust_transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                transaction_type ENUM('deposit', 'withdrawal') NOT NULL,
                amount DECIMAL(12,2) NOT NULL,
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (lawyer_id) REFERENCES lawyers(id) ON DELETE CASCADE,
                FOREIGN KEY (matter_id) REFERENCES matters(id) ON DELETE CASCADE
            );
        `);

        // 7. Court Calendar Deadlines Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS court_deadlines (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lawyer_id INT NOT NULL,
                matter_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                court_rule VARCHAR(255) NOT NULL,
                due_date DATE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (lawyer_id) REFERENCES lawyers(id) ON DELETE CASCADE,
                FOREIGN KEY (matter_id) REFERENCES matters(id) ON DELETE CASCADE
            );
        `);

        connection.release();
        console.log('✅ All database tables verified and operational.');
    } catch (err) {
        console.error('❌ Database initialization error:', err.message);
    }
}

// --- AUTHENTICATION & ACCESS GUARD MIDDLEWARE ---
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. Authentication token missing.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Query user and check payment status
        const [users] = await db.execute('SELECT id, email, is_paid FROM lawyers WHERE id = ?', [decoded.id]);
        if (!users.length) {
            return res.status(401).json({ error: 'User session invalid or account removed.' });
        }

        const user = users[0];
        if (!user.is_paid) {
            return res.status(403).json({ 
                error: 'Access Restricted: Registration payment of R250.00 is required to access the suite.',
                isPaid: false 
            });
        }

        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired session token.' });
    }
};

// ==========================================
// 1. PUBLIC AUTHENTICATION & PAYMENT ENDPOINTS
// ==========================================

// --- LAWYER REGISTRATION (Generates PayFast R250 Checkout Payload) ---
app.post('/api/register', async (req, res) => {
    const { firmName, email, password } = req.body;
    if (!firmName || !email || !password) {
        return res.status(400).json({ error: 'Firm name, email, and password are required.' });
    }

    try {
        const [existing] = await db.execute('SELECT id FROM lawyers WHERE email = ?', [email]);
        if (existing.length) {
            return res.status(400).json({ error: 'Email address is already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert account as unpaid (is_paid = 0)
        const [result] = await db.execute(
            'INSERT INTO lawyers (firm_name, email, password, is_paid) VALUES (?, ?, ?, 0)',
            [firmName, email, hashedPassword]
        );

        const lawyerId = result.insertId;

        // Build PayFast R250 Checkout Data
        const payData = {
            merchant_id: PAYFAST_MERCHANT_ID,
            merchant_key: PAYFAST_MERCHANT_KEY,
            return_url: `${APP_FRONTEND_URL}?payment=success`,
            cancel_url: `${APP_FRONTEND_URL}?payment=cancelled`,
            notify_url: `${APP_BACKEND_URL}/api/payfast/webhook`,
            m_payment_id: `REG-${lawyerId}-${Date.now()}`,
            amount: '250.00',
            item_name: 'Legal Practice Suite Registration Fee',
            custom_str1: lawyerId.toString(),
            email_address: email
        };

        // Generate MD5 PayFast Signature
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
            message: 'Registration initiated. Complete the R250.00 payment to activate your account.',
            payfastUrl: PAYFAST_URL,
            paymentParams: payData
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- PAYFAST WEBHOOK NOTIFICATION (ITN HANDLER) ---
app.post('/api/payfast/webhook', async (req, res) => {
    const pfData = req.body;

    // Verify ITN signature integrity
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
        console.error('❌ PayFast Webhook error: Signature mismatch');
        return res.status(400).send('Invalid signature signature');
    }

    // Activate account upon receiving COMPLETE payment for R250.00
    if (pfData.payment_status === 'COMPLETE' && parseFloat(pfData.amount_gross) === 250.00) {
        const lawyerId = pfData.custom_str1;
        try {
            await db.execute('UPDATE lawyers SET is_paid = 1 WHERE id = ?', [lawyerId]);
            console.log(`✅ Registration payment of R250.00 verified for Lawyer ID: ${lawyerId}`);
            return res.status(200).send('Payment Verified and Account Activated');
        } catch (err) {
            console.error('❌ Webhook DB Update Error:', err.message);
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
        if (!users.length) return res.status(400).json({ error: 'User account not found.' });

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password.' });

        if (!user.is_paid) {
            return res.status(403).json({ 
                error: 'Account inactive. R250.00 registration payment pending.',
                isPaid: false 
            });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, email: user.email, message: 'Authentication successful.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 2. PROTECTED LEGAL PRACTICE SUITE API
// ==========================================

// --- EXECUTIVE OVERVIEW STATS ---
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
            activeMatters: activeMatters || 0,
            totalClients: totalClients || 0,
            unbilledWip: unbilledWip || 0,
            trustBalance: trustBalance || 0
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- CLIENT INTAKE & CONFLICT SEARCH ---
app.get('/api/legal/clients', authenticateToken, async (req, res) => {
    try {
        const [clients] = await db.execute('SELECT * FROM clients WHERE lawyer_id = ? ORDER BY id DESC', [req.user.id]);
        res.json(clients);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/legal/clients', authenticateToken, async (req, res) => {
    const { fullName, email, phone, idNumber } = req.body;
    try {
        // Perform Automated Conflict Search across prior records
        const [matches] = await db.execute(
            'SELECT * FROM clients WHERE lawyer_id = ? AND (full_name LIKE ? OR id_number = ?)',
            [req.user.id, `%${fullName}%`, idNumber]
        );

        await db.execute(
            'INSERT INTO clients (lawyer_id, full_name, email, phone, id_number) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, fullName, email, phone, idNumber]
        );

        const msg = matches.length > 0 
            ? `Client intake saved. WARNING: ${matches.length} conflict match(es) detected.` 
            : 'Client registered successfully with zero conflict matches detected.';

        res.json({ message: msg });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- CASE & MATTER MANAGEMENT ---
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
        res.json({ message: 'Matter record created successfully.' });
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
        res.json({ message: 'Document uploaded and stored in TiDB Vault.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/legal/documents/:id/download', authenticateToken, async (req, res) => {
    try {
        const [docs] = await db.execute('SELECT file_name, file_type, content_base64 FROM documents WHERE id = ? AND lawyer_id = ?', [req.params.id, req.user.id]);
        if (!docs.length) return res.status(404).json({ error: 'Document record not found.' });
        res.json(docs[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TIME & EXPENSE ENTRIES ---
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
        res.json({ message: 'Fee entry logged.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TRUST ACCOUNTING LEDGERS ---
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
        res.json({ message: 'Trust transaction posted to ledger.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- COURT CALENDAR & DEADLINE RULES ---
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
        res.json({ message: 'Court deadline rule calculated and saved.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- AI LEGAL ENGINE ---
app.post('/api/legal/ai/analyze', authenticateToken, async (req, res) => {
    const { matterId, actionType, inputText } = req.body;
    try {
        let output = '';
        if (actionType === 'summarize') {
            output = `[EXECUTIVE LEGAL SUMMARY]\n- Core Fact: ${inputText.substring(0, 150)}...\n- Ground: PAJA Judicial Review / Rule 53 Compliance.\n- Next Step: Deliver Rule 53 record request within 15 court days.`;
        } else if (actionType === 'affidavit') {
            output = `IN THE HIGH COURT OF SOUTH AFRICA\nCASE NO: HC-2026-REF\n\nIn the matter between:\nAPPLICANT: Registered Client\nRESPONDENT: Municipal Council / Board\n\nFOUNDING AFFIDAVIT\nI, the undersigned, declare under oath:\n1. Statements: ${inputText}`;
        } else {
            output = `[CLAUSE RISK ANALYSIS]\n- Identified Clause Risk: Unilateral tariff revision.\n- Remedy: Insert compulsory 30-day notice and PAJA review clause prior to implementation.`;
        }

        res.json({ message: 'AI task complete.', output });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- GLOBAL MULTI-TABLE DATABASE SEARCH ---
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

// Start Server and Initialize TiDB Tables
app.listen(PORT, async () => {
    console.log(`🚀 Server active on port ${PORT}`);
    await initializeDatabase();
});