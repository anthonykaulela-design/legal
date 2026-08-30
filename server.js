require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// ==========================================
// 1. SERVER CONFIGURATION & MIDDLEWARE
// ==========================================
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// 2. DATABASE CONNECTION POOL (TiDB SSL ENABLED)
// ==========================================
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 4000, // Default TiDB port
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ==========================================
// 3. UTILITY FUNCTIONS
// ==========================================
// Generates MD5 signature for PayFast authentication
function generateSignature(payload) {
    const params = new URLSearchParams();
    for (const key in payload) {
        if (payload[key] !== '') {
            params.append(key, payload[key]);
        }
    }
    const paramString = params.toString().replace(/%20/g, '+');
    return crypto.createHash('md5').update(paramString).digest('hex');
}

// ==========================================
// 4. CUSTOM MIDDLEWARES
// ==========================================
// Verifies JWT token on incoming requests
const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Access denied. No valid token provided." });
    }
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'super_secret_key');
        next();
    } catch (error) {
        return res.status(401).json({ error: "Invalid or expired token." });
    }
};

// Checks 2-day free trial or active subscription status
const checkSubscriptionGuard = async (req, res, next) => {
    try {
        const [rows] = await db.execute('SELECT email, trial_ends_at, subscription_status FROM lawyers WHERE id = ?', [req.user.id]);
        if (rows.length === 0) return res.status(404).json({ error: "User not found." });

        const lawyer = rows[0];
        const now = new Date();

        // Lifetime admin account bypass OR active subscriber
        if (lawyer.email.toLowerCase() === 'tebogoanthony455@gmail.com' || lawyer.subscription_status === 'active') {
            return next();
        }

        // Active 2-day trial check
        if (lawyer.subscription_status === 'trial' && new Date(lawyer.trial_ends_at) > now) {
            return next();
        }

        return res.status(403).json({
            error: "Your 2-day free trial has expired.",
            subscribe_url: "/api/billing/checkout"
        });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
};

// ==========================================
// 5. AUTHENTICATION ROUTES
// ==========================================
app.post('/api/register', async (req, res) => {
    const { firmName, email, password } = req.body;

    // Lifetime Free Admin account bypass check
    const isLifetimeAdmin = email.trim().toLowerCase() === 'tebogoanthony455@gmail.com';

    const trialEndsAt = new Date();
    if (isLifetimeAdmin) {
        trialEndsAt.setFullYear(2099); // Expiration set to year 2099
    } else {
        trialEndsAt.setDate(trialEndsAt.getDate() + 2); // Standard 2-day trial
    }

    const initialStatus = isLifetimeAdmin ? 'active' : 'trial';

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO lawyers (firm_name, email, password_hash, trial_ends_at, subscription_status) VALUES (?, ?, ?, ?, ?)',
            [firmName, email, passwordHash, trialEndsAt, initialStatus]
        );

        res.status(201).json({
            message: isLifetimeAdmin
                ? "Lifetime Admin Account Created & Activated."
                : "Account created. 2-day free trial activated."
        });
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

        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET || 'super_secret_key',
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.json({
            message: "Login successful",
            token,
            isLifetimeAdmin: user.email.toLowerCase() === 'tebogoanthony455@gmail.com'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 6. PAYFAST BILLING ROUTES
// ==========================================
app.get('/api/billing/checkout', requireAuth, (req, res) => {
    const payload = {
        merchant_id: '36897869',
        merchant_key: 'fbmom4obobv6j',
        return_url: 'https://legal-bb34.onrender.com/dashboard',
        cancel_url: 'https://legal-bb34.onrender.com/subscribe',
        notify_url: 'https://legal-bb34.onrender.com/api/billing/itn',
        m_payment_id: req.user.id.toString(),
        amount: '200.00',
        item_name: 'Legal Practice Software - Monthly Subscription',
        subscription_type: '1',
        recurring_amount: '200.00',
        frequency: '3',
        cycles: '0'
    };

    payload.signature = generateSignature(payload);
    const queryString = new URLSearchParams(payload).toString();
    res.json({ checkout_url: `https://www.payfast.co.za/eng/process?${queryString}` });
});

app.post('/api/billing/itn', async (req, res) => {
    const itnData = req.body;
    if (itnData.payment_status === 'COMPLETE') {
        const lawyerId = itnData.m_payment_id;
        const pfToken = itnData.token;

        await db.execute(
            'UPDATE lawyers SET subscription_status = ?, payfast_token = ? WHERE id = ?',
            ['active', pfToken, lawyerId]
        );
    }
    res.status(200).send('OK');
});

// ==========================================
// 7. PROTECTED LEGAL MODULE ROUTES
// ==========================================
app.use('/api/legal', requireAuth, checkSubscriptionGuard);

// Client Intake & CRM
app.post('/api/legal/clients', async (req, res) => {
    const { fullName } = req.body;
    try {
        const [existing] = await db.execute('SELECT id FROM clients WHERE full_name LIKE ?', [`%${fullName}%`]);
        if (existing.length > 0) return res.status(409).json({ error: "Potential Conflict of Interest detected." });

        await db.execute('INSERT INTO clients (lawyer_id, full_name) VALUES (?, ?)', [req.user.id, fullName]);
        res.status(201).json({ message: "Client created and cleared for intake." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Trust Accounting & Financial Compliance
app.post('/api/legal/trust/deposit', async (req, res) => {
    const { matterId, amount } = req.body;
    try {
        await db.execute('INSERT INTO trust_ledgers (matter_id, transaction_type, amount) VALUES (?, ?, ?)', [matterId, 'deposit', amount]);
        res.status(201).json({ message: "Funds secured in Trust Ledger." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Time Tracking & Expenses
app.post('/api/legal/time', async (req, res) => {
    const { matterId, hours, rate, description } = req.body;
    try {
        await db.execute(
            'INSERT INTO time_entries (matter_id, billable_hours, rate_per_hour, description) VALUES (?, ?, ?, ?)',
            [matterId, hours, rate, description]
        );
        res.status(201).json({ message: "Time tracked successfully." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Matter Dashboard Overview
app.get('/api/legal/matters/:matterId', async (req, res) => {
    const { matterId } = req.params;
    try {
        const [matterData] = await db.execute('SELECT * FROM matters WHERE id = ? AND lawyer_id = ?', [matterId, req.user.id]);
        const [trustData] = await db.execute('SELECT * FROM trust_ledgers WHERE matter_id = ?', [matterId]);
        const [timeData] = await db.execute('SELECT * FROM time_entries WHERE matter_id = ?', [matterId]);

        res.json({ matter: matterData[0] || null, trustLedger: trustData, billables: timeData });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 8. START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Legal Practice SaaS Server running on port ${PORT}`));