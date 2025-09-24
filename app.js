const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const app = express();

//require('dotenv').config();

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('MySQL connection failed:', err.message);
        console.log('⚠️  Running without database - form submissions will be logged only');
        return;
    }
    console.log('Connected to MySQL database ✅');
});



app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Security headers
app.use(helmet());
// Cookies for CSRF token storage
app.use(cookieParser(process.env.COOKIE_SECRET || 'change_me'));

// Set Content Security Policy to allow fonts and other resources
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "font-src 'self' data: https://fonts.gstatic.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; " +
        "connect-src 'self' https://www.google-analytics.com; " +
        "img-src 'self' data:;"
    );
    next();
});

// Trust proxy headers (needed when running behind load balancers/CDNs)
//app.enable('trust proxy');
app.set('trust proxy', 1);

// Enforce HTTPS in production
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
        //const isSecure = req.secure || req.headers['x-forwarded-proto']//?.startsWith('https');
        if (!isSecure) {
            console.warn(`Redirecting insecure request: ${req.originalUrl}`);
            const host = req.headers.host;
            const url = `https://${host}${req.originalUrl}`;
            return res.redirect(301, url);
        }
    }
    next();
});

// CSRF protection (using double-submit cookie pattern)
const csrfProtection = csrf({
    cookie: {
        key: '_csrf',
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production'
    }
});
app.use(csrfProtection);

// Endpoint to fetch CSRF token for clients
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Rate limiter for form submissions
const submitFormLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5,              // limit each IP to 5 requests per minute
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        return res.status(429).redirect(303, '/error');
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Success and error pages
app.get('/thank-you', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'thank_you.html'));
});

app.get('/error', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'error.html'));
});

app.get('/terms', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'terms.html'));
});

app.get('/privacy-policy', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'privacy-policy.html'));
});

app.get('/refund-policy', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'refund-policy.html'));
});

// Validation & sanitization for form submission
const validateForm = [
    body('name')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Invalid name')
        .matches(/^[a-zA-Z\s'.-]+$/)
        .withMessage('Invalid name characters')
        .escape(),
    body('email')
        .trim()
        .isEmail()
        .withMessage('Invalid email')
        .normalizeEmail()
        .isLength({ max: 100 })
        .withMessage('Email too long'),
    body('phone_no')
        .trim()
        .isLength({ min: 10, max: 15 })
        .withMessage('Invalid phone length')
        .matches(/^[0-9+\-()\s]+$/)
        .withMessage('Invalid phone digits')
        .escape(),
    body('business_type')
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('Invalid business type')
        .escape(),
    body('gst_type')
        .trim()
        .isIn(['Unregistered', 'Registered - Regular', 'Registered - Composition'])
        .withMessage('Invalid GST type'),
    body('city')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Invalid city')
        .matches(/^[a-zA-Z\s'.-]+$/)
        .withMessage('Invalid city characters')
        .escape()
];

app.post('/submit-form', submitFormLimiter, validateForm, (req, res) => {
    console.log('Form submission received:', req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.warn('Validation failed:', errors.array().map(e => e.param));
        return res.redirect(303, '/error');
    }
    const { name, email, phone_no, business_type, gst_type, city } = req.body;
    
    // Basic validation
    if (!name || !email || !phone_no || !business_type || !gst_type || !city) {
        console.log('Validation failed - missing fields:', { name: !!name, email: !!email, phone_no: !!phone_no, business_type: !!business_type, gst_type: !!gst_type, city: !!city });
        return res.status(400).send('All fields are required');
    }
    
    // Check database connection
    if (!db || db.state === 'disconnected') {
        console.log('Database not available - logging submission only');
        console.log('Form submission data:', { name, email, phone_no, business_type, gst_type, city });
        
        // Redirect to success page even without database for testing
        return res.redirect(303, '/thank-you');
    }
    
    const sql = 'INSERT INTO signup_form (name, email, phone_no, business_type, gst_type, city) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, email, phone_no, business_type, gst_type, city], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            console.error('SQL:', sql);
            console.error('Values:', [name, email, phone_no, business_type, gst_type, city]);
            return res.redirect(303, '/error');
        }
        
        console.log('New user registered successfully:', { name, email, business_type, id: result.insertId });
        return res.redirect(303, '/thank-you');
    });
});

// Handle CSRF token errors gracefully
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        console.warn('Invalid CSRF token');
        return res.redirect(303, '/error');
    }
    next(err);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`RetailStackIn running at http://localhost:${PORT}`);
});