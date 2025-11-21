// index.js (All-in-One Authentication Server)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const knex = require('knex')({
    client: 'mysql2',
    connection: {
        // Reads MySQL credentials from Railway Environment Variables
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE,
        port: process.env.MYSQL_PORT || 3306,
    },
});


const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET_CHANGE_ME';
const SALT_ROUNDS = 10;
const TOKEN_EXPIRATION = '1d'; 

// --- CORS Configuration ---
const allowedOrigins = [
    'http://localhost:5500', 
    'http://127.0.0.1:5500',
    'https://davs8.dreamhosters.com' // Your Frontend Domain
];

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, 
};

// --- Middleware ---
app.use(cors(corsOptions));
app.use(express.json()); 
app.use(cookieParser());

// --- Authentication Logic (Controller Functions) ---

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION }); 
};

// --- Routes ---

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const existingUser = await knex('users').where({ email }).first();
        if (existingUser) {
            return res.status(409).json({ error: 'A user already exists with that email.' });
        }

        const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

        // Note: MySQL's knex returns the insert ID, not the object.
        const [insertId] = await knex('users') 
            .insert({ email, password_hash });

        res.status(201).json({ 
            message: 'User created successfully. Proceed to sign in.',
            userId: insertId
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const user = await knex('users').where({ email }).first();
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = generateToken(user.id);

        // Set JWT as an HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'Lax', 
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });
        
        res.status(200).json({ 
            message: 'Login successful.',
            token,
            userId: user.id
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during sign in.' });
    }
});

// Basic Health Check Route
app.get('/', (req, res) => {
    res.send('ClarityAI Backend (MySQL) is operational.');
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
