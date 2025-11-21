// index.js
// 🚨 NOTE: This file assumes you have already run your Knex migration 
// to create the 'users' table in your MySQL database on Railway.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- Knex Database Setup (for MySQL) ---
// This configuration attempts to connect to the MySQL database using 
// environment variables set on Railway.
const knex = require('knex')({
    client: 'mysql2',
    connection: {
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE,
        port: process.env.MYSQL_PORT || 3306,
    },
});

const app = express();
const PORT = process.env.PORT || 3000;

// --- Security Constants ---
// Ensure JWT_SECRET is set in your Railway environment!
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET_CHANGE_THIS_IN_PROD'; 
const SALT_ROUNDS = 10;
const TOKEN_EXPIRATION = '1d'; 

// --- CORS Configuration ---
// Allows access only from your specific frontend and local development
const allowedOrigins = [
    'http://localhost:5500', 
    'https://davs8.dreamhosters.com' // Your Frontend Domain
];

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.warn('CORS Blocked Origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // Essential for session cookies
};

// --- Middleware (Ordered for correctness) ---
app.use(cors(corsOptions));
app.use(express.json()); // Parses incoming JSON payloads
app.use(cookieParser()); // Handles session cookies

// --- Controller Logic Functions ---

/**
 * Generates a JSON Web Token (JWT).
 */
const generateToken = (userId) => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION }); 
};

// --- Routes ---

/**
 * POST /api/auth/signup: Handles new user registration.
 */
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // 1. Check if user exists
        const existingUser = await knex('users').where({ email }).first();
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists.' });
        }

        // 2. Hash password
        const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

        // 3. Insert new user
        const [insertId] = await knex('users') 
            .insert({ email, password_hash });

        // 4. Respond
        res.status(201).json({ 
            message: 'Account created successfully.',
            userId: insertId
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

/**
 * POST /api/auth/login: Handles user sign-in and session creation.
 */
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // 1. Find user
        const user = await knex('users').where({ email }).first();
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // 2. Compare password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // 3. Generate token
        const token = generateToken(user.id);

        // 4. Set JWT as HTTP-only session cookie
        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'Lax', 
            maxAge: 24 * 60 * 60 * 1000 
        });
        
        // 5. Respond
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
