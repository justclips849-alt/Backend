// index.js (Final Version designed to prevent 502/CORS errors)

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const knex = require('knex');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET_CHANGE_THIS_IN_PROD'; 
const SALT_ROUNDS = 10;
const TOKEN_EXPIRATION = '1d'; 

// --- Database Connection Factory ---
// This function creates the Knex instance when needed, 
// prioritizing the standard DATABASE_URL provided by Railway.
function getKnexInstance() {
    const connectionConfig = process.env.DATABASE_URL || {
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE,
        port: process.env.MYSQL_PORT || 3306,
    };

    return knex({
        client: 'mysql2',
        connection: connectionConfig,
        pool: { min: 0, max: 7 }
    });
}


// --- CORS Configuration ---
const allowedOrigins = [
    'http://localhost:5500', 
    'https://davs8.dreamhosters.com' 
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
    credentials: true,
};

// --- Middleware (Execution Order is Critical for CORS) ---
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// --- Controller Logic Functions ---
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

    // Get the database instance inside the route handler
    const db = getKnexInstance();

    try {
        // Check if user exists
        const existingUser = await db('users').where({ email }).first();
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists.' });
        }

        // Hash password
        const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

        // Insert new user
        const [insertId] = await db('users') 
            .insert({ email, password_hash });

        // Respond
        res.status(201).json({ 
            message: 'Account created successfully. Proceed to sign in.',
            userId: insertId
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Server or Database error during registration.' });
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

    // Get the database instance inside the route handler
    const db = getKnexInstance();

    try {
        // Find user
        const user = await db('users').where({ email }).first();
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Generate token
        const token = generateToken(user.id);

        // Set JWT as HTTP-only session cookie
        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'Lax', 
            maxAge: 24 * 60 * 60 * 1000 
        });
        
        // Respond
        res.status(200).json({ 
            message: 'Login successful.',
            token,
            userId: user.id
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server or Database error during sign in.' });
    }
});

// Basic Health Check Route
app.get('/', (req, res) => {
    res.send('ClarityAI Backend is running and endpoints are ready.');
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
