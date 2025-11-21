// index.js (Final Self-Healing Version)

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const knex = require('knex');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Security Constants ---
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET_CHANGE_THIS_IN_PROD'; 
const SALT_ROUNDS = 10;
const TOKEN_EXPIRATION = '1d'; 

// --- Database Connection Factory ---
// Creates the Knex instance using variables set on Railway.
function getKnexInstance() {
    const connectionConfig = process.env.DATABASE_URL || {
        // Uses individual variables if DATABASE_URL is not set
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE,
        port: process.env.MYSQL_PORT || 3306,
    };

    return knex({
        client: 'mysql2',
        connection: connectionConfig,
        pool: { min: 0, max: 7 } // Added pool settings for stability
    });
}

// --- CORS Configuration ---
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
    credentials: true,
};

// --- Middleware ---
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// --- Database Initialization Function ---
async function initializeDatabase() {
    const db = getKnexInstance();
    try {
        console.log("Attempting to verify/create 'users' table...");
        
        await db.schema.createTableIfNotExists('users', (table) => {
            table.increments('id').primary();
            table.string('email', 255).unique().notNullable();
            table.string('password_hash', 255).notNullable();
            table.timestamp('created_at').defaultTo(db.fn.now());
        });
        
        console.log("Database initialized: 'users' table is ready.");
    } catch (error) {
        console.error("!!! FATAL DATABASE SCHEMA ERROR !!!", error);
        // We will NOT exit the process here, allowing the server to run for health checks, 
        // but API calls will still fail until the DB is fixed.
    }
}


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

    const db = getKnexInstance();

    try {
        const existingUser = await db('users').where({ email }).first();
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists.' });
        }

        const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

        const [insertId] = await db('users') 
            .insert({ email, password_hash });

        res.status(201).json({ 
            message: 'Account created successfully. Proceed to sign in.',
            userId: insertId
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal Server Error. Check database connection or logs.' });
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

    const db = getKnexInstance();

    try {
        const user = await db('users').where({ email }).first();
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = generateToken(user.id);

        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'Lax', 
            maxAge: 24 * 60 * 60 * 1000 
        });
        
        res.status(200).json({ 
            message: 'Login successful.',
            token,
            userId: user.id
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal Server Error. Check database connection or logs.' });
    }
});

// Basic Health Check Route
app.get('/', (req, res) => {
    res.send('ClarityAI Backend is running and endpoints are ready.');
});

// --- START SERVER ---
async function startServer() {
    // Run initialization before starting to listen for requests
    await initializeDatabase(); 
    
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

startServer();
