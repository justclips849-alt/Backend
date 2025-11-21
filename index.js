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
function getKnexInstance() {
    const connectionConfig = {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT || 3306,
        // Added for external MySQL connections (like DreamHost)
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
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
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
};

// --- Middleware ---
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION }); 
};

// --- SCHEMA INITIALIZATION (Self-Creation Logic) ---
async function initializeDatabase() {
    const db = getKnexInstance();
    try {
        console.log("Attempting to verify and create 'users' table...");

        // This is the simplified, fail-safe schema creation. 
        // It guarantees the table and the correct columns exist.
        await db.schema.createTableIfNotExists('users', (table) => {
            table.increments('id').primary();
            table.string('email', 255).unique().notNullable();
            table.string('password_hash', 255).notNullable(); // <--- GUARANTEED TO BE HERE NOW
            table.timestamp('created_at').defaultTo(db.fn.now());
        });
        
        console.log("Database initialized: 'users' table is ready.");
    } catch (error) {
        console.error("!!! FATAL DATABASE SCHEMA ERROR !!! Your database connection might be severely misconfigured.", error);
    }
}


// --- Routes ---

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
        // If the table was already created, but the previous bad column exists, 
        // this will catch the error and log it.
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal Server Error. Check database connection or logs.' });
    }
});

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

app.get('/', (req, res) => {
    res.send('ClarityAI Backend is running and endpoints are ready.');
});

// --- START SERVER ---
async function startServer() {
    await initializeDatabase(); 
    
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

startServer();
