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

function getKnexInstance() {
    const connectionConfig = {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT || 3306,
        // Added for external MySQL connections like DreamHost
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
    };

    return knex({
        client: 'mysql2',
        connection: connectionConfig,
        pool: { min: 0, max: 7 }
    });
}

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

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION }); 
};

// --- MODIFIED DATABASE INITIALIZATION ---
// This function ensures the 'users' table and the 'password_hash' column exist.
async function initializeDatabase() {
    const db = getKnexInstance();
    try {
        console.log("Attempting to verify and repair 'users' table schema...");

        // 1. Create table if it doesn't exist
        await db.schema.createTableIfNotExists('users', (table) => {
            table.increments('id').primary();
            table.string('email', 255).unique().notNullable();
            // We use name 'password' here for safety, then ensure 'password_hash' exists below.
            // This is a common pattern to handle schema changes gracefully.
            table.string('password', 255); 
            table.timestamp('created_at').defaultTo(db.fn.now());
        });

        // 2. Ensure 'password_hash' column exists (the specific column the code uses)
        const hasPasswordHash = await db.schema.hasColumn('users', 'password_hash');
        
        if (!hasPasswordHash) {
             await db.schema.table('users', (table) => {
                // Add the missing password_hash column
                table.string('password_hash', 255).notNullable();
                
                // If the old, incorrect 'password' column exists, remove it
                table.dropColumn('password');
             });
             console.log("Schema repair successful: 'password_hash' column added and verified.");
        }
        
        console.log("Database initialized: 'users' table is ready.");
    } catch (error) {
        // Log the error but DO NOT crash the server here, as Knex might have temporary issues.
        console.error("!!! FATAL DATABASE SCHEMA ERROR !!! Database access might fail.", error);
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

async function startServer() {
    // Attempt database initialization before starting the Express server
    await initializeDatabase(); 
    
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

startServer();
