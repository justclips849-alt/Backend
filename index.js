// index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./src/routes/authRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// =================================================================
// ✅ CORRECT CORS Configuration for MySQL and your Frontend
// =================================================================
const allowedOrigins = [
    'http://localhost:5500', 
    'http://127.0.0.1:5500',
    'https://davs8.dreamhosters.com' // <-- YOUR ACTUAL FRONTEND DOMAIN
];

const corsOptions = {
    // This allows specific origins to make requests
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            // Block requests from unauthorized origins
            callback(new Error('Not allowed by CORS'));
        }
    },
    // ESSENTIAL for sending the JWT in an HTTP-only cookie
    credentials: true, 
};

// --- Middleware ---
app.use(cors(corsOptions));
app.use(express.json()); 
app.use(cookieParser());

// --- Routes ---
// The /api/auth prefix is applied here
app.use('/api/auth', authRoutes);

// Basic Health Check Route
app.get('/', (req, res) => {
    res.send('ClarityAI Backend (MySQL) is operational.');
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
