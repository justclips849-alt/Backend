require('dotenv').config()

const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
// FIXED: Corrected typo from 'require = require'
const bcrypt = require('bcryptjs') 
const jwt = require('jsonwebtoken')
const mysql = require('mysql2/promise')
// Required to serve static files
const path = require('path') 

const app = express()

const PORT = process.env.PORT || 3000
// CLIENT_URL is used for CORS on external requests, but the app serves the frontend directly now.
const CLIENT_URL = process.env.CLIENT_URL || 'https://davs8.dreamhosters.com' 
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'

const requiredEnv = [
  'MYSQLHOST',
  'MYSQLPORT',
  'MYSQLUSER',
  'MYSQLPASSWORD',
  'MYSQLDATABASE'
]

const missing = requiredEnv.filter((key) => !process.env[key])
if (missing.length) {
  console.error('Missing MySQL env vars:', missing.join(', '))
  process.exit(1)
}

const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  port: Number(process.env.MYSQLPORT),
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
})

app.use(express.json())
app.use(cookieParser())

// 🛑 TEMPORARILY REMOVED: app.use(express.static(path.join(__dirname, 'public')))
// We will test the explicit route first to avoid middleware interference.

// 2. CORS: Handles requests coming from external origins if needed.
app.use(
  cors({
    origin: CLIENT_URL, 
    credentials: true 
  })
)

async function findUserByEmail(email) {
  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email])
  return rows[0]
}

async function createUser({ email, passwordHash }) {
  const [result] = await pool.query(
    'INSERT INTO users (email, password_hash, provider, provider_id, created_at) VALUES (?, ?, "local", NULL, NOW())',
    [email, passwordHash]
  )
  const insertedId = result.insertId
  const [rows] = await pool.query(
    'SELECT id, email, provider, provider_id FROM users WHERE id = ?',
    [insertedId]
  )
  return rows[0]
}

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  )
}

function setAuthCookie(res, token) {
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  })
}

// Route to check API status explicitly
app.get('/api/status', (req, res) => {
  res.send('ClarityAI backend API is running.')
})

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body || {}

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required.' })
    }

    const existing = await findUserByEmail(email)
    if (existing) {
      return res.status(409).json({ error: 'User with this email already exists.' })
    }

    const hash = await bcrypt.hash(password, 10)
    const user = await createUser({ email, passwordHash: hash })
    const token = signToken(user)
    setAuthCookie(res, token)

    res.status(201).json({
      token,
      user: {
        id: user.id,
        email: user.email
      }
    })
  } catch (err) {
    console.error('Signup error:', err)
    res.status(500).json({ error: 'Internal server error.' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {}

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required.' })
    }

    const user = await findUserByEmail(email)
    if (!user || !user.password_hash) {
      return res.status(401).json({ error: 'Invalid email or password.' })
    }

    const match = await bcrypt.compare(password, user.password_hash)
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' })
    }

    const cleanUser = {
      id: user.id,
      email: user.email
    }

    const token = signToken(cleanUser)
    setAuthCookie(res, token)

    res.json({
      token,
      user: cleanUser
    })
  } catch (err) {
    console.error('Login error:', err)
    res.status(500).json({ error: 'Internal server error.' })
  }
})

app.get('/api/auth/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || ''
    const cookieToken = req.cookies.auth_token
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : cookieToken

    if (!token) {
      return res.status(401).json({ error: 'Not authenticated.' })
    }

    const decoded = jwt.verify(token, JWT_SECRET)
    const [rows] = await pool.query(
      'SELECT id, email, provider, provider_id FROM users WHERE id = ?',
      [decoded.id]
    )

    if (!rows[0]) {
      return res.status(404).json({ error: 'User not found.' })
    }

    res.json({ user: rows[0] })
  } catch (err) {
    console.error('Me error:', err)
    res.status(401).json({ error: 'Invalid or expired token.' })
  }
})

// 3. 🛑 CATCH-ALL ROUTING FIXES
// Explicitly serve index.html for the root path (the only route we are testing now)
app.get('/', (req, res) => {
    // If this route works, it confirms the file structure and path.join are correct.
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// REMOVED: app.get('*', ...)

// ------------------------------

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
