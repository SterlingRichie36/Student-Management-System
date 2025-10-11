const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key';

app.use(cors());
app.use(express.json());

// Initialize SQLite database
const db = new sqlite3.Database('./database.sqlite');

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS students (
        id TEXT PRIMARY KEY,
        name TEXT,
        email TEXT,
        department TEXT,
        year TEXT
    )`);
});

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if user exists
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (user) return res.status(400).json({ error: 'Username already exists' });
            
            // Hash password and create user
            const passwordHash = await bcrypt.hash(password, 10);
            db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, passwordHash], function(err) {
                if (err) return res.status(500).json({ error: 'Error creating user' });
                res.json({ message: 'User created successfully' });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// User Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });
        
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) return res.status(400).json({ error: 'Invalid credentials' });
        
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET);
        res.json({ token, user: { username: user.username } });
    });
});

// Student CRUD operations
app.get('/api/students', authenticateToken, (req, res) => {
    db.all('SELECT * FROM students', (err, students) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(students);
    });
});

app.post('/api/students', authenticateToken, (req, res) => {
    const { id, name, email, department, year } = req.body;
    
    db.run('INSERT INTO students (id, name, email, department, year) VALUES (?, ?, ?, ?, ?)', 
        [id, name, email, department, year], function(err) {
        if (err) return res.status(500).json({ error: 'Error adding student' });
        res.json({ message: 'Student added successfully', id: this.lastID });
    });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});