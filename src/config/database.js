const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const fs = require('fs');

// Ensure db directory exists
const dbDir = path.join(__dirname, '../../db');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// Ensure sessions directory exists
const sessionsDir = path.join(dbDir, 'sessions');
if (!fs.existsSync(sessionsDir)) {
    fs.mkdirSync(sessionsDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'database.sqlite');
console.log('Database path:', dbPath);

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err);
        throw err; // Throw error to prevent server from starting with invalid database
    } else {
        console.log('Connected to SQLite database');
    }
});

function initializeDatabase() {
    return new Promise((resolve, reject) => {
        console.log('Starting database initialization...');

        db.serialize(() => {
            // Users table
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin', 'dashboard', 'both')),
                approved BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (err) => {
                if (err) {
                    console.error('Error creating users table:', err);
                    reject(err);
                    return;
                }
                console.log('Users table created or already exists');

                // Add new columns if they don't exist
                db.run("PRAGMA table_info(users)", (err, rows) => {
                    if (err) {
                        console.error('Error checking table structure:', err);
                        return;
                    }

                    // Check and add role column if it doesn't exist
                    db.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin', 'dashboard', 'both'))", (err) => {
                        if (err && !err.message.includes('duplicate column name')) {
                            console.error('Error adding role column:', err);
                        }
                    });

                    // Check and add approved column if it doesn't exist
                    db.run("ALTER TABLE users ADD COLUMN approved BOOLEAN DEFAULT 0", (err) => {
                        if (err && !err.message.includes('duplicate column name')) {
                            console.error('Error adding approved column:', err);
                        }
                    });
                });
            });

            // Create admin user if not exists
            const adminPassword = 'admin123'; // Change this in production
            bcrypt.hash(adminPassword, 10, (err, hash) => {
                if (err) {
                    console.error('Error hashing admin password:', err);
                    reject(err);
                    return;
                }

                db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
                    if (err) {
                        console.error('Error checking for admin user:', err);
                        reject(err);
                        return;
                    }

                    if (!row) {
                        console.log('Creating admin user...');
                        db.run(
                            'INSERT INTO users (username, email, password, role, approved) VALUES (?, ?, ?, ?, ?)',
                            ['admin', 'admin@clearvision.com', hash, 'admin', 1],
                            (err) => {
                                if (err) {
                                    console.error('Error creating admin user:', err);
                                    reject(err);
                                    return;
                                }
                                console.log('Admin user created successfully');
                                resolve();
                            }
                        );
                    } else {
                        // Ensure existing admin user is approved
                        db.run('UPDATE users SET approved = 1, role = ? WHERE username = ?', ['admin', 'admin'], (err) => {
                            if (err) {
                                console.error('Error updating admin user:', err);
                            }
                            console.log('Admin user already exists and is approved');
                            resolve();
                        });
                    }
                });
            });
        });
    });
}

// Test database connection
db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
    if (err) {
        console.error('Error checking database tables:', err);
    } else {
        console.log('Database tables check:', row ? 'Tables exist' : 'No tables found');
    }
});

module.exports = {
    db,
    initializeDatabase
}; 