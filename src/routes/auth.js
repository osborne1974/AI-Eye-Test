const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const { db } = require('../config/database');

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    db.get('SELECT role FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user || (user.role !== 'admin' && user.role !== 'both')) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        next();
    });
};

// Register validation
const registerValidation = [
    body('username').trim().isLength({ min: 3 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('role').optional().isIn(['user', 'admin', 'dashboard', 'both'])
];

// Register route
router.post('/register', registerValidation, async (req, res) => {
    console.log('Register request received:', req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, role = 'user' } = req.body;

    try {
        // Check if user already exists
        db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, row) => {
            if (err) {
                console.error('Database error during user check:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                console.log('User already exists:', username);
                return res.status(400).json({ error: 'Username or email already exists' });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user
            db.run(
                'INSERT INTO users (username, email, password, role, approved) VALUES (?, ?, ?, ?, ?)',
                [username, email, hashedPassword, role, role === 'admin' || role === 'both' ? 1 : 0],
                function (err) {
                    if (err) {
                        console.error('Error creating user:', err);
                        return res.status(500).json({ error: 'Failed to create user' });
                    }
                    console.log('User created successfully:', username);
                    res.status(201).json({ message: 'User registered successfully' });
                }
            );
        });
    } catch (error) {
        console.error('Server error during registration:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login route
router.post('/login', async (req, res) => {
    console.log('Login request received:', req.body);
    const { username, password } = req.body;

    if (!username || !password) {
        console.log('Missing username or password');
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                console.error('Database error during login:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                console.log('User not found:', username);
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            console.log('Found user:', { id: user.id, username: user.username, role: user.role, approved: user.approved });

            try {
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    console.log('Invalid password for user:', username);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                console.log('Password validated for user:', username);

                // Regenerate session to prevent session fixation
                req.session.regenerate((err) => {
                    if (err) {
                        console.error('Error regenerating session:', err);
                        return res.status(500).json({ error: 'Session error' });
                    }

                    req.session.userId = user.id;
                    req.session.role = user.role;
                    console.log('Session created:', { userId: user.id, role: user.role });

                    // Check if user is admin or both role - they should be auto-approved
                    if (user.role === 'admin' || user.role === 'both') {
                        // Ensure admin users are approved
                        db.run('UPDATE users SET approved = 1 WHERE id = ?', [user.id], (err) => {
                            if (err) {
                                console.error('Error updating admin approval status:', err);
                            }
                        });
                        user.approved = 1;
                    }

                    res.json({
                        message: 'Logged in successfully',
                        user: {
                            id: user.id,
                            username: user.username,
                            email: user.email,
                            role: user.role,
                            approved: user.approved
                        }
                    });
                });
            } catch (error) {
                console.error('Error comparing passwords:', error);
                return res.status(500).json({ error: 'Authentication error' });
            }
        });
    } catch (error) {
        console.error('Server error during login:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout route
router.post('/logout', (req, res) => {
    console.log('Logout request received');
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.status(500).json({ error: 'Failed to logout' });
        }
        console.log('User logged out successfully');
        res.json({ message: 'Logged out successfully' });
    });
});

// Get all users (admin only)
router.get('/users', isAdmin, (req, res) => {
    db.all('SELECT id, username, email, role, approved, created_at FROM users', [], (err, users) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).json({ error: 'Failed to fetch users' });
        }
        res.json(users);
    });
});

// Update user role (admin only)
router.put('/users/:userId/role', isAdmin, [
    body('role').isIn(['user', 'admin', 'dashboard', 'both'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { userId } = req.params;
    const { role } = req.body;

    // Prevent admin from changing their own role
    if (userId === req.session.userId) {
        return res.status(400).json({ error: 'Cannot change your own role' });
    }

    db.run(
        'UPDATE users SET role = ?, approved = ? WHERE id = ?',
        [role, role === 'admin' || role === 'both' ? 1 : 0, userId],
        function (err) {
            if (err) {
                console.error('Error updating user role:', err);
                return res.status(500).json({ error: 'Failed to update user role' });
            }
            res.json({ message: 'User role updated successfully' });
        }
    );
});

// Approve user (admin only, for /auth endpoint)
router.put('/users/:userId/approve', isAdmin, (req, res) => {
    const { userId } = req.params;
    db.run('UPDATE users SET approved = 1 WHERE id = ?', [userId], function (err) {
        if (err) {
            console.error('Error approving user:', err);
            return res.status(500).json({ error: 'Failed to approve user' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User approved successfully' });
    });
});

// Delete user (admin only, for /auth endpoint)
router.delete('/users/:userId', isAdmin, (req, res) => {
    const { userId } = req.params;
    // Prevent admin from deleting themselves
    if (userId === req.session.userId) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
        if (err) {
            console.error('Error deleting user:', err);
            return res.status(500).json({ error: 'Failed to delete user' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    });
});

module.exports = router; 