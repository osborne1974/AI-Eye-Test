const express = require('express');
const router = express.Router();
const { isAuthenticated, isApproved } = require('../middleware/auth');
const { db } = require('../config/database');

// Middleware to check if user has dashboard access
const hasDashboardAccess = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    db.get('SELECT role FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user || (user.role !== 'dashboard' && user.role !== 'both')) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        next();
    });
};

// Get user profile
router.get('/profile', isAuthenticated, (req, res) => {
    db.get(
        'SELECT id, username, email, role, approved, created_at FROM users WHERE id = ?',
        [req.session.userId],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json(user);
        }
    );
});

// Check approval status
router.get('/approval-status', isAuthenticated, (req, res) => {
    db.get(
        'SELECT approved FROM users WHERE id = ?',
        [req.session.userId],
        (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ approved: row.approved });
        }
    );
});

// Access MD page (protected by approval and role)
router.get('/md', isAuthenticated, isApproved, hasDashboardAccess, (req, res) => {
    res.sendFile('MD.html', { root: './views' });
});

module.exports = router; 