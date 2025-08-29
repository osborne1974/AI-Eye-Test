const express = require('express');
const router = express.Router();
const { db } = require('../config/database');
const { isAdmin } = require('../middleware/auth');

// Get all users
router.get('/users', isAdmin, (req, res) => {
    db.all('SELECT id, username, email, role, approved, created_at FROM users', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(rows);
    });
});

// Approve user
router.post('/users/:id/approve', isAdmin, (req, res) => {
    const userId = req.params.id;
    db.run('UPDATE users SET approved = 1 WHERE id = ?', [userId], function (err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User approved successfully' });
    });
});

// Delete user
router.delete('/users/:id', isAdmin, (req, res) => {
    const userId = req.params.id;
    db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    });
});

// Get pending approvals
router.get('/pending-approvals', isAdmin, (req, res) => {
    db.all('SELECT id, username, email, created_at FROM users WHERE approved = 0', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(rows);
    });
});

module.exports = router; 