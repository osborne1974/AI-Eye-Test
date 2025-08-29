const { db } = require('../config/database');

const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.session && req.session.userId) {
        db.get('SELECT role FROM users WHERE id = ?', [req.session.userId], (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row && (row.role === 'admin' || row.role === 'both')) {
                next();
            } else {
                res.status(403).json({ error: 'Forbidden' });
            }
        });
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

const isApproved = (req, res, next) => {
    if (req.session && req.session.userId) {
        db.get('SELECT approved FROM users WHERE id = ?', [req.session.userId], (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row && row.approved) {
                next();
            } else {
                res.status(403).json({ error: 'Account pending approval' });
            }
        });
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

module.exports = {
    isAuthenticated,
    isAdmin,
    isApproved
}; 