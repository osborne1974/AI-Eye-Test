# ClearVision - Modern Eye Care Platform

A secure web application for eye care services with user authentication, admin dashboard, and protected content access.

## Features

- Secure user authentication with password hashing
- Admin dashboard for user management
- Protected MD portal for approved users
- SQLite database for data persistence
- Session-based authentication
- Input validation and security best practices

## Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd clearvision
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```
PORT=3000
SESSION_SECRET=your-secret-key
NODE_ENV=development
```

4. Create the database directory:
```bash
mkdir db
```

## Running the Application

1. Start the development server:
```bash
npm run dev
```

2. For production:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## Default Admin Account

- Username: admin
- Password: admin123

**Important**: Change the default admin password in production!

## Project Structure

```
clearvision/
├── src/
│   ├── app.js              # Main application file
│   ├── config/
│   │   └── database.js     # Database configuration
│   ├── middleware/
│   │   └── auth.js         # Authentication middleware
│   └── routes/
│       ├── admin.js        # Admin routes
│       ├── auth.js         # Authentication routes
│       └── user.js         # User routes
├── views/
│   ├── index.html          # Home page
│   ├── login.html          # Login page
│   ├── admin.html          # Admin dashboard
│   └── MD.html             # Protected MD portal
├── db/                     # Database files
├── package.json
└── README.md
```

## Security Features

- Password hashing using bcrypt
- Session management with express-session
- SQL injection prevention
- XSS protection with helmet
- Input validation
- CSRF protection
- Secure cookie settings

## API Endpoints

### Authentication
- POST /auth/register - Register new user
- POST /auth/login - User login
- POST /auth/logout - User logout

### Admin
- GET /admin/users - Get all users
- POST /admin/users/:id/approve - Approve user
- DELETE /admin/users/:id - Delete user
- GET /admin/pending-approvals - Get pending approvals

### User
- GET /user/profile - Get user profile
- GET /user/approval-status - Check approval status
- GET /user/md - Access MD portal (requires approval)

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License. 