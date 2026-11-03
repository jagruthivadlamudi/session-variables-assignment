
const express = require('express');
const mysql = require('mysql2');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');

const app = express();

// Configure session storage
app.use(session({
  secret: process.env.SESSION_SECRET || 'local-development-only-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Allow the server to read form data
app.use(express.urlencoded({ extended: true }));

// Serve HTML files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Connect to the MySQL database
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.ROOTPASS || '',
  database: 'paws',
  port: 3306
});

db.connect(err => {
  if (err) {
    console.error('MySQL connection failed:', err.message);
  } else {
    console.log('Connected to MySQL');
  }
});

// Escape user-provided text before displaying it in HTML
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

// Display a message with a link to the login page
function page(message) {
  return `<h2>${message}</h2>
          <p><a href="/login.html">Back to login</a></p>`;
}

// Redirect visitors to the registration page
app.get('/', (req, res) => {
  res.redirect('/register.html');
});

// Register a new user
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send(page('Please complete all fields.'));
  }

  // Securely hash the password before storing it
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(
    password, salt, 100000, 64, 'sha512'
  ).toString('hex');

  db.query(
    'INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)',
    [username, email, hash, salt],
    (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).send(
            page('Username or email already registered.')
          );
        }

        console.error(err);
        return res.status(500).send(
          page('Registration failed. Please try again.')
        );
      }

      res.send(page('You have successfully registered'));
    }
  );
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send(
      page('Login credentials were incorrect')
    );
  }

  // Find the user in the database
  db.query(
    'SELECT password, salt FROM users WHERE username = ?',
    [username],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).send(
          page('Login could not be completed.')
        );
      }

      if (rows.length === 0) {
        return res.status(401).send(
          page('Login credentials were incorrect')
        );
      }

      // Verify the entered password
      const hash = crypto.pbkdf2Sync(
        password, rows[0].salt, 100000, 64, 'sha512'
      ).toString('hex');

      const stored = Buffer.from(rows[0].password, 'hex');
      const entered = Buffer.from(hash, 'hex');

      if (
        stored.length !== entered.length ||
        !crypto.timingSafeEqual(stored, entered)
      ) {
        return res.status(401).send(
          page('Login credentials were incorrect')
        );
      }

      // Regenerate the session after successful authentication
      req.session.regenerate(sessionError => {
        if (sessionError) {
          console.error(sessionError);
          return res.status(500).send(
            page('Login could not be completed.')
          );
        }

        // Store the logged-in username in the session
        req.session.username = username;

        req.session.save(saveError => {
          if (saveError) {
            console.error(saveError);
            return res.status(500).send(
              page('Login could not be completed.')
            );
          }

          res.send(`
            <h2>You have logged in successfully!</h2>
            <p>Welcome, ${escapeHTML(username)}!</p>
            <p><a href="/profile">View Profile</a></p>
            <p><a href="/logout">Logout</a></p>
          `);
        });
      });
    }
  );
});

// Profile page: display the username stored in the session
app.get('/profile', (req, res) => {
  if (!req.session.username) {
    return res.redirect('/login.html');
  }

  res.send(`
    <h1>User Profile</h1>
    <h2>Welcome, ${escapeHTML(req.session.username)}!</h2>
    <p>You are currently logged in.</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

// Logout endpoint: destroy the user's session
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).send('Logout failed.');
    }

    // Remove the session cookie from the browser
    res.clearCookie('connect.sid');

    res.send(`
      <h2>You have successfully logged out!</h2>
      <p><a href="/login.html">Login Again</a></p>
    `);
  });
});

// Start the server
app.listen(3000, () => {
  console.log('Open http://localhost:3000');
});
