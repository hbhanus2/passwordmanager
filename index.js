const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { create } = require('express-handlebars');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config(); // Load environment variables from .env file

const app = express();
const PORT = 8000;
const SALT_ROUNDS = 10;
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // Persistent encryption key
const IV_LENGTH = 16; // Initialization vector length

// Encryption function
function encryptPassword(password) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(password, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
}

// Decryption function
function decryptPassword(encryptedPassword) {
    try {
        const [iv, encrypted] = encryptedPassword.split(':');
        if (!iv || !encrypted) throw new Error('Invalid encrypted password format');

        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, Buffer.from(iv, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error('Decryption error:', err.message);
        throw new Error('Error decrypting password');
    }
}

// Initialize Handlebars
const hbs = create({ defaultLayout: 'main', extname: '.handlebars' });

// Setup SQLite database
const db = new sqlite3.Database('./database/passwordmanager.sqlite', (err) => {
    if (err) console.error('Error connecting to SQLite database:', err.message);
});

// Middleware
app.use(express.urlencoded({ extended: false })); // For form submissions
app.use(express.json()); // For JSON requests
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Setup Handlebars
app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
    res.render('home');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (row) {
            res.send("Username already exists");
        } else {
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
            db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
                if (err) {
                    res.send("Error creating user");
                } else {
                    res.redirect('/');
                }
            });
        }
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            res.cookie('username', username);
            res.redirect('/savedpasswords');
        } else {
            const errorMessage = user ? "Invalid password" : "User not found";
            res.render('login', { errorMessage });
        }
    });
});

// Show Saved Passwords Route
app.get('/savedpasswords', (req, res) => {
    const username = req.cookies.username;
    if (!username) return res.redirect('/');

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (user) {
            db.all('SELECT * FROM savedpass WHERE user_id = ?', [user.user_id], (err, savedPasswords) => {
                res.render('savepass', { username, savedPasswords });
            });
        } else {
            res.redirect('/');
        }
    });
});

// Add New Password Route
app.get('/add_password', (req, res) => {
    const username = req.cookies.username;
    if (!username) return res.redirect('/');
    res.render('addpassword'); // Render the add password form
});

// Handle Add Password Form Submission
app.post('/add_password', (req, res) => {
    const { websiteName, username, password } = req.body;
    const currentUser = req.cookies.username;

    if (!currentUser) {
        return res.redirect('/');
    }

    const encryptedPassword = encryptPassword(password);

    db.get('SELECT * FROM users WHERE username = ?', [currentUser], (err, user) => {
        if (user) {
            db.run(
                'INSERT INTO savedpass (user_id, name, login_username, encrypted_password) VALUES (?, ?, ?,?)',
                [user.user_id, websiteName, username, encryptedPassword],
                (err) => {
                    if (err) {
                        console.error("Error saving password:", err);
                        return res.send("Error saving password");
                    }
                    res.redirect('/savedpasswords');
                }
            );
        } else {
            res.redirect('/');
        }
    });
});

app.get('/passpage', (req, res) => {
    const username = req.cookies.username;
    if (!username) return res.redirect('/');

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (user) {
            db.all('SELECT * FROM savedpass WHERE user_id = ?', [user.user_id], (err, savedPasswords) => {
                res.render('savepass', { username, savedPasswords });
            });
        } else {
            res.redirect('/');
        }
    });
});
// Edit password route: GET
app.get('/editpassword/:pass_id', async (req, res) => {
    const { pass_id } = req.params;

    try {
        const query = 'SELECT * FROM savedpass WHERE pass_id = ?';
        const password = await db.get(query, [pass_id]);
        if (password) {
            res.render('editpassword', { password });
        } else {
            res.status(404).send('Password entry not found.');
        }
    } catch (error) {
        console.error('Error fetching password entry:', error);
        res.status(500).send('Internal server error');
    }
});



app.post('/editpassword/:pass_id', async (req, res) => {
    const { pass_id } = req.params;
    const { name, login_username, encrypted_password } = req.body;

    try {
        const query = `
            UPDATE savedpass 
            SET name = ?, login_username = ?, encrypted_password = ? 
            WHERE pass_id = ?`;
        await db.run(query, [name, login_username, encrypted_password, pass_id]);
        res.redirect('/savedpasswords'); // Redirect to password list after successful edit
    } catch (error) {
        console.error('Error updating password entry:', error);
        res.status(500).send('Internal server error');
    }
});




// Decrypt Password Route
app.post('/decrypt-password', (req, res) => {
    const { encryptedPassword } = req.body;
    try {
        const decryptedPassword = decryptPassword(encryptedPassword);
        res.json({ decryptedPassword });
    } catch (err) {
        res.status(500).send("Error decrypting password");
    }
});


app.post('/deletepassword/:pass_id', async (req, res) => {
    const { pass_id } = req.params;

    try {
        const query = 'DELETE FROM savedpass WHERE pass_id = ?';
        await db.run(query, [pass_id]);
        res.redirect('/savedpasswords'); // Redirect to password list after deletion
    } catch (error) {
        console.error('Error deleting password entry:', error);
        res.status(500).send('Internal server error');
    }
});



// Logout
app.get('/logout', (req, res) => {
    res.clearCookie('username');
    res.redirect('/');
});

// Server Start
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
