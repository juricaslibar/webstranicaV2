require('dotenv').config()

const dotenv = require('dotenv');
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require('bcrypt'); 
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session'); 
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)

const app = express(); 

// Middleware
app.use(express.json());

// Session setup
app.use(session({
    secret: 'your-secret-key', // Change this to a strong secret
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
})); 

// Create data directory if it doesn't exist
const DATA_DIR = './data';
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

// Ensure users file exists
const USERS_FILE = path.join(DATA_DIR, 'users.json');
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify({}), 'utf8');
}

// Encryption setup 
const ENCRYPTION_KEY = process.env.RANDOM_ENCRYPT; // Store this securely in a real application
const IV_LENGTH = 16;

// Function to encrypt data
const encrypt = (text) => {
    const iv = crypto.randomBytes(IV_LENGTH); 
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

// Function to decrypt data
const decrypt = (text) => {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
};

// Generate device ID
const generateDeviceId = (ip) => {
    return encrypt(ip);
};

// Read users function
const readUsers = () => {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading users file:', error);
        return {};
    }
};

// Write users function
const writeUsers = (users) => {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    } catch (error) {
        console.error('Error writing users file:', error);
    }
};

// Get client IP and user agent
const getClientInfo = (req) => {  
    const ip = req.ip ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];
    return { ip, userAgent };
};

// Middleware to serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Set up EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


app.use(passport.initialize());
app.use(passport.session()); 


// Passport strategy for Google login
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
            passReqToCallback: true,
        },
        (req, accessToken, refreshToken, profile, done) => {
            try {
                const users = readUsers();
                const email = profile.emails[0].value; // Extract user's email
                const userId = email + "@google";

                // Ensure user exists in the system
                if (!users[userId]) {
                    // Create new user for Google login
                    users[userId] = {
                        name: profile.name.givenName,
                        email,
                        password: null, // Not applicable for Google login
                        registrationDate: new Date().toISOString(),
                        isConfirmed: true, // Google users are considered confirmed
                        isSubscribed1: false,
                        isSubscribed2: false,
                        devices: {},
                    };
                }

                const user = users[userId];
                let devices = user.devices || {};

                // Extract client info (IP, user-agent) only if session is already initialized
                const ip = req.session ? getClientInfo(req).ip : null;
                const userAgent = req.session ? getClientInfo(req).userAgent : null;
                const encryptedIP = ip ? encrypt(ip) : null;

                // Check existing devices
                const deviceKeys = Object.keys(devices);

                if (deviceKeys.length == 0) {
                    // First device
                    devices[deviceKeys.length] = {
                        ip: encryptedIP,
                        lastUsed: new Date().toISOString(),
                        userAgent,
                    };
                    req.session.username = userId; 
                } else if (deviceKeys.length == 1) {
                    // Second device
                    if (decrypt(devices[0].ip) == ip) {
                        devices[0].lastUsed = new Date().toISOString();
                        devices[0].userAgent = userAgent;
                    } else {
                        devices[deviceKeys.length] = {
                            ip: encryptedIP,
                            lastUsed: new Date().toISOString(),
                            userAgent,
                        };
                    }
                } else {
                    // Handle exceeding device limits
                    return done(null, null);
                }

                user.devices = devices;
                writeUsers(users);

                return done(null, {
                    id: userId, // Ensure this field exists
                    email: user.email,
                    isConfirmed: user.isConfirmed,
                    devices: devices,
                });
            } catch (error) {
                console.error("Google login error:", error);
                return done(error, null);
            }
        }
    )
);


passport.serializeUser((user, done) => {
    if (user && user.id) {
        console.log("Serializing user:", user.id);
        done(null, user.id); // Store only the user ID in the session
    } else {
        console.error("Failed to serialize user: Missing user.id", user);
        done(null, false); // Pass `false` to indicate failure without throwing an error
    }
});

passport.deserializeUser((id, done) => {
    const users = readUsers();
    const user = users[id]; // Retrieve the full user object
    if (user) {
        done(null, user); // Pass the full user object to the request
    } else {
        console.error("Failed to deserialize user: User not found");
        done(null, false); // Pass `false` to indicate failure without throwing an error
    }
});

// Authentication routes
app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
        console.log("Authenticated user:", req.user); // Debug log
        if (req.user) {
            req.session.username = req.user.id;
            console.log("Session username set to:", req.session.username);
        } else {
            console.error("Authentication failed: req.user is undefined.");
        }

        res.redirect("/");
    }
);


const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_PORT === '465',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const users = readUsers();

        // Check if username exists
        if (users[username]) {
            return res.status(400).json({ error: 'Korisnicko ime vec postoji' });
        }

        // Check if email is already in use
        const emailInUse = Object.values(users).some(user => user.email === email);
        if (emailInUse) {
            return res.status(400).json({ error: 'Email vec postoji' });
        }

        // Get client info and create first device
        const { ip, userAgent } = getClientInfo(req);
        const encryptedIP = encrypt(ip);

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Store user with first device
        users[username] = {
            name: username,
            email,
            password: hashedPassword,
            registrationDate: new Date().toISOString(),
            isConfirmed: false,
            isSubscribed1: false,
            isSubscribed2: false,
            devices: {
                [0]: {
                    ip: encryptedIP,
                    userAgent,
                    lastUsed: new Date().toISOString(),
                }
            }
        };
        writeUsers(users);

        // Generate email token
        const emailToken = jwt.sign(
            { username }, // Store username instead of user object
            process.env.EMAIL_SECRET,
            { expiresIn: '1d' }
        );

        const url = `${process.env.BASE_URL}/confirmation/${emailToken}`;


        // Send confirmation email
        transporter.sendMail({
            from: '"Stat&Mat" <your-email@gmail.com>',
            to: email,
            subject: 'Potvrda e-mail adrese',
            html: `
<div style="font-family: Arial, sans-serif; line-height: 1.5; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
    <div style="text-align: center; margin-bottom: 20px;">
        <img src="cid:logo" style="max-width: 150px;">
    </div>
    <h2 style="text-align: center; color: #007bff;">Potvrdite svoju e-mail adresu</h2>
    <p>Poštovani,</p>
    <p>Hvala što ste se registrirali! Kako bismo dovršili postupak registracije, molimo Vas da potvrdite svoju e-mail adresu klikom na donji gumb:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="${url}" style="background-color: #007bff; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-size: 16px;">Potvrdi e-mail</a>
    </div>
    <p>Ako ne možete kliknuti na gumb, kopirajte i zalijepite sljedeći link u svoj preglednik:</p>
    <p style="word-break: break-word; text-align: center; color: #555;">${url}</p>
    <p>Za dodatne informacije slobodno nas kontaktirajte.</p>
    <p>S poštovanjem,</p>
    <p><strong>Vaš Tim</strong></p>
</div>
`,
            attachments: [
                {
                    filename: 'logo.ico',
                    path: './public/sprites/logo.ico', // Path to the logo file
                    cid: 'logo' // Same as the cid used in the img src
                }
            ]
        });

        // Send JSON response first
        res.json({
            message: 'Registration successful',
            redirect: '/load'
        });


    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


app.get('/confirmation/:token', async (req, res) => { 
    try {
        // Verify token
        const { username } = jwt.verify(req.params.token, process.env.EMAIL_SECRET); 

        const users = readUsers();

        // Check if the user exists
        if (!users[username]) {
            return res.status(400).send('Invalid or expired token.');
        }

        // Mark user as confirmed
        users[username].isConfirmed = true;
        writeUsers(users);

        res.redirect(`${process.env.BASE_URL}/login`);
    } catch (error) {
        console.error('Email confirmation error:', error);
        res.status(400).send('Invalid or expired token.');
    }
});

app.post('/resend-email', async (req, res) => {
    try {
        const { emails } = req.body;

        if (!emails || emails.length === 0) {
            return res.status(400).json({ error: 'Please provide an email address.' });
        }

        const email = emails[0];  // Since we allow only one email

        const users = readUsers();

        const user = Object.values(users).find(u => u.email === email && !u.isConfirmed);

        if (!user) {
            return res.status(404).json({ error: 'Email address not found or already confirmed.' });
        }

        // Generate email token
        const emailToken = jwt.sign(
            { username: user.username },
            process.env.EMAIL_SECRET,
            { expiresIn: '1d' }
        );

        const url = `${process.env.BASE_URL}/confirmation/${emailToken}`;

        // Send confirmation email
        await transporter.sendMail({
            from: '"Stat&Mat" <your-email@gmail.com>',
            to: email,
            subject: 'Potvrda e-mail adrese',
            html: `
<div style="font-family: Arial, sans-serif; line-height: 1.5; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
    <div style="text-align: center; margin-bottom: 20px;">
        <img src="cid:logo" style="max-width: 150px;">
    </div>
    <h2 style="text-align: center; color: #007bff;">Potvrdite svoju e-mail adresu</h2>
    <p>Poštovani,</p>
    <p>Hvala što ste se registrirali! Kako bismo dovršili postupak registracije, molimo Vas da potvrdite svoju e-mail adresu klikom na donji gumb:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="${url}" style="background-color: #007bff; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-size: 16px;">Potvrdi e-mail</a>
    </div>
    <p>Ako ne možete kliknuti na gumb, kopirajte i zalijepite sljedeći link u svoj preglednik:</p>
    <p style="word-break: break-word; text-align: center; color: #555;">${url}</p>
    <p>Za dodatne informacije slobodno nas kontaktirajte.</p>
    <p>S poštovanjem,</p>
    <p><strong>Vaš Tim</strong></p>
</div>
`,
            attachments: [
                {
                    filename: 'logo.ico',
                    path: './public/sprites/logo.ico', // Path to the logo file
                    cid: 'logo' // Same as the cid used in the img src
                }
            ]
        });

        res.json({
            message: 'Confirmation email has been resent.',
            url: url
        });

    } catch (error) {
        console.error('Error resending email:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


app.post('/api/login', async (req, res) => {
    try {
        const { userInput, password, deviceId } = req.body;

        // Validation
        if (!userInput || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const users = readUsers();

        // Find user
        const username = Object.keys(users).find(key =>
            key === userInput || users[key].email === userInput
        );

        if (!username || !users[username]) {
            return res.status(401).json({ error: 'Netocno korisnicko ime' });
        }

        if (!users[username].isConfirmed) {
            return res.status(401).json({ error: 'Potvrdite email adresu za nastavak' }); 
        }

        // Verify password
        const isValid = await bcrypt.compare(password, users[username].password);
        if (!isValid) {
            return res.status(401).json({ error: 'Netocna lozinka' });
        }

        const { ip, userAgent } = getClientInfo(req);
        const user = users[username];
        const devices = user.devices;

        // Check existing devices
        const deviceKeys = Object.keys(devices);

        if (deviceKeys.length == 1) {
            // Second device
            if (decrypt(devices[0].ip) == ip && devices[0].userAgent == userAgent) {
                devices[0].lastUsed = new Date().toISOString();
            } else {
                devices[deviceKeys.length] = {
                    ip: encrypt(ip),
                    userAgent,
                    lastUsed: new Date().toISOString(),
                };
            }
        } else {
            if (decrypt(devices[0].ip) == ip && devices[0].userAgent == userAgent) {
                devices[0].lastUsed = new Date().toISOString();
            }
            else if (decrypt(devices[1].ip) == ip && devices[1].userAgent == userAgent) {
                devices[1].lastUsed = new Date().toISOString();
            } else {
                return res.status(400).json({
                    error: 'Maximum device limit reached',
                    message: 'You have reached the maximum number of devices (2) for this account.',
                    devices: deviceList });
            }            
        }

        writeUsers(users);
            req.session.username = username; // Store username in session
            return res.json({
                message: 'Login successful',
                redirect: '/',
                deviceId
            });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Middleware to ensure user is logged in
function ensureLoggedIn(req, res, next) {
    if (req.session && req.session.username) {
        return next(); // User is logged in, proceed to the next middleware/route handler
    } else {
        res.redirect('/login'); // Redirect to login page if not authenticated
    }
}

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out' });
        }
        res.json({ message: 'Logout successful' });
    });
});

app.get('/api/check-login', (req, res) => {
    if (req.session.username) {
        if (req.session.username.endsWith("@google")) {
            return res.status(200).json({
                loggedIn: true,
                username: req.session.username.slice(0, -"@google".length) // Include the username in the response
            });
        }
        return res.status(200).json({
            loggedIn: true,
            username: req.session.username // Include the username in the response
        });
    }
    res.status(401).json({ loggedIn: false });
});

// Get registered devices
app.get('/api/devices/:username', async (req, res) => {
    try {
        const users = readUsers(); // Read the users from the JSON file
        const user = users[req.params.username]; // Get the user by username

        if (!user) {
            return res.status(404).json({ error: 'User  not found' }); // Return error if user does not exist
        }

        // Map the devices to a more readable format
        const devices = Object.entries(user.devices).map(([id, device]) => ({
            id,
            lastUsed: device.lastUsed,
            userAgent: device.userAgent
        }));

        res.json({ devices }); // Return the devices in the response
    } catch (error) {
        console.error('Error fetching devices:', error);
        res.status(500).json({ error: 'Server error' }); // Handle server errors
    }
});

//Subscription - prvi kolokvij

// Function to check subscription status
const getSubscriptionStatus1 = (username) => {
    const users = readUsers(); // Read the users from the JSON file
    const user = users[username]; // Get the user by username

    if (user && user.isSubscribed1) {
        return { isSubscribed1: true };
    } else {
        return { isSubscribed1: false };
    }
};

// Middleware to check if the user is subscribed
const requireSubscription1 = (req, res, next) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const status = getSubscriptionStatus1(username); // Get the subscription status of the user

    if (!status.isSubscribed1) {
        return res.status(403).json({ error: 'Subscription required' });
    }

    next(); // User is subscribed, proceed to the next middleware or route handler
};

// Endpoint to get subscription status
app.get('/api/subscription-status1', (req, res) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const status = getSubscriptionStatus1(username); // Get the subscription status of the logged-in user

    res.json(status); // Return the subscription status in the response
}); 

app.post('/checkout1', ensureLoggedIn, async (req, res) => {
    const session = await stripe.checkout.sessions.create({
        line_items: [
            {
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: 'Matematika - prvi kolokvij'
                    },
                    unit_amount: 20 * 100
                },
                quantity: 1
            }
        ],
        mode: 'payment',
        success_url: `${process.env.BASE_URL}/complete1?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.BASE_URL}/cancel`  
    })

    res.redirect(session.url) 
})
 
app.get('/complete1', async (req, res) => {
    const [session, lineItems] = await Promise.all([
            stripe.checkout.sessions.retrieve(req.query.session_id, { expand: ['payment_intent.payment_method'] }),
            stripe.checkout.sessions.listLineItems(req.query.session_id)
        ]);

<<<<<<< HEAD
=======
    console.log(JSON.stringify(result, null, 2)); // 2 spaces for indentation
>>>>>>> ce79962be2adc503e2721e8d74f70abb71fd7b17
        // Log the session and line items details
        console.log("Session Details:", {
            id: session.id,
            amount_total: session.amount_total,
            currency: session.currency,
            payment_status: session.payment_status,
            customer_email: session.customer_details?.email,
            line_items: lineItems.data.map(item => ({
                description: item.description,
                amount: item.amount_total,
            })),
        });

    const username = req.session.username;
    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const users = readUsers();
    const user = users[username];
    user.isSubscribed1 = true;  // Set the subscription status to true
    writeUsers(users); 

    // Send email
    const mailOptions = {
        from: '"Stat&Mat" <your-email@gmail.com>',
        to: user.email,
        subject: 'Zahvaljujemo na kupovini!',
        html: `<!DOCTYPE html>
<html lang="hr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zahvalnica za kupovinu</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f9f9f9;
        }
        .email-container {
            max-width: 600px;
            margin: 20px auto;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .header img {
            width: 80px;
            height: auto;
        }
        .content {
            text-align: left;
        }
        .content h1 {
            color: #333333;
            font-size: 24px;
        }
        .content p {
            color: #555555;
            font-size: 16px;
            margin: 10px 0;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #777777;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <img src="cid:logo.ico" alt="Logo">
        </div>
        <div class="content">
            <h1>Hvala Vam na kupovini!</h1>
            <p>Poštovani/a,</p>
            <p>Zahvaljujemo na Vašoj narudžbi. Uspješno ste kupili proizvod <strong>"Matematika - prvi kolokvij"</strong>.</p>
            <p>Želimo Vam puno uspjeha u učenju i savladavanju gradiva.</p>
            <p>Ako imate dodatnih pitanja, slobodno nas kontaktirajte putem e-maila ili telefona.</p>
            <p>Srdačan pozdrav,</p>
            <p><strong>Vaš Tim</strong></p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Vaša Tvrtka. Sva prava pridržana.</p>
        </div>
    </div>
</body>
</html>`,
        attachments: [
            {
                filename: 'logo.ico',
                path: './public/sprites/logo.ico',
                cid: 'logo.ico' // CID mora odgovarati src u HTML-u
            }
        ]
    };

    transporter.sendMail(mailOptions);

    res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Payment Successful</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding: 2rem;
                        background-color: #f8fafc;
                        color: #1e293b;
                    }
                    .message {
                        font-size: 1.5rem;
                        margin-bottom: 1rem;
                    }
                    .redirect {
                        font-size: 1rem;
                        color: #64748b;
                    }
                </style>
                <script>
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 2000); // Redirect after 2 seconds
                </script>
            </head>
            <body>
                <div class="message">Your payment was successful!</div>
                <div class="redirect">Redirecting to the homepage...</div>
            </body>
            </html>
        `);
})

//Subscription - drugi kolokvij

// Function to check subscription status
const getSubscriptionStatus2 = (username) => {
    const users = readUsers(); // Read the users from the JSON file
    const user = users[username]; // Get the user by username

    if (user && user.isSubscribed2) {
        return { isSubscribed2: true };
    } else {
        return { isSubscribed2: false };
    }
};

// Middleware to check if the user is subscribed
const requireSubscription2 = (req, res, next) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const status = getSubscriptionStatus2(username); // Get the subscription status of the user

    if (!status.isSubscribed2) {
        return res.status(403).json({ error: 'Subscription required' });
    }

    next(); // User is subscribed, proceed to the next middleware or route handler
};

// Endpoint to get subscription status
app.get('/api/subscription-status2', (req, res) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const status = getSubscriptionStatus2(username); // Get the subscription status of the logged-in user

    res.json(status); // Return the subscription status in the response
});

app.post('/checkout2', ensureLoggedIn, async (req, res) => {
    const session = await stripe.checkout.sessions.create({
        line_items: [
            {
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: 'Matematika - drugi kolokvij'
                    },
                    unit_amount: 20 * 100
                },
                quantity: 1
            }
        ],
        mode: 'payment',
        success_url: `${process.env.BASE_URL}/complete2?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.BASE_URL}/cancel`
    })

    res.redirect(session.url)
})

app.get('/complete2', async (req, res) => {
    const [session, lineItems] = await Promise.all([
            stripe.checkout.sessions.retrieve(req.query.session_id, { expand: ['payment_intent.payment_method'] }),
            stripe.checkout.sessions.listLineItems(req.query.session_id)
        ]);

        // Log the session and line items details
        console.log("Session Details:", {
            id: session.id,
            amount_total: session.amount_total,
            currency: session.currency,
            payment_status: session.payment_status,
            customer_email: session.customer_details?.email,
            line_items: lineItems.data.map(item => ({
                description: item.description,
                amount: item.amount_total,
            })),
        });

    const username = req.session.username; 
    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const users = readUsers();
    const user = users[username];
    user.isSubscribed2 = true;  // Set the subscription status to true
    writeUsers(users);

    res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Payment Successful</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding: 2rem;
                        background-color: #f8fafc;
                        color: #1e293b;
                    }
                    .message {
                        font-size: 1.5rem;
                        margin-bottom: 1rem;
                    }
                    .redirect {
                        font-size: 1rem;
                        color: #64748b;
                    }
                </style>
                <script>
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 2000); // Redirect after 2 seconds
                </script>
            </head>
            <body>
                <div class="message">Your payment was successful!</div>
                <div class="redirect">Redirecting to the homepage...</div>
            </body>
            </html>
        `);
})

// Routes
app.get('/Matematika1', (req, res) => {
    res.render('Matematika1.ejs')
})
app.get('/Matematika2', (req, res) => {
    res.render('Matematika2.ejs')
})
app.get('/load', (req, res) => {
    res.render('loading.ejs')
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'main.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/cancel', (req, res) => {
    res.redirect('/')
})
// Protected routes requiring subscription
app.get('/Matematika_prvi_kol', requireSubscription1, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Matematika_prvi_kol.html')); 
});

app.get('/Matematika_drugi_kol', requireSubscription2, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Matematika_drugi_kol.html'));
});

app.get('/video1', requireSubscription1  , (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'video1.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server started'))
