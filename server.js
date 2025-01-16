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
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const User = require('./models/user');
const axios = require('axios'); // CommonJS syntax
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;


const mongoURI = `${process.env.MONGODB_URI}`;
mongoose.connect(mongoURI)
    .then(() => app.listen(PORT, () => console.log('Server started')))
    .catch((err) => console.log(err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Allow requests from your frontend domain
app.use(cors({
    origin: '*',  // Allow all origins
    credentials: true // Allow cookies and credentials
}));

// Session setup 
app.use(session({
    secret: process.env.EMAIL_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: mongoURI,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60, // 14 days
        autoRemove: 'native',
    }),
    cookie: {
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',  // Fixes the syntax issue
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));


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

// Get all users
const readUsers = async () => {
    try {
        const users = await User.find();
        return users;
    } catch (error) {
        console.error('Error reading users from the database:', error);
        return {};
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


passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
            passReqToCallback: true,
        },
        async (req, accessToken, refreshToken, profile, done) => {
            try {
                const email = profile.emails[0].value; // Extract user's email
                const userId = crypto.randomBytes(15).toString('hex') + "@google";

                const ip = req.session ? getClientInfo(req).ip : null;
                const userAgent = req.session ? getClientInfo(req).userAgent : null;
                const encryptedIP = ip ? encrypt(ip) : null;

                let user = await User.findOne({ email: email });

                if (!user) {
                    // Create a new user if not found
                    user = new User({
                        name: userId,
                        email: email,
                        password: null,
                        isConfirmed: true,
                        isSubscribed1: false,
                        isSubscribed2: false,
                        devices: [{ ip: encryptedIP, userAgent: userAgent }],
                    });
                    await user.save();
                    return done(null, userId); // Pass user ID for session
                }

                // If the user exists, check device registration
                const isDeviceRegistered = user.devices.some(
                    (dev) =>
                        dev.userAgent === userAgent
                );

                if (!isDeviceRegistered) {
                    if (user.devices.length >= 2) {
                        // Prevent login if the user tries to register a third device
                        console.warn(
                            `User ${userId} tried to register a third device. Login denied.`
                        );
                        return done(null, false, { message: "Too many devices registered." });
                    }

                    // Register the new device
                    user.devices.push({ ip: encryptedIP, userAgent: userAgent });
                    await user.save();
                }

                return done(null, userId); // Pass user ID for session
            } catch (error) {
                console.error("Google login error:", error);
                return done(error, null);
            }
        }
    )
);


passport.serializeUser((userId, done) => {
    done(null, userId); // Store only the user ID in the session
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findOne({ name: id });
        if (!user) {
            console.error("Failed to deserialize user: User not found");
            return done(null, false);
        }
        return done(null, user); // Pass the full user object
    } catch (error) {
        console.error("Error during deserialization:", error);
        done(error, null);
    }
});

// Google Authentication Initiation
app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    async (req, res) => {
        try {
            if (req.user) {
                req.session.username = req.user; // Save the username to the session
                await req.session.save(); // Ensure the session is saved
                res.redirect("/"); // Redirect to the homepage
            } else {
                console.error("Authentication failed: req.user is undefined or login denied.");
                res.redirect("/error"); // Redirect to an error page
            }
        } catch (error) {
            console.error("Error during Google auth callback:", error);
            res.redirect("/error"); // Redirect to an error page
        }
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

        // Get client info and create first device
        const { ip, userAgent } = getClientInfo(req);
        const encryptedIP = encrypt(ip);

        // Check if username exists
        const usernameExists = await User.findOne({ name: username });
        if (usernameExists) {
            return res.status(400).json({ error: 'Korisnicko ime vec postoji' });
        }

        // Check if email is already in use
        const emailExists = await User.findOne({ email });
        if (emailExists) {
            return res.status(400).json({ error: 'Email vec postoji' });
        }

        // Store username and device information
        const user = new User({
            name: username,
            email: email,
            password: password,
            isConfirmed: false,
            isSubscribed1: false,
            isSubscribed2: false,
            devices: { ip: encryptedIP, userAgent },
        });

        await user.save(); // Save the user to the database

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
    <p><strong>Stat&Mat</strong></p>
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

        // Send JSON response
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
        User.findOne({ name: username })
            .then(present => {
                if (present == null) {
                    return res.status(400).send('Invalid or expired token.');
                }
                present.isConfirmed = true;
                present.save();
                res.redirect(`${process.env.BASE_URL}/login`);
            })
            .catch(err => {
                console.error('Email confirmation error:', error);
                res.status(400).send('Invalid or expired token.');
            });

    } catch (error) {
        console.error('Could not verify token', error);
        res.status(400).send('Could not verify token');
    }
});

app.post('/resend-email', async (req, res) => {
    try {
        const { emails } = req.body;

        if (!emails || emails.length === 0) {
            return res.status(400).json({ error: 'Please provide an email address.' });
        }

        const email = emails[0];  // Since we allow only one email

        User.findOne({ email: email })
            .then(present => {
                if (present == null || present.isConfirmed) {
                    return res.status(400).json({ error: 'Email address not found or already confirmed.' });
                }


                // Generate email token
                const emailToken = jwt.sign(
                    { username: present.username },
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
    <p><strong>Stat&Mat</strong></p>
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
            })

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

        // Get client info
        const ip = req.session ? getClientInfo(req).ip : null;
        const userAgent = req.session ? getClientInfo(req).userAgent : null;
        const encryptedIP = ip ? encrypt(ip) : null;

        const user = await User.findOne({
            $or: [{ name: userInput }, { email: userInput }]
        });

        if (!user) {
            return res.status(401).json({ error: 'Netočno korisničko ime ili email adresa' });
        }
        if (user.password !== password) {
            return res.status(401).json({ error: 'Netočna lozinka' });
        }
        if (!user.isConfirmed) {
            return res.status(401).json({ error: 'Potvrdite email adresu za nastavak' });
        }

        const device = user.devices;
        let sessionSet = false;

        // Iterate through devices
        for (const dev of device) {
            if (!dev) continue;

            if (dev.userAgent !== userAgent && device.length < 2) {
                user.devices.push({ ip: encryptedIP, userAgent });
                await user.save();
                req.session.username = user.name;

                await req.session.save(); // Ensure the session is saved
                sessionSet = true;
                return res.json({ message: 'Uspješna prijava', redirect: '/' });
            }

            if (decrypt(dev.ip) === ip && dev.userAgent === userAgent) {
                req.session.username = user.name;

                await req.session.save(); // Ensure the session is saved
                sessionSet = true;
                return res.json({ message: 'Uspješna prijava', redirect: '/' });
            }
        }

        if (!sessionSet) {
            return res.status(400).json({
                error: 'Maksimalan broj uređaja dostignut',
                message: 'Maksimalan broj uređaja (2) dostignut za ovaj račun.'
            });
        }
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


// Logout route to destroy the session
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out' });
        }

        // Also remove session from the MongoDB store
        req.sessionStore.destroy(req.sessionID, (storeErr) => {
            if (storeErr) {
                return res.status(500).json({ error: 'Could not log out and delete session from database' });
            }

            res.json({ message: 'Odjava uspješna' });
        });
    });
});

app.get('/api/check-login', (req, res) => {
    if (req.session.username) {
        let username = req.session.username
        // Check if username ends with '@google' and remove it
        if (username.endsWith('@google')) {
            username = ""; // Remove the last 7 characters ('@google')
        } else {
            username = ", " + username;
        }

        return res.status(200).json({
            loggedIn: true,
            username: username // Return the cleaned username
        });
    }
    res.status(401).json({ loggedIn: false });
});

//Subscription - prvi kolokvij

// Function to check subscription status
const getSubscriptionStatus1 = async (username) => {
    try {
        const user = await User.findOne({ name: username });
        if (!user) {
            return { isSubscribed1: false }; // User not found
        }
        return { isSubscribed1: user.isSubscribed1 }; // Return user's subscription status
    } catch (err) {
        console.error('Error fetching subscription status:', err);
        return { isSubscribed1: false }; // Default to unsubscribed on error
    }
};

// Middleware to check if the user is subscribed
const requireSubscription1 = async (req, res, next) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' }); // No username in session
    }

    try {
        const status = await getSubscriptionStatus1(username); // Await the subscription status

        if (!status.isSubscribed1) {
            return res.status(403).json({ error: 'Subscription required' }); // User is not subscribed
        }

        next(); // User is subscribed, proceed to the next middleware or route handler
    } catch (err) {
        console.error('Error in requireSubscription1 middleware:', err);
        return res.status(500).json({ error: 'Internal server error' }); // Handle unexpected errors
    }
};

// Endpoint to get subscription status
app.get('/api/subscription-status1', async (req, res) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' }); // No username in session
    }

    try {
        const status = await getSubscriptionStatus1(username); // Await the subscription status
        res.json(status); // Return the subscription status in the response
    } catch (err) {
        console.error('Error fetching subscription status:', err);
        res.status(500).json({ error: 'Internal server error' }); // Handle unexpected errors
    }
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

    User.findOne({
        name: username
    })
        .then(present => {
            if (present == null) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            present.isSubscribed1 = true;
            present.save();

            let name = present.name;
            // Check if username ends with '@google' and remove it
            if (name.endsWith('@google')) {
                name = name.slice(0, -7); // Remove the last 7 characters ('@google')
            }

            // Send email
            const mailOptions = {
                from: '"Stat&Mat" <your-email@gmail.com>',
                to: session.customer_details?.email,
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
            <p>Zahvaljujemo na Vašoj narudžbi. Uspješno ste kupili proizvod <strong>"Matematika - prvi kolokvij"</strong> za račun <strong>${name}</strong>.</p>
            <p>Želimo Vam puno uspjeha u učenju i savladavanju gradiva.</p>
            <p>Ako imate dodatnih pitanja, slobodno nas kontaktirajte putem e-maila ili telefona.</p>
            <p>Srdačan pozdrav,</p>
            <p><strong>Vaš Stat&mat</strong></p>
        </div>
        <div class="footer">
            <p>&copy; 2024 Stat&mat. Sva prava zadržana.</p>
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
        .catch(err => {
            console.error(err);
        });
})

//Subscription - drugi kolokvij

// Function to check subscription status
const getSubscriptionStatus2 = async (username) => {
    try {
        const user = await User.findOne({ name: username });
        if (!user) {
            return { isSubscribed2: false }; // User not found
        }
        return { isSubscribed2: user.isSubscribed2 }; // Return user's subscription status
    } catch (err) {
        console.error('Error fetching subscription status:', err);
        return { isSubscribed2: false }; // Default to unsubscribed on error
    }
};

// Middleware to check if the user is subscribed
const requireSubscription2 = async (req, res, next) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' }); // No username in session
    }

    try {
        const status = await getSubscriptionStatus2(username); // Await the subscription status

        if (!status.isSubscribed2) {
            return res.status(403).json({ error: 'Subscription required' }); // User is not subscribed
        }

        next(); // User is subscribed, proceed to the next middleware or route handler
    } catch (err) {
        console.error('Error in requireSubscription1 middleware:', err);
        return res.status(500).json({ error: 'Internal server error' }); // Handle unexpected errors
    }
};

// Endpoint to get subscription status
app.get('/api/subscription-status2', async (req, res) => {
    const username = req.session.username; // Get the logged-in username from session

    if (!username) {
        return res.status(401).json({ error: 'Unauthorized' }); // No username in session
    }

    try {
        const status = await getSubscriptionStatus2(username); // Await the subscription status
        res.json(status); // Return the subscription status in the response
    } catch (err) {
        console.error('Error fetching subscription status:', err);
        res.status(500).json({ error: 'Internal server error' }); // Handle unexpected errors
    }
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
    User.findOne({
        name: username
    })
        .then(present => {
            if (present == null) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            present.isSubscribed2 = true;
            present.save();

            let name = present.name;
            // Check if username ends with '@google' and remove it
            if (name.endsWith('@google')) {
                name = name.slice(0, -7); // Remove the last 7 characters ('@google')
            }

            // Send email
            const mailOptions = {
                from: '"Stat&Mat" <your-email@gmail.com>',
                to: session.customer_details?.email,
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
            <p>Zahvaljujemo na Vašoj narudžbi. Uspješno ste kupili proizvod <strong>"Matematika - drugi kolokvij"</strong> za račun <strong>${name}</strong>.</p>
            <p>Želimo Vam puno uspjeha u učenju i savladavanju gradiva.</p>
            <p>Ako imate dodatnih pitanja, slobodno nas kontaktirajte putem e-maila ili telefona.</p>
            <p>Srdačan pozdrav,</p>
            <p><strong>Vaš Stat&mat</strong></p>
        </div>
        <div class="footer">
            <p>&copy; 2024 Stat&mat. Sva prava zadržana.</p>
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
        .catch(err => {
            console.error(err);
        });
})

// Proxy route to handle video requests with subscription check -- 1. kolokvij
app.get('/proxy/1video', async (req, res) => {
    try {

        let videoUrl;
        const queryParams = req.query;
        const Param = queryParams.Param || '';

        //Url za vide
        if (Param == '1.2.1') {
            videoUrl = 'https://iframe.mediadelivery.net/embed/368157/5eee48d7-6981-461f-9185-1d51c8f34764?autoplay=false&loop=false&muted=false&preload=true&responsive=true';
        }
        if (Param == '1.2.2') {
            videoUrl = 'https://iframe.mediadelivery.net/embed/368157/15ee6ea2-83b9-474a-a658-fd4920548cbc?autoplay=false&loop=false&muted=false&preload=true&responsive=true';
        }

        // First, check if the user is subscribed
        const username = req.session.username;
        if (!username) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        // Fetch user subscription status
        const present = await User.findOne({ name: username });

        if (present == null) {
            return res.status(403).json({ error: 'User not found' });
        } else if (!present.isSubscribed1) {
            return res.status(403).json({ error: 'Subscription required' });
        }

        // Make a GET request to fetch the video content
        const response = await axios.get(videoUrl, {
            responseType: 'stream'
        });

        // Pipe the response content to the client's response
        response.data.pipe(res);

    } catch (error) {
        console.error('Error fetching video:', error);
        res.status(500).json({ error: 'Failed to fetch the video' });
    }
});

// Proxy route to handle video requests with subscription check -- 2.kolokvij
app.get('/proxy/2video', async (req, res) => {
    try {

        let videoUrl;
        const queryParams = req.query;
        const Param = queryParams.Param || '';

        //Url za vide
        if (Param == '2.2.1') {
            videoUrl = 'https://iframe.mediadelivery.net/embed/368157/5eee48d7-6981-461f-9185-1d51c8f34764?autoplay=false&loop=false&muted=false&preload=true&responsive=true';
        }
        if (Param == '2.2.2') {
            videoUrl = 'https://iframe.mediadelivery.net/embed/368157/15ee6ea2-83b9-474a-a658-fd4920548cbc?autoplay=false&loop=false&muted=false&preload=true&responsive=true';
        }

        // First, check if the user is subscribed
        const username = req.session.username;
        if (!username) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        // Fetch user subscription status
        const present = await User.findOne({ name: username });

        if (present == null) {
            return res.status(403).json({ error: 'User not found' });
        } else if (!present.isSubscribed2) {
            return res.status(403).json({ error: 'Subscription required' });
        }

        // Make a GET request to fetch the video content
        const response = await axios.get(videoUrl, {
            responseType: 'stream'
        });

        // Pipe the response content to the client's response
        response.data.pipe(res);

    } catch (error) {
        console.error('Error fetching video:', error);
        res.status(500).json({ error: 'Failed to fetch the video' });
    }
});

// Routes
app.get('/Matematika1', (req, res) => {
    res.render('Matematika1.ejs')
})
app.get('/Matematika2', (req, res) => {
    res.render('Matematika2.ejs')
})
app.get('/Statistika1', (req, res) => {
    res.render('Statistika1.ejs')
})
app.get('/Statistika2', (req, res) => {
    res.render('Statistika2.ejs')
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
