const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: false },
    registrationDate: { type: Date, required: false },
    isConfirmed: { type: Boolean, required: true },
    isSubscribed1: { type: Boolean, required: true },
    isSubscribed2: { type: Boolean, required: true },
    devices: [
        {
            ip: { type: String, required: false },
            userAgent: { type: String, required: false },
        }
    ],
});

const User = mongoose.model('User', userSchema);
module.exports = User;
