const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

client.connect();

const db = client.db('express-auth');
const usersCollection = db.collection('users');

const register = async (req, res) => {
    const { name, username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { name, username, password: hashedPassword };
        const isExist = await usersCollection.findOne({ username });
        if (isExist) return res.status(400).json({ error: 'Username already exists' });
        const result = await usersCollection.insertOne(user);
        // const token = jwt.sign({ id: result.insertedId }, 'secretkey');
        res.status(200).json({ result });
    } catch (error) {
        console.log(error);
        res.status(400).json({ error: 'Username already exists' });
    }
};

const login = async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await usersCollection.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id }, 'secretkey');
        res.status(200).json({ token, user });
    } catch (error) {
        res.status(500).json({ error: 'Something went wrong' });
    }
};

module.exports = { register, login };