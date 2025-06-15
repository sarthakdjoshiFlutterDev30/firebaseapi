const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const cors = require("cors");
const { v1: uuidv1 } = require('uuid');
const fs = require('fs');


const serviceAccount = JSON.parse(fs.readFileSync('apitest-db8a0-firebase-adminsdk-l09c9-3b29cfb0e5.json', 'utf8'));

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: 'apitest-db8a0.firebasestorage.app' 
});

const db = admin.firestore();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'db9ce127f0826e017282a339f17bd1dd39875824b2b78edd72b33a2ef00e1f02';

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.json());

// Multer config
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Signup route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  try {
    const userRecord = await admin.auth().createUser({ email });
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').doc(userRecord.uid).set({ email, password: hashedPassword });

    res.status(201).json({ uid: userRecord.uid, email: userRecord.email });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  try {
    const userRecord = await admin.auth().getUserByEmail(email);
    const userDoc = await db.collection('users').doc(userRecord.uid).get();
    if (!userDoc.exists) return res.status(401).json({ error: 'Authentication failed' });

    const userData = userDoc.data();
    const passwordMatch = await bcrypt.compare(password, userData.password);
    if (!passwordMatch) return res.status(401).json({ error: 'Authentication failed' });

    const token = jwt.sign({ uid: userRecord.uid, email: userRecord.email }, JWT_SECRET);
    res.status(200).json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// JWT auth middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// CRUD routes (items)
app.post('/api/items', authenticateJWT, async (req, res) => {
  try {
    const item = req.body;
    const docRef = await db.collection('items').add(item);
    res.status(201).json({ id: docRef.id, ...item });
  } catch (error) {
    console.error('Create item error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/items', authenticateJWT, async (req, res) => {
  try {
    const snapshot = await db.collection('items').get();
    const items = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(items);
  } catch (error) {
    console.error('Get items error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/items/:id', authenticateJWT, async (req, res) => {
  try {
    const doc = await db.collection('items').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Item not found' });
    res.json({ id: doc.id, ...doc.data() });
  } catch (error) {
    console.error('Get item error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/items/:id', authenticateJWT, async (req, res) => {
  try {
    const item = req.body;
    await db.collection('items').doc(req.params.id).set(item, { merge: true });
    res.json({ id: req.params.id, ...item });
  } catch (error) {
    console.error('Update item error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/items/:id', authenticateJWT, async (req, res) => {
  try {
    await db.collection('items').doc(req.params.id).delete();
    res.status(204).send();
  } catch (error) {
    console.error('Delete item error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Image upload route
app.post('/api/upload-image', authenticateJWT, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const bucket = admin.storage().bucket();
    const { originalname, mimetype, buffer } = req.file;
    const extension = path.extname(originalname);
    const fileName = `uploads/${uuidv1()}${extension}`;
    const file = bucket.file(fileName);

    const stream = file.createWriteStream({ metadata: { contentType: mimetype } });
    stream.on('error', (err) => {
      console.error('Upload error:', err);
      res.status(500).json({ error: err.message });
    });

    stream.on('finish', async () => {
      await file.makePublic(); // Optional for dev only
      const publicUrl = `https://storage.googleapis.com/${bucket.name}/${file.name}`;
      res.status(200).json({ imageUrl: publicUrl });
    });


    stream.end(buffer);
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: error.message });
  }
});


app.get('/', (req, res) => {
  res.send('Firebase CRUD API with JWT Auth + Image Upload');
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
