require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const MONGO_URI = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/readline';

// ---------- Auth config ----------
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (IS_PROD) {
    console.error('JWT_SECRET is required when NODE_ENV=production.');
    process.exit(1);
  }
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('JWT_SECRET is not set. Using a temporary secret; everyone is signed out on restart.');
}
const TOKEN_TTL_DAYS = 7;
const COOKIE_NAME = 'readline_token';
const cookieBase = { httpOnly: true, sameSite: 'lax', secure: IS_PROD, path: '/' };

app.disable('x-powered-by');
if (IS_PROD) app.set('trust proxy', 1);
else if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
// The UI is served from this same server, so CORS is only needed for a separate front-end origin.
if (process.env.CLIENT_ORIGIN) {
  app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true }));
}
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const STATUSES = ['Unread', 'Reading', 'Done'];
const TYPES = ['Article', 'Paper', 'Book', 'Video'];

// ---------- Models ----------
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
    passwordHash: { type: String, required: true }
  },
  { timestamps: true }
);
userSchema.methods.toPublic = function () {
  return { id: String(this._id), email: this.email };
};
const User = mongoose.model('User', userSchema);

const itemSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, required: true, trim: true, maxlength: 140 },
    src: { type: String, default: '', trim: true, maxlength: 300 },
    type: { type: String, enum: TYPES, default: 'Article' },
    status: { type: String, enum: STATUSES, default: 'Unread' },
    notes: { type: String, default: '' },
    added: { type: String, required: true }
  },
  { timestamps: true }
);

itemSchema.set('toJSON', {
  virtuals: true,
  versionKey: false,
  transform: (_doc, ret) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.userId; // never expose ownership details to the client
    return ret;
  }
});

const Item = mongoose.model('Item', itemSchema);

// Sample items every new account starts with (delete the insertMany call in /register to start empty).
const seedItems = [
  { title: 'The Case for Slow Software', src: 'https://example.com/slow-software', type: 'Article', status: 'Reading', added: 'Nov 18',
    notes: 'Argues that teams ship better work when release cadence follows the problem, not the calendar. The section on “maintenance as design” is worth rereading before the Q1 planning doc.' },
  { title: 'Attention Is All You Need', src: 'arxiv.org/abs/1706.03762', type: 'Paper', status: 'Done', added: 'Nov 11',
    notes: 'Reread for the positional encoding details. Still the clearest explanation of why self-attention scales the way it does. Figure 2 is the one to show colleagues.' },
  { title: 'A Pattern Language', src: 'Christopher Alexander, 1977', type: 'Book', status: 'Reading', added: 'Nov 3',
    notes: 'Reading three patterns a night. Pattern 159, Light on Two Sides of Every Room, changed how I look at my own desk.' },
  { title: 'How Bridges Actually Fail', src: 'https://example.com/bridge-failures', type: 'Video', status: 'Unread', added: 'Nov 20',
    notes: 'Recommended by Maya. About 40 minutes. Look for the Tacoma Narrows section and the segment on fatigue cracking.' },
  { title: 'Sleep, Memory, and the Hippocampus', src: 'nature.com/articles/neuro-sleep', type: 'Paper', status: 'Unread', added: 'Nov 19',
    notes: 'Background for the study-habits piece. Check the sample size in the methods before citing anything.' },
  { title: 'Notes on Writing Plainly', src: 'https://example.com/plain-writing', type: 'Article', status: 'Done', added: 'Oct 29',
    notes: 'Short and useful. Takeaway: cut every sentence that exists to introduce the next one.' },
  { title: 'The Overstory', src: 'Richard Powers, 2018', type: 'Book', status: 'Unread', added: 'Oct 22',
    notes: 'Lent by Daniel. Start after finishing A Pattern Language.' },
  { title: 'Why Typefaces Feel the Way They Do', src: 'https://example.com/type-feel', type: 'Video', status: 'Done', added: 'Oct 15',
    notes: 'Good grounding for the type scale discussion. Skip the first five minutes.' }
];

function seedFor(userId) {
  const now = Date.now();
  // Stagger createdAt so the newest-first sort keeps the sample order stable.
  return seedItems.map((s, i) => ({ ...s, userId, createdAt: new Date(now - i * 1000) }));
}

// ---------- Auth helpers ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;
const DUMMY_HASH = bcrypt.hashSync('readline-timing-placeholder', 10);

function setSession(res, userId) {
  const token = jwt.sign({ sub: String(userId) }, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: `${TOKEN_TTL_DAYS}d`
  });
  res.cookie(COOKIE_NAME, token, { ...cookieBase, maxAge: TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000 });
}

function readToken(req) {
  if (req.cookies && req.cookies[COOKIE_NAME]) return req.cookies[COOKIE_NAME];
  const header = req.get('authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}

function requireAuth(req, res, next) {
  const token = readToken(req);
  if (!token) return res.status(401).json({ error: 'Please sign in.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    if (!OBJECT_ID_RE.test(String(payload.sub))) throw new Error('bad subject');
    req.userId = payload.sub;
    next();
  } catch (_err) {
    res.status(401).json({ error: 'Your session has expired. Please sign in again.' });
  }
}

// Small in-memory throttle for register/login (per IP). Use a shared store if you run several instances.
const attempts = new Map();
function authLimiter(req, res, next) {
  const WINDOW_MS = 15 * 60 * 1000;
  const MAX = 20;
  const now = Date.now();
  const rec = attempts.get(req.ip);
  if (!rec || rec.reset < now) {
    attempts.set(req.ip, { count: 1, reset: now + WINDOW_MS });
    return next();
  }
  if (rec.count >= MAX) {
    return res.status(429).json({ error: 'Too many attempts. Please try again in a few minutes.' });
  }
  rec.count += 1;
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of attempts) if (rec.reset < now) attempts.delete(ip);
}, 10 * 60 * 1000).unref();

// ---------- Auth routes ----------
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    if (!EMAIL_RE.test(email) || email.length > 254) {
      return res.status(400).json({ error: 'Enter a valid email address.' });
    }
    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: 'Use a password between 8 and 72 characters.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });
    await Item.insertMany(seedFor(user._id));
    setSession(res, user._id);
    res.status(201).json({ user: user.toPublic() });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Could not create your account.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    const user = await User.findOne({ email });
    // Always run a compare so response time doesn't reveal whether the email exists.
    const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
    if (!user || !ok) {
      return res.status(401).json({ error: 'Incorrect email or password.' });
    }
    setSession(res, user._id);
    res.json({ user: user.toPublic() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not sign you in.' });
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      res.clearCookie(COOKIE_NAME, cookieBase);
      return res.status(401).json({ error: 'Please sign in.' });
    }
    res.json({ user: user.toPublic() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load your account.' });
  }
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME, cookieBase);
  res.json({ ok: true });
});

// ---------- Item routes (all scoped to the signed-in user) ----------
app.use('/api/items', requireAuth);

app.get('/api/items', async (req, res) => {
  try {
    const docs = await Item.find({ userId: req.userId }).sort({ createdAt: -1, _id: -1 });
    res.json(docs.map((d) => d.toJSON()));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load items' });
  }
});

app.post('/api/items', async (req, res) => {
  try {
    const title = String(req.body.title || '').trim();
    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }
    const type = TYPES.includes(req.body.type) ? req.body.type : 'Article';
    const status = STATUSES.includes(req.body.status) ? req.body.status : 'Unread';
    const src = String(req.body.src || '').trim();
    const notes = String(req.body.notes || '').trim();
    const added =
      String(req.body.added || '').trim() ||
      new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

    const created = await Item.create({ userId: req.userId, title, src, type, status, notes, added });
    res.status(201).json(created.toJSON());
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Failed to create item' });
  }
});

app.patch('/api/items/:id', async (req, res) => {
  try {
    if (!OBJECT_ID_RE.test(req.params.id)) {
      return res.status(404).json({ error: 'Item not found' });
    }
    const patch = {};
    if (req.body.status !== undefined) {
      if (!STATUSES.includes(req.body.status)) {
        return res.status(400).json({ error: 'Invalid status' });
      }
      patch.status = req.body.status;
    }
    if (req.body.notes !== undefined) {
      patch.notes = String(req.body.notes);
    }
    if (!Object.keys(patch).length) {
      return res.status(400).json({ error: 'Nothing to update' });
    }

    const updated = await Item.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { $set: patch },
      { new: true, runValidators: true }
    );
    if (!updated) {
      return res.status(404).json({ error: 'Item not found' });
    }
    res.json(updated.toJSON());
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Failed to update item' });
  }
});

app.delete('/api/items/:id', async (req, res) => {
  try {
    if (!OBJECT_ID_RE.test(req.params.id)) {
      return res.status(404).json({ error: 'Item not found' });
    }
    const deleted = await Item.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!deleted) {
      return res.status(404).json({ error: 'Item not found' });
    }
    res.json({ ok: true, id: req.params.id });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Failed to delete item' });
  }
});

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('Connected to MongoDB:', MONGO_URI);
    app.listen(PORT, () => {
      console.log(`Readline running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });
