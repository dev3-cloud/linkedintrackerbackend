require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'siox-linkedin-floor-secret';

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI in .env');
  process.exit(1);
}

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Actor, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  group: { type: String, enum: ['a', 'b', 'c'], required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user', index: true },
  lastLoginAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const dayStatusSchema = new mongoose.Schema({
  dateKey: { type: String, required: true, unique: true, index: true },
  status: { type: String, enum: ['posted', 'missed'], required: true },
  group: { type: String, enum: ['A', 'B', 'C'], default: null },
  topic: { type: String, default: '' },
  updatedBy: { type: String, default: 'Unknown' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  updatedAt: { type: Date, default: Date.now }
});

const memberSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  group: { type: String, enum: ['a', 'b', 'c'], required: true },
  addedBy: { type: String, default: 'Unknown' },
  createdAt: { type: Date, default: Date.now }
});

const activitySchema = new mongoose.Schema({
  type: { type: String, required: true, index: true },
  actor: { type: String, default: 'Unknown', index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  ip: { type: String, default: '' },
  userAgent: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now, index: true }
});

const User = mongoose.model('User', userSchema);
const DayStatus = mongoose.model('DayStatus', dayStatusSchema);
const Member = mongoose.model('Member', memberSchema);
const Activity = mongoose.model('Activity', activitySchema);

function dbReady() {
  return mongoose.connection.readyState === 1;
}

function requireDb(_req, res, next) {
  if (!dbReady()) return res.status(503).json({ error: 'Database offline. Allow this PC in MongoDB Atlas.' });
  next();
}

function bearerToken(req) {
  const header = req.get('authorization') || '';
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  return '';
}

function signUser(user) {
  return jwt.sign(
    { id: String(user._id), name: user.name, username: user.username, group: user.group, role: user.role || 'user' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function serializeUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    username: user.username,
    group: user.group,
    role: user.role || 'user'
  };
}

async function requireAdmin(req, res, next) {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admins only' });
    }
    req.user.role = 'admin';
    next();
  } catch (_err) {
    res.status(500).json({ error: 'Could not verify admin' });
  }
}

function requireAuth(req, res, next) {
  const token = bearerToken(req);
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (_err) {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

function actorFrom(req) {
  if (req.user && req.user.name) return req.user.name;
  return 'Unknown';
}

function clientIp(req) {
  const forwarded = req.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || '';
}

async function logActivity(req, type, details) {
  await Activity.create({
    type,
    actor: actorFrom(req),
    userId: req.user && req.user.id ? req.user.id : null,
    details: details || {},
    ip: clientIp(req),
    userAgent: (req.get('user-agent') || '').slice(0, 400)
  });
}

function serializeMember(doc) {
  return {
    id: String(doc._id),
    name: doc.name,
    group: doc.group,
    addedBy: doc.addedBy,
    createdAt: doc.createdAt
  };
}

async function peopleStats() {
  const users = await User.find().sort({ name: 1 }).lean();
  const [posted, missed, copies, lastActs] = await Promise.all([
    DayStatus.aggregate([
      { $match: { status: 'posted', userId: { $ne: null } } },
      { $group: { _id: '$userId', count: { $sum: 1 } } }
    ]),
    DayStatus.aggregate([
      { $match: { status: 'missed', userId: { $ne: null } } },
      { $group: { _id: '$userId', count: { $sum: 1 } } }
    ]),
    Activity.aggregate([
      { $match: { type: 'copy_post', userId: { $ne: null } } },
      { $group: { _id: '$userId', count: { $sum: 1 } } }
    ]),
    Activity.aggregate([
      { $match: { userId: { $ne: null } } },
      { $sort: { createdAt: -1 } },
      { $group: { _id: '$userId', lastActive: { $first: '$createdAt' }, lastType: { $first: '$type' } } }
    ])
  ]);

  function mapCount(rows) {
    const out = {};
    for (const row of rows) out[String(row._id)] = row.count;
    return out;
  }

  const postedMap = mapCount(posted);
  const missedMap = mapCount(missed);
  const copyMap = mapCount(copies);
  const lastMap = {};
  for (const row of lastActs) {
    lastMap[String(row._id)] = { lastActive: row.lastActive, lastType: row.lastType };
  }

  return users.map((user) => {
    const id = String(user._id);
    const last = lastMap[id] || {};
    return {
      id,
      name: user.name,
      username: user.username,
      group: user.group,
      role: user.role || 'user',
      posted: postedMap[id] || 0,
      missed: missedMap[id] || 0,
      copies: copyMap[id] || 0,
      lastActive: last.lastActive || user.lastLoginAt || user.createdAt,
      lastType: last.lastType || 'signed_up'
    };
  }).sort((a, b) => b.posted - a.posted || a.name.localeCompare(b.name));
}

app.get('/api/health', async (_req, res) => {
  res.json({ ok: true, db: dbReady() ? 'connected' : 'disconnected', service: 'siox-linkedin-tracker' });
});

app.use('/api', function (req, res, next) {
  if (req.path === '/health') return next();
  return requireDb(req, res, next);
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const group = String(req.body.group || '').toLowerCase();

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({ error: 'Enter your full name' });
    }
    if (!/^[a-z0-9._]{3,24}$/.test(username)) {
      return res.status(400).json({ error: 'Username must be 3-24 letters, numbers, . or _' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (!['a', 'b', 'c'].includes(group)) {
      return res.status(400).json({ error: 'Pick Group A, B, or C' });
    }

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'That username is already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, username, passwordHash, group, role: 'user' });
    const token = signUser(user);
    await Activity.create({
      type: 'signup',
      actor: user.name,
      userId: user._id,
      details: { group },
      ip: clientIp(req),
      userAgent: (req.get('user-agent') || '').slice(0, 400)
    });
    res.status(201).json({ token, user: serializeUser(user) });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ error: 'That username is already taken' });
    }
    console.error('POST /api/auth/signup', err);
    res.status(500).json({ error: 'Could not create account' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Wrong username or password' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Wrong username or password' });
    user.lastLoginAt = new Date();
    await user.save();
    const token = signUser(user);
    await Activity.create({
      type: 'login',
      actor: user.name,
      userId: user._id,
      details: {},
      ip: clientIp(req),
      userAgent: (req.get('user-agent') || '').slice(0, 400)
    });
    res.json({ token, user: serializeUser(user) });
  } catch (err) {
    console.error('POST /api/auth/login', err);
    res.status(500).json({ error: 'Could not sign in' });
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ error: 'Account not found' });
    const people = await peopleStats();
    const mine = people.find((row) => row.id === String(user._id)) || {
      posted: 0, missed: 0, copies: 0
    };
    res.json({ user: serializeUser(user), stats: { posted: mine.posted, missed: mine.missed, copies: mine.copies } });
  } catch (err) {
    console.error('GET /api/auth/me', err);
    res.status(500).json({ error: 'Could not load profile' });
  }
});

app.get('/api/people', requireAuth, async (_req, res) => {
  try {
    res.json({ people: await peopleStats() });
  } catch (err) {
    console.error('GET /api/people', err);
    res.status(500).json({ error: 'Could not load people' });
  }
});

function ymdValid(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || ''));
}

function weekdaySlots(fromKey, toKey) {
  const floorStart = new Date(2026, 8, 9);
  const from = new Date(fromKey + 'T00:00:00');
  const to = new Date(toKey + 'T00:00:00');
  let count = 0;
  const groups = { A: 0, B: 0, C: 0 };
  const cur = new Date(from);
  let seq = 0;
  const walker = new Date(floorStart);
  while (walker < from) {
    if (walker.getDay() !== 0 && walker.getDay() !== 6) seq += 1;
    walker.setDate(walker.getDate() + 1);
  }
  while (cur <= to) {
    if (cur >= floorStart && cur.getDay() !== 0 && cur.getDay() !== 6) {
      const grp = ['A', 'B', 'C'][seq % 3];
      groups[grp] += 1;
      count += 1;
      seq += 1;
    }
    cur.setDate(cur.getDate() + 1);
  }
  return { count, groups };
}

app.get('/api/analytics', requireAuth, requireAdmin, async (req, res) => {
  try {
    const today = new Date();
    const defaultFrom = '2026-09-09';
    const defaultTo = [
      today.getFullYear(),
      String(today.getMonth() + 1).padStart(2, '0'),
      String(today.getDate()).padStart(2, '0')
    ].join('-');
    const from = ymdValid(req.query.from) ? req.query.from : defaultFrom;
    const to = ymdValid(req.query.to) ? req.query.to : defaultTo;
    const statusFilter = ['posted', 'missed', 'all'].includes(req.query.status) ? req.query.status : 'all';
    const groupFilter = ['A', 'B', 'C'].includes(req.query.group) ? req.query.group : '';
    const userId = String(req.query.userId || '').trim();

    const dayQuery = { dateKey: { $gte: from, $lte: to } };
    if (groupFilter) dayQuery.group = groupFilter;
    if (userId) dayQuery.userId = userId;

    const actQuery = {
      createdAt: {
        $gte: new Date(from + 'T00:00:00.000Z'),
        $lte: new Date(to + 'T23:59:59.999Z')
      }
    };
    if (userId) actQuery.userId = userId;

    const [allDays, activities, users] = await Promise.all([
      DayStatus.find(dayQuery).sort({ dateKey: 1 }).lean(),
      Activity.find(actQuery).lean(),
      User.find().select('name username group role').lean()
    ]);
    const days = statusFilter === 'all' ? allDays : allDays.filter((day) => day.status === statusFilter);

    const byPerson = {};
    for (const user of users) {
      byPerson[String(user._id)] = {
        id: String(user._id),
        name: user.name,
        username: user.username,
        group: user.group,
        role: user.role || 'user',
        posted: 0,
        missed: 0,
        copies: 0,
        views: 0,
        logins: 0
      };
    }

    const byGroup = {
      A: { posted: 0, missed: 0 },
      B: { posted: 0, missed: 0 },
      C: { posted: 0, missed: 0 }
    };
    const byTopic = {};
    const byDay = {};
    let posted = 0;
    let missed = 0;

    for (const day of allDays) {
      if (day.status === 'posted') posted += 1;
      if (day.status === 'missed') missed += 1;
      if (day.group && byGroup[day.group]) byGroup[day.group][day.status] += 1;
      const uid = day.userId ? String(day.userId) : '';
      if (uid && byPerson[uid] && (day.status === 'posted' || day.status === 'missed')) {
        byPerson[uid][day.status] += 1;
      }
    }

    for (const day of days) {
      const topic = day.topic || 'Untitled';
      byTopic[topic] = (byTopic[topic] || 0) + 1;
      byDay[day.dateKey] = byDay[day.dateKey] || { posted: 0, missed: 0 };
      byDay[day.dateKey][day.status] += 1;
    }

    let copies = 0;
    let views = 0;
    let logins = 0;
    for (const row of activities) {
      const uid = row.userId ? String(row.userId) : '';
      if (row.type === 'copy_post') {
        copies += 1;
        if (uid && byPerson[uid]) byPerson[uid].copies += 1;
      }
      if (row.type === 'view_post') {
        views += 1;
        if (uid && byPerson[uid]) byPerson[uid].views += 1;
      }
      if (row.type === 'login') {
        logins += 1;
        if (uid && byPerson[uid]) byPerson[uid].logins += 1;
      }
    }

    const slots = weekdaySlots(from, to);
    ['A', 'B', 'C'].forEach((grp) => {
      byGroup[grp].planned = slots.groups[grp] || 0;
      byGroup[grp].unmarked = Math.max(byGroup[grp].planned - byGroup[grp].posted - byGroup[grp].missed, 0);
    });
    const planned = groupFilter ? slots.groups[groupFilter] : slots.count;
    const completion = planned ? Math.round((posted / planned) * 100) : 0;
    const people = Object.values(byPerson)
      .filter((row) => {
        if (userId && row.id !== userId) return false;
        if (groupFilter && String(row.group).toUpperCase() !== groupFilter) return false;
        return true;
      })
      .sort((a, b) => b.posted - a.posted || a.name.localeCompare(b.name));

    const topics = Object.entries(byTopic)
      .map(([topic, count]) => ({ topic, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    const timeline = Object.keys(byDay).sort().map((dateKey) => ({
      dateKey,
      posted: byDay[dateKey].posted,
      missed: byDay[dateKey].missed
    }));

    res.json({
      filters: { from, to, status: statusFilter, group: groupFilter || 'all', userId: userId || '' },
      summary: {
        posted,
        missed,
        copies,
        views,
        logins,
        planned,
        unmarked: Math.max(planned - posted - missed, 0),
        completion,
        activePosters: people.filter((row) => row.posted > 0).length
      },
      byGroup,
      people,
      topics,
      timeline,
      rows: days.map((day) => ({
        dateKey: day.dateKey,
        status: day.status,
        group: day.group,
        topic: day.topic,
        updatedBy: day.updatedBy,
        userId: day.userId ? String(day.userId) : null,
        updatedAt: day.updatedAt
      }))
    });
  } catch (err) {
    console.error('GET /api/analytics', err);
    res.status(500).json({ error: 'Could not load analytics' });
  }
});

app.get('/api/state', requireAuth, async (_req, res) => {
  try {
    const [days, roster, people] = await Promise.all([
      DayStatus.find().lean(),
      Member.find().sort({ createdAt: 1 }).lean(),
      peopleStats()
    ]);

    const statuses = {};
    const statusMeta = {};
    for (const day of days) {
      statuses[day.dateKey] = day.status;
      statusMeta[day.dateKey] = {
        updatedBy: day.updatedBy,
        updatedAt: day.updatedAt,
        group: day.group,
        topic: day.topic,
        userId: day.userId ? String(day.userId) : null
      };
    }

    const members = { a: [], b: [], c: [] };
    for (const person of roster) {
      members[person.group].push(serializeMember(person));
    }

    res.json({ statuses, statusMeta, members, people });
  } catch (err) {
    console.error('GET /api/state', err);
    res.status(500).json({ error: 'Could not load tracker state' });
  }
});

app.put('/api/days/:dateKey', requireAuth, async (req, res) => {
  try {
    const dateKey = String(req.params.dateKey || '');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) {
      return res.status(400).json({ error: 'dateKey must be YYYY-MM-DD' });
    }

    const nextStatus = req.body.status === 'clear' || req.body.status === null
      ? null
      : req.body.status;
    if (nextStatus && !['posted', 'missed'].includes(nextStatus)) {
      return res.status(400).json({ error: 'status must be posted, missed, or clear' });
    }

    const actor = actorFrom(req);
    const group = ['A', 'B', 'C'].includes(req.body.group) ? req.body.group : null;
    const topic = typeof req.body.topic === 'string' ? req.body.topic.slice(0, 120) : '';
    const existing = await DayStatus.findOne({ dateKey });

    if (existing) {
      const ownerId = existing.userId ? String(existing.userId) : '';
      const isOwner = ownerId
        ? ownerId === String(req.user.id)
        : Boolean(existing.updatedBy && req.user.name &&
            String(existing.updatedBy).toLowerCase() === String(req.user.name).toLowerCase());
      let isAdminUser = req.user.role === 'admin';
      if (!isAdminUser) {
        const me = await User.findById(req.user.id).select('role');
        isAdminUser = Boolean(me && me.role === 'admin');
      }
      if (!isOwner && !isAdminUser) {
        return res.status(403).json({
          error: 'Only ' + (existing.updatedBy || 'the person who marked this') + ' can change this day',
          dateKey: existing.dateKey,
          status: existing.status,
          updatedBy: existing.updatedBy,
          userId: ownerId || null,
          updatedAt: existing.updatedAt
        });
      }
    }

    if (!nextStatus) {
      await DayStatus.deleteOne({ dateKey });
      await logActivity(req, 'mark_clear', { dateKey, group, topic });
      return res.json({ dateKey, status: null, people: await peopleStats() });
    }

    const day = await DayStatus.findOneAndUpdate(
      { dateKey },
      {
        status: nextStatus,
        group,
        topic,
        updatedBy: actor,
        userId: req.user.id,
        updatedAt: new Date()
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    await logActivity(req, `mark_${nextStatus}`, { dateKey, group, topic });
    res.json({
      dateKey: day.dateKey,
      status: day.status,
      updatedBy: day.updatedBy,
      userId: String(day.userId || req.user.id),
      updatedAt: day.updatedAt,
      people: await peopleStats()
    });
  } catch (err) {
    console.error('PUT /api/days', err);
    res.status(500).json({ error: 'Could not save day status' });
  }
});

app.post('/api/members', requireAuth, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const group = String(req.body.group || '').toLowerCase();
    const actor = actorFrom(req);
    if (!name) return res.status(400).json({ error: 'Name is required' });
    if (!['a', 'b', 'c'].includes(group)) {
      return res.status(400).json({ error: 'Group must be a, b, or c' });
    }
    const person = await Member.create({ name: name.slice(0, 80), group, addedBy: actor });
    await logActivity(req, 'add_member', { name: person.name, group });
    res.status(201).json(serializeMember(person));
  } catch (err) {
    console.error('POST /api/members', err);
    res.status(500).json({ error: 'Could not add team member' });
  }
});

app.delete('/api/members/:id', requireAuth, async (req, res) => {
  try {
    const person = await Member.findByIdAndDelete(req.params.id);
    if (!person) return res.status(404).json({ error: 'Member not found' });
    await logActivity(req, 'remove_member', { name: person.name, group: person.group });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/members/:id', err);
    res.status(500).json({ error: 'Could not remove team member' });
  }
});

app.delete('/api/members', requireAuth, async (req, res) => {
  try {
    const result = await Member.deleteMany({});
    await logActivity(req, 'clear_members', { removed: result.deletedCount });
    res.json({ ok: true, removed: result.deletedCount });
  } catch (err) {
    console.error('DELETE /api/members', err);
    res.status(500).json({ error: 'Could not clear team members' });
  }
});

app.get('/api/activity', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 40, 200);
    const rows = await Activity.find().sort({ createdAt: -1 }).limit(limit).lean();
    res.json({
      activities: rows.map((row) => ({
        id: String(row._id),
        type: row.type,
        actor: row.actor,
        userId: row.userId ? String(row.userId) : null,
        details: row.details || {},
        createdAt: row.createdAt
      }))
    });
  } catch (err) {
    console.error('GET /api/activity', err);
    res.status(500).json({ error: 'Could not load activity' });
  }
});

app.post('/api/activity', requireAuth, async (req, res) => {
  try {
    const type = String(req.body.type || '').trim();
    if (!type || type.length > 60) {
      return res.status(400).json({ error: 'Activity type is required' });
    }
    const allowed = new Set(['session_start', 'view_post', 'copy_post', 'set_actor', 'login', 'signup']);
    if (!allowed.has(type)) return res.status(400).json({ error: 'Unknown activity type' });
    const details = req.body.details && typeof req.body.details === 'object' ? req.body.details : {};
    await logActivity(req, type, details);
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('POST /api/activity', err);
    res.status(500).json({ error: 'Could not record activity' });
  }
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function ensureAdmin() {
  const username = String(process.env.ADMIN_USERNAME || 'priya').trim().toLowerCase();
  if (username) {
    const promoted = await User.findOneAndUpdate(
      { username },
      { $set: { role: 'admin' } },
      { new: true }
    );
    if (promoted) console.log('Admin account:', promoted.username);
  }
  const hasAdmin = await User.exists({ role: 'admin' });
  if (!hasAdmin) {
    const first = await User.findOne().sort({ createdAt: 1 });
    if (first) {
      first.role = 'admin';
      await first.save();
      console.log('First user promoted to admin:', first.username);
    }
  }
}

async function connectDb() {
  if (dbReady() || mongoose.connection.readyState === 2) return;
  try {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
    console.log('MongoDB connected');
    await ensureAdmin();
  } catch (err) {
    console.error('MongoDB not connected yet:', err.message);
  }
}

async function start() {
  if (!process.env.JWT_SECRET) {
    console.log('JWT_SECRET missing in .env — using a local default. Set one before going live.');
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Siox LinkedIn tracker running at http://localhost:${PORT}`);
  });
  await connectDb();
  setInterval(connectDb, 20000);
}

start().catch((err) => {
  console.error('Failed to start server:', err.message);
  process.exit(1);
});
