// JobSphere Backend - server.js
// Run: node server.js
// Requires: npm install express better-sqlite3 bcryptjs jsonwebtoken cors multer uuid

const express = require('express');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'jobsphere_secret_change_in_production';

// ============ MIDDLEWARE ============
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ============ DATABASE ============
const db = new Database(path.join(__dirname, 'jobsphere.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, role TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, icon TEXT);
  CREATE TABLE IF NOT EXISTS job_postings (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, company TEXT NOT NULL,
    location TEXT NOT NULL, salary_min INTEGER, salary_max INTEGER,
    category_id INTEGER REFERENCES categories(id), job_type TEXT DEFAULT 'full-time',
    description TEXT, requirements TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, is_active INTEGER DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS user_profiles (
    id TEXT PRIMARY KEY, user_id TEXT UNIQUE REFERENCES users(id),
    bio TEXT, skills TEXT, experience TEXT, education TEXT,
    phone TEXT, website TEXT, linkedin TEXT, github TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS resumes (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    filename TEXT NOT NULL, original_name TEXT NOT NULL,
    file_path TEXT NOT NULL, file_size INTEGER, uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed categories & jobs
if (!db.prepare('SELECT COUNT(*) as c FROM categories').get().c) {
  const cats = [['Engineering','⚙️'],['Design','🎨'],['Product','📦'],['Marketing','📣'],['Sales','💼'],['Data Science','📊'],['DevOps','🔧'],['Finance','💰'],['HR','👥'],['Legal','⚖️']];
  cats.forEach(([n,i]) => db.prepare('INSERT INTO categories (name,icon) VALUES (?,?)').run(n,i));
}
if (!db.prepare('SELECT COUNT(*) as c FROM job_postings').get().c) {
  const jobs = [
    {title:'Senior Full Stack Engineer',company:'Stripe',location:'San Francisco, CA',min:160000,max:220000,cat:1,type:'full-time',desc:'Build the financial infrastructure of the internet.',req:'React, Node.js, PostgreSQL, 5+ years'},
    {title:'Product Designer',company:'Figma',location:'New York, NY',min:130000,max:180000,cat:2,type:'full-time',desc:'Design tools that empower teams worldwide.',req:'Figma, Design Systems, 3+ years'},
    {title:'ML Engineer',company:'OpenAI',location:'Remote',min:200000,max:300000,cat:6,type:'remote',desc:'Work on cutting-edge AI research.',req:'Python, PyTorch, ML research'},
    {title:'DevOps Engineer',company:'Cloudflare',location:'Austin, TX',min:140000,max:190000,cat:7,type:'full-time',desc:'Scale infrastructure serving millions.',req:'Kubernetes, Terraform, AWS'},
    {title:'Frontend Engineer',company:'Vercel',location:'Remote',min:120000,max:170000,cat:1,type:'remote',desc:'Build the future of web development.',req:'React, Next.js, TypeScript'},
    {title:'Product Manager',company:'Notion',location:'San Francisco, CA',min:150000,max:200000,cat:3,type:'full-time',desc:'Drive product strategy.',req:'Product thinking, data analysis'},
    {title:'Backend Engineer',company:'PlanetScale',location:'Remote',min:130000,max:180000,cat:1,type:'remote',desc:'Build the most scalable DB platform.',req:'Go, MySQL, distributed systems'},
    {title:'Data Scientist',company:'Airbnb',location:'Seattle, WA',min:145000,max:195000,cat:6,type:'full-time',desc:'Turn data into product insights.',req:'Python, SQL, A/B testing'},
    {title:'Staff Engineer',company:'Shopify',location:'Remote',min:200000,max:260000,cat:1,type:'remote',desc:'Drive technical excellence.',req:'Ruby on Rails, leadership, 8+ years'},
    {title:'Finance Analyst',company:'Brex',location:'San Francisco, CA',min:100000,max:140000,cat:8,type:'full-time',desc:'Analyze financial operations.',req:'Excel, financial modeling'},
  ];
  jobs.forEach(j => db.prepare(`INSERT INTO job_postings (id,title,company,location,salary_min,salary_max,category_id,job_type,description,requirements) VALUES (?,?,?,?,?,?,?,?,?,?)`).run(uuidv4(),j.title,j.company,j.location,j.min,j.max,j.cat,j.type,j.desc,j.req));
}

// ============ AUTH MIDDLEWARE ============
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ============ ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
    const id = uuidv4();
    const hashed = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (id,name,email,password,role) VALUES (?,?,?,?,?)').run(id, name, email.toLowerCase(), hashed, role);
    db.prepare('INSERT INTO user_profiles (id,user_id) VALUES (?,?)').run(uuidv4(), id);
    const token = jwt.sign({ id, name, email: email.toLowerCase(), role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id, name, email: email.toLowerCase(), role } });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email?.toLowerCase());
    if (!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Get current user
app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id,name,email,role,created_at FROM users WHERE id=?').get(req.user.id);
  res.json({ user });
});

// Get jobs (with search & filters)
app.get('/api/jobs', (req, res) => {
  const { search, location, category, job_type, page=1, limit=12 } = req.query;
  let q = `SELECT jp.*, c.name as category_name, c.icon as category_icon FROM job_postings jp LEFT JOIN categories c ON jp.category_id=c.id WHERE jp.is_active=1`;
  const params = [];
  if (search) { q += ` AND (jp.title LIKE ? OR jp.company LIKE ? OR jp.description LIKE ?)`; const s=`%${search}%`; params.push(s,s,s); }
  if (location && location!=='all') { q += ` AND jp.location LIKE ?`; params.push(`%${location}%`); }
  if (category && category!=='all') { q += ` AND c.name=?`; params.push(category); }
  if (job_type && job_type!=='all') { q += ` AND jp.job_type=?`; params.push(job_type); }
  q += ` ORDER BY jp.created_at DESC LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), (parseInt(page)-1)*parseInt(limit));
  res.json({ jobs: db.prepare(q).all(...params) });
});

// Get categories
app.get('/api/jobs/categories', (req, res) => res.json({ categories: db.prepare('SELECT * FROM categories').all() }));

// Get profile
app.get('/api/profile', auth, (req, res) => {
  const user = db.prepare('SELECT id,name,email,role,created_at FROM users WHERE id=?').get(req.user.id);
  const profile = db.prepare('SELECT * FROM user_profiles WHERE user_id=?').get(req.user.id);
  const resume = db.prepare('SELECT * FROM resumes WHERE user_id=? ORDER BY uploaded_at DESC LIMIT 1').get(req.user.id);
  res.json({ user, profile, resume });
});

// Save profile
app.put('/api/profile', auth, (req, res) => {
  const { bio, skills, experience, education, phone, website, linkedin, github, name } = req.body;
  const existing = db.prepare('SELECT id FROM user_profiles WHERE user_id=?').get(req.user.id);
  const skillsStr = Array.isArray(skills) ? skills.join(',') : skills;
  if (existing) {
    db.prepare(`UPDATE user_profiles SET bio=?,skills=?,experience=?,education=?,phone=?,website=?,linkedin=?,github=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?`)
      .run(bio,skillsStr,experience,education,phone,website,linkedin,github,req.user.id);
  } else {
    db.prepare(`INSERT INTO user_profiles (id,user_id,bio,skills,experience,education,phone,website,linkedin,github) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(uuidv4(),req.user.id,bio,skillsStr,experience,education,phone,website,linkedin,github);
  }
  if (name) db.prepare('UPDATE users SET name=? WHERE id=?').run(name, req.user.id);
  res.json({ message: 'Profile saved' });
});

// Upload resume
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const upload = multer({ storage: multer.diskStorage({ destination: uploadsDir, filename: (req,f,cb) => cb(null,`${uuidv4()}-${f.originalname}`) }), limits: { fileSize: 5*1024*1024 }, fileFilter: (req,f,cb) => f.mimetype==='application/pdf' ? cb(null,true) : cb(new Error('PDF only')) });

app.post('/api/profile/resume', auth, upload.single('resume'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const id = uuidv4();
  db.prepare(`INSERT INTO resumes (id,user_id,filename,original_name,file_path,file_size) VALUES (?,?,?,?,?,?)`)
    .run(id,req.user.id,req.file.filename,req.file.originalname,req.file.path,req.file.size);
  res.json({ message: 'Resume uploaded', resume: { id, original_name: req.file.originalname, file_size: req.file.size } });
});

app.get('/api/health', (req,res) => res.json({ status:'ok' }));

app.listen(PORT, () => console.log(`🚀 JobSphere API → http://localhost:${PORT}`));
