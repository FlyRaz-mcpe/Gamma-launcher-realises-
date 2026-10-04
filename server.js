require('dotenv').config();
const express=require('express'), session=require('express-session'), multer=require('multer'), crypto=require('crypto'), fs=require('fs');
const Database=require('better-sqlite3');
const app=express();
const DATA_DIR=process.env.DATA_DIR || './data';
fs.mkdirSync(DATA_DIR,{recursive:true});
const db=new Database(`${DATA_DIR}/gamma.db`);
const PORT=process.env.PORT||3000;
const ALLOWED=new Set(['flyraz_mc','yuno8340']);
const UPLOAD_DIR=process.env.UPLOAD_DIR || `${DATA_DIR}/uploads`;
fs.mkdirSync(UPLOAD_DIR,{recursive:true});

db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT, provider_id TEXT UNIQUE, username TEXT, created_at TEXT); CREATE TABLE IF NOT EXISTS releases(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,version TEXT,category TEXT,description TEXT,filename TEXT,author TEXT,created_at TEXT)`);
app.use(express.json()); app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||'dev-secret-change-me',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production'}}));
app.use(express.static('public'));
const upload=multer({dest:UPLOAD_DIR+'/','limits:{fileSize:500*1024*1024},fileFilter:(req,file,cb)=>cb(null,file.originalname.toLowerCase().endsWith('.apk'))});
function publisher(req){return !!(req.session.user && ALLOWED.has((req.session.user.username||'').toLowerCase()));}
app.get('/api/me',(req,res)=>res.json({user:req.session.user||null,publisher:publisher(req)}));
app.get('/api/releases',(req,res)=>res.json(db.prepare('SELECT id,title,version,category,description,filename,author,created_at FROM releases ORDER BY id DESC').all()));
app.get('/download/:id',(req,res)=>{const r=db.prepare('SELECT * FROM releases WHERE id=?').get(req.params.id);if(!r||!fs.existsSync(r.filename))return res.sendStatus(404);res.download(r.filename,r.title+'.apk')});

// Telegram Login Widget callback. Telegram sends verified user data to this endpoint.
app.post('/auth/telegram',(req,res)=>{
 const data={...req.body}; const hash=data.hash; delete data.hash; if(!hash)return res.status(400).json({error:'missing hash'});
 const check=Object.keys(data).sort().map(k=>`${k}=${data[k]}`).join('\n');
 const secret=crypto.createHash('sha256').update(process.env.TELEGRAM_BOT_TOKEN||'').digest();
 const expected=crypto.createHmac('sha256',secret).update(check).digest('hex');
 if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(hash)))return res.status(401).json({error:'invalid telegram auth'});
 if(data.auth_date && Date.now()/1000-Number(data.auth_date)>86400)return res.status(401).json({error:'expired login'});
 const username=(data.username||'').toLowerCase();
 db.prepare('INSERT INTO users(provider,provider_id,username,created_at) VALUES(?,?,?,?) ON CONFLICT(provider_id) DO UPDATE SET username=excluded.username').run('telegram',String(data.id),username,new Date().toISOString());
 req.session.user={provider:'telegram',id:String(data.id),username}; res.json({ok:true,user:req.session.user,publisher:ALLOWED.has(username)});
});

app.get('/auth/discord',(req,res)=>{const p=new URLSearchParams({client_id:process.env.DISCORD_CLIENT_ID||'',response_type:'code',redirect_uri:process.env.DISCORD_REDIRECT_URI||`${process.env.SITE_URL}/auth/discord/callback`,scope:'identify'});res.redirect('https://discord.com/oauth2/authorize?'+p)});
app.get('/auth/discord/callback',async(req,res)=>{
 try{const body=new URLSearchParams({client_id:process.env.DISCORD_CLIENT_ID,client_secret:process.env.DISCORD_CLIENT_SECRET,grant_type:'authorization_code',code:req.query.code,redirect_uri:process.env.DISCORD_REDIRECT_URI});const t=await fetch('https://discord.com/api/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});const token=await t.json();const u=await (await fetch('https://discord.com/api/users/@me',{headers:{Authorization:`Bearer ${token.access_token}`}})).json();const username=(u.username||'').toLowerCase();db.prepare('INSERT INTO users(provider,provider_id,username,created_at) VALUES(?,?,?,?) ON CONFLICT(provider_id) DO UPDATE SET username=excluded.username').run('discord',u.id,username,new Date().toISOString());req.session.user={provider:'discord',id:u.id,username};res.redirect('/');}catch(e){res.status(500).send('Discord login failed')}});
app.post('/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.post('/api/releases',upload.single('apk'),(req,res)=>{if(!publisher(req))return res.status(403).json({error:'Only @flyraz_mc and @yuno8340 can publish'});if(!req.file)return res.status(400).json({error:'APK required'});const r=db.prepare('INSERT INTO releases(title,version,category,description,filename,author,created_at) VALUES(?,?,?,?,?,?,?)').run(req.body.title,req.body.version,req.body.category,req.body.description,req.file.path,req.session.user.username,new Date().toISOString());res.json({ok:true,id:r.lastInsertRowid})});
app.get('/healthz',(req,res)=>res.json({ok:true}));
app.listen(PORT,'0.0.0.0',()=>console.log(`Gamma Releases running on ${PORT}`));
