import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import crypto from "crypto";

dotenv.config();
const app=express();
const PORT=process.env.PORT||3000;
const SECRET=process.env.JWT_SECRET||"change-me";
const ADMIN_USER=process.env.ADMIN_USER||"Raiyan";
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"raiyan123";
app.use(cors({origin:process.env.CORS_ORIGIN||"*"}));
app.use(express.json());

const db=new Database("data.sqlite");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,email TEXT UNIQUE,password TEXT,balance REAL DEFAULT 0,created_at TEXT);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,user_id TEXT,data TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS services(id TEXT PRIMARY KEY,data TEXT);
CREATE TABLE IF NOT EXISTS settings(id TEXT PRIMARY KEY,data TEXT);
`);

const uid=()=>crypto.randomUUID(), now=()=>new Date().toISOString();
const token=(p,exp="12h")=>jwt.sign(p,SECRET,{expiresIn:exp});
function admin(req,res,next){try{const p=jwt.verify((req.headers.authorization||"").replace("Bearer ",""),SECRET);if(p.role!=="admin")throw 0;next()}catch{res.status(401).json({error:"Admin login required"})}}
function user(req,res,next){try{const p=jwt.verify((req.headers.authorization||"").replace("Bearer ",""),SECRET);if(p.role!=="user")throw 0;req.user=p;next()}catch{res.status(401).json({error:"Login required"})}}

app.get("/api/health",(q,r)=>r.json({ok:true}));
app.post("/api/admin/login",(q,r)=>q.body.user===ADMIN_USER&&q.body.password===ADMIN_PASSWORD?r.json({token:token({role:"admin"})}):r.status(401).json({error:"Wrong admin user or password"}));

app.post("/api/auth/register",async(q,r)=>{
 const {name,email,password}=q.body||{}; if(!name||!email||!password)return r.status(400).json({error:"Fill all fields"});
 try{const id=uid();const hash=await bcrypt.hash(password,10);db.prepare("INSERT INTO users VALUES(?,?,?,?,?,?,?)").run(id,name,email.toLowerCase(),hash,0,now(),now());r.json({token:token({role:"user",id},"30d"),user:{id,name,email,balance:0}})}
 catch{r.status(409).json({error:"Email already exists"})}
});
app.post("/api/auth/login",async(q,r)=>{
 const {email,password}=q.body||{};const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase());
 if(!u||!(await bcrypt.compare(password||"",u.password)))return r.status(401).json({error:"Invalid login"});
 r.json({token:token({role:"user",id:u.id},"30d"),user:{id:u.id,name:u.name,email:u.email,balance:u.balance}});
});
app.get("/api/me",user,(q,r)=>r.json(db.prepare("SELECT id,name,email,balance FROM users WHERE id=?").get(q.user.id)));

app.get("/api/services",(q,r)=>r.json(db.prepare("SELECT id,data FROM services").all().map(x=>({id:x.id,...JSON.parse(x.data)}))));
app.post("/api/services",admin,(q,r)=>{const id=q.body.id||uid(),d={...q.body};delete d.id;db.prepare("INSERT OR REPLACE INTO services VALUES(?,?)").run(id,JSON.stringify(d));r.json({id,...d})});
app.delete("/api/services/:id",admin,(q,r)=>{db.prepare("DELETE FROM services WHERE id=?").run(q.params.id);r.json({ok:true})});

app.get("/api/settings/:id",(q,r)=>{const x=db.prepare("SELECT data FROM settings WHERE id=?").get(q.params.id);r.json(x?JSON.parse(x.data):{})});
app.put("/api/settings/:id",admin,(q,r)=>{db.prepare("INSERT OR REPLACE INTO settings VALUES(?,?)").run(q.params.id,JSON.stringify(q.body));r.json(q.body)});

app.get("/api/orders",admin,(q,r)=>r.json(db.prepare("SELECT id,user_id,data,created_at FROM orders ORDER BY created_at DESC").all().map(x=>({id:x.id,userId:x.user_id,...JSON.parse(x.data),createdAt:x.created_at}))));
app.get("/api/my-orders",user,(q,r)=>r.json(db.prepare("SELECT id,data,created_at FROM orders WHERE user_id=? ORDER BY created_at DESC").all(q.user.id).map(x=>({id:x.id,...JSON.parse(x.data),createdAt:x.created_at}))));
app.post("/api/orders",user,(q,r)=>{
 const u=db.prepare("SELECT * FROM users WHERE id=?").get(q.user.id),price=Number(q.body.price||0);
 if(!u||price<0||u.balance<price)return r.status(400).json({error:"Insufficient balance"});
 const id=uid(),d={...q.body,status:"pending",date:now()};
 db.transaction(()=>{db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(price,u.id);db.prepare("INSERT INTO orders VALUES(?,?,?,?)").run(id,u.id,JSON.stringify(d),now())})();
 r.json({id,...d});
});
app.patch("/api/orders/:id",admin,(q,r)=>{const x=db.prepare("SELECT data FROM orders WHERE id=?").get(q.params.id);if(!x)return r.status(404).json({error:"Not found"});const d={...JSON.parse(x.data),...q.body};db.prepare("UPDATE orders SET data=? WHERE id=?").run(JSON.stringify(d),q.params.id);r.json({id:q.params.id,...d})});
app.get("/api/users",admin,(q,r)=>r.json(db.prepare("SELECT id,name,email,balance,created_at FROM users ORDER BY created_at DESC").all()));
app.patch("/api/users/:id/balance",admin,(q,r)=>{const b=Number(q.body.balance);if(!Number.isFinite(b)||b<0)return r.status(400).json({error:"Invalid balance"});db.prepare("UPDATE users SET balance=? WHERE id=?").run(b,q.params.id);r.json({ok:true,balance:b})});
app.get("/api/admin/stats",admin,(q,r)=>r.json({users:db.prepare("SELECT count(*) n FROM users").get().n,orders:db.prepare("SELECT count(*) n FROM orders").get().n,services:db.prepare("SELECT count(*) n FROM services").get().n}));
app.listen(PORT,()=>console.log("Server running on port "+PORT));
