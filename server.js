import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=dirname(fileURLToPath(import.meta.url));
const dir=process.env.DATA_DIR||resolve(root,'data'); mkdirSync(dir,{recursive:true});
const db=new DatabaseSync(resolve(dir,'finance.sqlite')); db.exec('PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS reports(year INTEGER, month INTEGER, rows TEXT NOT NULL, PRIMARY KEY(year,month)); CREATE TABLE IF NOT EXISTS years(year INTEGER PRIMARY KEY);');
db.exec('CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY CHECK(id=1), login TEXT NOT NULL, password_hash TEXT NOT NULL, code_hash TEXT NOT NULL)');
const storedCredentials=()=>db.prepare('SELECT * FROM credentials WHERE id=1').get();
const encode=value=>{const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(value,salt,32).toString('hex');};
const verify=(value,encoded)=>{if(typeof value!=='string'||value.length>1024)return false;const [salt,digest]=encoded.split(':');return timingSafeEqual(scryptSync(value,salt,32),Buffer.from(digest,'hex'));};
const sessions=new Map();
const hash=v=>scryptSync(v,'seller-finance-auth-v1',32);
const equal=(a,b)=>timingSafeEqual(hash(String(a||'')),hash(String(b||'')));
const configured=()=>Boolean(storedCredentials()||(process.env.ADMIN_LOGIN&&process.env.ADMIN_PASSWORD&&process.env.CLIENT_CODE));
const period=(y,m)=>Number.isInteger(y)&&y>=2000&&y<=2100&&Number.isInteger(m)&&m>=1&&m<=12;
const cookie=req=>{const token=/finance_session=([a-f0-9]+)/.exec(req.headers.cookie||'')?.[1];const s=sessions.get(token);if(s&&s.expires>Date.now())return s; if(token)sessions.delete(token);};
async function body(req){let text='';for await(const c of req){text+=c;if(Buffer.byteLength(text)>1024*1024)throw Error('Слишком большой запрос');}return JSON.parse(text||'{}');}
const send=(res,status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
const attempts=new Map();
export const server=http.createServer(async(req,res)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'");
try{const u=new URL(req.url,'http://localhost');
if(!u.pathname.startsWith('/api/')){const files={'/':'index.html','/admin':'index.html','/app.js':'app.js','/style.css':'style.css','/exceljs.min.js':'../node_modules/exceljs/dist/exceljs.min.js'};const file=files[u.pathname];if(!file){res.writeHead(404);return res.end('Not found');}res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript; charset=utf-8':file.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8');return res.end(readFileSync(resolve(root,'public',file)));}

if(!['GET','HEAD'].includes(req.method)&&req.headers.origin&&req.headers.origin!==`${req.socket.encrypted?'https':'http'}://${req.headers.host}`&&req.headers.origin!==process.env.APP_ORIGIN)return send(res,403,{error:'Недопустимый источник запроса'});
if(u.pathname==='/api/setup'&&req.method==='GET')return send(res,200,{required:!configured(),available:Boolean(process.env.SETUP_KEY&&process.env.SETUP_KEY.length>=16)});
if(u.pathname==='/api/setup'&&req.method==='POST'){
 if(configured())return send(res,409,{error:'Первичная настройка уже завершена'});
 if(!process.env.SETUP_KEY||process.env.SETUP_KEY.length<16)return send(res,503,{error:'Для первого запуска задайте SETUP_KEY (не менее 16 символов) в настройках Node.js в Plesk.'});
 const ip=req.socket.remoteAddress;let a=attempts.get(ip);if(!a||a.until<Date.now()){a={count:0,until:Date.now()+900000};attempts.set(ip,a);}if(a.count>=10)return send(res,429,{error:'Слишком много попыток. Повторите через 15 минут.'});
 const b=await body(req);if(typeof b.key!=='string'||b.key.length>1024||!equal(b.key,process.env.SETUP_KEY)){a.count++;return send(res,403,{error:'Неверный ключ установки'});}
 if(typeof b.login!=='string'||b.login.trim().length<3||b.login.length>100||typeof b.password!=='string'||b.password.length<12||b.password.length>256||typeof b.code!=='string'||b.code.length<8||b.code.length>256)return send(res,400,{error:'Логин: 3–100 символов, пароль: 12–256, код клиента: 8–256.'});
 const passwordHash=encode(b.password),codeHash=encode(b.code);
 // Body reading is asynchronous: recheck before the synchronous insert to prevent competing setup requests.
 if(configured())return send(res,409,{error:'Первичная настройка уже завершена'});
 db.prepare('INSERT INTO credentials VALUES(1,?,?,?)').run(b.login.trim(),passwordHash,codeHash);attempts.delete(ip);return send(res,201,{saved:true});
}
if(!configured())return send(res,503,{error:'Откройте /admin для первичной настройки.'});
if(u.pathname==='/api/login'&&req.method==='POST'){const ip=req.socket.remoteAddress;let a=attempts.get(ip);if(!a||a.until<Date.now()){a={count:0,until:Date.now()+900000};attempts.set(ip,a);}if(a.count>=10)return send(res,429,{error:'Слишком много попыток. Повторите через 15 минут.'});const b=await body(req);const admin=b.role==='admin';const credentials=storedCredentials();const ok=credentials?(admin?(equal(b.login,credentials.login)&&verify(b.password,credentials.password_hash)):verify(b.code,credentials.code_hash)):(admin?(equal(b.login,process.env.ADMIN_LOGIN)&&equal(b.password,process.env.ADMIN_PASSWORD)):equal(b.code,process.env.CLIENT_CODE));if(!ok){a.count++;return send(res,401,{error:'Неверные данные для входа'});}attempts.delete(ip);const token=randomBytes(32).toString('hex');sessions.set(token,{role:admin?'admin':'client',expires:Date.now()+28800000});res.setHeader('Set-Cookie',`finance_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.NODE_ENV==='production'?'; Secure':''}`);return send(res,200,{role:admin?'admin':'client'});}
const s=cookie(req);if(!s)return send(res,401,{error:'Необходим вход'});
if(u.pathname==='/api/session')return send(res,200,{role:s.role});
if(u.pathname==='/api/logout'&&req.method==='POST'){const token=/finance_session=([a-f0-9]+)/.exec(req.headers.cookie||'')?.[1];sessions.delete(token);res.setHeader('Set-Cookie','finance_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return send(res,200,{});}
if(u.pathname==='/api/years'&&req.method==='GET')return send(res,200,db.prepare('SELECT year FROM years ORDER BY year DESC').all().map(x=>x.year));
if(req.method!=='GET'&&s.role!=='admin')return send(res,403,{error:'Только для администратора'});
if(u.pathname==='/api/years'&&req.method==='POST'){const {year}=await body(req);if(!period(year,1))return send(res,400,{error:'Год должен быть от 2000 до 2100'});db.prepare('INSERT OR IGNORE INTO years VALUES(?)').run(year);return send(res,200,{year});}
if(u.pathname==='/api/report'&&req.method==='GET'){const year=Number(u.searchParams.get('year')),month=Number(u.searchParams.get('month'));if(!period(year,month))return send(res,400,{error:'Неверный период'});const report=db.prepare('SELECT rows FROM reports WHERE year=? AND month=?').get(year,month);return send(res,200,{rows:report?JSON.parse(report.rows):[]});}
if(u.pathname==='/api/report'&&req.method==='PUT'){const {year,month,rows}=await body(req);if(!period(year,month)||!Array.isArray(rows)||rows.length>2000||rows.some(r=>!['income','expense'].includes(r.type)||typeof r.name!=='string'||!r.name.trim()||r.name.length>500||!Number.isSafeInteger(r.amount)||r.amount<0||r.amount>1e12)||!Number.isSafeInteger(rows.reduce((s,r)=>s+r.amount,0)))return send(res,400,{error:'Проверьте названия и суммы. Суммы должны быть положительными, максимум 10 млрд ₽.'});const clean=rows.map(({type,name,amount})=>({type,name:name.trim(),amount}));db.exec('BEGIN');try{db.prepare('INSERT OR IGNORE INTO years VALUES(?)').run(year);db.prepare('INSERT INTO reports VALUES(?,?,?) ON CONFLICT(year,month) DO UPDATE SET rows=excluded.rows').run(year,month,JSON.stringify(clean));db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}return send(res,200,{saved:true});}
return send(res,404,{error:'Не найдено'});
}catch(e){console.error(e.message);send(res,400,{error:'Не удалось обработать запрос'});}});
if(process.argv[1]===fileURLToPath(import.meta.url))server.listen(Number(process.env.PORT)||3000,process.env.HOST||'0.0.0.0',()=>console.log('Finance server started'));
