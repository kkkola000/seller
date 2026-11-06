import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
process.env.DATA_DIR=mkdtempSync(join(tmpdir(),'seller-test-'));process.env.ADMIN_LOGIN='tester';process.env.ADMIN_PASSWORD='test-password';process.env.CLIENT_CODE='test-code';
const {server}=await import('../server.js');
test('authentication, permissions, periods, validation, persistence and logout',async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const base=`http://127.0.0.1:${server.address().port}`;async function call(path,method='GET',data,cookie){const r=await fetch(base+'/api/'+path,{method,headers:{'Content-Type':'application/json',...(cookie?{Cookie:cookie}:{})},body:data?JSON.stringify(data):undefined});return {status:r.status,body:await r.json(),cookie:r.headers.get('set-cookie')?.split(';')[0]};}try{
assert.equal((await call('report?year=2026&month=9')).status,401);
assert.equal((await call('login','POST',{role:'admin',login:'tester',password:'bad'})).status,401);
const admin=await call('login','POST',{role:'admin',login:'tester',password:'test-password'});assert.equal(admin.status,200);
const client=await call('login','POST',{code:'test-code'});assert.equal(client.status,200);
assert.equal((await call('years','POST',{year:2026},client.cookie)).status,403);
assert.equal((await call('years','POST',{year:2026},admin.cookie)).status,200);
const rows=[{type:'income',name:'Продажи',amount:105050},{type:'expense',name:'Услуги',amount:2030}];
assert.equal((await call('report','PUT',{year:2026,month:9,rows},admin.cookie)).status,200);
assert.deepEqual((await call('report?year=2026&month=9','GET',null,client.cookie)).body.rows,rows);
assert.deepEqual((await call('report?year=2026&month=10','GET',null,client.cookie)).body.rows,[]);
assert.equal((await call('report','PUT',{year:2026,month:9,rows:[{type:'income',name:'',amount:-1}]},admin.cookie)).status,400);
assert.equal((await call('report?year=2026&month=13','GET',null,client.cookie)).status,400);
assert.equal((await call('report','PUT',{year:2026,month:9,rows:[]},admin.cookie)).status,200);
assert.deepEqual((await call('report?year=2026&month=9','GET',null,client.cookie)).body.rows,[]);
await call('logout','POST',{},client.cookie);assert.equal((await call('session','GET',null,client.cookie)).status,401);
const page=await fetch(base+'/admin');assert.equal(page.status,200);assert.match(await page.text(),/Финансовая отчётность/);
for(const path of ['/seller/public/index.html','/seller/public/app.js','/seller/public/style.css']){const response=await fetch(base+path);assert.equal(response.status,200,path);assert.match(response.headers.get('content-type'),path.endsWith('.js')?/javascript/:path.endsWith('.css')?/css/:/html/);}
const script=await fetch(base+'/exceljs.min.js');assert.equal(script.status,200);
}finally{await new Promise(r=>server.close(r));rmSync(process.env.DATA_DIR,{recursive:true,force:true});}});
