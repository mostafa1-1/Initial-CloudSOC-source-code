import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createDatabase } from './db';
import { createApp, ingestSecurityEventAndEvaluate } from './app';
import { buildReportData } from './reports';
import { evaluateDetectionRules, type DetectionRuleConfig, type SecurityEventRecord } from './detection';

async function start() {
  const db = createDatabase(':memory:');
  const app = createApp(db);
  const server = await new Promise<ReturnType<typeof app.listen>>(resolve => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const auth = await fetch(url+'/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({identifier:'admin@cloudsoc.local',password:'Admin@CloudSOC2026!'}) });
  assert.equal(auth.status,200);
  const cookie = (auth.headers.get('set-cookie')||'').split(';')[0];
  const json = await auth.json() as {csrfToken:string};
  const headers = {'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':json.csrfToken};
  return {db,url,headers,close:()=>new Promise<void>(resolve=>server.close(()=>{db.close();resolve();}))};
}

test('Hardening: forged login IP and untrusted proxy headers cannot affect audit IP',async()=>{
  const s=await start(); try {
    const res=await fetch(s.url+'/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json','X-Forwarded-For':'203.0.113.99','X-Forwarded-Proto':'https'},body:JSON.stringify({identifier:'user_ip_probe_unknown',password:'invalid',simulated_ip:'198.51.100.77'})});
    assert.equal(res.status,401);
    assert.match(res.headers.get('set-cookie')||'', /^$/);
    const row=s.db.prepare("SELECT source_ip FROM security_events WHERE username = 'user_ip_probe_unknown' ORDER BY id DESC LIMIT 1").get() as {source_ip:string};
    assert.equal(row.source_ip,'127.0.0.1');
  } finally {await s.close();}
});

test('Hardening: simulation marks generated events and alerts as demo telemetry',async()=>{
  const s=await start(); try {
    const res=await fetch(s.url+'/api/events/simulate-bruteforce',{method:'POST',headers:s.headers,body:JSON.stringify({source_ip:'198.51.100.181',username:'hardening_user',attempts:10})});
    assert.equal(res.status,201);
    const events=s.db.prepare("SELECT is_demo FROM security_events WHERE source_ip='198.51.100.181'").all() as Array<{is_demo:number}>;
    assert.ok(events.length>=10 && events.every(x=>x.is_demo===1));
    const alerts=s.db.prepare("SELECT is_demo FROM alerts WHERE source_ip='198.51.100.181'").all() as Array<{is_demo:number}>;
    assert.ok(alerts.length>=1 && alerts.every(x=>x.is_demo===1));
  } finally {await s.close();}
});

test('Hardening: expired threat intelligence indicators cannot trigger RULE-004',async()=>{
  const s=await start();try {
    const ip='198.51.100.193';
    s.db.prepare("INSERT INTO threat_indicators(indicator_type,indicator_value,reputation_score,verdict,source,raw_summary,cached_until) VALUES ('ipv4', ?, 97, 'Malicious','Local Test','{}',?)").run(ip,'2000-01-01T00:00:00.000Z');
    const result=ingestSecurityEventAndEvaluate(s.db,{source_ip:ip,username:'cache_probe',event_type:'Successful Login',severity:'Medium',description:'expired IOC test'});
    const codes=s.db.prepare('SELECT dr.rule_code FROM alerts a JOIN detection_rules dr ON a.rule_id=dr.id WHERE a.trigger_event_id=?').all(result.event.id) as Array<{rule_code:string}>;
    assert.ok(!codes.some(x=>x.rule_code==='RULE-004'));
    s.db.prepare('UPDATE threat_indicators SET cached_until=? WHERE indicator_value=?').run('2999-01-01T00:00:00.000Z',ip);
    const fresh=ingestSecurityEventAndEvaluate(s.db,{source_ip:ip,username:'cache_probe',event_type:'Successful Login',severity:'Medium',description:'fresh IOC test'});
    const codesFresh=s.db.prepare('SELECT dr.rule_code FROM alerts a JOIN detection_rules dr ON a.rule_id=dr.id WHERE a.trigger_event_id=?').all(fresh.event.id) as Array<{rule_code:string}>;
    assert.ok(codesFresh.some(x=>x.rule_code==='RULE-004'));
  }finally {await s.close();}
});

test('Hardening: Dashboard KPIs and charts respect selected time period',async()=>{
  const s=await start(); try {
    s.db.exec("UPDATE security_events SET timestamp='2024-01-01T00:00:00.000Z'; UPDATE alerts SET created_at='2024-01-01T00:00:00.000Z'; UPDATE incidents SET created_at='2024-01-01T00:00:00.000Z'");
    const res=await fetch(s.url+'/api/dashboard?days=7',{headers:s.headers});
    assert.equal(res.status,200);
    const data=await res.json() as {kpis:Record<string,number>;charts:Record<string,Array<unknown>>;refreshIntervalSeconds:number};
    assert.equal(data.kpis.totalEvents,0);assert.equal(data.kpis.totalAlerts,0);assert.equal(data.kpis.criticalAlerts,0);
    assert.equal(data.kpis.openIncidents,0);assert.equal(data.kpis.resolvedIncidents,0);
    assert.equal(data.charts.alertsBySeverity.length,0);assert.equal(data.charts.incidentsByStatus.length,0);
    assert.equal(data.refreshIntervalSeconds,30);
  } finally {await s.close();}
});

test('Hardening: report severity/date filters are applied to every relevant metric',async()=>{
  const s=await start();try {
    const r=buildReportData(s.db,{type:'severity',severity:'Critical',startDate:'2020-01-01',endDate:'2998-01-01'});
    assert.ok(r.rows.length>0 && r.rows.every(x=>x.severity==='Critical'));
    const past=buildReportData(s.db,{type:'analyst_activity',startDate:'2020-01-01',endDate:'2020-01-02'});
    assert.ok(past.rows.every(x=>Number(x.assigned_alerts)===0 && Number(x.assigned_incidents)===0 && Number(x.notes_authored)===0 && Number(x.response_actions)===0 && Number(x.audit_actions)===0));
    const current=buildReportData(s.db,{type:'analyst_activity',startDate:'2020-01-01',endDate:'2998-01-01'});
    assert.equal(current.summary.activeUsers,2);
  } finally {await s.close();}
});

test('Hardening: assignment rejects admin user; last admin and settings cannot be invalidated',async()=>{
  const s=await start(); try {
    const admins=s.db.prepare("SELECT u.id FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='ADMIN'").get() as {id:number};
    const alert=s.db.prepare('SELECT id FROM alerts LIMIT 1').get() as {id:number};
    const badAssign=await fetch(s.url+`/api/alerts/${alert.id}`,{method:'PATCH',headers:s.headers,body:JSON.stringify({assigned_to:admins.id})});
    assert.equal(badAssign.status,400);
    const badIncident=await fetch(s.url+'/api/incidents',{method:'POST',headers:s.headers,body:JSON.stringify({title:'Test incident case',description:'Security test',assigned_to:admins.id})});
    assert.equal(badIncident.status,400);
    const downgrade=await fetch(s.url+`/api/users/${admins.id}`,{method:'PATCH',headers:s.headers,body:JSON.stringify({role:'SECURITY_ANALYST'})});
    assert.equal(downgrade.status,400);
    const unknownSetting=await fetch(s.url+'/api/settings',{method:'PATCH',headers:s.headers,body:JSON.stringify({settings:{nonexistent_setting:'x'}})});
    assert.equal(unknownSetting.status,400);
    const badAllowlist=await fetch(s.url+'/api/settings',{method:'PATCH',headers:s.headers,body:JSON.stringify({settings:{allowlisted_ips:'definitely_not_an_IP'}})});
    assert.equal(badAllowlist.status,400);
  }finally {await s.close();}
});

test('Hardening: RULE-004 respects configurable threshold over sliding event window',()=>{
  const now=new Date().toISOString();
  const rule:DetectionRuleConfig={id:4,rule_code:'RULE-004',name:'IP reputation',description:'',event_type_target:'*',threshold:2,time_window_minutes:60,severity:'High',is_enabled:1,explanation_template:''};
  const ev=(id:number):SecurityEventRecord=>({id,event_uid:`EVT-${id}`,timestamp:now,source_ip:'198.51.100.222',username:'user',event_type:'Successful Login',description:'',severity:'Low',user_agent:'',detection_status:'Processed'});
  const params={incomingEvent:ev(2),rules:[rule],activeAlerts:[],allowlistedIps:new Set<string>(),knownMaliciousIps:new Map([['198.51.100.222',{indicator_value:'198.51.100.222',verdict:'Malicious',reputation_score:90,source:'test'}]])};
  assert.equal(evaluateDetectionRules({...params,recentEvents:[ev(2)]}).length,0);
  assert.equal(evaluateDetectionRules({...params,recentEvents:[ev(1),ev(2)]}).length,1);
});
