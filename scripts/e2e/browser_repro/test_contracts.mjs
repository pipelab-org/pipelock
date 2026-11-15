// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import {test} from 'node:test';
import {checkAPIError,checkManagedIdentity,checkTLSBrowserResources,checkTLSProbe,checkTLSRendered,collectScenarios,isLoginRequired,
  responseBlockReason,tlsProbePlan,tlsRouteLabel} from './contracts.mjs';

test('truncated API requires the actual proxy parse-error refusal, not any 403',()=>{
  const state={state:'error',error:'HTTP 403'};
  assert.doesNotThrow(()=>checkAPIError('incomplete',state,{status:403,block_reason:'parse_error'}));
  for(const response of [undefined,{status:200},{status:502},{status:403},
    {status:403,block_reason:'dlp_match'},{status:403,block_reason:'prompt_injection'}])
    assert.throws(()=>checkAPIError('incomplete',state,response));
  for(const error of ['Failed to fetch','HTTP 502','HTTP 503'])
    assert.throws(()=>checkAPIError('incomplete',{state:'error',error},{status:403,block_reason:'parse_error'}));
  assert.throws(()=>checkAPIError('incomplete',{state:'ready'},{status:403,block_reason:'parse_error'}));
  assert.doesNotThrow(()=>checkAPIError('error',{state:'error',error:'HTTP 503'},{status:503}));
  assert.throws(()=>checkAPIError('error',state,{status:403,block_reason:'parse_error'}));
  assert.equal(responseBlockReason({'X-Pipelock-Block-Reason':'parse_error'}),'parse_error');
  assert.equal(responseBlockReason({}),null);
});

test('login readiness requires the exact form and origin, not just a path',()=>{
  const origin='http://browser.fixture.example';
  const form={ready:'complete',origin,action_origin:origin,path:'/account',form:'fixture-login',method:'post',
    action:'/session',user:true,code:true,submit:true,appReady:false};
  assert.equal(isLoginRequired(form,origin),true);
  assert.equal(isLoginRequired({...form,path:'/login'},origin),true);
  for(const delta of [{ready:'loading'},{path:'/session'},{form:null},{method:'get'},
    {action:'/other'},{origin:'http://other.fixture.example'},
    {action_origin:'http://other.fixture.example'},{user:false},{code:false},{submit:false},{appReady:true}])
    assert.equal(isLoginRequired({...form,...delta},origin),false);
  assert.equal(isLoginRequired({path:'/login'},origin),false);
  assert.equal(isLoginRequired(null,origin),false);
  assert.equal(isLoginRequired(form),false);
});

test('a failed independent scenario remains failed without hiding later observations',async()=>{
  const observed=[];
  const cases=await collectScenarios(['incomplete','pending','later'],async name=>{
    observed.push(name);
    if(name==='incomplete')checkAPIError(name,{state:'error',error:'HTTP 403'},
      {status:403,block_reason:'dlp_match'});
    return {status:name==='pending'?'expected_pending':'pass'};
  });
  assert.deepEqual(observed,['incomplete','pending','later']);
  assert.deepEqual(cases.map(({status})=>status),['fail','expected_pending','pass']);
  assert.equal(cases.some(({status})=>status==='fail'),true);
});

test('managed launch requires native nonroot identity and the exact installed route',()=>{
  const settings={expected_uid:1200,expected_gid:1200,expected_node:{exec_path:'/usr/bin/node',version:'24.0.0'},
    expected_proxy:'http://127.0.0.1:8888'};
  const identity={uid:1200,gid:1200,exec_path:'/usr/bin/node',version:'24.0.0',release:'node'};
  const route={upper:settings.expected_proxy,lower:settings.expected_proxy};
  assert.doesNotThrow(()=>checkManagedIdentity(settings,identity,route));
  for(const delta of [{uid:0},{gid:0},{uid:'1200'},{uid:1201},{gid:1201},
    {exec_path:'/usr/bin/mise'},{version:'22.0.0'},{release:'other'}])
    assert.throws(()=>checkManagedIdentity(settings,{...identity,...delta},route));
  for(const delta of [{upper:'http://other.fixture.example'},{lower:''},{lower:undefined}])
    assert.throws(()=>checkManagedIdentity(settings,identity,{...route,...delta}));
  assert.throws(()=>checkManagedIdentity({...settings,proxy:settings.expected_proxy},identity,route));
});

const tlsHosts={page:'page.fixture.example',cdn:'cdn.fixture.example',third:'third.fixture.example'};
const tlsPaths={script:'/assets/'+'S'.repeat(60)+'.js',style:'/assets/'+'T'.repeat(60)+'.css',
  image:'/assets/'+'I'.repeat(60)+'.png',third:'/assets/'+'C'.repeat(60)+'.png',root:'/assets/'+'R'.repeat(60)+'.png'};

test('TLS probe plan: every negative is a distinct, attributed refusal and only the declared exact resources pass',()=>{
  const plan=tlsProbePlan({hosts:tlsHosts,paths:tlsPaths,queryToken:'Q'.repeat(40),canary:'SYNTHETIC_CANARY'});
  assert.deepEqual(plan.before.map(p=>p.expect),Array(4).fill({status:403,block_reason:'path_entropy'}));
  assert.deepEqual(plan.before.map(p=>p.host),[tlsHosts.cdn,tlsHosts.cdn,tlsHosts.cdn,tlsHosts.third]);
  assert.deepEqual(plan.allowed.map(p=>[p.host,p.path,p.method,p.expect.status]),
    [...['script','style','image'].map(kind=>[tlsHosts.cdn,tlsPaths[kind],'GET',200]),[tlsHosts.third,tlsPaths.root,'GET',200]]);
  // The onward path (named only by the CDN stylesheet) is never in the allowed set.
  assert.ok(!plan.allowed.some(p=>p.path===tlsPaths.third));
  const byName=Object.fromEntries(plan.negatives.map(p=>[p.name,p]));
  assert.deepEqual(Object.keys(byName),['altered_path','high_entropy_query_on_declared_path','canary_on_declared_path',
    'post_body_on_declared_path','get_with_body_on_declared_path','third_origin_resource']);
  assert.notEqual(byName.altered_path.path,tlsPaths.script);
  assert.equal(byName.altered_path.path.length,tlsPaths.script.length);
  assert.equal(byName.high_entropy_query_on_declared_path.expect.block_reason,'query_entropy');
  assert.ok(byName.high_entropy_query_on_declared_path.path.startsWith(tlsPaths.script+'?'));
  assert.equal(byName.canary_on_declared_path.expect.block_reason,'dlp_match');
  assert.equal(byName.post_body_on_declared_path.method,'POST');
  assert.equal(typeof byName.post_body_on_declared_path.body,'string');
  assert.equal(byName.get_with_body_on_declared_path.method,'GET');
  assert.equal(typeof byName.get_with_body_on_declared_path.body,'string');
  assert.equal(byName.third_origin_resource.host,tlsHosts.third);
  for(const probe of plan.negatives)assert.equal(probe.expect.status,403);
});

test('TLS probe check requires the attributed layer, not any refusal or any success',()=>{
  const denied={name:'x',expect:{status:403,block_reason:'path_entropy'}};
  assert.doesNotThrow(()=>checkTLSProbe(denied,{status:403,block_reason:'path_entropy'}));
  for(const result of [{status:403,block_reason:null},{status:403,block_reason:'dlp_match'},{status:200,block_reason:null},undefined])
    assert.throws(()=>checkTLSProbe(denied,result));
  const allowed={name:'y',expect:{status:200,block_reason:null}};
  assert.doesNotThrow(()=>checkTLSProbe(allowed,{status:200}));
  assert.throws(()=>checkTLSProbe(allowed,{status:403,block_reason:'path_entropy'}));
  assert.throws(()=>checkTLSProbe(allowed,{status:200,block_reason:'path_entropy'}));
});

test('TLS rendered check fails a blank, unstyled, image-less or non-HTTPS page',()=>{
  const origin='https://page.fixture.example:443';
  const dom={protocol:'https:',origin,state:'ready',heading:'Synthetic CDN page',styledColor:'rgb(0, 128, 0)',
    imageComplete:true,imageNatural:64,imageBox:[64,64],scriptRan:true,rootNatural:64};
  assert.doesNotThrow(()=>checkTLSRendered(dom,origin,64));
  assert.throws(()=>checkTLSRendered(null,origin,64));
  assert.throws(()=>checkTLSRendered({},origin,64));
  for(const delta of [{protocol:'http:'},{origin:'https://other.fixture.example'},{state:'loading'},{state:'error'},
    {heading:''},{styledColor:'rgb(0, 0, 0)'},{imageComplete:false},{imageNatural:0},{rootNatural:0},{imageBox:[0,0]},{scriptRan:undefined}])
    assert.throws(()=>checkTLSRendered({...dom,...delta},origin,64));
});

test('TLS browser network check needs 200s over the expected protocol and the third origin refused for entropy',()=>{
  const ok={status:200,block_reason:null,error:null,protocol:'h2'};
  const observed={'cdn:script':ok,'cdn:style':ok,'cdn:image':ok,'third:root':ok,'third:third':{status:403,block_reason:'path_entropy',error:'net::ERR_BLOCKED_BY_ORB'}};
  assert.doesNotThrow(()=>checkTLSBrowserResources(observed,'h2'));
  assert.doesNotThrow(()=>checkTLSBrowserResources(observed));
  assert.throws(()=>checkTLSBrowserResources(observed,'http/1.1'));
  // Each CDN item alone on the wrong protocol must fail, not only the third-origin one.
  for(const kind of ['script','style','image'])
    assert.throws(()=>checkTLSBrowserResources({...observed,[`cdn:${kind}`]:{...ok,protocol:'http/1.1'}},'h2'));
  for(const kind of ['script','style','image']){
    assert.throws(()=>checkTLSBrowserResources({...observed,[`cdn:${kind}`]:{...ok,status:403}},'h2'));
    assert.throws(()=>checkTLSBrowserResources({...observed,[`cdn:${kind}`]:{...ok,error:'net::ERR_BLOCKED_BY_ORB'}},'h2'));
    const {[`cdn:${kind}`]:_dropped,...rest}=observed;
    assert.throws(()=>checkTLSBrowserResources(rest,'h2'));
  }
  assert.throws(()=>checkTLSBrowserResources({...observed,'third:root':{...ok,status:403}},'h2'));
  assert.throws(()=>checkTLSBrowserResources({...observed,'third:root':{...ok,protocol:'http/1.1'}},'h2'));
  assert.throws(()=>checkTLSBrowserResources({...observed,'third:third':{status:200,block_reason:null,protocol:'h2'}},'h2'));
  assert.throws(()=>checkTLSBrowserResources({...observed,'third:third':{status:403,block_reason:'dlp_match'}},'h2'));
  assert.throws(()=>checkTLSBrowserResources({...observed,'third:third':undefined},'h2'));
});

test('TLS route labels name origin and role, never a hashed path',()=>{
  const label=url=>tlsRouteLabel(url,tlsHosts,tlsPaths);
  assert.equal(label('https://page.fixture.example:9/'),'page:/');
  assert.equal(label('https://page.fixture.example:9/favicon.ico'),'page:favicon');
  assert.equal(label('https://cdn.fixture.example:9'+tlsPaths.script),'cdn:script');
  assert.equal(label('https://cdn.fixture.example:9'+tlsPaths.script+'?v=1'),'cdn:script');
  assert.equal(label('https://cdn.fixture.example:9/assets/other.js'),'cdn:other');
  assert.equal(label('https://third.fixture.example:9'+tlsPaths.third),'third:third');
  assert.equal(label('https://www.google.com/'),'other-origin');
  assert.equal(label('not a url'),'unknown');
  for(const url of ['https://cdn.fixture.example:9'+tlsPaths.style,'https://cdn.fixture.example:9/zzz'])
    assert.ok(!label(url).includes('/assets/'));
});
