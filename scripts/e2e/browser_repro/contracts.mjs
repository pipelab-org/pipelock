// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Pure observations shared with contract tests; no browser/process side effects.
export function responseBlockReason(headers) {
  const entry=Object.entries(headers||{}).find(([name])=>name.toLowerCase()==='x-pipelock-block-reason');
  return entry?String(entry[1]):null;
}

export function checkAPIError(scenario, state, response) {
  if(state?.state!=='error')throw Error(`${scenario} did not reach an application error`);
  if(scenario==='error'){
    if(state.error!=='HTTP 503'||response?.status!==503)throw Error('error case did not observe intended HTTP 503');
  }else if(scenario==='incomplete'){
    // A truncated upstream body is rejected by Pipelock before delivery.
    // A generic 403 (allowlist/auth/etc.) is not evidence of this control.
    if(state.error!=='HTTP 403'||response?.status!==403||response.block_reason!=='parse_error')
      throw Error('incomplete case did not observe the attributed proxy parse-error refusal');
  }else throw Error(`unsupported error scenario: ${scenario}`);
}

export function isLoginRequired(state, expectedOrigin) {
  // Observe the form and its origin, not just a URL transition. A fixture can
  // serve its login state at /account or redirect the browser to /login.
  return typeof expectedOrigin==='string'&&state?.origin===expectedOrigin&&state.action_origin===expectedOrigin&&
    state.ready==='complete'&&['/account','/login'].includes(state.path)&&
    state.form==='fixture-login'&&state.method==='post'&&state.action==='/session'&&
    state.user===true&&state.code===true&&state.submit===true&&state.appReady===false;
}

export async function collectScenarios(names, observe) {
  const results=[];
  for(const name of names){
    try{results.push({name,...await observe(name)});}
    catch(error){results.push({name,status:'fail',failure:String(error.message||error).slice(0,512)});}
  }
  return results;
}

export function checkManagedIdentity(settings, identity, route) {
  if(!Number.isInteger(identity?.uid)||identity.uid<=0||identity.uid!==settings.expected_uid||
    !Number.isInteger(identity.gid)||identity.gid<=0||identity.gid!==settings.expected_gid)
    throw Error('managed runtime is not the expected nonroot identity');
  if(identity.exec_path!==settings.expected_node?.exec_path||identity.version!==settings.expected_node?.version||
    identity.release!=='node')throw Error('managed Node identity differs from prepared runtime');
  if(settings.proxy||route.upper!==settings.expected_proxy||route.lower!==route.upper)
    throw Error('managed proxy route differs from the installed runtime contract');
}

export const loginObservation=`(()=>{const form=document.getElementById('fixture-login');const action=form?new URL(form.action):null;return {
  ready:document.readyState,origin:location.origin,path:location.pathname,form:form?.id||null,
  method:form?.method||null,action:action?.pathname||null,action_origin:action?.origin||null,
  user:!!form?.querySelector('#user'),code:!!form?.querySelector('#code'),
  submit:!!form?.querySelector('#login'),appReady:window.fixture?.state==='ready'
}})()`;

// TLS/CDN scenario: pure plan and checks. The page origin (A) declares exact
// resources on a CDN origin (B); B's stylesheet names a resource on a third
// origin (C). Hashed paths come from the caller and never enter a report.
export function tlsRouteLabel(url, hosts, paths) {
  let parsed;
  try { parsed=new URL(url); } catch { return 'unknown'; }
  const key=Object.entries(hosts).find(([,host])=>host===parsed.hostname)?.[0];
  if(!key)return 'other-origin';
  const known=Object.entries(paths).find(([,path])=>path===parsed.pathname)?.[0];
  if(key==='page'&&parsed.pathname==='/')return 'page:/';
  if(key==='page'&&parsed.pathname==='/favicon.ico')return 'page:favicon';
  return `${key}:${known||'other'}`;
}

function alteredPath(path) {
  // Replace one interior character so the path stays high-entropy but is no
  // longer the exact declared resource.
  const at=Math.floor(path.length/2);
  return path.slice(0,at)+(path[at]==='Q'?'R':'Q')+path.slice(at+1);
}

export function tlsProbePlan({hosts, paths, queryToken, canary}) {
  const cdn=hosts.cdn;
  const refused=(name,host,path,extra={})=>({name,host,path,method:'GET',...extra,
    expect:{status:403,block_reason:extra.reason||'path_entropy'}});
  const before=['script','style','image'].map(kind=>refused(`before_delivery_${kind}`,cdn,paths[kind]));
  // C is allowlisted, so this refusal is the entropy gate, not destination policy.
  before.push(refused('before_delivery_third_root',hosts.third,paths.root));
  const allowed=['script','style','image'].map(kind=>({name:`declared_${kind}`,host:cdn,path:paths[kind],
    method:'GET',expect:{status:200,block_reason:null}}));
  allowed.push({name:'declared_third_root',host:hosts.third,path:paths.root,method:'GET',expect:{status:200,block_reason:null}});
  const negatives=[
    refused('altered_path',cdn,alteredPath(paths.script)),
    refused('high_entropy_query_on_declared_path',cdn,`${paths.script}?v=${queryToken}`,{reason:'query_entropy'}),
    refused('canary_on_declared_path',cdn,`${paths.script}?marker=${canary}`,{reason:'dlp_match'}),
    refused('post_body_on_declared_path',cdn,paths.script,{method:'POST',body:'synthetic=body'}),
    refused('get_with_body_on_declared_path',cdn,paths.script,{body:'synthetic=body'}),
    refused('third_origin_resource',hosts.third,paths.third),
  ];
  return {before,allowed,negatives};
}

export function checkTLSProbe(probe, result) {
  if(result?.status!==probe.expect.status)
    throw Error(`${probe.name} returned ${result?.status}, expected ${probe.expect.status}`);
  // A bare 403 (allowlist, rate limit, auth) is not evidence of the entropy gate.
  if((result.block_reason||null)!==probe.expect.block_reason)
    throw Error(`${probe.name} block reason ${result.block_reason}, expected ${probe.expect.block_reason}`);
}

export function checkTLSRendered(dom, expectedOrigin, imageSide) {
  // A blank page must not pass: every assertion reads what the browser rendered.
  const failures=[];
  if(dom?.protocol!=='https:'||dom.origin!==expectedOrigin)failures.push('page was not served over the expected HTTPS origin');
  if(dom?.state!=='ready')failures.push(`page state ${dom?.state}`);
  if(dom?.heading!=='Synthetic CDN page')failures.push('page heading missing');
  if(dom?.styledColor!=='rgb(0, 128, 0)')failures.push('CDN stylesheet did not apply');
  if(!dom?.imageComplete||dom.imageNatural!==imageSide)failures.push('CDN image did not decode');
  if(!(dom?.imageBox?.[0]>0&&dom.imageBox[1]>0))failures.push('CDN image is not laid out');
  if(dom?.rootNatural!==imageSide)failures.push('independently declared third-origin image did not decode');
  if(dom?.scriptRan!==true)failures.push('CDN script did not run');
  if(failures.length)throw Error(failures.join('; '));
}

export function checkTLSBrowserResources(observed, protocol=null) {
  // observed maps route label to {status, block_reason, error, protocol} from the
  // browser's own network events. B resources load; C's is refused for path
  // entropy. When a protocol is named, every CDN load must have used it, so a run
  // cannot pass over HTTP/1.1 while claiming the browser's default h2.
  for(const kind of ['script','style','image']){
    const item=observed[`cdn:${kind}`];
    if(item?.status!==200||item.error)throw Error(`browser did not load declared ${kind} (${item?.status})`);
    if(protocol&&item.protocol!==protocol)throw Error(`declared ${kind} used ${item.protocol}, expected ${protocol}`);
  }
  const root=observed['third:root'];
  if(root?.status!==200||root.error)throw Error(`browser did not load the independently declared third-origin root (${root?.status})`);
  if(protocol&&root.protocol!==protocol)throw Error(`third-origin root used ${root.protocol}, expected ${protocol}`);
  const third=observed['third:third'];
  if(third?.status!==403||third.block_reason!=='path_entropy')
    throw Error('third-origin resource named by the CDN stylesheet was not refused for path entropy');
}
