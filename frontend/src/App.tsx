import {Component, ErrorInfo, FormEvent, ReactNode, useEffect, useMemo, useState} from 'react';

type Endpoint={ip:string;port:number};
type EvidenceRef={ID?:string;Kind?:string;ContentType?:string;Filename?:string;SHA256?:string;Size?:number;id?:string;kind?:string;content_type?:string;filename?:string;sha256?:string;size?:number};
export type EventItem={id:string;timestamp:string;sensor_id:string;session_id:string;sequence:number;source:Endpoint;destination:Endpoint;protocol:string;event_type:string;outcome:string;persona:string;attributes?:Record<string,unknown>;protocol_attributes?:Record<string,unknown>;evidence_refs?:EvidenceRef[]};
type Sensor={id:string;status:string;last_seen:string};
type Overview={events_24h:number;sessions_24h:number;sources_24h:number;artifacts_24h:number;protocols?:Record<string,number>;sensors?:Sensor[]};
type Row=Record<string,unknown>;
type Insight={id:string;severity:'high'|'medium'|'low';title:string;description:string;href:string;source?:string;count?:number};
type Route={page:'overview'|'activity'|'sessions'|'session'|'sources'|'source'|'artifacts'|'alerts'|'settings'|'event'|'raw'|'not-found';id?:string;rawKind?:'events'|'sessions'|'sources'};
type TimeRange='15m'|'1h'|'24h'|'7d'|'all'|'custom';
export type ActivityFilters={search:string;protocol:string;type:string;outcome:string;range:TimeRange;customSince:string;customUntil:string};
type EventPageResponse={items:EventItem[]|null;limit:number;offset:number;total:number};
type PageResponse<T>={items:T[]|null;limit:number;offset:number;total:number};
type Finding={id:string;rule:string;title:string;summary:string;severity:'critical'|'high'|'medium'|'low';status:'open'|'acknowledged'|'resolved';source_ip?:string;first_seen:string;last_seen:string;event_count:number;observables?:{kind:string;value:string}[]};
type AlertPreferences={webhooks:string[]|null;source_spike_per_minute:number;webhook_signing_secret?:string;rules?:Record<string,{enabled:boolean;severity?:string;cooldown_minutes?:number}>};
type RulePreference={enabled:boolean;severity:string;cooldown_minutes:number};

const nav=[['Overview','/'],['Activity','/activity'],['Sessions','/sessions'],['Sources','/sources'],['Artifacts','/artifacts'],['Alerts','/alerts']] as const;
const severityRank={high:3,medium:2,low:1};
const eventTypes=['authentication.attempt','command','emulation.gap','http.request','http.malformed','artifact.upload','ssh.scp','session.start','session.end','transcript.chunk','alert'];
const timeRanges:[TimeRange,string][]=[['15m','15 min'],['1h','1 hour'],['24h','24 hours'],['7d','7 days'],['all','All time'],['custom','Custom']];
const defaultAlertRules:Record<string,RulePreference>={successful_emulated_login:{enabled:true,severity:'high',cooldown_minutes:15},artifact_upload:{enabled:true,severity:'high',cooldown_minutes:15},unhealthy_sensor:{enabled:true,severity:'high',cooldown_minutes:0},post_login_activity:{enabled:true,severity:'medium',cooldown_minutes:15},staged_download:{enabled:true,severity:'high',cooldown_minutes:15},novel_fingerprint:{enabled:true,severity:'medium',cooldown_minutes:15},source_spike:{enabled:true,severity:'medium',cooldown_minutes:15},cross_protocol_activity:{enabled:true,severity:'medium',cooldown_minutes:15},http_enumeration:{enabled:true,severity:'medium',cooldown_minutes:15},reused_secret:{enabled:true,severity:'medium',cooldown_minutes:15},emulation_gap:{enabled:true,severity:'low',cooldown_minutes:15}};

export function pageItems<T>(page?:{items?:T[]|null}):T[]{
  return Array.isArray(page?.items)?page.items:[];
}

export function joinLines(items?:string[]|null):string{
  return (items||[]).join('\n');
}

export function parseRoute(pathname:string):Route {
  const parts=pathname.split('/').filter(Boolean).map(part=>{try{return decodeURIComponent(part)}catch{return part}});
  if(parts[0]==='sessions'&&parts[1])return{page:'session',id:parts[1]};
  if(parts[0]==='sources'&&parts[1])return{page:'source',id:parts[1]};
  if(parts[0]==='events'&&parts[1])return{page:'event',id:parts[1]};
  if(parts[0]==='raw'&&['events','sessions','sources'].includes(parts[1])&&parts[2])return{page:'raw',rawKind:parts[1] as Route['rawKind'],id:parts[2]};
  if(!parts.length)return{page:'overview'};
  if(['activity','sessions','sources','artifacts','alerts','settings'].includes(parts[0])&&parts.length===1)return{page:parts[0] as Route['page']};
  return{page:'not-found'};
}

function useRoute(){
  const[route,setRoute]=useState(()=>parseRoute(window.location.pathname));
  useEffect(()=>{const update=()=>setRoute(parseRoute(window.location.pathname));window.addEventListener('popstate',update);return()=>window.removeEventListener('popstate',update)},[]);
  const go=(href:string)=>{if(href===window.location.pathname)return;window.history.pushState({},'',href);setRoute(parseRoute(href));window.scrollTo({top:0,behavior:'smooth'})};
  return{route,go};
}

function useData<T>(url:string){
  const[data,setData]=useState<T>();const[error,setError]=useState('');const[loading,setLoading]=useState(true);
  useEffect(()=>{let active=true;setLoading(true);setError('');get<T>(url).then(value=>active&&setData(value)).catch(e=>active&&setError(e instanceof Error?e.message:String(e))).finally(()=>active&&setLoading(false));return()=>{active=false}},[url]);
  return{data,error,loading};
}

function useCompleteEvents(filter:string){
  const[data,setData]=useState<EventItem[]>([]);const[error,setError]=useState('');const[loading,setLoading]=useState(true);
  useEffect(()=>{let active=true;(async()=>{setLoading(true);setError('');const all:EventItem[]=[];let offset=0;for(;;){const page=await get<EventPageResponse>(`/api/v1/events?${filter}&limit=500&offset=${offset}`);const items=pageItems(page);all.push(...items);offset+=items.length;if(offset>=page.total||items.length===0)break}if(active)setData(all)})().catch(e=>active&&setError(e instanceof Error?e.message:String(e))).finally(()=>active&&setLoading(false));return()=>{active=false}},[filter]);
  return{data,error,loading};
}

function useCompletePage<T>(base:string){
  const[data,setData]=useState<T[]>([]);const[total,setTotal]=useState(0);const[error,setError]=useState('');const[loading,setLoading]=useState(true);
  useEffect(()=>{let active=true;(async()=>{setLoading(true);setError('');const all:T[]=[];let offset=0;const separator=base.includes('?')?'&':'?';for(;;){const page=await get<PageResponse<T>>(`${base}${separator}limit=500&offset=${offset}`);const items=pageItems(page);all.push(...items);offset+=items.length;if(offset>=page.total||items.length===0){if(active)setTotal(page.total);break}}if(active)setData(all)})().catch(e=>active&&setError(e instanceof Error?e.message:String(e))).finally(()=>active&&setLoading(false));return()=>{active=false}},[base]);
  return{data,total,error,loading};
}

function useEventFeed(url:string){
  const{data,error,loading}=useData<{items:EventItem[]|null}>(url);const[items,setItems]=useState<EventItem[]>([]);
  useEffect(()=>{if(data)setItems(data.items||[])},[data]);
  useEffect(()=>{const stream=new EventSource('/api/v1/stream');const receive=(raw:Event)=>{const next=JSON.parse((raw as MessageEvent).data) as EventItem;setItems(current=>current.some(item=>item.id===next.id)?current:[next,...current].slice(0,1000))};stream.addEventListener('event',receive);return()=>stream.close()},[]);
  return{items,error,loading};
}

function AppLink({href,go,className,children,title}:{href:string;go:(href:string)=>void;className?:string;children:ReactNode;title?:string}){
  return <a href={href} className={className} title={title} onClick={e=>{if(!e.metaKey&&!e.ctrlKey&&!e.shiftKey&&!e.altKey){e.preventDefault();go(href)}}}>{children}</a>;
}

export function App(){
  const{route,go}=useRoute();
  const{data:overview}=useData<Overview>('/api/v1/overview');
  const[theme,setTheme]=useState(localStorage.getItem('fyke-theme')||'dark');
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem('fyke-theme',theme)},[theme]);
  const active=route.page==='event'||route.page==='raw'?'activity':route.page==='session'?'sessions':route.page==='source'?'sources':route.page;
  return <>
    <a className="skip-link" href="#main">Skip to content</a>
    <header className="topbar">
      <AppLink href="/" go={go} className="brand" title="Fyke home"><span className="brand-mark">FY</span><span>Fyke</span></AppLink>
      <nav aria-label="Primary navigation">{nav.map(([label,href])=><AppLink key={href} href={href} go={go} className={active===label.toLowerCase()?'active':undefined}>{label}</AppLink>)}</nav>
      <div className="topbar-actions"><span className="collector-state"><i/>collecting</span><button className="quiet-button" onClick={()=>setTheme(theme==='dark'?'light':'dark')} aria-label="Switch color theme">{theme==='dark'?'Light':'Dark'}</button><AppLink href="/settings" go={go} className={active==='settings'?'icon-link active':'icon-link'} title="Settings">⌁</AppLink></div>
    </header>
    <main id="main" className="page-shell"><PageErrorBoundary key={`${route.page}:${route.id||''}`}><Page route={route} go={go} overview={overview}/></PageErrorBoundary></main>
  </>;
}

class PageErrorBoundary extends Component<{children:ReactNode},{message:string}>{
  state={message:''};
  static getDerivedStateFromError(error:unknown){return{message:error instanceof Error?error.message:String(error)}}
  componentDidCatch(error:unknown,info:ErrorInfo){console.error('Fyke page render failed',error,info.componentStack)}
  render(){return this.state.message?<div className="page-stack"><ErrorState message={this.state.message}/><button className="button" onClick={()=>window.location.reload()}>Reload page</button></div>:this.props.children}
}

function Page({route,go,overview}:{route:Route;go:(href:string)=>void;overview?:Overview}){
  switch(route.page){
    case'overview':return <OverviewPage overview={overview} go={go}/>;
    case'activity':return <ActivityPage go={go}/>;
    case'sessions':return <SessionsPage go={go}/>;
    case'session':return <SessionPage id={route.id!} go={go}/>;
    case'sources':return <SourcesPage go={go}/>;
    case'source':return <SourcePage ip={route.id!} go={go}/>;
    case'artifacts':return <ArtifactsPage/>;
    case'alerts':return <AlertsPage go={go}/>;
    case'settings':return <SettingsPage/>;
    case'event':return <EventPage id={route.id!} go={go}/>;
    case'raw':return <RawPage kind={route.rawKind!} id={route.id!} go={go}/>;
    case'not-found':return <NotFoundPage go={go}/>;
  }
}

function NotFoundPage({go}:{go:(href:string)=>void}){return <div className="not-found"><span>404</span><h1>That page is outside the trap.</h1><p>The address does not match an investigation, evidence record, or controller page.</p><AppLink href="/" go={go} className="button">Return to overview</AppLink></div>}

function OverviewPage({overview,go}:{overview?:Overview;go:(href:string)=>void}){
  const since=useMemo(()=>new Date(Date.now()-24*60*60*1000).toISOString(),[]);
  const{items:events,error,loading}=useEventFeed(`/api/v1/events?since=${encodeURIComponent(since)}&limit=1000`);
  const{data:findingData}=useData<PageResponse<Finding>>('/api/v1/findings?status=open&limit=5');const findings=findingData?.items||[];
  const posture=findings.some(x=>x.severity==='critical'||x.severity==='high')?'Elevated':findings.some(x=>x.severity==='medium')?'Guarded':'Quiet';
  const postureTone=posture==='Elevated'?'danger':posture==='Guarded'?'warning':'good';
  if(loading&&!overview)return <DashboardSkeleton/>;
  return <div className="page-stack">
    <PageHeader eyebrow="Operations overview" title="What needs your attention" description="Fyke turns the last 24 hours of honeypot evidence into a short investigation queue." actions={<AppLink href="/activity" go={go} className="button">Open activity log</AppLink>}/>
    {error&&<ErrorState message={error}/>}
    <section className="posture-grid">
      <article className={`posture-card ${postureTone}`}><div><span className="section-kicker">Current posture</span><h2>{posture}</h2><p>{posture==='Quiet'?'No high-confidence behaviors require review.':`${findings.length} persisted finding${findings.length===1?'':'s'} require review.`}</p></div><div className="radar" aria-hidden="true"><span/><span/><span/><i/></div></article>
      <div className="metric-grid">
        <Metric label="Events" value={overview?.events_24h} note="observations in 24h"/>
        <Metric label="Sources" value={overview?.sources_24h} note="unique origins"/>
        <Metric label="Sessions" value={overview?.sessions_24h} note="correlated connections"/>
        <Metric label="Evidence" value={overview?.artifacts_24h} note="sealed records"/>
      </div>
    </section>
    <section className="two-column">
      <article className="surface signal-surface"><SectionHeading title="Findings for review" note="Durable explainable detections"/>{findings.length?<div className="signal-list">{findings.map(item=><AppLink href={item.source_ip?`/sources/${encodeURIComponent(item.source_ip)}`:'/alerts'} go={go} className="signal" key={item.id}><span className={`severity-dot ${item.severity}`}/><span><b>{item.title}</b><small>{item.summary}</small></span><strong>{item.event_count}</strong><em>→</em></AppLink>)}</div>:<EmptyState title="No investigation queue" body="Fyke is collecting normally. New login, command, upload, or enumeration behavior will appear here."/>}</article>
      <article className="surface"><SectionHeading title="Protocol mix" note="Share of captured events"/><ProtocolMix protocols={overview?.protocols||{}}/><SectionHeading title="Sensor health" note={`${overview?.sensors?.length||0} reporting`} compact/><SensorList sensors={overview?.sensors||[]}/></article>
    </section>
    <section className="surface"><SectionHeading title="Recent evidence" note="Readable summaries of the newest events" action={<AppLink href="/activity" go={go}>View all →</AppLink>}/><EventList events={events.slice(0,8)} go={go}/></section>
  </div>;
}

function ActivityPage({go}:{go:(href:string)=>void}){
  const[filters,setFilters]=useState<ActivityFilters>({search:'',protocol:'all',type:'all',outcome:'all',range:'24h',customSince:'',customUntil:''});
  const[searchInput,setSearchInput]=useState('');const[pageSize,setPageSize]=useState(25);const[page,setPage]=useState(1);const[refresh,setRefresh]=useState(0);const[pending,setPending]=useState(0);
  const query=useMemo(()=>`${buildEventQuery(filters,page,pageSize)}&refresh=${refresh}`,[filters,page,pageSize,refresh]);
  const{data,error,loading}=useData<EventPageResponse>(query);const events=data?.items||[];const total=data?.total||0;const pageCount=Math.max(1,Math.ceil(total/pageSize));
  useEffect(()=>{if(page>pageCount)setPage(pageCount)},[page,pageCount]);
  useEffect(()=>{const stream=new EventSource('/api/v1/stream');const receive=()=>setPending(value=>value+1);stream.addEventListener('event',receive);return()=>stream.close()},[]);
  function update<K extends keyof ActivityFilters>(key:K,value:ActivityFilters[K]){setFilters(current=>({...current,[key]:value}));setPage(1)}
  function search(event:FormEvent){event.preventDefault();update('search',searchInput.trim())}
  function clear(){setFilters({search:'',protocol:'all',type:'all',outcome:'all',range:'24h',customSince:'',customUntil:''});setSearchInput('');setPage(1)}
  function reload(){setRefresh(value=>value+1);setPending(0);setPage(1)}
  return <div className="page-stack"><PageHeader eyebrow="Evidence explorer" title="Activity log" description="Scan normalized events in plain language, then open any record for structured detail." actions={<a className="text-action" href="/api/v1/exports?format=jsonl">Export JSONL ↗</a>}/>
    <section className="surface filter-panel"><form className="filter-surface" onSubmit={search}><label className="search-field"><span>Search evidence</span><input value={searchInput} onChange={e=>setSearchInput(e.target.value)} placeholder="IP, command, path, event…"/></label><FilterSelect label="Protocol" value={filters.protocol} onChange={value=>update('protocol',value)} options={['all','ssh','telnet','http','https','sensor']}/><FilterSelect label="Event" value={filters.type} onChange={value=>update('type',value)} options={['all',...eventTypes]}/><FilterSelect label="Outcome" value={filters.outcome} onChange={value=>update('outcome',value)} options={['all','success','failure','triggered']}/><button className="filter-apply" type="submit">Apply</button></form>
      <div className="time-filter"><span>Time window</span><div className="range-options">{timeRanges.map(([value,label])=><button key={value} className={filters.range===value?'active':''} onClick={()=>update('range',value)}>{label}</button>)}</div>{filters.range==='custom'&&<div className="custom-dates"><label><span>From</span><input type="datetime-local" value={filters.customSince} onChange={e=>update('customSince',e.target.value)}/></label><label><span>To</span><input type="datetime-local" value={filters.customUntil} onChange={e=>update('customUntil',e.target.value)}/></label></div>}<button className="clear-filters" onClick={clear}>Reset filters</button></div>
    </section>
    {pending>0&&<button className="new-evidence" onClick={reload}><span>{pending}</span> new event{pending===1?'':'s'} available · refresh results</button>}
    {error&&<ErrorState message={error}/>} {loading?<TableSkeleton/>:<section className="surface log-surface"><EventList events={events} go={go} detailed/><Pagination page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={value=>{setPageSize(value);setPage(1)}}/></section>}
  </div>;
}

function SessionsPage({go}:{go:(href:string)=>void}){
  const[page,setPage]=useState(1);const[pageSize,setPageSize]=useState(25);const{data,error,loading}=useData<PageResponse<Row>>(`/api/v1/sessions?limit=${pageSize}&offset=${(page-1)*pageSize}`);
  return <CollectionPage eyebrow="Connection timelines" title="Sessions" description="Follow each interaction from first contact through commands, requests, and disconnect." error={error} loading={loading} count={data?.total||0}>
    <DataTable columns={['started_at','source_ip','protocol','events','last_seen']} rows={data?.items||[]} keyField="session_id" onOpen={row=>go(`/sessions/${encodeURIComponent(String(row.session_id))}`)}/><Pagination page={page} pageSize={pageSize} total={data?.total||0} onPage={setPage} onPageSize={value=>{setPageSize(value);setPage(1)}}/>
  </CollectionPage>;
}

function SourcesPage({go}:{go:(href:string)=>void}){
  const[page,setPage]=useState(1);const[pageSize,setPageSize]=useState(25);const{data,error,loading}=useData<PageResponse<Row>>(`/api/v1/sources?limit=${pageSize}&offset=${(page-1)*pageSize}`);
  return <CollectionPage eyebrow="Source profiles" title="Sources" description="Review activity grouped by origin without treating an address as an attacker identity." error={error} loading={loading} count={data?.total||0}>
    <DataTable columns={['source_ip','first_seen','last_seen','events','sessions']} rows={data?.items||[]} keyField="source_ip" onOpen={row=>go(`/sources/${encodeURIComponent(String(row.source_ip))}`)}/>
    <Pagination page={page} pageSize={pageSize} total={data?.total||0} onPage={setPage} onPageSize={value=>{setPageSize(value);setPage(1)}}/>
  </CollectionPage>;
}

function SessionPage({id,go}:{id:string;go:(href:string)=>void}){
  const{data,error,loading}=useCompleteEvents(`session=${encodeURIComponent(id)}`);const events=[...data].sort((a,b)=>a.sequence-b.sequence);const first=events[0];
  const commands=events.filter(e=>e.event_type==='command');
  return <div className="page-stack"><Breadcrumbs go={go} items={[['Sessions','/sessions'],[shortID(id),'']]}/><PageHeader eyebrow="Session investigation" title={first?`${first.protocol.toUpperCase()} from ${first.source.ip}`:'Session detail'} description={`${events.length} events in one ordered connection timeline.`} actions={<AppLink href={`/raw/sessions/${encodeURIComponent(id)}`} go={go} className="text-action">Raw record →</AppLink>}/>{error&&<ErrorState message={error}/>} {loading?<DashboardSkeleton/>:events.length?<>
    <section className="detail-summary"><DetailStat label="Started" value={formatDate(events[0].timestamp)}/><DetailStat label="Last activity" value={formatDate(events.at(-1)?.timestamp)}/><DetailStat label="Commands" value={String(commands.length)}/><DetailStat label="Outcome" value={sessionOutcome(events)}/></section>
    {commands.length>0&&<section className="surface command-strip"><SectionHeading title="Commands observed" note="Arguments remain protected as evidence"/><div>{commands.map(command=><AppLink href={`/events/${command.id}`} go={go} key={command.id}><code>{String(command.attributes?.command||'unsupported input')}</code><span>{formatTime(command.timestamp)}</span></AppLink>)}</div></section>}
    <section className="surface"><SectionHeading title="Timeline" note="Oldest to newest"/><Timeline events={events} go={go}/></section></>:<EmptyState title="Session not found" body="The event metadata may have expired under the retention policy."/>}</div>;
}

function SourcePage({ip,go}:{ip:string;go:(href:string)=>void}){
  const{data:events,error,loading}=useCompleteEvents(`source=${encodeURIComponent(ip)}`);const{data:findings}=useCompletePage<Finding>(`/api/v1/findings?source=${encodeURIComponent(ip)}`);const{data:contextData}=useData<Row>(`/api/v1/sources/${encodeURIComponent(ip)}/context`);const observables=Array.from(new Map(findings.flatMap(item=>item.observables||[]).map(item=>[`${item.kind}\0${item.value}`,item])).values());const protocols=Array.from(new Set(events.map(e=>e.protocol)));const[label,setLabel]=useState('');const[country,setCountry]=useState('');const[asn,setASN]=useState('');const[ignored,setIgnored]=useState(false);const[contextStatus,setContextStatus]=useState('');const[pivot,setPivot]=useState<{kind:string;value:string}>();
  useEffect(()=>{if(contextData){setLabel(String(contextData.label||''));setCountry(String(contextData.country||''));setASN(String(contextData.asn||''));setIgnored(Boolean(contextData.ignored))}},[contextData]);
  async function saveContext(){await requestJSON(`/api/v1/sources/${encodeURIComponent(ip)}/context`,'PUT',{label,country,asn,ignored});setContextStatus('Source context saved.')}
  return <div className="page-stack"><Breadcrumbs go={go} items={[['Sources','/sources'],[ip,'']]}/><PageHeader eyebrow="Source profile" title={ip} description="Behavior across every observed protocol and connection." actions={<AppLink href={`/raw/sources/${encodeURIComponent(ip)}`} go={go} className="text-action">Raw record →</AppLink>}/>{error&&<ErrorState message={error}/>} {loading?<DashboardSkeleton/>:<>
    <section className="detail-summary"><DetailStat label="Events" value={String(events.length)}/><DetailStat label="Sessions" value={String(new Set(events.map(e=>e.session_id)).size)}/><DetailStat label="Protocols" value={protocols.join(', ')||'—'}/><DetailStat label="Findings" value={String(findings.length)}/></section>
    <section className="surface"><SectionHeading title="Local source context" note="Operator-supplied offline enrichment"/><div className="source-context-form"><input value={label} onChange={e=>setLabel(e.target.value)} placeholder="Local label"/><input value={country} onChange={e=>setCountry(e.target.value)} placeholder="Country"/><input value={asn} onChange={e=>setASN(e.target.value)} placeholder="ASN"/><label><input type="checkbox" checked={ignored} onChange={e=>setIgnored(e.target.checked)}/> Ignore for Findings</label><button className="button" onClick={saveContext}>Save context</button>{contextStatus&&<small>{contextStatus}</small>}</div></section>
    {findings.length>0&&<section className="surface"><SectionHeading title="Observed behaviors" note="Persisted explainable Findings"/><div className="signal-list">{findings.map(item=><div className="signal static" key={item.id}><span className={`severity-dot ${item.severity}`}/><span><b>{item.title}</b><small>{item.summary}</small></span></div>)}</div></section>}
    {observables.length>0&&<section className="surface"><SectionHeading title="Observable pivots" note="Exact correlation, not identity attribution"/><div className="observable-list">{observables.map(item=><button key={`${item.kind}-${item.value}`} onClick={()=>setPivot(item)}><span>{humanize(item.kind)}</span><code>{item.value}</code></button>)}</div></section>}
    {pivot&&<ObservableEvidence pivot={pivot} go={go}/>}
    <section className="surface"><SectionHeading title="Evidence trail" note="Newest first"/><EventList events={events} go={go} detailed/></section></>}</div>;
}

function ObservableEvidence({pivot,go}:{pivot:{kind:string;value:string};go:(href:string)=>void}){const base=`/api/v1/observables?kind=${encodeURIComponent(pivot.kind)}&value=${encodeURIComponent(pivot.value)}`;const{data,total,error,loading}=useCompletePage<EventItem>(base);return <section className="surface"><SectionHeading title={`${humanize(pivot.kind)}: ${pivot.value}`} note={`${total} correlated Events`}/>{error?<ErrorState message={error}/>:loading?<TableSkeleton/>:<EventList events={data} go={go} detailed/>}</section>}

function EventPage({id,go}:{id:string;go:(href:string)=>void}){
  const{data:event,error,loading}=useData<EventItem>(`/api/v1/events/${encodeURIComponent(id)}`);const[preview,setPreview]=useState<Row>();const[previewError,setPreviewError]=useState('');
  async function openEvidence(ref:EvidenceRef){const normalized=normalizeEvidence(ref);if(!normalized.id)return;setPreviewError('');try{setPreview(await get<Row>(`/api/v1/artifacts/${normalized.id}/preview`))}catch(e){setPreviewError(e instanceof Error?e.message:String(e))}}
  if(loading)return <DashboardSkeleton/>;
  if(error||!event)return <ErrorState message={error||'Event not found'}/>;
  const refs=event.evidence_refs||[];
  return <div className="page-stack"><Breadcrumbs go={go} items={[['Activity','/activity'],[shortID(id),'']]}/><PageHeader eyebrow={`${event.protocol} · ${event.event_type}`} title={eventTitle(event)} description={eventDescription(event)} actions={<AppLink href={`/raw/events/${encodeURIComponent(id)}`} go={go} className="text-action">View raw JSON →</AppLink>}/>
    <section className="detail-layout"><article className="surface detail-card"><SectionHeading title="Event facts" note="Normalized metadata"/><dl className="fact-list"><Fact label="Observed" value={formatDate(event.timestamp)}/><Fact label="Source" value={`${event.source.ip}:${event.source.port}`} href={`/sources/${encodeURIComponent(event.source.ip)}`} go={go}/><Fact label="Destination" value={`${event.destination.ip}:${event.destination.port}`}/><Fact label="Session" value={shortID(event.session_id)} href={`/sessions/${encodeURIComponent(event.session_id)}`} go={go}/><Fact label="Sensor" value={event.sensor_id}/><Fact label="Outcome" value={event.outcome||'recorded'}/><Fact label="Sequence" value={String(event.sequence)}/></dl></article>
      <article className="surface detail-card"><SectionHeading title="Observed details" note="Safe searchable fields"/><ReadableObject value={event.attributes||{}} empty="No additional attributes were recorded."/>{Object.keys(event.protocol_attributes||{}).length>0&&<><SectionHeading title="Protocol context" note="Normalized protocol fields" compact/><ReadableObject value={event.protocol_attributes||{}}/></>}</article></section>
    <section className="surface"><SectionHeading title="Protected evidence" note={`${refs.length} encrypted item${refs.length===1?'':'s'}`}/>{refs.length?<div className="evidence-grid">{refs.map((ref,index)=>{const item=normalizeEvidence(ref);return <button key={item.id||index} className="evidence-card" onClick={()=>openEvidence(ref)}><span className="file-glyph">{item.kind==='transcript'?'TXT':'EV'}</span><span><b>{humanize(item.kind||'evidence')}</b><small>{formatBytes(item.size)} · {item.contentType||'binary'}</small></span><em>Preview</em></button>})}</div>:<EmptyState title="No protected evidence" body="This event contains metadata only."/>}{previewError&&<ErrorState message={previewError}/>} {preview&&<EvidencePreview preview={preview}/>}</section>
  </div>;
}

function ArtifactsPage(){
  const[page,setPage]=useState(1);const[pageSize,setPageSize]=useState(25);const{data,error,loading}=useData<PageResponse<Row>>(`/api/v1/artifacts?limit=${pageSize}&offset=${(page-1)*pageSize}`);const[preview,setPreview]=useState<Row>();const[selected,setSelected]=useState<Row>();const[previewError,setPreviewError]=useState('');const[recipient,setRecipient]=useState('');const[bundleStatus,setBundleStatus]=useState('');const[analysis,setAnalysis]=useState<Row>();const[analysisStatus,setAnalysisStatus]=useState('');
  async function open(row:Row){setSelected(row);setPreviewError('');setAnalysis(undefined);setAnalysisStatus('');try{setPreview(await get<Row>(`/api/v1/artifacts/${row.id}/preview`));try{setAnalysis(await get<Row>(`/api/v1/artifacts/${row.id}/analysis`))}catch{/* no prior analysis */}}catch(e){setPreviewError(e instanceof Error?e.message:String(e))}}
  async function bundle(){if(!selected||!recipient)return;setBundleStatus('Preparing encrypted bundle…');try{const response=await fetch('/api/v1/investigation-bundles',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({artifact_ids:[selected.id],recipient})});if(!response.ok)throw Error((await response.json()).title||response.statusText);downloadBlob(await response.blob(),'fyke-investigation.tar.age');setBundleStatus('Encrypted bundle downloaded.')}catch(e){setBundleStatus(e instanceof Error?e.message:String(e))}}
  async function analyze(){if(!selected)return;setAnalysisStatus('Queueing safe inspection…');try{await requestJSON(`/api/v1/artifacts/${selected.id}/analysis`,'POST',{});setAnalysis({status:'pending'});setAnalysisStatus('Queued. Refresh this artifact in a few seconds for results.')}catch(e){setAnalysisStatus(e instanceof Error?e.message:String(e))}}
  return <div className="page-stack"><PageHeader eyebrow="Encrypted evidence" title="Artifacts" description="Preview and pivot on captured evidence without exposing it in the searchable event index."/>{error&&<ErrorState message={error}/>} {loading?<TableSkeleton/>:<section className="surface"><DataTable columns={['kind','filename','sha256','size','created_at']} rows={data?.items||[]} keyField="id" actionLabel="Preview" onOpen={open}/><Pagination page={page} pageSize={pageSize} total={data?.total||0} onPage={setPage} onPageSize={value=>{setPageSize(value);setPage(1)}}/></section>}{previewError&&<ErrorState message={previewError}/>} {preview&&selected&&<section className="surface preview-panel"><SectionHeading title={String(selected.filename||'Evidence preview')} note={String(preview.encoding||'protected evidence')} action={<a className="text-action" href={`/api/v1/artifacts/${selected.id}/download`}>Download explicitly ↗</a>}/><EvidencePreview preview={preview}/><div className="artifact-actions"><button className="button secondary" onClick={analyze}>Inspect in isolated worker</button>{analysisStatus&&<small>{analysisStatus}</small>}</div>{analysis&&<div className="analysis-panel"><SectionHeading title="Safe artifact inspection" note={String(analysis.status||'result')} compact/><ReadableObject value={analysis}/></div>}<div className="bundle-form"><label><span>Age recipient</span><input value={recipient} onChange={e=>setRecipient(e.target.value)} placeholder="age1…"/></label><button className="button" onClick={bundle} disabled={!recipient}>Create encrypted Investigation Bundle</button>{bundleStatus&&<small>{bundleStatus}</small>}</div></section>}</div>;
}

function AlertsPage({go}:{go:(href:string)=>void}){
  const[refresh,setRefresh]=useState(0);const[selected,setSelected]=useState('');const{data,error,loading}=useData<PageResponse<Finding>>(`/api/v1/findings?limit=100&refresh=${refresh}`);const{data:deliveries}=useData<PageResponse<Row>>(`/api/v1/alert-deliveries?limit=25&refresh=${refresh}`);
  const findings=pageItems(data);
  async function status(id:string,value:string){await requestJSON(`/api/v1/findings/${encodeURIComponent(id)}/status`,'PUT',{status:value});setRefresh(x=>x+1)}
  async function retry(id:string){await requestJSON(`/api/v1/alert-deliveries/${encodeURIComponent(id)}/retry`,'POST',{});setRefresh(x=>x+1)}
  return <div className="page-stack" data-refresh={refresh}><PageHeader eyebrow="Detection queue" title="Findings & alerts" description="Explainable persisted analysis and the delivery state of outbound notifications."/>{error&&<ErrorState message={error}/>} {loading?<TableSkeleton/>:<section className="surface alert-list">{findings.length?findings.map(item=><div className="alert-row" key={item.id}><span className="alert-mark">!</span><span><b>{item.title}</b><small>{item.summary} · {item.source_ip||'Controller'} · {formatDate(item.last_seen)}</small></span><div className="row-controls"><select value={item.status} onChange={e=>status(item.id,e.target.value)}><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select><button className="row-action" onClick={()=>setSelected(item.id)}>Evidence</button>{item.source_ip&&<AppLink href={`/sources/${encodeURIComponent(item.source_ip)}`} go={go}>Source →</AppLink>}</div></div>):<EmptyState title="No findings" body="Explainable rule matches will appear here while the complete evidence trail remains in Activity."/>}</section>}{selected&&<FindingEvidence id={selected} go={go}/>}<section className="surface"><SectionHeading title="Webhook deliveries" note="Durable at-least-once handoff"/><DataTable columns={['status','endpoint','attempts','last_error','updated_at']} rows={pageItems(deliveries)} keyField="id" actionLabel="Retry" onOpen={row=>row.status==='failed'&&retry(String(row.id))}/></section></div>;
}

function FindingEvidence({id,go}:{id:string;go:(href:string)=>void}){const{data,total,error,loading}=useCompletePage<EventItem>(`/api/v1/findings/${encodeURIComponent(id)}/events`);return <section className="surface"><SectionHeading title="Finding evidence" note={`${total} linked Events`}/>{error?<ErrorState message={error}/>:loading?<TableSkeleton/>:<EventList events={data} go={go} detailed/>}</section>}

function SettingsPage(){
  const{data:retention,error}=useData<Row>('/api/v1/retention');const{data:storage}=useData<Row>('/api/v1/storage');const{data:audit}=useData<PageResponse<Row>>('/api/v1/audit?limit=25');const{data:alertData}=useData<AlertPreferences>('/api/v1/preferences/alerts');const[result,setResult]=useState('');const[running,setRunning]=useState(false);const[webhooks,setWebhooks]=useState('');const[spike,setSpike]=useState(60);const[secret,setSecret]=useState('');const[saveStatus,setSaveStatus]=useState('');const[rules,setRules]=useState<Record<string,RulePreference>>(defaultAlertRules);
  useEffect(()=>{if(alertData){setWebhooks(joinLines(alertData.webhooks));setSpike(alertData.source_spike_per_minute);setRules(current=>{const next={...current};for(const[name,value]of Object.entries(alertData.rules||{})){next[name]={enabled:value.enabled,severity:value.severity||current[name]?.severity||'medium',cooldown_minutes:value.cooldown_minutes??15}}return next})}},[alertData]);
  async function run(){setRunning(true);try{const response=await fetch('/api/v1/retention/run',{method:'POST'});setResult(JSON.stringify(await response.json()))}finally{setRunning(false)}}
  async function saveAlerts(){setSaveStatus('Saving…');try{await requestJSON('/api/v1/preferences/alerts','PUT',{webhooks:webhooks.split(/\s+/).filter(Boolean),source_spike_per_minute:spike,rules,...(secret?{webhook_signing_secret:secret}:{})});setSecret('');setSaveStatus('Alert settings saved.')}catch(e){setSaveStatus(e instanceof Error?e.message:String(e))}}
  function updateRule(name:string,patch:Partial<RulePreference>){setRules(current=>({...current,[name]:{...current[name],...patch}}))}
  return <div className="page-stack"><PageHeader eyebrow="Controller operations" title="Settings" description="Review delivery, storage, data lifecycle, and trustworthy external handoffs."/>{error&&<ErrorState message={error}/>}<section className="settings-grid"><article className="surface settings-card"><SectionHeading title="Retention policy" note="Current controller configuration"/><ReadableObject value={retention||{}}/><button className="button" disabled={running} onClick={run}>{running?'Running…':'Run retention now'}</button>{result&&<p className="status-note">Retention completed: <code>{result}</code></p>}</article><article className="surface settings-card"><SectionHeading title="Storage pressure" note="Complete controller data directory"/><ReadableObject value={storage||{}}/></article><article className="surface settings-card"><SectionHeading title="Alert delivery" note="Signed, durable, at least once"/><div className="settings-form"><label><span>HTTPS webhooks, one per line</span><textarea value={webhooks} onChange={e=>setWebhooks(e.target.value)}/></label><label><span>Source events per minute</span><input type="number" min="0" value={spike} onChange={e=>setSpike(Number(e.target.value))}/></label><label><span>Replace signing secret (optional)</span><input type="password" value={secret} onChange={e=>setSecret(e.target.value)} placeholder="At least 32 characters"/></label><button className="button" onClick={saveAlerts}>Save alert settings</button>{saveStatus&&<small>{saveStatus}</small>}</div></article><article className="surface settings-card"><SectionHeading title="Evidence exports" note="Point-in-time complete"/><p>Metadata exports contain every matching Event present when the download begins. Sensitive Evidence is available only through an encrypted Investigation Bundle.</p><div className="button-row"><a className="button" href="/api/v1/exports?format=jsonl">Download JSONL</a><a className="button secondary" href="/api/v1/exports?format=csv">Download CSV</a></div></article></section><section className="surface"><SectionHeading title="Finding rules" note="Local, deterministic, and explainable" action={<button className="button secondary" onClick={saveAlerts}>Save rules</button>}/><div className="rule-grid">{Object.entries(rules).map(([name,rule])=><div className="rule-row" key={name}><label><input type="checkbox" checked={rule.enabled} onChange={e=>updateRule(name,{enabled:e.target.checked})}/><b>{humanize(name)}</b></label><select value={rule.severity} onChange={e=>updateRule(name,{severity:e.target.value})}><option>low</option><option>medium</option><option>high</option><option>critical</option></select><label><span>Cooldown min</span><input type="number" min="0" max="10080" value={rule.cooldown_minutes} onChange={e=>updateRule(name,{cooldown_minutes:Number(e.target.value)})}/></label></div>)}</div></section><section className="surface"><SectionHeading title="Operator audit" note={`${audit?.total||0} recorded actions`}/><DataTable columns={['timestamp','action','remote_ip','details']} rows={audit?.items||[]} keyField="id" actionLabel="Recorded" onOpen={()=>{}}/></section></div>;
}

function RawPage({kind,id,go}:{kind:'events'|'sessions'|'sources';id:string;go:(href:string)=>void}){
  const url=kind==='events'?`/api/v1/events/${encodeURIComponent(id)}`:`/api/v1/events?${kind==='sessions'?'session':'source'}=${encodeURIComponent(id)}&limit=1000`;
  const{data,error,loading}=useData<unknown>(url);const back=kind==='events'?`/events/${encodeURIComponent(id)}`:kind==='sessions'?`/sessions/${encodeURIComponent(id)}`:`/sources/${encodeURIComponent(id)}`;
  return <div className="page-stack raw-page"><Breadcrumbs go={go} items={[['Readable view',back],['Raw JSON','']]}/><PageHeader eyebrow="Machine-readable record" title="Raw JSON" description="The unformatted API response is kept separate from the investigation view." actions={<AppLink href={back} go={go} className="button">Return to readable view</AppLink>}/>{error&&<ErrorState message={error}/>} {loading?<DashboardSkeleton/>:<pre>{JSON.stringify(data,null,2)}</pre>}</div>;
}

function CollectionPage({eyebrow,title,description,error,loading,count,children}:{eyebrow:string;title:string;description:string;error:string;loading:boolean;count:number;children:ReactNode}){
  return <div className="page-stack"><PageHeader eyebrow={eyebrow} title={title} description={description}/>{error&&<ErrorState message={error}/>}<section className="surface"><SectionHeading title={`${count.toLocaleString()} records`} note="Select a row to investigate"/>{loading?<TableSkeleton/>:children}</section></div>;
}

function PageHeader({eyebrow,title,description,actions}:{eyebrow:string;title:string;description:string;actions?:ReactNode}){return <header className="page-header"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{actions&&<div className="page-actions">{actions}</div>}</header>}
function SectionHeading({title,note,action,compact=false}:{title:string;note?:string;action?:ReactNode;compact?:boolean}){return <header className={`section-heading ${compact?'compact':''}`}><div><h2>{title}</h2>{note&&<p>{note}</p>}</div>{action}</header>}
function Metric({label,value,note}:{label:string;value?:number;note:string}){return <article className="metric"><span>{label}</span><strong>{value===undefined?'—':value.toLocaleString()}</strong><small>{note}</small></article>}
function DetailStat({label,value}:{label:string;value:string}){return <div><span>{label}</span><b>{value}</b></div>}
function FilterSelect({label,value,onChange,options}:{label:string;value:string;onChange:(value:string)=>void;options:string[]}){return <label className="select-field"><span>{label}</span><select value={value} onChange={e=>onChange(e.target.value)}>{options.map(option=><option key={option} value={option}>{option==='all'?'All':humanize(option)}</option>)}</select></label>}
function Pagination({page,pageSize,total,onPage,onPageSize}:{page:number;pageSize:number;total:number;onPage:(page:number)=>void;onPageSize:(size:number)=>void}){
  const pageCount=Math.max(1,Math.ceil(total/pageSize));const start=total?(page-1)*pageSize+1:0;const end=Math.min(page*pageSize,total);const pages=paginationWindow(page,pageCount);
  return <footer className="pagination"><div className="page-size"><span>Rows per page</span><select value={pageSize} onChange={event=>onPageSize(Number(event.target.value))}>{[10,25,100].map(size=><option value={size} key={size}>{size}</option>)}</select></div><p><b>{start.toLocaleString()}–{end.toLocaleString()}</b> of {total.toLocaleString()} events</p><nav aria-label="Activity pages"><button onClick={()=>onPage(1)} disabled={page===1} aria-label="First page">«</button><button onClick={()=>onPage(page-1)} disabled={page===1} aria-label="Previous page">‹</button>{pages.map(value=><button key={value} className={value===page?'active':''} onClick={()=>onPage(value)} aria-current={value===page?'page':undefined}>{value}</button>)}<button onClick={()=>onPage(page+1)} disabled={page===pageCount} aria-label="Next page">›</button><button onClick={()=>onPage(pageCount)} disabled={page===pageCount} aria-label="Last page">»</button></nav></footer>
}
function ErrorState({message}:{message:string}){return <div role="alert" className="error-state"><b>Could not load this view</b><span>{message}</span></div>}
function EmptyState({title,body}:{title:string;body:string}){return <div className="empty-state"><span>○</span><b>{title}</b><p>{body}</p></div>}
function DashboardSkeleton(){return <div className="dashboard-skeleton"><i/><i/><i/><i/></div>}
function TableSkeleton(){return <div className="table-skeleton">{Array.from({length:6},(_,i)=><i key={i}/>)}</div>}

function EventList({events,go,detailed=false}:{events:EventItem[];go:(href:string)=>void;detailed?:boolean}){
  if(!events.length)return <EmptyState title="No evidence found" body="Try a different filter or wait for the sensors to report activity."/>;
  return <div className={`event-list ${detailed?'detailed':''}`}>{events.map(event=><AppLink href={`/events/${event.id}`} go={go} className="event-row" key={event.id}><span className={`event-icon ${eventTone(event)}`}>{protocolMonogram(event.protocol)}</span><span className="event-primary"><b>{eventTitle(event)}</b><small>{eventDescription(event)}</small></span><span className="event-source"><code>{event.source?.ip||'controller'}</code><small>{shortID(event.session_id)}</small></span><span className="event-time"><time dateTime={event.timestamp}>{formatTime(event.timestamp)}</time><small>{formatDay(event.timestamp)}</small></span><em>→</em></AppLink>)}</div>;
}

function Timeline({events,go}:{events:EventItem[];go:(href:string)=>void}){return <ol className="timeline">{events.map(event=><li key={event.id}><span className={`timeline-dot ${eventTone(event)}`}/><AppLink href={`/events/${event.id}`} go={go}><time>{formatTime(event.timestamp)}</time><div><b>{eventTitle(event)}</b><p>{eventDescription(event)}</p></div><em>Open →</em></AppLink></li>)}</ol>}

function DataTable({columns,rows,keyField,onOpen,actionLabel='Open'}:{columns:string[];rows:Row[];keyField:string;onOpen:(row:Row)=>void;actionLabel?:string}){
  if(!rows.length)return <EmptyState title="No records found" body="Fyke has not collected any matching evidence yet."/>;
  return <div className="table-wrap"><table><thead><tr>{columns.map(column=><th key={column}>{humanize(column)}</th>)}<th><span className="sr-only">Action</span></th></tr></thead><tbody>{rows.map((row,index)=><tr key={String(row[keyField]||index)} onClick={()=>onOpen(row)} tabIndex={0} onKeyDown={e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onOpen(row)}}}>{columns.map(column=><td key={column}><Cell column={column} value={row[column]}/></td>)}<td><button className="row-action" onClick={e=>{e.stopPropagation();onOpen(row)}}>{actionLabel} →</button></td></tr>)}</tbody></table></div>;
}

function Cell({column,value}:{column:string;value:unknown}){if(column==='protocol'||column==='kind'||column==='status')return <span className="tag">{humanize(String(value||'—'))}</span>;if(column.includes('size'))return <span>{formatBytes(Number(value||0))}</span>;const raw=value&&typeof value==='object'?formatValue(value):String(value??'—');const text=column.includes('seen')||column.includes('_at')||column==='timestamp'?formatDate(raw):raw;return <span title={text}>{text.length>72?`${text.slice(0,69)}…`:text}</span>}
function Fact({label,value,href,go}:{label:string;value:string;href?:string;go?:(href:string)=>void}){return <div><dt>{label}</dt><dd>{href&&go?<AppLink href={href} go={go}>{value} →</AppLink>:value}</dd></div>}
function ReadableObject({value,empty}:{value:Record<string,unknown>;empty?:string}){const entries=Object.entries(value);if(!entries.length)return <p className="muted-copy">{empty||'No values recorded.'}</p>;return <dl className="readable-object">{entries.map(([key,item])=><div key={key}><dt>{humanize(key)}</dt><dd>{formatValue(item)}</dd></div>)}</dl>}
function EvidencePreview({preview}:{preview:Row}){return <div className="evidence-preview"><div><span>{String(preview.encoding||'preview')}</span>{Boolean(preview.truncated)&&<b>truncated</b>}</div><pre>{String(preview.content||'No preview content')}</pre></div>}

function ProtocolMix({protocols}:{protocols:Record<string,number>}){const entries=Object.entries(protocols).sort((a,b)=>b[1]-a[1]);const total=entries.reduce((sum,[,value])=>sum+value,0);if(!total)return <EmptyState title="No protocol activity" body="The distribution will appear after the first sensor event."/>;return <div className="protocol-mix">{entries.map(([name,value])=><div key={name}><span><b>{name.toUpperCase()}</b><em>{Math.round(value/total*100)}%</em></span><i><u style={{width:`${value/total*100}%`}}/></i></div>)}</div>}
function SensorList({sensors}:{sensors:Sensor[]}){if(!sensors.length)return <p className="muted-copy sensor-empty">No sensors have checked in.</p>;return <div className="sensor-list">{sensors.map(sensor=><div key={sensor.id}><span className={`sensor-dot ${sensor.status}`}/><b>{sensor.id}</b><small>{sensor.status} · {formatRelative(sensor.last_seen)}</small></div>)}</div>}
function Breadcrumbs({items,go}:{items:[string,string][];go:(href:string)=>void}){return <nav className="breadcrumbs" aria-label="Breadcrumb">{items.map(([label,href],index)=><span key={`${label}-${index}`}>{index>0&&<i>/</i>}{href?<AppLink href={href} go={go}>{label}</AppLink>:<b>{label}</b>}</span>)}</nav>}

export function buildEventQuery(filters:ActivityFilters,page:number,pageSize:number,now=new Date()):string{
  const params=new URLSearchParams();const size=[10,25,100].includes(pageSize)?pageSize:25;const current=Math.max(1,page);
  params.set('limit',String(size));params.set('offset',String((current-1)*size));
  if(filters.search)params.set('q',filters.search);
  if(filters.protocol!=='all')params.set('protocol',filters.protocol);
  if(filters.type!=='all')params.set('type',filters.type);
  if(filters.outcome!=='all')params.set('outcome',filters.outcome);
  const durations:Partial<Record<TimeRange,number>>={"15m":15*60*1000,"1h":60*60*1000,"24h":24*60*60*1000,"7d":7*24*60*60*1000};const duration=durations[filters.range];
  if(duration)params.set('since',new Date(now.getTime()-duration).toISOString());
  if(filters.range==='custom'){
    const since=parseLocalDate(filters.customSince);const until=parseLocalDate(filters.customUntil);
    if(since)params.set('since',since.toISOString());if(until)params.set('until',until.toISOString());
  }
  return`/api/v1/events?${params.toString()}`;
}

export function paginationWindow(page:number,pageCount:number):number[]{
  const count=Math.max(1,pageCount);const current=Math.min(Math.max(1,page),count);const start=Math.max(1,Math.min(current-2,count-4));const end=Math.min(count,start+4);return Array.from({length:end-start+1},(_,index)=>start+index);
}

export function deriveInsights(events:EventItem[]):Insight[]{
  const findings:Insight[]=[];const bySource=new Map<string,EventItem[]>();
  for(const event of events){const ip=event.source?.ip;if(ip){const list=bySource.get(ip)||[];list.push(event);bySource.set(ip,list)}}
  for(const[ip,sourceEvents]of bySource){
    const http=sourceEvents.filter(e=>e.event_type==='http.request');const paths=new Set(http.map(e=>String(e.attributes?.['url.path']||'')));const agents=http.map(e=>String(e.attributes?.['http.user_agent']||'').toLowerCase());const namedScanner=agents.find(agent=>agent.includes('gobuster')||agent.includes('dirbuster'));
    if(namedScanner||(http.length>=20&&paths.size/http.length>=.75))findings.push({id:`scan-${ip}`,severity:namedScanner?'high':'medium',title:namedScanner?'Known web enumerator observed':'Probable content enumeration',description:`${http.length} web requests reached ${paths.size} distinct paths from ${ip}.`,href:`/sources/${encodeURIComponent(ip)}`,source:ip,count:http.length});
    const login=sourceEvents.find(e=>e.event_type==='authentication.attempt'&&e.outcome==='success');if(login)findings.push({id:`login-${ip}`,severity:'high',title:'Interactive access obtained',description:`Fyke accepted an emulated ${login.protocol.toUpperCase()} login from ${ip}.`,href:`/sessions/${encodeURIComponent(login.session_id)}`,source:ip});
    const commands=sourceEvents.filter(e=>e.event_type==='command');if(commands.length)findings.push({id:`commands-${ip}`,severity:'medium',title:'Post-login commands observed',description:`${commands.length} command${commands.length===1?' was':'s were'} entered after access from ${ip}.`,href:`/sources/${encodeURIComponent(ip)}`,source:ip,count:commands.length});
    const uploads=sourceEvents.filter(e=>e.event_type==='artifact.upload'||e.evidence_refs?.some(ref=>normalizeEvidence(ref).kind==='artifact.upload'));if(uploads.length)findings.push({id:`upload-${ip}`,severity:'high',title:'Payload placed in quarantine',description:`${uploads.length} upload${uploads.length===1?' was':'s were'} captured from ${ip}.`,href:`/sources/${encodeURIComponent(ip)}`,source:ip,count:uploads.length});
  }
  return findings.sort((a,b)=>severityRank[b.severity]-severityRank[a.severity]||(b.count||0)-(a.count||0));
}

export function eventTitle(event:EventItem):string{
  const a=event.attributes||{};switch(event.event_type){
    case'authentication.attempt':return event.outcome==='success'?`Accepted ${event.protocol.toUpperCase()} login`:`Rejected ${event.protocol.toUpperCase()} login`;
    case'command':return a.command?`Command: ${String(a.command)}`:'Unsupported shell input';
    case'emulation.gap':return `Emulation gap: ${String(a.gap||a.feature||'unmodeled behavior')}`;
    case'http.request':return `${String(a['http.method']||'HTTP')} ${String(a['url.path']||'/')}`;
    case'session.start':return `${event.protocol.toUpperCase()} session opened`;
    case'session.end':return `${event.protocol.toUpperCase()} session closed`;
    case'artifact.upload':return 'Artifact captured in quarantine';
    case'transcript.chunk':return 'Session transcript recorded';
    case'ssh.scp':return 'SCP execution rejected';
    case'http.malformed':return 'Malformed HTTP request captured';
    case'alert':return alertTitle(String(a.rule||''));
    default:return humanize(event.event_type);
  }
}

export function eventDescription(event:EventItem):string{
  const a=event.attributes||{};switch(event.event_type){
    case'authentication.attempt':return `${String(a.username||'unknown user')} via ${String(a.method||'password')} · ${event.outcome}`;
    case'command':{const urls=Array.isArray(a.urls)&&a.urls.length?` · ${a.urls.length} URL${a.urls.length===1?'':'s'} observed`:'';return `Captured in ${shortID(event.session_id)}${a.unsupported_syntax?' · syntax rejected':''}${urls}`}
    case'http.request':return `${String(a['http.host']||event.destination.ip)} · ${String(a['http.user_agent']||'No user agent')}`;
    case'alert':return `Rule ${humanize(String(a.rule||'unknown'))} matched this evidence.`;
    case'artifact.upload':return `${String(a.path||'Uploaded file')} was encrypted and isolated.`;
    case'transcript.chunk':return 'Encrypted input and emulated output are available as protected evidence.';
    default:return `${event.source?.ip||'Controller'} · ${event.outcome||'recorded'}`;
  }
}

function alertTitle(rule:string){const labels:Record<string,string>={successful_emulated_login:'Successful emulated login',artifact_upload:'Artifact upload captured',unhealthy_sensor:'Sensor stopped reporting',novel_fingerprint:'New SSH key fingerprint',source_spike:'Source activity spike'};return labels[rule]||humanize(rule||'Triggered alert')}
function eventTone(event:EventItem){if(event.event_type==='alert'||event.event_type==='artifact.upload'||(event.event_type==='authentication.attempt'&&event.outcome==='success'))return'danger';if(event.event_type==='command'||event.event_type==='http.malformed'||event.event_type==='ssh.scp')return'warning';return'neutral'}
function protocolMonogram(protocol:string){return({ssh:'SH',telnet:'TN',http:'HT',https:'TS',sensor:'SN'} as Record<string,string>)[protocol]||protocol.slice(0,2).toUpperCase()}
function sessionOutcome(events:EventItem[]){if(events.some(e=>e.event_type==='authentication.attempt'&&e.outcome==='success'))return'Access granted';if(events.some(e=>e.event_type==='command'))return'Interaction';return'Observed'}
function normalizeEvidence(ref:EvidenceRef){return{id:String(ref.id??ref.ID??''),kind:String(ref.kind??ref.Kind??''),contentType:String(ref.content_type??ref.ContentType??''),filename:String(ref.filename??ref.Filename??''),sha256:String(ref.sha256??ref.SHA256??''),size:Number(ref.size??ref.Size??0)}}
function formatValue(value:unknown):string{if(Array.isArray(value))return value.length?value.map(String).join(', '):'None';if(value&&typeof value==='object')return Object.entries(value as Record<string,unknown>).map(([key,item])=>`${humanize(key)}: ${formatValue(item)}`).join(' · ');if(typeof value==='boolean')return value?'Yes':'No';return String(value??'—')}
function humanize(value:string){return value.replaceAll('.',' ').replaceAll('_',' ').replace(/\b\w/g,char=>char.toUpperCase())}
function shortID(value?:string){return value?value.length>15?`${value.slice(0,8)}…${value.slice(-4)}`:value:'—'}
function formatDate(value?:string){if(!value)return'—';const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toLocaleString()}
function formatTime(value:string){const date=new Date(value);return Number.isNaN(date.getTime())?'—':date.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}
function formatDay(value:string){const date=new Date(value);return Number.isNaN(date.getTime())?'':date.toLocaleDateString([],{month:'short',day:'numeric'})}
function formatRelative(value:string){const seconds=Math.round((new Date(value).getTime()-Date.now())/1000);const abs=Math.abs(seconds);if(abs<60)return'just now';if(abs<3600)return`${Math.round(abs/60)}m ago`;if(abs<86400)return`${Math.round(abs/3600)}h ago`;return`${Math.round(abs/86400)}d ago`}
function formatBytes(value:number){if(!Number.isFinite(value)||value<=0)return'0 B';const units=['B','KB','MB','GB'];const i=Math.min(Math.floor(Math.log(value)/Math.log(1024)),units.length-1);return`${(value/1024**i).toFixed(i?1:0)} ${units[i]}`}
function parseLocalDate(value:string){if(!value)return undefined;const date=new Date(value);return Number.isNaN(date.getTime())?undefined:date}
async function requestJSON<T=unknown>(url:string,method:string,body:unknown):Promise<T>{const response=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!response.ok){const problem=await response.json().catch(()=>({})) as{title?:string};throw Error(problem.title||`${response.status} ${response.statusText}`)}return response.json() as Promise<T>}
function downloadBlob(blob:Blob,name:string){const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=name;document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url)}
async function get<T>(url:string):Promise<T>{const response=await fetch(url);if(!response.ok){const problem=await response.json().catch(()=>({})) as{title?:string};throw Error(problem.title?`${response.status} · ${problem.title}`:`${response.status} ${response.statusText}`)}return response.json() as Promise<T>}
