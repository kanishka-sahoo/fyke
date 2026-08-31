import {ReactNode, useEffect, useMemo, useState} from 'react';

type Endpoint={ip:string;port:number};
type EvidenceRef={ID?:string;Kind?:string;ContentType?:string;Filename?:string;SHA256?:string;Size?:number;id?:string;kind?:string;content_type?:string;filename?:string;sha256?:string;size?:number};
export type EventItem={id:string;timestamp:string;sensor_id:string;session_id:string;sequence:number;source:Endpoint;destination:Endpoint;protocol:string;event_type:string;outcome:string;persona:string;attributes?:Record<string,unknown>;protocol_attributes?:Record<string,unknown>;evidence_refs?:EvidenceRef[]};
type Sensor={id:string;status:string;last_seen:string};
type Overview={events_24h:number;sessions_24h:number;sources_24h:number;artifacts_24h:number;protocols?:Record<string,number>;sensors?:Sensor[]};
type Row=Record<string,unknown>;
type Insight={id:string;severity:'high'|'medium'|'low';title:string;description:string;href:string;source?:string;count?:number};
type Route={page:'overview'|'activity'|'sessions'|'session'|'sources'|'source'|'artifacts'|'alerts'|'settings'|'event'|'raw'|'not-found';id?:string;rawKind?:'events'|'sessions'|'sources'};

const nav=[['Overview','/'],['Activity','/activity'],['Sessions','/sessions'],['Sources','/sources'],['Artifacts','/artifacts'],['Alerts','/alerts']] as const;
const severityRank={high:3,medium:2,low:1};

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

function useEventFeed(url:string){
  const{data,error,loading}=useData<{items:EventItem[]}>(url);const[items,setItems]=useState<EventItem[]>([]);
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
    <main id="main" className="page-shell"><Page route={route} go={go} overview={overview}/></main>
  </>;
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
  const insights=useMemo(()=>deriveInsights(events),[events]);
  const posture=insights.some(x=>x.severity==='high')?'Elevated':insights.some(x=>x.severity==='medium')?'Guarded':'Quiet';
  const postureTone=posture==='Elevated'?'danger':posture==='Guarded'?'warning':'good';
  if(loading&&!overview)return <DashboardSkeleton/>;
  return <div className="page-stack">
    <PageHeader eyebrow="Operations overview" title="What needs your attention" description="Fyke turns the last 24 hours of honeypot evidence into a short investigation queue." actions={<AppLink href="/activity" go={go} className="button">Open activity log</AppLink>}/>
    {error&&<ErrorState message={error}/>}
    <section className="posture-grid">
      <article className={`posture-card ${postureTone}`}><div><span className="section-kicker">Current posture</span><h2>{posture}</h2><p>{posture==='Quiet'?'No high-confidence behaviors require review.':`${insights.length} behavior${insights.length===1?'':'s'} surfaced from recent evidence.`}</p></div><div className="radar" aria-hidden="true"><span/><span/><span/><i/></div></article>
      <div className="metric-grid">
        <Metric label="Events" value={overview?.events_24h} note="observations in 24h"/>
        <Metric label="Sources" value={overview?.sources_24h} note="unique origins"/>
        <Metric label="Sessions" value={overview?.sessions_24h} note="correlated connections"/>
        <Metric label="Evidence" value={overview?.artifacts_24h} note="sealed records"/>
      </div>
    </section>
    <section className="two-column">
      <article className="surface signal-surface"><SectionHeading title="Signals for review" note="Behavioral summaries, not log lines"/>{insights.length?<div className="signal-list">{insights.slice(0,5).map(item=><AppLink href={item.href} go={go} className="signal" key={item.id}><span className={`severity-dot ${item.severity}`}/><span><b>{item.title}</b><small>{item.description}</small></span>{item.count&&<strong>{item.count}</strong>}<em>→</em></AppLink>)}</div>:<EmptyState title="No investigation queue" body="Fyke is collecting normally. New login, command, upload, or enumeration behavior will appear here."/>}</article>
      <article className="surface"><SectionHeading title="Protocol mix" note="Share of captured events"/><ProtocolMix protocols={overview?.protocols||{}}/><SectionHeading title="Sensor health" note={`${overview?.sensors?.length||0} reporting`} compact/><SensorList sensors={overview?.sensors||[]}/></article>
    </section>
    <section className="surface"><SectionHeading title="Recent evidence" note="Readable summaries of the newest events" action={<AppLink href="/activity" go={go}>View all →</AppLink>}/><EventList events={events.slice(0,8)} go={go}/></section>
  </div>;
}

function ActivityPage({go}:{go:(href:string)=>void}){
  const{items:events,error,loading}=useEventFeed('/api/v1/events?limit=1000');
  const[search,setSearch]=useState('');const[protocol,setProtocol]=useState('all');const[type,setType]=useState('all');
  const types=useMemo(()=>Array.from(new Set(events.map(e=>e.event_type))).sort(),[events]);
  const filtered=useMemo(()=>events.filter(event=>{
    const haystack=[eventTitle(event),eventDescription(event),event.source?.ip,event.session_id,event.protocol,event.event_type,JSON.stringify(event.attributes||{})].join(' ').toLowerCase();
    return(protocol==='all'||event.protocol===protocol)&&(type==='all'||event.event_type===type)&&haystack.includes(search.toLowerCase());
  }),[events,protocol,type,search]);
  return <div className="page-stack"><PageHeader eyebrow="Evidence explorer" title="Activity log" description="Scan normalized events in plain language, then open any record for structured detail." actions={<a className="text-action" href="/api/v1/exports?format=jsonl">Export JSONL ↗</a>}/>
    <section className="surface filter-surface"><label className="search-field"><span>Search evidence</span><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="IP, command, path, event…"/></label><FilterSelect label="Protocol" value={protocol} onChange={setProtocol} options={['all','ssh','telnet','http','https','sensor']}/><FilterSelect label="Event" value={type} onChange={setType} options={['all',...types]}/><div className="result-count"><b>{filtered.length}</b><span>shown</span></div></section>
    {error&&<ErrorState message={error}/>} {loading?<TableSkeleton/>:<section className="surface log-surface"><EventList events={filtered} go={go} detailed/><footer className="table-footer">Showing up to 1,000 newest records. Use export for offline analysis.</footer></section>}
  </div>;
}

function SessionsPage({go}:{go:(href:string)=>void}){
  const{data,error,loading}=useData<{items:Row[]}>('/api/v1/sessions?limit=500');
  return <CollectionPage eyebrow="Connection timelines" title="Sessions" description="Follow each interaction from first contact through commands, requests, and disconnect." error={error} loading={loading} count={data?.items.length||0}>
    <DataTable columns={['started_at','source_ip','protocol','events','last_seen']} rows={data?.items||[]} keyField="session_id" onOpen={row=>go(`/sessions/${encodeURIComponent(String(row.session_id))}`)}/>
  </CollectionPage>;
}

function SourcesPage({go}:{go:(href:string)=>void}){
  const{data,error,loading}=useData<{items:Row[]}>('/api/v1/sources?limit=500');
  return <CollectionPage eyebrow="Actor profiles" title="Sources" description="Review activity grouped by origin to see persistence across protocols and sessions." error={error} loading={loading} count={data?.items.length||0}>
    <DataTable columns={['source_ip','first_seen','last_seen','events','sessions']} rows={data?.items||[]} keyField="source_ip" onOpen={row=>go(`/sources/${encodeURIComponent(String(row.source_ip))}`)}/>
  </CollectionPage>;
}

function SessionPage({id,go}:{id:string;go:(href:string)=>void}){
  const{data,error,loading}=useData<{items:EventItem[]}>(`/api/v1/events?session=${encodeURIComponent(id)}&limit=1000`);const events=[...(data?.items||[])].sort((a,b)=>a.sequence-b.sequence);const first=events[0];
  const commands=events.filter(e=>e.event_type==='command');
  return <div className="page-stack"><Breadcrumbs go={go} items={[['Sessions','/sessions'],[shortID(id),'']]}/><PageHeader eyebrow="Session investigation" title={first?`${first.protocol.toUpperCase()} from ${first.source.ip}`:'Session detail'} description={`${events.length} events in one ordered connection timeline.`} actions={<AppLink href={`/raw/sessions/${encodeURIComponent(id)}`} go={go} className="text-action">Raw record →</AppLink>}/>{error&&<ErrorState message={error}/>} {loading?<DashboardSkeleton/>:events.length?<>
    <section className="detail-summary"><DetailStat label="Started" value={formatDate(events[0].timestamp)}/><DetailStat label="Last activity" value={formatDate(events.at(-1)?.timestamp)}/><DetailStat label="Commands" value={String(commands.length)}/><DetailStat label="Outcome" value={sessionOutcome(events)}/></section>
    {commands.length>0&&<section className="surface command-strip"><SectionHeading title="Commands observed" note="Arguments remain protected as evidence"/><div>{commands.map(command=><AppLink href={`/events/${command.id}`} go={go} key={command.id}><code>{String(command.attributes?.command||'unsupported input')}</code><span>{formatTime(command.timestamp)}</span></AppLink>)}</div></section>}
    <section className="surface"><SectionHeading title="Timeline" note="Oldest to newest"/><Timeline events={events} go={go}/></section></>:<EmptyState title="Session not found" body="The event metadata may have expired under the retention policy."/>}</div>;
}

function SourcePage({ip,go}:{ip:string;go:(href:string)=>void}){
  const{data,error,loading}=useData<{items:EventItem[]}>(`/api/v1/events?source=${encodeURIComponent(ip)}&limit=1000`);const events=data?.items||[];const insights=deriveInsights(events);const protocols=Array.from(new Set(events.map(e=>e.protocol)));
  return <div className="page-stack"><Breadcrumbs go={go} items={[['Sources','/sources'],[ip,'']]}/><PageHeader eyebrow="Source profile" title={ip} description="Behavior across every observed protocol and connection." actions={<AppLink href={`/raw/sources/${encodeURIComponent(ip)}`} go={go} className="text-action">Raw record →</AppLink>}/>{error&&<ErrorState message={error}/>} {loading?<DashboardSkeleton/>:<>
    <section className="detail-summary"><DetailStat label="Events" value={String(events.length)}/><DetailStat label="Sessions" value={String(new Set(events.map(e=>e.session_id)).size)}/><DetailStat label="Protocols" value={protocols.join(', ')||'—'}/><DetailStat label="Signals" value={String(insights.length)}/></section>
    {insights.length>0&&<section className="surface"><SectionHeading title="Observed behaviors" note="Derived from this source's evidence"/><div className="signal-list">{insights.map(item=><div className="signal static" key={item.id}><span className={`severity-dot ${item.severity}`}/><span><b>{item.title}</b><small>{item.description}</small></span></div>)}</div></section>}
    <section className="surface"><SectionHeading title="Evidence trail" note="Newest first"/><EventList events={events} go={go} detailed/></section></>}</div>;
}

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
  const{data,error,loading}=useData<{items:Row[]}>('/api/v1/artifacts?limit=500');const[preview,setPreview]=useState<Row>();const[previewError,setPreviewError]=useState('');
  async function open(row:Row){setPreviewError('');try{setPreview(await get<Row>(`/api/v1/artifacts/${row.id}/preview`))}catch(e){setPreviewError(e instanceof Error?e.message:String(e))}}
  return <div className="page-stack"><PageHeader eyebrow="Encrypted evidence" title="Artifacts" description="Preview captured transcripts, command arguments, request bodies, and quarantined uploads without exposing them in the event index."/>{error&&<ErrorState message={error}/>} {loading?<TableSkeleton/>:<section className="surface"><DataTable columns={['kind','filename','content_type','size','created_at']} rows={data?.items||[]} keyField="id" actionLabel="Preview" onOpen={open}/></section>}{previewError&&<ErrorState message={previewError}/>} {preview&&<section className="surface preview-panel"><SectionHeading title={String(preview.filename||'Evidence preview')} note={String(preview.encoding||'protected evidence')}/><EvidencePreview preview={preview}/></section>}</div>;
}

function AlertsPage({go}:{go:(href:string)=>void}){
  const{data,error,loading}=useData<{items:EventItem[]}>('/api/v1/alerts');
  return <div className="page-stack"><PageHeader eyebrow="Detection queue" title="Alerts" description="Rule matches that need review, expressed as investigation prompts rather than controller records."/>{error&&<ErrorState message={error}/>} {loading?<TableSkeleton/>:<section className="surface alert-list">{data?.items.length?data.items.map(event=><AppLink href={`/events/${event.id}`} go={go} className="alert-row" key={event.id}><span className="alert-mark">!</span><span><b>{alertTitle(String(event.attributes?.rule||''))}</b><small>{event.source?.ip||'Controller'} · {formatDate(event.timestamp)}</small></span><em>Investigate →</em></AppLink>):<EmptyState title="No triggered alerts" body="Rule matches will appear here while the complete evidence trail remains available in Activity."/>}</section>}</div>;
}

function SettingsPage(){
  const{data:retention,error}=useData<Row>('/api/v1/retention');const[result,setResult]=useState('');const[running,setRunning]=useState(false);
  async function run(){setRunning(true);try{const response=await fetch('/api/v1/retention/run',{method:'POST'});setResult(JSON.stringify(await response.json()))}finally{setRunning(false)}}
  return <div className="page-stack"><PageHeader eyebrow="Controller operations" title="Settings" description="Review data lifecycle controls and export normalized evidence for external analysis."/>{error&&<ErrorState message={error}/>}<section className="settings-grid"><article className="surface settings-card"><SectionHeading title="Retention policy" note="Current controller configuration"/><ReadableObject value={retention||{}}/><button className="button" disabled={running} onClick={run}>{running?'Running…':'Run retention now'}</button>{result&&<p className="status-note">Retention completed: <code>{result}</code></p>}</article><article className="surface settings-card"><SectionHeading title="Evidence exports" note="Sensitive access is audited"/><p>Download normalized metadata for a SIEM or offline analysis. Sensitive evidence requires an explicit CLI or API request.</p><div className="button-row"><a className="button" href="/api/v1/exports?format=jsonl">Download JSONL</a><a className="button secondary" href="/api/v1/exports?format=csv">Download CSV</a></div></article></section></div>;
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

function Cell({column,value}:{column:string;value:unknown}){if(column==='protocol'||column==='kind')return <span className="tag">{humanize(String(value||'—'))}</span>;if(column.includes('size'))return <span>{formatBytes(Number(value||0))}</span>;const text=column.includes('seen')||column.includes('_at')?formatDate(String(value||'')):String(value??'—');return <span title={text}>{text.length>72?`${text.slice(0,69)}…`:text}</span>}
function Fact({label,value,href,go}:{label:string;value:string;href?:string;go?:(href:string)=>void}){return <div><dt>{label}</dt><dd>{href&&go?<AppLink href={href} go={go}>{value} →</AppLink>:value}</dd></div>}
function ReadableObject({value,empty}:{value:Record<string,unknown>;empty?:string}){const entries=Object.entries(value);if(!entries.length)return <p className="muted-copy">{empty||'No values recorded.'}</p>;return <dl className="readable-object">{entries.map(([key,item])=><div key={key}><dt>{humanize(key)}</dt><dd>{formatValue(item)}</dd></div>)}</dl>}
function EvidencePreview({preview}:{preview:Row}){return <div className="evidence-preview"><div><span>{String(preview.encoding||'preview')}</span>{Boolean(preview.truncated)&&<b>truncated</b>}</div><pre>{String(preview.content||'No preview content')}</pre></div>}

function ProtocolMix({protocols}:{protocols:Record<string,number>}){const entries=Object.entries(protocols).sort((a,b)=>b[1]-a[1]);const total=entries.reduce((sum,[,value])=>sum+value,0);if(!total)return <EmptyState title="No protocol activity" body="The distribution will appear after the first sensor event."/>;return <div className="protocol-mix">{entries.map(([name,value])=><div key={name}><span><b>{name.toUpperCase()}</b><em>{Math.round(value/total*100)}%</em></span><i><u style={{width:`${value/total*100}%`}}/></i></div>)}</div>}
function SensorList({sensors}:{sensors:Sensor[]}){if(!sensors.length)return <p className="muted-copy sensor-empty">No sensors have checked in.</p>;return <div className="sensor-list">{sensors.map(sensor=><div key={sensor.id}><span className={`sensor-dot ${sensor.status}`}/><b>{sensor.id}</b><small>{sensor.status} · {formatRelative(sensor.last_seen)}</small></div>)}</div>}
function Breadcrumbs({items,go}:{items:[string,string][];go:(href:string)=>void}){return <nav className="breadcrumbs" aria-label="Breadcrumb">{items.map(([label,href],index)=><span key={`${label}-${index}`}>{index>0&&<i>/</i>}{href?<AppLink href={href} go={go}>{label}</AppLink>:<b>{label}</b>}</span>)}</nav>}

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
async function get<T>(url:string):Promise<T>{const response=await fetch(url);if(!response.ok)throw Error(`${response.status} ${response.statusText}`);return response.json() as Promise<T>}
