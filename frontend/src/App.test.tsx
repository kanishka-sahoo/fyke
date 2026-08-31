import {describe, expect, it} from 'vitest';
import {App, buildEventQuery, deriveInsights, eventTitle, joinLines, pageItems, paginationWindow, parseRoute, type ActivityFilters, type EventItem} from './App';

describe('dashboard entry point', () => {
  it('exports the application component', () => {
    expect(App).toBeTypeOf('function');
  });

  it('maps addressable drill-down routes', () => {
    expect(parseRoute('/sessions/session-1')).toEqual({page:'session',id:'session-1'});
    expect(parseRoute('/sources/192.0.2.4')).toEqual({page:'source',id:'192.0.2.4'});
    expect(parseRoute('/raw/events/event-1')).toEqual({page:'raw',rawKind:'events',id:'event-1'});
    expect(parseRoute('/does-not-exist')).toEqual({page:'not-found'});
  });

  it('describes normalized events in plain language', () => {
    expect(eventTitle(event({event_type:'command',attributes:{command:'wget'}}))).toBe('Command: wget');
    expect(eventTitle(event({protocol:'https',event_type:'http.request',attributes:{'http.method':'GET','url.path':'/.git'}}))).toBe('GET /.git');
  });

  it('surfaces scanner behavior and post-login activity', () => {
    const events=[
      event({id:'login',event_type:'authentication.attempt',outcome:'success'}),
      event({id:'command',event_type:'command',attributes:{command:'uname'}}),
      event({id:'probe',protocol:'http',event_type:'http.request',attributes:{'http.method':'GET','url.path':'/admin','http.user_agent':'gobuster/3.8'}}),
    ];
    const insights=deriveInsights(events);
    expect(insights.map(item=>item.title)).toContain('Known web enumerator observed');
    expect(insights.map(item=>item.title)).toContain('Interactive access obtained');
    expect(insights.map(item=>item.title)).toContain('Post-login commands observed');
  });

  it('builds server-side pagination and time filters', () => {
    const filters:ActivityFilters={search:'gobuster',protocol:'http',type:'http.request',outcome:'success',range:'1h',customSince:'',customUntil:''};
    const query=new URL(buildEventQuery(filters,3,25,new Date('2026-08-31T12:00:00Z')),'http://fyke.local');
    expect(query.searchParams.get('limit')).toBe('25');
    expect(query.searchParams.get('offset')).toBe('50');
    expect(query.searchParams.get('since')).toBe('2026-08-31T11:00:00.000Z');
    expect(query.searchParams.get('protocol')).toBe('http');
    expect(query.searchParams.get('type')).toBe('http.request');
    expect(query.searchParams.get('outcome')).toBe('success');
    expect(query.searchParams.get('q')).toBe('gobuster');
  });

  it('keeps pagination controls centered around the current page', () => {
    expect(paginationWindow(1,12)).toEqual([1,2,3,4,5]);
    expect(paginationWindow(7,12)).toEqual([5,6,7,8,9]);
    expect(paginationWindow(12,12)).toEqual([8,9,10,11,12]);
  });

  it('treats an empty API page encoded as null as an empty collection', () => {
    expect(pageItems<{id:string}>({items:null})).toEqual([]);
  });

  it('treats null webhook preferences as an empty editor value', () => {
    expect(joinLines(null)).toBe('');
  });
});

function event(overrides:Partial<EventItem>):EventItem {
  return {id:'event',timestamp:'2026-08-30T12:00:00Z',sensor_id:'ssh',session_id:'session',sequence:1,source:{ip:'192.0.2.4',port:50000},destination:{ip:'192.0.2.10',port:22},protocol:'ssh',event_type:'session.start',outcome:'success',persona:'default',...overrides};
}
