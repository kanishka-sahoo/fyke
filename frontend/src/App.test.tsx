import {describe, expect, it} from 'vitest';
import {App, deriveInsights, eventTitle, parseRoute, type EventItem} from './App';

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
});

function event(overrides:Partial<EventItem>):EventItem {
  return {id:'event',timestamp:'2026-08-30T12:00:00Z',sensor_id:'ssh',session_id:'session',sequence:1,source:{ip:'192.0.2.4',port:50000},destination:{ip:'192.0.2.10',port:22},protocol:'ssh',event_type:'session.start',outcome:'success',persona:'default',...overrides};
}
