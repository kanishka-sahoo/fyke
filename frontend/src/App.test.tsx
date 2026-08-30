import {describe, expect, it} from 'vitest';
import {App} from './App';

describe('dashboard entry point', () => {
  it('exports the application component', () => {
    expect(App).toBeTypeOf('function');
  });
});
