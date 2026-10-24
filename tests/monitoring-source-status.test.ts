import { describe, expect, it } from 'vitest';
import { filterCurrentSourceStatuses } from '../frontend/src/monitoring';

describe('Monitoring source status display', () => {
  it('hides historical Reddit status without relabeling it as Bluesky', () => {
    const statuses = filterCurrentSourceStatuses([
      {
        source: 'reddit',
        status: 'unavailable',
        candidatesFound: 0,
        error: 'Missing credentials',
      },
      {
        source: 'bluesky',
        status: 'available',
        candidatesFound: 2,
      },
    ]);

    expect(statuses).toEqual([
      {
        source: 'bluesky',
        status: 'available',
        candidatesFound: 2,
      },
    ]);
  });

  it('preserves the actual Bluesky status, result count, and error', () => {
    const statuses = filterCurrentSourceStatuses([
      {
        source: 'bluesky',
        status: 'unavailable',
        candidatesFound: 0,
        error: 'HTTP 429',
      },
    ]);

    expect(statuses).toEqual([
      {
        source: 'bluesky',
        status: 'unavailable',
        candidatesFound: 0,
        error: 'HTTP 429',
      },
    ]);
  });
});
