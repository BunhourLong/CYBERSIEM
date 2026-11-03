import { describeAttack, metadataEntries, observedEvidence } from './alert-insights';

describe('alert insights', () => {
  it('prefers payload, then query, then request target', () => {
    expect(observedEvidence({ payload: "' OR 1=1", query: 'q=1' })).toBe("' OR 1=1");
    expect(observedEvidence({ payload: '', query: 'q=1', request_target: '/x?q=1' })).toBe('q=1');
    expect(observedEvidence({ request_target: '/admin' })).toBe('/admin');
  });

  it('falls back to matched patterns and sampled user agents', () => {
    expect(observedEvidence({ matched_patterns: ['union', 'select'] })).toBe('union, select');
    expect(observedEvidence({ matched_patterns: [], sample_uas: ['curl', 'wget'] })).toBe(
      'UAs: curl, wget',
    );
    expect(observedEvidence({ window_seconds: 60 })).toBeNull();
  });

  it('lists non-evidence metadata with readable keys and values', () => {
    expect(
      metadataEntries({
        payload: 'hidden',
        window_seconds: 60,
        endpoints: ['/a', '/b'],
        extra: { nested: true },
      }),
    ).toEqual([
      { key: 'window seconds', value: '60' },
      { key: 'endpoints', value: '/a, /b' },
      { key: 'extra', value: '{"nested":true}' },
    ]);
  });

  it('describes known and unknown attack types', () => {
    expect(describeAttack('brute_force')).toContain('failed login attempts');
    expect(describeAttack('something_new')).toBe('Suspicious activity detected.');
  });
});
