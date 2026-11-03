import {
  enforcementWindow,
  formatScore,
  humanize,
  joinPresent,
  percentOf,
  severityTone,
  stateTone,
} from './format';

describe('format helpers', () => {
  it('humanize replaces every underscore and handles null or undefined', () => {
    expect(humanize('payload_sqli')).toBe('payload sqli');
    expect(humanize('a_b_c_d')).toBe('a b c d');
    expect(humanize(null)).toBe('');
    expect(humanize(undefined)).toBe('');
  });

  it('formatScore fixes two decimals and treats null or undefined as zero', () => {
    expect(formatScore(3.14159)).toBe('3.14');
    expect(formatScore(2)).toBe('2.00');
    expect(formatScore(0.5)).toBe('0.50');
    expect(formatScore(null)).toBe('0.00');
    expect(formatScore(undefined)).toBe('0.00');
  });

  it('stateTone maps known states and uses the fallback otherwise', () => {
    expect(stateTone('blocked', 'muted')).toBe('red');
    expect(stateTone('throttled', 'muted')).toBe('orange');
    expect(stateTone('suspicious', 'muted')).toBe('amber');
    expect(stateTone('allowed', 'muted')).toBe('muted');
    expect(stateTone(null, 'soft')).toBe('soft');
    expect(stateTone(undefined, 'soft')).toBe('soft');
  });

  it('severityTone maps high and medium and uses the fallback otherwise', () => {
    expect(severityTone('high', 'muted')).toBe('red');
    expect(severityTone('medium', 'muted')).toBe('amber');
    expect(severityTone('low', 'muted')).toBe('muted');
    expect(severityTone(null, 'bright')).toBe('bright');
    expect(severityTone(undefined, 'bright')).toBe('bright');
  });

  it('percentOf rounds to a whole percentage of max', () => {
    expect(percentOf(50, 100)).toBe(50);
    expect(percentOf(1, 3)).toBe(33);
    expect(percentOf(2, 3)).toBe(67);
  });

  it('percentOf guards zero and negative max by treating max as 1', () => {
    expect(percentOf(0, 0)).toBe(0);
    expect(percentOf(5, 0)).toBe(500);
    expect(percentOf(10, -5)).toBe(1000);
  });

  it('joinPresent skips null, undefined and empty parts', () => {
    expect(joinPresent(['a', null, undefined, '', 'b'])).toBe('a, b');
    expect(joinPresent([null, undefined, ''])).toBe('');
    expect(joinPresent([])).toBe('');
  });

  it('joinPresent uses a custom separator and defaults to ", "', () => {
    expect(joinPresent(['a', null, 'b'], ' | ')).toBe('a | b');
    expect(joinPresent(['a', 'b'], '')).toBe('ab');
    expect(joinPresent(['a', 'b'])).toBe('a, b');
  });

  it('enforcementWindow returns null for zero or null countdowns', () => {
    expect(
      enforcementWindow({ block_countdown_seconds: 0, cooldown_countdown_seconds: 0 }),
    ).toBeNull();
    expect(
      enforcementWindow({ block_countdown_seconds: null, cooldown_countdown_seconds: null }),
    ).toBeNull();
    expect(
      enforcementWindow({ block_countdown_seconds: -5, cooldown_countdown_seconds: null }),
    ).toBeNull();
  });

  it('enforcementWindow shows the block countdown with the label before cooldown', () => {
    expect(
      enforcementWindow(
        { block_countdown_seconds: 30, cooldown_countdown_seconds: null },
        'blocked ',
      ),
    ).toBe('blocked 30s');
    expect(enforcementWindow({ block_countdown_seconds: 30, cooldown_countdown_seconds: 15 })).toBe(
      '30s',
    );
  });

  it('enforcementWindow shows cooldown without the block label when no block is active', () => {
    expect(
      enforcementWindow({ block_countdown_seconds: 0, cooldown_countdown_seconds: 15 }, 'blocked '),
    ).toBe('cooldown 15s');
    expect(
      enforcementWindow({ block_countdown_seconds: null, cooldown_countdown_seconds: 10 }),
    ).toBe('cooldown 10s');
  });
});
