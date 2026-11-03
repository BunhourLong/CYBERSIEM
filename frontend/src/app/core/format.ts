// Display helpers shared by the dashboard and alerts screens. Tone names map to
// the .tone-* classes in src/styles.css.

export type Tone = 'red' | 'orange' | 'amber' | 'emerald' | 'bright' | 'strong' | 'soft' | 'muted';

/** "payload_sqli" -> "payload sqli" */
export function humanize(value: string | null | undefined): string {
  return (value ?? '').replaceAll('_', ' ');
}

export function formatScore(value: number | null | undefined): string {
  return (value ?? 0).toFixed(2);
}

export function stateTone(state: string | null | undefined, fallback: Tone): Tone {
  switch (state) {
    case 'blocked':
      return 'red';
    case 'throttled':
      return 'orange';
    case 'suspicious':
      return 'amber';
    default:
      return fallback;
  }
}

export function severityTone(severity: string | null | undefined, fallback: Tone): Tone {
  switch (severity) {
    case 'high':
      return 'red';
    case 'medium':
      return 'amber';
    default:
      return fallback;
  }
}

/** Bar width as a whole percentage of `max`, guarding against divide-by-zero. */
export function percentOf(value: number, max: number): number {
  return Math.round((value / Math.max(max, 1)) * 100);
}

export function joinPresent(parts: (string | null | undefined)[], separator = ', '): string {
  return parts.filter(Boolean).join(separator);
}

/** "Xs" while a block/cooldown timer runs, otherwise null. */
export function enforcementWindow(
  item: { block_countdown_seconds: number | null; cooldown_countdown_seconds: number | null },
  blockLabel = '',
): string | null {
  if (item.block_countdown_seconds && item.block_countdown_seconds > 0) {
    return `${blockLabel}${item.block_countdown_seconds}s`;
  }
  if (item.cooldown_countdown_seconds && item.cooldown_countdown_seconds > 0) {
    return `cooldown ${item.cooldown_countdown_seconds}s`;
  }
  return null;
}
