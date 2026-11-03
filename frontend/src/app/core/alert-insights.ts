import { Alert } from './models';

const ATTACK_DESCRIPTIONS: Record<string, string> = {
  payload_sqli: 'Possible SQL Injection attempt using malicious query manipulation.',
  xss_payload: 'Cross-site scripting payload detected in request.',
  brute_force: 'Multiple failed login attempts indicating a credential attack.',
  credential_stuffing: 'Automated credential list attack across multiple endpoints or user agents.',
  rate_abuse: 'High-frequency requests indicating abuse or scanning.',
  scraping: 'Systematic crawling of many unique endpoints (scraping/enumeration).',
  path_probe: 'Broad endpoint enumeration suggesting directory or path probing.',
  '404_spray': 'High volume of 404 responses suggesting automated resource discovery.',
  user_agent_rotation: 'Multiple distinct user agents from the same IP indicating evasion.',
};

/** Metadata keys surfaced as "evidence" rather than in the generic metadata grid. */
const EVIDENCE_KEYS = new Set(['payload', 'query', 'request_target', 'matched_patterns', 'sample_uas']);

export function describeAttack(type: string): string {
  return ATTACK_DESCRIPTIONS[type] ?? 'Suspicious activity detected.';
}

function nonEmptyList(value: unknown): string[] | null {
  return Array.isArray(value) && value.length ? value.map(String) : null;
}

/** First available payload-like evidence, in detector priority order. */
export function observedEvidence(metadata: Record<string, unknown>): string | null {
  for (const key of ['payload', 'query', 'request_target']) {
    const value = metadata[key];
    if (value) {
      return String(value);
    }
  }
  const patterns = nonEmptyList(metadata['matched_patterns']);
  if (patterns) {
    return patterns.join(', ');
  }
  const userAgents = nonEmptyList(metadata['sample_uas']);
  if (userAgents) {
    return `UAs: ${userAgents.join(', ')}`;
  }
  return null;
}

function formatMetadataValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value.map(String).join(', ');
  }
  if (value !== null && typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
}

export function metadataEntries(metadata: Record<string, unknown>): { key: string; value: string }[] {
  return Object.entries(metadata)
    .filter(([key]) => !EVIDENCE_KEYS.has(key))
    .map(([key, value]) => ({ key: key.replaceAll('_', ' '), value: formatMetadataValue(value) }));
}

export function confidenceLevel(confidence: number): 'high' | 'medium' | 'low' {
  if (confidence >= 80) return 'high';
  if (confidence >= 60) return 'medium';
  return 'low';
}

/** Unresolved + malicious alerts that keep an alert hold in place. */
export function pendingReviewCount(alert: Alert): number {
  return (alert.unresolved_alert_count || 0) + (alert.malicious_alert_count || 0);
}

export function isBlocked(alert: Alert): boolean {
  return alert.manual_blocked || alert.current_state === 'blocked';
}

export function isTrusted(alert: Alert): boolean {
  return alert.whitelist || alert.analyst_override === 'trusted';
}

export function isSuppressed(alert: Alert): boolean {
  return (
    alert.analyst_override === 'suppress_auto_block' &&
    !!alert.cooldown_countdown_seconds &&
    alert.cooldown_countdown_seconds > 0
  );
}
