import type { EvidenceChannelStatus, EvidenceSummary, EvidenceStatus } from './catalog-schema';

export type EvidenceChannelName = 'signature' | 'provenance' | 'sbom' | 'tests' | 'vulnerabilities';

export function legacyEvidenceChannel(channel: EvidenceChannelName, present: boolean | undefined): EvidenceChannelStatus {
  const presentStatus = channel === 'sbom' || channel === 'vulnerabilities' ? 'observed' : 'verified';
  return { status: present ? presentStatus : 'missing', source: 'legacy-boolean' };
}

export function channelStatus(
  evidence: EvidenceSummary | undefined,
  channel: EvidenceChannelName,
  legacyPresent?: boolean,
): EvidenceChannelStatus {
  return evidence?.statuses?.[channel] ?? legacyEvidenceChannel(channel, legacyPresent ?? evidence?.[channel]);
}

export function isEvidencePresent(status: EvidenceStatus | undefined): boolean {
  return status === 'observed' || status === 'verified' || status === 'attested' || status === 'stale';
}

export function isEvidenceVerified(status: EvidenceStatus | undefined): boolean {
  return status === 'verified';
}

export function statusLabel(status: EvidenceStatus | undefined): string {
  switch (status) {
    case 'observed':
      return 'Observed';
    case 'verified':
      return 'Verified';
    case 'attested':
      return 'Attested';
    case 'stale':
      return 'Stale';
    case 'unknown':
      return 'Unknown';
    case 'missing':
    default:
      return 'Missing';
  }
}

export function evidencePillKind(status: EvidenceStatus | undefined): 'ok' | 'warn' | 'info' {
  if (isEvidenceVerified(status)) return 'ok';
  if (status === 'observed' || status === 'attested' || status === 'stale') return 'info';
  return 'warn';
}

export function evidenceTextClass(status: EvidenceStatus | undefined): string {
  if (isEvidenceVerified(status)) return 'text-emerald-400';
  if (status === 'observed' || status === 'attested' || status === 'stale') return 'text-sky-300';
  return 'text-amber-500';
}

export function evidenceTitle(label: string, channel: EvidenceChannelStatus): string {
  const status = statusLabel(channel.status).toLowerCase();
  if (channel.claim) return `${label}: ${status}. ${channel.claim}`;
  return `${label}: ${status}.`;
}
