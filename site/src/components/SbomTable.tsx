import { useMemo, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useRef } from 'react';
import type { ArchPayload, PackageEntry } from '../lib/catalog-schema';

type Props = {
  architectures: ArchPayload[];
  rawSbomUrls: Record<string, string>;
};

type SortKey = 'name' | 'version' | 'license' | 'cpes';
type SortDir = 'asc' | 'desc';

export default function SbomTable({ architectures, rawSbomUrls }: Props) {
  const [arch, setArch] = useState<string>(architectures[0]?.arch ?? 'amd64');
  const [filter, setFilter] = useState('');
  const [licenseFilter, setLicenseFilter] = useState<string>('all');
  const [onlyNix, setOnlyNix] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>('name');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const current = architectures.find((a) => a.arch === arch) ?? architectures[0];
  const packages: PackageEntry[] = current?.sbom.packages ?? [];

  const licenses = useMemo(() => {
    const set = new Set<string>();
    for (const p of packages) set.add(p.license);
    return Array.from(set).sort();
  }, [packages]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const rows = packages.filter((p) => {
      if (onlyNix && !p.nixStorePath) return false;
      if (licenseFilter !== 'all' && p.license !== licenseFilter) return false;
      if (!q) return true;
      return (
        p.name.toLowerCase().includes(q) ||
        p.version.toLowerCase().includes(q) ||
        (p.purl?.toLowerCase().includes(q) ?? false) ||
        p.cpes.some((c) => c.toLowerCase().includes(q))
      );
    });
    rows.sort((a, b) => {
      const fa = pickSort(a, sortKey);
      const fb = pickSort(b, sortKey);
      const cmp = fa.localeCompare(fb, undefined, { numeric: true });
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return rows;
  }, [packages, filter, licenseFilter, onlyNix, sortKey, sortDir]);

  const parentRef = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 56,
    overscan: 12,
  });

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex flex-col">
          <label className="text-[11px] uppercase tracking-wider text-ink-300">Arch</label>
          <div className="mt-1 inline-flex rounded-lg border border-ink-700 bg-ink-900 p-0.5">
            {architectures.map((a) => (
              <button
                key={a.arch}
                type="button"
                onClick={() => setArch(a.arch)}
                className={`rounded-md px-3 py-1 font-mono text-xs transition ${
                  a.arch === arch ? 'bg-accent/15 text-accent-soft' : 'text-ink-200 hover:text-ink-50'
                }`}
              >
                {a.arch}
              </button>
            ))}
          </div>
        </div>
        <div className="flex grow flex-col">
          <label className="text-[11px] uppercase tracking-wider text-ink-300">Filter</label>
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="name · version · purl · CPE"
            className="mt-1 rounded-lg border border-ink-700 bg-ink-900 px-3 py-1.5 text-sm text-ink-100 placeholder:text-ink-300 focus:border-accent focus:outline-none"
          />
        </div>
        <div className="flex flex-col">
          <label className="text-[11px] uppercase tracking-wider text-ink-300">License</label>
          <select
            value={licenseFilter}
            onChange={(e) => setLicenseFilter(e.target.value)}
            className="mt-1 rounded-lg border border-ink-700 bg-ink-900 px-3 py-1.5 text-sm text-ink-100 focus:border-accent focus:outline-none"
          >
            <option value="all">All ({licenses.length})</option>
            {licenses.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
        </div>
        <label className="mt-5 inline-flex select-none items-center gap-2 text-sm text-ink-200">
          <input
            type="checkbox"
            checked={onlyNix}
            onChange={(e) => setOnlyNix(e.target.checked)}
            className="h-4 w-4 rounded border-ink-700 bg-ink-900 text-accent focus:ring-accent"
          />
          Only Nix store packages
        </label>
        <div className="ml-auto flex items-center gap-3 text-xs text-ink-300">
          <span>{filtered.length} / {packages.length} packages</span>
          {rawSbomUrls[arch] && (
            <a
              href={rawSbomUrls[arch]}
              className="chip hover:border-accent/40"
              target="_blank" rel="noreferrer"
            >Raw SPDX</a>
          )}
        </div>
      </div>

      <div className="surface-soft overflow-hidden">
        <div className="grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.5fr)_minmax(0,1fr)] border-b border-ink-700/60 bg-ink-900/80 text-xs uppercase tracking-wider text-ink-200">
          {(['name','version','license','cpes'] as SortKey[]).map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => {
                if (sortKey === k) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
                else { setSortKey(k); setSortDir('asc'); }
              }}
              className="flex items-center gap-1.5 px-4 py-2.5 text-left hover:text-ink-50"
            >
              {labelFor(k)}
              {sortKey === k && <span aria-hidden>{sortDir === 'asc' ? '▲' : '▼'}</span>}
            </button>
          ))}
        </div>
        <div ref={parentRef} className="max-h-[640px] overflow-auto">
          <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
            {virt.getVirtualItems().map((vi) => {
              const p = filtered[vi.index];
              return (
                <div
                  key={vi.key}
                  style={{
                    position: 'absolute', top: 0, left: 0, right: 0,
                    transform: `translateY(${vi.start}px)`,
                  }}
                  className="grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.5fr)_minmax(0,1fr)] border-b border-ink-800/70 text-sm hover:bg-ink-800/50"
                >
                  <div className="truncate px-4 py-3">
                    <div className="font-mono text-ink-50">{p.name}</div>
                    {p.purl && (
                      <div className="truncate text-[11px] text-ink-300" title={p.purl}>{p.purl}</div>
                    )}
                  </div>
                  <div className="px-4 py-3 font-mono text-ink-100">{p.version}</div>
                  <div className="truncate px-4 py-3 text-ink-100">{p.license}</div>
                  <div className="px-4 py-3 text-ink-200">{p.cpes.length}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}

function pickSort(p: PackageEntry, k: SortKey): string {
  switch (k) {
    case 'name': return p.name;
    case 'version': return p.version;
    case 'license': return p.license;
    case 'cpes': return String(p.cpes.length).padStart(4, '0');
  }
}
function labelFor(k: SortKey): string {
  switch (k) {
    case 'name': return 'Package';
    case 'version': return 'Version';
    case 'license': return 'License';
    case 'cpes': return 'CPEs';
  }
}
