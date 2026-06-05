import { useMemo, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useRef } from 'react';
import type { ArchPayload, PackageEntry } from '../lib/catalog-schema';
import { displayLanguage, isPrimaryRuntimePackage } from '../lib/runtime-taxonomy';

type Props = {
  architectures: ArchPayload[];
  rawSbomUrls: Record<string, string>;
  language?: string;
  tier?: string;
};

type SortKey = 'name' | 'version' | 'license' | 'cpes';
type SortDir = 'asc' | 'desc';

type PackageCategory = 'runtime' | 'system_tool' | 'security' | 'library' | 'dependency';

function classifyPackage(name: string): PackageCategory {
  const n = name.toLowerCase();
  
  if (
    n.includes('python') || n.includes('node') || n.includes('openjdk') || 
    n.includes('zulu') || n.includes('dotnet') || n === 'go' || 
    n === 'rustc' || n === 'gcc' || n === 'clang' || n.includes('aspnetcore')
  ) {
    return 'runtime';
  }
  
  if (
    n === 'bash' || n === 'busybox' || n === 'coreutils' || 
    n === 'shadow' || n === 'tar' || n === 'curl' || n === 'git'
  ) {
    return 'system_tool';
  }
  
  if (
    n.includes('cacert') || n.includes('ca-certificates') || n.includes('nss')
  ) {
    return 'security';
  }
  
  if (
    n.includes('glibc') || n.includes('zlib') || n.includes('ssl') || 
    n.includes('crypto') || n.includes('ncurses') || n.includes('readline')
  ) {
    return 'library';
  }
  
  return 'dependency';
}

const CATEGORY_STYLE: Record<PackageCategory, { label: string; chipClass: string; icon: string; dotBg: string }> = {
  runtime: { label: 'runtime', chipClass: 'border-accent/30 bg-accent/10 text-accent-soft', icon: '⚡', dotBg: 'bg-accent' },
  system_tool: { label: 'system util', chipClass: 'border-warn/30 bg-warn/10 text-warn', icon: '🛠️', dotBg: 'bg-warn' },
  security: { label: 'ca trust', chipClass: 'border-pink-500/30 bg-pink-500/10 text-pink-400', icon: '🛡️', dotBg: 'bg-pink-500' },
  library: { label: 'library', chipClass: 'border-teal-500/30 bg-teal-500/10 text-teal-400', icon: '📦', dotBg: 'bg-teal-500' },
  dependency: { label: 'dependency', chipClass: 'border-ink-700 bg-ink-800/40 text-ink-300', icon: '📎', dotBg: 'bg-ink-600' },
};

function sbomInclusionSummary(packageName: string, language: string, tier: string): string {
  const pkg = packageName.toLowerCase();
  const lang = displayLanguage(language);
  if (isPrimaryRuntimePackage(language, packageName)) {
    return `Primary ${lang} runtime closure requirement.`;
  }
  if (pkg === 'cacert' || pkg === 'nss-cacert') {
    return 'TLS Certificate authority trust store for secure networking.';
  }
  if (tier === 'slim' && (pkg === 'bash' || pkg === 'bash-interactive' || pkg === 'busybox')) {
    return 'Slim-tier diagnostic shell / utility (removed in distroless).';
  }
  if (language === 'java' && pkg === 'cups') {
    return 'Java runtime dependency for printing / AWT component compatibility.';
  }
  if (language === 'java' && pkg === 'libtiff') {
    return 'Java runtime dependency for image stack / typography features.';
  }
  return `Transitive library closure of the ${lang} ${tier} Nix workspace.`;
}

export default function SbomTable({ architectures, rawSbomUrls, language, tier }: Props) {
  const [arch, setArch] = useState<string>(architectures[0]?.arch ?? 'amd64');
  const [filter, setFilter] = useState('');
  const [licenseFilter, setLicenseFilter] = useState<string>('all');
  const [catFilter, setCatFilter] = useState<Set<PackageCategory>>(new Set());
  const [onlyNix, setOnlyNix] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>('name');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const current = architectures.find((a) => a.arch === arch) ?? architectures[0];
  const packages: PackageEntry[] = current?.sbom.packages ?? [];

  const licenseCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const p of packages) {
      const lic = p.license || 'unknown';
      counts[lic] = (counts[lic] || 0) + 1;
    }
    return counts;
  }, [packages]);

  const licenses = useMemo(() => {
    return Object.keys(licenseCounts).sort();
  }, [licenseCounts]);

  const categoryCounts = useMemo(() => {
    const counts: Record<PackageCategory, number> = {
      runtime: 0,
      system_tool: 0,
      security: 0,
      library: 0,
      dependency: 0,
    };
    for (const p of packages) {
      const cat = classifyPackage(p.name);
      counts[cat] += 1;
    }
    return counts;
  }, [packages]);

  const toggleCat = (k: PackageCategory) => {
    const next = new Set(catFilter);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    setCatFilter(next);
  };

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const rows = packages.filter((p) => {
      if (onlyNix && !p.nixStorePath) return false;
      if (licenseFilter !== 'all' && p.license !== licenseFilter) return false;
      if (catFilter.size > 0 && !catFilter.has(classifyPackage(p.name))) return false;
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
  }, [packages, filter, licenseFilter, catFilter, onlyNix, sortKey, sortDir]);

  const parentRef = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 104,
    measureElement:
      typeof window !== 'undefined'
        ? (element) => element?.getBoundingClientRect().height ?? 104
        : undefined,
    overscan: 12,
  });

  return (
    <section className="space-y-4">
      {/* Unified Control Deck / Dashboard Panel */}
      <div className="surface border border-ink-800 bg-ink-950/20 backdrop-blur-md rounded-2xl p-4 sm:p-5 space-y-4 shadow-xl shadow-ink-950/50">
        
        {/* Top Header Row of the Panel */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-ink-800/50 pb-3">
          {/* Arch selector and title combined */}
          <div className="flex items-center gap-3">
            <span className="text-[10px] uppercase tracking-wider text-ink-300 font-semibold font-mono">Arch:</span>
            <div className="inline-flex rounded-lg border border-ink-800 bg-ink-900/60 p-0.5">
              {architectures.map((a) => (
                <button
                  key={a.arch}
                  type="button"
                  onClick={() => {
                    setArch(a.arch);
                    setLicenseFilter('all');
                  }}
                  className={`rounded-md px-3 py-1 font-mono text-[11px] font-medium transition cursor-pointer ${
                    a.arch === arch 
                      ? 'bg-accent/20 text-accent-soft shadow-sm border border-accent/20' 
                      : 'text-ink-300 hover:text-ink-100 border border-transparent'
                  }`}
                >
                  {a.arch}
                </button>
              ))}
            </div>
            <span className="text-[10px] text-ink-400 font-mono hidden sm:inline">|</span>
            <h3 className="text-[10px] uppercase tracking-wider text-ink-300 font-semibold font-mono hidden sm:flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-accent inline-block animate-pulse shrink-0" />
              SBOM package ledger
            </h3>
          </div>
          
          {/* Findings count and SPDX downloader */}
          <div className="flex items-center gap-3 text-xs">
            <span className="rounded-full bg-ink-800/60 px-2.5 py-0.5 text-[11px] font-semibold text-ink-200 border border-ink-700/40 font-mono">
              {packages.length} packages indexed
            </span>
            {rawSbomUrls[arch] && (
              <a
                href={rawSbomUrls[arch]}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg border border-ink-800 bg-ink-900/80 text-[11px] font-semibold text-ink-200 hover:border-accent/40 hover:text-accent-soft hover:shadow-glow shadow-sm transition-all duration-200 cursor-pointer"
                target="_blank" 
                rel="noreferrer"
              >
                <span>Raw SPDX</span>
                <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </a>
            )}
          </div>
        </div>

        {/* Package Category Filters Row */}
        <div className="flex flex-wrap items-center gap-2 border-b border-ink-800/40 pb-4">
          <span className="text-[9px] uppercase tracking-wider text-ink-300 font-semibold font-mono mr-1">Filter by Type:</span>
          {(Object.keys(categoryCounts) as PackageCategory[]).map((k) => {
            const count = categoryCounts[k] || 0;
            if (count === 0) return null;
            
            const isActive = catFilter.has(k);
            const isAnyActive = catFilter.size > 0;
            const isFaded = isAnyActive && !isActive;
            const style = CATEGORY_STYLE[k];
            
            const activeClass = isActive 
              ? 'border-accent/80 bg-accent/15 text-ink-50 shadow-sm shadow-accent/5 ring-1 ring-accent/30' 
              : 'border-ink-800 bg-ink-900/40 text-ink-300 hover:border-ink-700 hover:text-ink-100';
              
            const opacityClass = isFaded ? 'opacity-40 hover:opacity-100' : 'opacity-100';
            
            return (
              <button
                key={k}
                type="button"
                onClick={() => toggleCat(k)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-[10px] font-medium transition-all duration-200 cursor-pointer ${activeClass} ${opacityClass}`}
                title={`Toggle ${style.label} filter`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${style.dotBg} shrink-0 ${isActive ? 'animate-pulse ring-2 ring-accent/30' : ''}`} />
                <span className="capitalize">{style.label}</span>
                <strong className={`font-semibold ${isActive ? 'text-accent-soft' : 'text-ink-100'}`}>{count}</strong>
              </button>
            );
          })}
          {catFilter.size > 0 && (
            <button
              type="button"
              onClick={() => setCatFilter(new Set())}
              className="text-[9px] text-accent hover:text-accent-soft underline underline-offset-2 ml-1 cursor-pointer font-medium transition"
            >
              Clear Type Filter
            </button>
          )}
        </div>

        {/* Toolbar Section (Collapsed License Select, Nix Filter & Text Search) */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-1">
          {/* Left Block: Nix Filter & Collapsed License Dropdown */}
          <div className="flex flex-wrap items-center gap-4">
            {/* Collapsed License Dropdown */}
            <div className="flex items-center gap-2">
              <span className="text-[9px] uppercase tracking-wider text-ink-300 font-semibold font-mono">License:</span>
              <select
                value={licenseFilter}
                onChange={(e) => setLicenseFilter(e.target.value)}
                className="rounded-lg border border-ink-800 bg-ink-900/60 px-3 py-1.5 text-xs text-ink-100 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/30 transition sm:w-48 truncate cursor-pointer font-mono"
              >
                <option value="all">All Licenses ({licenses.length})</option>
                {licenses.map((lic) => (
                  <option key={lic} value={lic}>
                    {licenseLabel(lic)} ({licenseCounts[lic]})
                  </option>
                ))}
              </select>
            </div>

            {/* Nix store filter */}
            <div className="flex items-center gap-2">
              <label className="inline-flex select-none items-center gap-2 text-xs text-ink-200 cursor-pointer hover:text-ink-50 transition">
                <input
                  type="checkbox"
                  checked={onlyNix}
                  onChange={(e) => setOnlyNix(e.target.checked)}
                  className="h-4 w-4 rounded border-ink-800 bg-ink-900 text-accent focus:ring-accent/40 cursor-pointer"
                />
                <span>Only Nix store packages</span>
              </label>
            </div>
          </div>

          {/* Right Block: Search Input & Match Count */}
          <div className="flex flex-wrap items-end gap-3 grow sm:grow-0">
            <div className="flex flex-col gap-1 w-full sm:w-64">
              <span className="text-[9px] uppercase tracking-wider text-ink-300 font-semibold font-mono">Search packages</span>
              <div className="relative">
                <input
                  type="text"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="name · version · purl · CPE"
                  className="w-full rounded-lg border border-ink-800 bg-ink-900/60 pl-8 pr-3 py-1.5 text-xs text-ink-100 placeholder:text-ink-400 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/30 transition-all duration-200"
                />
                <svg
                  className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-ink-400"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
            </div>

            {/* Match Indicator */}
            <div className="h-8 flex items-center justify-center rounded-lg border border-ink-800 bg-ink-900/40 px-3 font-mono text-[10px] text-ink-300">
              <span className="font-semibold text-accent-soft">{filtered.length}</span>
              <span className="mx-1">/</span>
              <span>{packages.length} matched</span>
            </div>
          </div>
        </div>

      </div>

      {/* SBOM Table Body */}
      <div className="surface-soft overflow-hidden">
        <div className="grid grid-cols-[minmax(0,2.2fr)_minmax(0,0.8fr)_minmax(0,1.2fr)_minmax(0,0.8fr)] border-b border-ink-700/60 bg-ink-900/80 text-xs uppercase tracking-wider text-ink-200">
          {(['name','version','license','cpes'] as SortKey[]).map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => {
                if (sortKey === k) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
                else { setSortKey(k); setSortDir('asc'); }
              }}
              className="flex items-center gap-1.5 px-4 py-2.5 text-left hover:text-ink-50 font-semibold cursor-pointer transition-colors"
            >
              {labelFor(k)}
              {sortKey === k && (
                <span className="text-accent-soft" aria-hidden>
                  {sortDir === 'asc' ? ' ▲' : ' ▼'}
                </span>
              )}
            </button>
          ))}
        </div>
        <div ref={parentRef} className="max-h-[640px] overflow-auto">
          {filtered.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-ink-300">
              No packages match the current filters.
            </div>
          ) : (
            <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
              {virt.getVirtualItems().map((vi) => {
                const p = filtered[vi.index];
                const cat = classifyPackage(p.name);
                const catStyle = CATEGORY_STYLE[cat];

                return (
                  <div
                    key={vi.key}
                    data-index={vi.index}
                    ref={virt.measureElement}
                    style={{
                      position: 'absolute', top: 0, left: 0, right: 0,
                      transform: `translateY(${vi.start}px)`,
                    }}
                    className="grid grid-cols-[minmax(0,2.2fr)_minmax(0,0.8fr)_minmax(0,1.2fr)_minmax(0,0.8fr)] border-b border-ink-800/70 text-sm hover:bg-ink-800/50 min-h-[6.5rem]"
                  >
                    <div className="px-4 py-3 min-w-0 flex flex-col justify-center gap-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-ink-50 font-bold text-xs truncate">{p.name}</span>
                        
                        <span className={`chip text-[9px] uppercase font-mono px-1 py-0.5 rounded border ${catStyle.chipClass}`} title={catStyle.label}>
                          {catStyle.icon} {catStyle.label}
                        </span>

                        {p.nixStorePath && (
                          <span 
                            className="text-[9px] font-mono px-1 py-0.5 rounded uppercase border border-accent/20 bg-accent/5 text-accent-soft select-all" 
                            title={`Nix Store Path: ${p.nixStorePath}`}
                          >
                            nix store
                          </span>
                        )}

                        <a
                          href={`https://search.nixos.org/packages?channel=unstable&query=${encodeURIComponent(p.name)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="ml-1 inline-flex items-center text-[9px] text-accent hover:text-accent-soft hover:underline font-mono"
                          title={`Search ${p.name} in NixOS unstable registry`}
                        >
                          nix-search ↗
                        </a>
                      </div>
                      
                      {p.purl && (
                        <div className="truncate text-[10px] text-ink-400 select-all font-mono leading-none" title={p.purl}>{p.purl}</div>
                      )}
                      <div className="text-[11px] leading-snug text-ink-300 font-sans mt-0.5">
                        {sbomInclusionSummary(p.name, language || 'core', tier || 'slim')}
                      </div>
                    </div>
                    
                    <div className="px-4 py-3 font-mono text-ink-100 flex items-center">{p.version}</div>
                    
                    <div className="truncate px-4 py-3 text-ink-100 flex items-center font-mono text-xs" title={p.license}>
                      {licenseLabel(p.license)}
                    </div>
                    
                    <div className="px-4 py-3 text-ink-200 flex items-center font-mono text-xs">
                      {p.cpes.length > 0 ? (
                        <span className="chip text-[10px] border-ink-700 bg-ink-800/40 text-ink-200 font-mono" title={p.cpes.join(', ')}>
                          {p.cpes.length} CPEs
                        </span>
                      ) : (
                        <span className="text-ink-400">—</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
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
    case 'name': return 'Package · why included';
    case 'version': return 'Version';
    case 'license': return 'License';
    case 'cpes': return 'CPEs';
  }
}

// SPDX `LicenseRef-<64-hex>` identifiers (and `… AND …` expressions of them)
// are unreadable at full length and blow out the <select> width. Collapse each
// hash to a short prefix and cap the overall label for the dropdown.
function licenseLabel(license: string): string {
  const short = license.replace(/LicenseRef-([0-9a-f]{6})[0-9a-f]+/gi, 'LicenseRef-$1…');
  return short.length > 48 ? `${short.slice(0, 47)}…` : short;
}
