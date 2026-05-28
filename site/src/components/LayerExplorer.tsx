import { useMemo, useState } from 'react';
import type { ArchPayload } from '../lib/catalog-schema';

type Props = { 
  architectures: ArchPayload[];
  imageName?: string;
  tierId?: string;
  imageTag?: string;
};

function humanBytes(n: number | null | undefined): string {
  if (!n && n !== 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

export default function LayerExplorer({ architectures, imageName, tierId }: Props) {
  const archs = architectures.filter((a) => a.layers && a.layers.length > 0);
  const [arch, setArch] = useState(archs[0]?.arch ?? architectures[0]?.arch ?? 'amd64');
  const current = architectures.find((a) => a.arch === arch) ?? architectures[0];
  const layers = current?.layers ?? [];
  const totalSize = useMemo(() => layers.reduce((s, l) => s + (l.size || 0), 0), [layers]);
  const [selected, setSelected] = useState<number>(0);
  const [detailTab, setDetailTab] = useState<'details' | 'packages' | 'vulnerabilities'>('details');
  const [packageSearch, setPackageSearch] = useState('');
  const [pullTool, setPullTool] = useState<'crane' | 'docker' | 'nix'>('crane');
  const [copySuccess, setCopySuccess] = useState(false);

  const sel = layers[selected];

  const packages = current?.sbom?.packages ?? [];
  const packagesInLayer = useMemo(() => {
    if (!sel) return [];
    return packages.filter((p: any) => p.layerDigest === sel.digest);
  }, [sel, packages]);

  const vulnsInLayer = useMemo(() => {
    if (!sel || !current?.vulnerabilities?.findings) return [];
    const pkgsSet = new Set(packagesInLayer.map((p) => `${p.name}@${p.version}`));
    return current.vulnerabilities.findings.filter((f: any) =>
      pkgsSet.has(`${f.packageName}@${f.packageVersion}`)
    );
  }, [sel, current, packagesInLayer]);

  const licenseBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    packagesInLayer.forEach((p: any) => {
      const lic = p.license || 'Unknown';
      counts[lic] = (counts[lic] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [packagesInLayer]);

  if (architectures.length === 0) return null;
  if (archs.length === 0) {
    return (
      <section className="space-y-3">
        <h2 className="heading text-lg">Layers</h2>
        <p className="surface-soft px-5 py-4 text-sm text-ink-300">
          Layer information will appear once the publish-pages workflow has probed GHCR for this
          release.
        </p>
      </section>
    );
  }

  const cumulativeToSel = layers
    .slice(0, selected + 1)
    .reduce((s, l) => s + (l.size || 0), 0);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 1500);
  };

  const imageRepoName = imageName || 'clearcutt-corelts';
  const tierSuffix = tierId ? `:${tierId}` : '';
  const pullRef = sel ? `ghcr.io/northcutted/${imageRepoName}${tierSuffix}@${sel.digest}` : '';

  return (
    <section className="space-y-3">
      <header className="flex flex-wrap items-baseline justify-between gap-3">
        <div>
          <h2 className="heading text-lg">Layer explorer</h2>
          <p className="mt-1 text-xs text-ink-300">
            Click any layer to inspect its digest, size, and position in the image. Bars show
            relative layer size within the selected architecture.
          </p>
        </div>
        <div className="flex flex-col">
          <label className="text-[11px] uppercase tracking-wider text-ink-300">Arch</label>
          <div className="mt-1 inline-flex rounded-lg border border-ink-700 bg-ink-900 p-0.5">
            {architectures.map((a) => (
              <button
                key={a.arch}
                type="button"
                onClick={() => {
                  setArch(a.arch);
                  setSelected(0);
                }}
                className={`rounded-md px-3 py-1 font-mono text-xs transition ${
                  a.arch === arch ? 'bg-accent/15 text-accent-soft' : 'text-ink-200 hover:text-ink-50'
                }`}
                disabled={!a.layers || a.layers.length === 0}
                title={!a.layers || a.layers.length === 0 ? 'no layer info' : undefined}
              >
                {a.arch}
              </button>
            ))}
          </div>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,3.2fr)_minmax(0,2fr)]">
        {/* Layer list + Visual Stack */}
        <div className="surface-soft overflow-hidden flex flex-col md:flex-row">
          {/* Visual Stack Tower */}
          <div className="hidden md:flex flex-col justify-end items-center gap-1.5 p-4 border-r border-ink-700/30 bg-ink-950/20 shrink-0 w-[130px] select-none">
            <div className="text-[10px] uppercase tracking-wider text-ink-300 font-semibold mb-2">Layer Stack</div>
            <div className="flex-1 flex flex-col justify-end w-full gap-1.5">
              {layers.map((_, idx) => {
                const i = layers.length - 1 - idx;
                const layerItem = layers[i];
                const isSel = i === selected;
                
                const sizeVal = layerItem.size || 0;
                const minHeight = 26;
                const maxHeight = 60;
                const height = totalSize > 0 
                  ? minHeight + Math.round((Math.log10(sizeVal + 1) / Math.log10(totalSize + 1)) * (maxHeight - minHeight)) 
                  : minHeight;

                const layerPkgs = packages.filter((p: any) => p.layerDigest === layerItem.digest);
                const pkgsSet = new Set(layerPkgs.map((p) => `${p.name}@${p.version}`));
                const layerVulns = (current?.vulnerabilities?.findings ?? []).filter((f: any) =>
                  pkgsSet.has(`${f.packageName}@${f.packageVersion}`)
                );

                let borderColor = 'border-ink-700/50';
                let bgColor = 'bg-ink-800/40';
                let textColor = 'text-ink-300';
                let glow = '';

                if (isSel) {
                  borderColor = 'border-accent';
                  bgColor = 'bg-accent/20';
                  textColor = 'text-accent-soft';
                  glow = 'shadow-[0_0_12px_rgba(var(--accent),0.25)]';
                } else if (layerVulns.length > 0) {
                  const hasCriticalOrHigh = layerVulns.some((f: any) => f.severity === 'critical' || f.severity === 'high');
                  borderColor = hasCriticalOrHigh ? 'border-danger/30 hover:border-danger/60' : 'border-warn/30 hover:border-warn/60';
                  bgColor = hasCriticalOrHigh ? 'bg-danger/5 hover:bg-danger/10' : 'bg-warn/5 hover:bg-warn/10';
                  textColor = hasCriticalOrHigh ? 'text-danger' : 'text-warn';
                } else {
                  borderColor = 'border-ink-700/40 hover:border-ink-500/80';
                  bgColor = 'bg-ink-900/30 hover:bg-ink-800/40';
                }

                return (
                  <button
                    key={layerItem.digest + ':stack:' + i}
                    type="button"
                    onClick={() => setSelected(i)}
                    style={{ height: `${height}px` }}
                    className={`w-full rounded-md border flex flex-col justify-center px-2 text-left transition-all duration-200 cursor-pointer overflow-hidden ${bgColor} ${borderColor} ${glow}`}
                    title={`Layer #${i + 1}\nDigest: ${layerItem.digest}\nSize: ${humanBytes(layerItem.size)}\nCVEs: ${layerVulns.length}`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className={`font-mono text-[9px] font-bold ${textColor}`}>L{i + 1}</span>
                      {layerVulns.length > 0 && (
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          layerVulns.some((f: any) => f.severity === 'critical' || f.severity === 'high') ? 'bg-danger animate-pulse' : 'bg-warn'
                        }`} />
                      )}
                    </div>
                    <span className="text-[8px] text-ink-400 font-mono truncate block mt-0.5">
                      {humanBytes(layerItem.size)}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Layer List Scrollable */}
          <div className="flex-1 flex flex-col min-w-0">
            <div className="flex items-center justify-between border-b border-ink-700/60 bg-ink-900/80 px-4 py-2.5 text-xs uppercase tracking-wider text-ink-200">
              <span>
                {layers.length} layer{layers.length === 1 ? '' : 's'}
              </span>
              <span className="text-ink-300">total {humanBytes(totalSize)}</span>
            </div>
            <ol className="max-h-[640px] overflow-auto divide-y divide-ink-800/40">
              {layers.map((l, i) => {
                const pct = totalSize > 0 ? Math.max(1, Math.round(((l.size || 0) / totalSize) * 100)) : 0;
                const isSel = i === selected;
                
                const layerPkgs = packages.filter((p: any) => p.layerDigest === l.digest);
                const pkgsSet = new Set(layerPkgs.map((p) => `${p.name}@${p.version}`));
                const layerVulns = (current?.vulnerabilities?.findings ?? []).filter((f: any) =>
                  pkgsSet.has(`${f.packageName}@${f.packageVersion}`)
                );

                return (
                  <li key={l.digest + ':' + i}>
                    <button
                      type="button"
                      onClick={() => setSelected(i)}
                      className={`flex w-full items-center gap-3 px-4 py-3 text-left transition ${
                        isSel ? 'bg-accent/10' : 'hover:bg-ink-800/50'
                      }`}
                    >
                      <span
                        className={`shrink-0 font-mono text-xs ${isSel ? 'text-accent-soft' : 'text-ink-300'}`}
                      >
                        {String(i + 1).padStart(2, '0')}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <div className="truncate font-mono text-[11px] text-ink-100" title={l.digest}>
                            {l.digest.replace(/^sha256:/, '').slice(0, 16)}…
                          </div>
                          {layerVulns.length > 0 && (
                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase ${
                              layerVulns.some((f: any) => f.severity === 'critical' || f.severity === 'high')
                                ? 'bg-danger/10 text-danger border border-danger/20'
                                : 'bg-warn/10 text-warn border border-warn/20'
                            }`}>
                              {layerVulns.length} cve{layerVulns.length === 1 ? '' : 's'}
                            </span>
                          )}
                        </div>
                        <div className="mt-1.5 h-1 w-full overflow-hidden rounded bg-ink-800">
                          <div
                            className={`h-full ${isSel ? 'bg-accent/70' : 'bg-ink-500'}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                      <span className="shrink-0 font-mono text-xs text-ink-200">
                        {humanBytes(l.size)}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </div>
        </div>

        {/* Detail panel */}
        <div className="surface-soft px-5 py-4 flex flex-col min-h-[480px]">
          {sel ? (
            <div className="space-y-4 flex-1 flex flex-col">
              {/* Tab Switcher */}
              <div className="flex border-b border-ink-700/60 text-xs shrink-0">
                <button
                  type="button"
                  onClick={() => setDetailTab('details')}
                  className={`flex-1 py-2 text-center font-medium transition border-b-2 ${
                    detailTab === 'details'
                      ? 'border-accent text-accent-soft'
                      : 'border-transparent text-ink-300 hover:text-ink-100'
                  }`}
                >
                  Metadata
                </button>
                <button
                  type="button"
                  onClick={() => setDetailTab('packages')}
                  className={`flex-1 py-2 text-center font-medium transition border-b-2 ${
                    detailTab === 'packages'
                      ? 'border-accent text-accent-soft'
                      : 'border-transparent text-ink-300 hover:text-ink-100'
                  }`}
                >
                  Packages ({packagesInLayer.length})
                </button>
                <button
                  type="button"
                  onClick={() => setDetailTab('vulnerabilities')}
                  className={`flex-1 py-2 text-center font-medium transition border-b-2 ${
                    detailTab === 'vulnerabilities'
                      ? 'border-accent text-accent-soft'
                      : 'border-transparent text-ink-300 hover:text-ink-100'
                  }`}
                >
                  CVEs ({vulnsInLayer.length})
                </button>
              </div>

              {/* Tab Panels */}
              <div className="flex-1 overflow-auto mt-2">
                {detailTab === 'details' && (
                  <div className="space-y-4 text-sm">
                    <div className="flex justify-between items-baseline">
                      <div>
                        <div className="text-[11px] uppercase tracking-wider text-ink-300">Layer</div>
                        <div className="mt-1 font-mono text-base text-ink-50">
                          #{selected + 1} of {layers.length}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] uppercase tracking-wider text-ink-300">Position</div>
                        <div className="mt-1 font-mono text-sm text-ink-100">
                          {selected === 0 ? 'base' : selected === layers.length - 1 ? 'top' : 'middle'}
                        </div>
                      </div>
                    </div>

                    <div>
                      <div className="text-[11px] uppercase tracking-wider text-ink-300">Digest</div>
                      <div className="mt-1 break-all font-mono text-xs text-ink-100">{sel.digest}</div>
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <div className="text-[11px] uppercase tracking-wider text-ink-300">Size</div>
                        <div className="mt-1 font-mono text-sm text-ink-100">{humanBytes(sel.size)}</div>
                      </div>
                      <div>
                        <div className="text-[11px] uppercase tracking-wider text-ink-300">% of image</div>
                        <div className="mt-1 font-mono text-sm text-ink-100">
                          {totalSize > 0 ? `${(((sel.size || 0) / totalSize) * 100).toFixed(1)}%` : '—'}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] uppercase tracking-wider text-ink-300">Cumulative</div>
                        <div className="mt-1 font-mono text-sm text-ink-100">
                          {humanBytes(cumulativeToSel)}
                        </div>
                      </div>
                    </div>

                    {/* Pull layer tab selector & commands */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="text-[11px] uppercase tracking-wider text-ink-300">Pull or Inspect Layer</div>
                        <div className="flex gap-1.5 text-[9px] font-mono">
                          {(['crane', 'docker', 'nix'] as const).map(t => (
                            <button
                              key={t}
                              type="button"
                              onClick={() => setPullTool(t)}
                              className={`px-1.5 py-0.5 rounded border transition ${
                                pullTool === t 
                                  ? 'bg-accent/15 text-accent-soft border-accent/40' 
                                  : 'bg-ink-950/40 text-ink-300 border-ink-800/50 hover:text-ink-100'
                              }`}
                            >
                              {t}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="relative group rounded-md border border-ink-700/60 bg-ink-950/80 p-2.5 font-mono text-[10.5px] text-ink-100 select-all min-h-[48px] flex items-center pr-12">
                        <span className="break-all leading-normal">
                          {pullTool === 'crane' && `crane blob ${pullRef}`}
                          {pullTool === 'docker' && `docker pull ${pullRef}`}
                          {pullTool === 'nix' && `nix store cat-path ${sel.digest}`}
                        </span>
                        <button 
                          type="button" 
                          onClick={() => {
                            const cmd = pullTool === 'crane' 
                              ? `crane blob ${pullRef}`
                              : pullTool === 'docker'
                                ? `docker pull ${pullRef}`
                                : `nix store cat-path ${sel.digest}`;
                            handleCopy(cmd);
                          }}
                          className="absolute top-1/2 -translate-y-1/2 right-1.5 px-2 py-1 bg-ink-800/80 hover:bg-accent/25 border border-ink-700/60 rounded text-[9px] text-ink-200 hover:text-accent-soft transition duration-150 shrink-0 select-none"
                        >
                          {copySuccess ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </div>

                    {/* Security Assessment Card */}
                    <div className="rounded-lg border border-ink-700/50 bg-ink-950/40 p-3 space-y-2.5">
                      <div className="text-[11px] uppercase tracking-wider text-ink-300 font-semibold flex items-center justify-between">
                        <span>Layer Security Status</span>
                        <span className={`text-[10px] font-bold ${vulnsInLayer.length === 0 ? 'text-emerald-400' : 'text-warn'}`}>
                          {vulnsInLayer.length === 0 ? '✓ SECURE' : `⚠ ${vulnsInLayer.length} FINDINGS`}
                        </span>
                      </div>
                      {vulnsInLayer.length === 0 ? (
                        <p className="text-[11.5px] text-ink-200 leading-relaxed">
                          No known vulnerabilities are introduced by the packages compiled in this specific Nix closure layer.
                        </p>
                      ) : (
                        <div className="space-y-2">
                          <div className="h-1.5 w-full bg-ink-800 rounded-full overflow-hidden flex">
                            {(() => {
                              const crit = vulnsInLayer.filter(f => f.severity === 'critical').length;
                              const high = vulnsInLayer.filter(f => f.severity === 'high').length;
                              const med = vulnsInLayer.filter(f => f.severity === 'medium').length;
                              const low = vulnsInLayer.filter(f => f.severity === 'low').length;
                              const total = vulnsInLayer.length;
                              
                              return (
                                <>
                                  {crit > 0 && <div className="bg-danger h-full" style={{ width: `${(crit / total) * 100}%` }} title={`${crit} Critical`} />}
                                  {high > 0 && <div className="bg-warn h-full" style={{ width: `${(high / total) * 100}%` }} title={`${high} High`} />}
                                  {med > 0 && <div className="bg-accent h-full" style={{ width: `${(med / total) * 100}%` }} title={`${med} Medium`} />}
                                  {low > 0 && <div className="bg-ink-500 h-full" style={{ width: `${(low / total) * 100}%` }} title={`${low} Low`} />}
                                </>
                              );
                            })()}
                          </div>
                          <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] font-mono text-ink-200">
                            {vulnsInLayer.filter(f => f.severity === 'critical').length > 0 && (
                              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-danger animate-pulse" /> {vulnsInLayer.filter(f => f.severity === 'critical').length} Critical</span>
                            )}
                            {vulnsInLayer.filter(f => f.severity === 'high').length > 0 && (
                              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-warn" /> {vulnsInLayer.filter(f => f.severity === 'high').length} High</span>
                            )}
                            {vulnsInLayer.filter(f => f.severity === 'medium').length > 0 && (
                              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-accent" /> {vulnsInLayer.filter(f => f.severity === 'medium').length} Med</span>
                            )}
                            {vulnsInLayer.filter(f => f.severity === 'low').length > 0 && (
                              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-ink-500" /> {vulnsInLayer.filter(f => f.severity === 'low').length} Low</span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* License Distribution Card */}
                    {packagesInLayer.length > 0 && (
                      <div className="rounded-lg border border-ink-700/50 bg-ink-950/40 p-3 space-y-2">
                        <div className="text-[11px] uppercase tracking-wider text-ink-300 font-semibold">
                          License Composition
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {licenseBreakdown.map(([license, count]) => {
                            const isCopyleft = /GPL|AGPL|LGPL|MPL/i.test(license);
                            const badgeColor = isCopyleft 
                              ? 'bg-danger/10 text-danger border-danger/25' 
                              : license === 'Unknown' || license === 'NOASSERTION'
                                ? 'bg-ink-800/30 text-ink-300 border-ink-700/30'
                                : 'bg-accent/10 text-accent-soft border-accent/25';
                            return (
                              <span 
                                key={license} 
                                className={`px-2 py-0.5 rounded-full text-[10px] font-mono border transition ${badgeColor}`}
                                title={`${count} package${count === 1 ? '' : 's'} under ${license}`}
                              >
                                {license} <span className="opacity-60 font-semibold">({count})</span>
                              </span>
                            );
                          })}
                        </div>
                        <p className="text-[9.5px] text-ink-300 leading-relaxed font-sans">
                          Nix closures trace full direct/transitive dependency trees, meaning all runtime libraries are cataloged with zero-trust cryptographic precision.
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {detailTab === 'packages' && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-2 shrink-0">
                      <div className="text-[11px] uppercase tracking-wider text-ink-300">Packages in this layer</div>
                      <input
                        type="text"
                        value={packageSearch}
                        onChange={(e) => setPackageSearch(e.target.value)}
                        placeholder="Filter packages..."
                        className="rounded bg-ink-950 px-2 py-1 text-xs border border-ink-700/60 text-ink-100 placeholder:text-ink-500 focus:outline-none focus:border-accent w-40"
                      />
                    </div>
                    {packagesInLayer.length === 0 ? (
                      <p className="text-xs text-ink-300 py-8 text-center bg-ink-950/20 rounded border border-ink-800/40">
                        No Nix packages declared in this layer.<br/>
                        <span className="text-[10px] text-ink-400 mt-1 block">(Likely base system files or scaffolding)</span>
                      </p>
                    ) : (
                      <div className="space-y-2 max-h-[350px] overflow-y-auto pr-1">
                        {packagesInLayer
                          .filter(p => p.name.toLowerCase().includes(packageSearch.toLowerCase()))
                          .map((p) => (
                            <div key={p.spdxId || p.name} className="p-2.5 rounded bg-ink-950/30 border border-ink-800/60 text-xs">
                              <div className="flex items-baseline justify-between font-mono">
                                <span className="font-semibold text-ink-50">{p.name}</span>
                                <span className="text-accent-soft font-bold">{p.version}</span>
                              </div>
                              {p.license && p.license !== 'NOASSERTION' && (
                                <div className="mt-1 text-[10px] text-ink-300">License: <span className="text-ink-200">{p.license}</span></div>
                              )}
                              {p.nixStorePath && (
                                <div className="mt-1 truncate font-mono text-[9px] text-ink-400 select-all" title={p.nixStorePath}>
                                  {p.nixStorePath}
                                </div>
                              )}
                            </div>
                          ))}
                      </div>
                    )}
                  </div>
                )}

                {detailTab === 'vulnerabilities' && (
                  <div className="space-y-3">
                    <div className="text-[11px] uppercase tracking-wider text-ink-300">CVEs introduced in this layer</div>
                    {vulnsInLayer.length === 0 ? (
                      <div className="rounded border border-emerald-500/20 bg-emerald-500/5 px-4 py-8 text-center text-xs text-emerald-400">
                        ✓ Clean layer — no CVEs introduced in this layer.
                      </div>
                    ) : (
                      <div className="space-y-2 max-h-[350px] overflow-y-auto pr-1">
                        {vulnsInLayer.map((v) => (
                          <div key={v.id} className="p-2.5 rounded bg-ink-950/30 border border-ink-800/60 text-xs space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-semibold text-ink-50">{v.id}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${
                                v.severity === 'critical' ? 'bg-danger/10 text-danger border-danger/20' :
                                v.severity === 'high' ? 'bg-warn/10 text-warn border-warn/20' :
                                'bg-accent/10 text-accent-soft border-accent/20'
                              }`}>
                                {v.severity}
                              </span>
                            </div>
                            <div className="text-ink-200">
                              Package: <span className="font-mono text-ink-50">{v.packageName} ({v.packageVersion})</span>
                            </div>
                            {v.fixedIn && (
                              <div className="text-[10px] text-emerald-400 font-medium font-mono">
                                Fixed in: {v.fixedIn}
                              </div>
                            )}
                            {v.description && (
                              <p className="text-[10px] text-ink-300 leading-relaxed line-clamp-2 mt-1" title={v.description}>{v.description}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-sm text-ink-300 m-auto">Select a layer from the list to begin exploring.</div>
          )}
        </div>
      </div>
    </section>
  );
}
