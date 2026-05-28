import { useMemo, useState } from 'react';
import type { ArchPayload } from '../lib/catalog-schema';

type Props = { architectures: ArchPayload[] };

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

export default function LayerExplorer({ architectures }: Props) {
  const archs = architectures.filter((a) => a.layers && a.layers.length > 0);
  const [arch, setArch] = useState(archs[0]?.arch ?? architectures[0]?.arch ?? 'amd64');
  const current = architectures.find((a) => a.arch === arch) ?? architectures[0];
  const layers = current?.layers ?? [];
  const totalSize = useMemo(() => layers.reduce((s, l) => s + (l.size || 0), 0), [layers]);
  const maxSize = useMemo(() => layers.reduce((m, l) => Math.max(m, l.size || 0), 0), [layers]);
  const [selected, setSelected] = useState<number>(0);
  const [detailTab, setDetailTab] = useState<'details' | 'packages' | 'vulnerabilities'>('details');
  const [packageSearch, setPackageSearch] = useState('');

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

      <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        {/* Layer list */}
        <div className="surface-soft overflow-hidden">
          <div className="flex items-center justify-between border-b border-ink-700/60 bg-ink-900/80 px-4 py-2.5 text-xs uppercase tracking-wider text-ink-200">
            <span>
              {layers.length} layer{layers.length === 1 ? '' : 's'}
            </span>
            <span className="text-ink-300">total {humanBytes(totalSize)}</span>
          </div>
          <ol className="max-h-[640px] overflow-auto">
            {layers.map((l, i) => {
              const pct = totalSize > 0 ? Math.max(1, Math.round(((l.size || 0) / totalSize) * 100)) : 0;
              const isSel = i === selected;
              return (
                <li key={l.digest + ':' + i}>
                  <button
                    type="button"
                    onClick={() => setSelected(i)}
                    className={`flex w-full items-center gap-3 border-b border-ink-800/70 px-4 py-2.5 text-left transition ${
                      isSel ? 'bg-accent/10' : 'hover:bg-ink-800/50'
                    }`}
                  >
                    <span
                      className={`shrink-0 font-mono text-xs ${isSel ? 'text-accent-soft' : 'text-ink-300'}`}
                    >
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-[11px] text-ink-100" title={l.digest}>
                        {l.digest.replace(/^sha256:/, '').slice(0, 16)}…
                      </div>
                      <div className="mt-1 h-1 w-full overflow-hidden rounded bg-ink-800">
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

        {/* Detail panel */}
        <div className="surface-soft px-5 py-4 flex flex-col min-h-[450px]">
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

                    <div>
                      <div className="text-[11px] uppercase tracking-wider text-ink-300">Pull this layer</div>
                      <div className="mt-1 break-all rounded-md border border-ink-700/60 bg-ink-950/80 p-2 font-mono text-[11px] text-ink-100 select-all">
                        crane blob {currentImageDigestHint(current)}@{sel.digest}
                      </div>
                    </div>

                    <p className="text-[11px] text-ink-300 leading-relaxed">
                      Nix-built layers are content-addressed by store path closure, so identical layers
                      across images (same glibc, openssl, etc.) share the same digest and are pulled
                      exactly once from the registry mirror.
                    </p>
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

function currentImageDigestHint(arch: ArchPayload | undefined): string {
  if (!arch?.imageDigest) return '<image-ref>';
  // Use the digest as-is; the user already knows the image name from the page header.
  return `<image-ref>`;
}
