import { useState, useEffect, useRef } from 'react';

type CommandOption = {
  name: string;
  command: string;
  output: string[];
};

const commands: CommandOption[] = [
  {
    name: 'clearcutt inspect',
    command: 'clearcutt inspect java25-distroless',
    output: [
      'Image Metadata Report for java25-distroless',
      '-----------------------------------------------------------------',
      'ID                     : java25-distroless',
      'Registry               : ghcr.io/northcutted/clearcutt',
      'FullName               : ghcr.io/northcutted/clearcutt/clearcutt-java25',
      'Runtime Line           : java25',
      'Tier                   : distroless (hardened, shell-free)',
      'Latest Release Version : v0.6.2',
      'Digest                 : sha256:8894dfc15a7721ff07d1ea21b2d7f5ca9158ba6ea6afe058ab6d1bd854f0466e',
      'Architectures          : amd64, arm64',
      'Size (Total)           : 48.7 MB',
      'Non-Root Execution     : Yes (UID 10001)',
      'CA Bundle Present      : Yes (/etc/ssl/certs/ca-certificates.crt)',
      'Timezone Database      : Yes (/usr/share/zoneinfo)',
      '-----------------------------------------------------------------',
      'Vulnerability Summary:',
      '  Critical : 0',
      '  High     : 2',
      '  Medium   : 12',
      '  Low      : 8',
      '  Active Exception Mappings : 1 (CVE-2026-9999 resolved)',
      '-----------------------------------------------------------------',
      'Status: ACTIVE (LTS Preview)'
    ]
  },
  {
    name: 'clearcutt verify',
    command: 'clearcutt verify image java25-distroless --max-critical 0 --max-high 3 --exceptions exceptions.yaml',
    output: [
      'Policy Gating Report for java25-distroless:v0.6.2',
      '-----------------------------------------------------------------',
      '[✔ PASS] digest.present                  : manifest digest present: sha256:8894dfc1...',
      '[✔ PASS] architectures.present           : architectures present: amd64, arm64',
      '[✔ PASS] signature.present               : Sigstore signature verified in release record',
      '[✔ PASS] sbom.present                    : SPDX SBOM evidence verified for all platforms',
      '[✔ PASS] provenance.present              : SLSA Level-3 build provenance attestation present',
      '[✔ PASS] tests.passed                    : conformance and smoke tests passed on all platforms',
      '[✔ PASS] vulnerabilities.scanned         : vulnerability scan results present for all platforms',
      '[✔ PASS] lifecycle.status                : lifecycle status verified: preview',
      '[✔ PASS] vulnerabilities.threshold.crit  : critical vulnerabilities within limits (0 found, max 0)',
      '[✔ PASS] vulnerabilities.threshold.high  : high vulnerabilities within limits (2 found, max 3)',
      '-----------------------------------------------------------------',
      'Verification Result: PASS'
    ]
  },
  {
    name: 'clearcutt app rebase',
    command: 'clearcutt app rebase --image ghcr.io/acme/my-app:1.0.0 --candidate-base java21-distroless --sign --attest',
    output: [
      '[rebase] pulling image metadata for ghcr.io/acme/my-app:1.0.0...',
      '[rebase] resolved base image reference: ghcr.io/northcutted/clearcutt/clearcutt-java21@sha256:a78b...',
      '[rebase] verifying dynamic ABI compatibility...',
      '  - Current Base: java21-distroless (v0.2.1)',
      '  - Candidate Base: java21-distroless (v0.2.2 - Patched)',
      '  - Result: ✔ COMPATIBLE (java21 preserved, major/minor matches)',
      '[rebase] extracting application layers...',
      '  - Found 1 application-specific layer (sha256:e32d6619...)',
      '[rebase] performing layer rebase swap...',
      '  - Dropped old base layers (v0.2.1)',
      '  - Grafted candidate base layers (v0.2.2)',
      '  - Preserved application layers byte-for-byte (sha256:e32d6619...)',
      '[rebase] generating signed rebase attestation...',
      '  - Subject: ghcr.io/acme/my-app:1.0.0-rebased',
      '  - Developer Signature: ✔ VERIFIED',
      '  - Attestation Decision: ALLOWED',
      '[rebase] pushing rebased image to registry...',
      '  - Pushed: ghcr.io/acme/my-app:1.0.0-rebased',
      '  - Pushed attestation referrer index',
      '[rebase] Success! Rebase complete in 1.4s.'
    ]
  }
];

export default function TerminalSimulator() {
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [displayedCommand, setDisplayedCommand] = useState('');
  const [displayedOutput, setDisplayedOutput] = useState<string[]>([]);
  const [isTyping, setIsTyping] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const typingTimer = useRef<NodeJS.Timeout | null>(null);
  const outputTimer = useRef<NodeJS.Timeout | null>(null);

  const startSimulation = (idx: number) => {
    // Clear any active timers
    if (typingTimer.current) clearTimeout(typingTimer.current);
    if (outputTimer.current) clearTimeout(outputTimer.current);

    setSelectedIdx(idx);
    setDisplayedCommand('');
    setDisplayedOutput([]);
    setIsTyping(true);
    setIsRunning(false);

    const fullCommand = commands[idx].command;
    let charIdx = 0;

    const typeCharacter = () => {
      if (charIdx < fullCommand.length) {
        setDisplayedCommand(prev => prev + fullCommand[charIdx]);
        charIdx++;
        typingTimer.current = setTimeout(typeCharacter, 20);
      } else {
        setIsTyping(false);
        setIsRunning(true);
        // Start rendering output lines one by one after a short delay
        let lineIdx = 0;
        const targetOutput = commands[idx].output;
        
        const renderLine = () => {
          if (lineIdx < targetOutput.length) {
            setDisplayedOutput(prev => [...prev, targetOutput[lineIdx]]);
            lineIdx++;
            outputTimer.current = setTimeout(renderLine, idx === 2 ? 80 : 30); // Rebase output runs a bit slower to feel like a real action
          } else {
            setIsRunning(false);
          }
        };

        outputTimer.current = setTimeout(renderLine, 300);
      }
    };

    typingTimer.current = setTimeout(typeCharacter, 100);
  };

  useEffect(() => {
    startSimulation(0);
    return () => {
      if (typingTimer.current) clearTimeout(typingTimer.current);
      if (outputTimer.current) clearTimeout(outputTimer.current);
    };
  }, []);

  return (
    <div className="surface-soft border border-ink-800/60 rounded-2xl overflow-hidden shadow-2xl flex flex-col font-sans">
      {/* Selector Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-ink-800/60 bg-ink-900/60 px-4 py-3">
        <div className="flex gap-2">
          {commands.map((cmd, idx) => (
            <button
              key={cmd.name}
              type="button"
              onClick={() => startSimulation(idx)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${
                selectedIdx === idx
                  ? 'bg-accent/15 text-accent-soft border border-accent/25'
                  : 'text-ink-300 hover:text-ink-100 border border-transparent'
              }`}
            >
              {cmd.name}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2.5 select-none shrink-0">
          <span className="rounded bg-ink-800/80 border border-ink-700 px-1.5 py-0.5 text-[8px] font-mono font-bold uppercase tracking-wider text-ink-400" title="Scripted sample output, not a live command run">
            Illustrative
          </span>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-red-500/80" />
            <span className="h-2 w-2 rounded-full bg-yellow-500/80" />
            <span className="h-2 w-2 rounded-full bg-green-500/80" />
          </div>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="bg-ink-950 p-5 font-mono text-xs text-ink-100 min-h-[320px] flex flex-col gap-3 max-h-[440px] overflow-y-auto leading-relaxed select-text">
        {/* Terminal Input Line */}
        <div className="flex items-center gap-2 text-ink-300 select-none">
          <span className="text-accent-soft font-bold">~</span>
          <span className="text-ink-400 font-semibold">$</span>
          <span className="text-ink-100 font-mono flex-1">
            {displayedCommand}
            {isTyping && <span className="animate-pulse bg-accent-soft w-1.5 h-3.5 inline-block align-middle ml-0.5" />}
          </span>
        </div>

        {/* Output lines */}
        <div className="space-y-1.5 font-mono text-[11px] text-ink-200">
          {displayedOutput.map((line, idx) => {
            const isPass = line.includes('[✔ PASS]') || line.includes('Success!') || line.includes('✔ COMPATIBLE') || line.includes('✔ VERIFIED') || line.includes('Result: PASS');
            const isWarning = line.includes('[rebase]') || line.includes('High     :');
            const textColor = isPass ? 'text-emerald-400' : isWarning ? 'text-accent-soft' : 'text-ink-200';
            
            return (
              <div key={idx} className={`${textColor} whitespace-pre-wrap`}>
                {line}
              </div>
            );
          })}
          {isRunning && !isTyping && (
            <div className="text-ink-400 animate-pulse text-[10px]">Processing request...</div>
          )}
        </div>
      </div>
    </div>
  );
}
