import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';

const SiteConfigInput = z
  .object({
    site: z
      .object({
        title: z.string().optional(),
        description: z.string().optional(),
        logo: z.string().optional(),
        theme: z
          .object({
            mode: z.enum(['system', 'light', 'dark']).optional(),
            accent: z.string().optional(),
          })
          .optional(),
        navigation: z
          .object({
            showMarketingHome: z.boolean().optional(),
            showGettingStarted: z.boolean().optional(),
            showCliDocs: z.boolean().optional(),
            showAuditGuide: z.boolean().optional(),
          })
          .optional(),
        features: z
          .object({
            sbomTable: z.boolean().optional(),
            vulnerabilityTable: z.boolean().optional(),
            layerExplorer: z.boolean().optional(),
            provenance: z.boolean().optional(),
            ociLabels: z.boolean().optional(),
            versionHistory: z.boolean().optional(),
            kyvernoPolicies: z.boolean().optional(),
          })
          .optional(),
        terminology: z
          .object({
            distroless: z.string().optional(),
            slim: z.string().optional(),
            dev: z.string().optional(),
          })
          .optional(),
        links: z
          .object({
            sourceRepo: z.string().optional(),
            registry: z.string().optional(),
            support: z.string().optional(),
            docs: z.string().optional(),
          })
          .optional(),
      })
      .optional(),
  })
  .optional();

export const defaultSiteConfig = {
  site: {
    title: 'ClearCutt Catalog',
    description:
      'Static evidence portal for base-image signatures, SBOMs, provenance, vulnerability findings, and runtime contracts.',
    logo: '',
    theme: {
      mode: 'system',
      accent: '#7c3aed',
    },
    navigation: {
      showMarketingHome: true,
      showGettingStarted: true,
      showCliDocs: true,
      showAuditGuide: true,
    },
    features: {
      sbomTable: true,
      vulnerabilityTable: true,
      layerExplorer: true,
      provenance: true,
      ociLabels: true,
      versionHistory: true,
      kyvernoPolicies: false,
    },
    terminology: {
      distroless: 'Distroless',
      slim: 'Slim',
      dev: 'Dev',
    },
    links: {
      sourceRepo: '',
      registry: '',
      support: '',
      docs: '',
    },
  },
};

export type SiteConfig = typeof defaultSiteConfig;

let cachedConfig: SiteConfig | null = null;

export function loadSiteConfig(): SiteConfig {
  if (cachedConfig) return cachedConfig;
  const file = path.resolve(process.cwd(), 'clearcutt.site.yaml');
  if (!fs.existsSync(file)) {
    cachedConfig = defaultSiteConfig;
    return cachedConfig;
  }
  const raw = parse(fs.readFileSync(file, 'utf8'));
  const parsed = SiteConfigInput.parse(raw) ?? {};
  cachedConfig = mergeSiteConfig(parsed);
  return cachedConfig;
}

export function accentStyle(config: SiteConfig): string | undefined {
  const rgb = hexToRGBTriple(config.site.theme.accent);
  if (!rgb) return undefined;
  return `--accent: ${rgb};`;
}

export function tierLabel(config: SiteConfig, id: string): string {
  const key = id as keyof SiteConfig['site']['terminology'];
  return config.site.terminology[key] ?? titleCase(id);
}

function mergeSiteConfig(input: z.infer<typeof SiteConfigInput>): SiteConfig {
  const site = input?.site ?? {};
  return {
    site: {
      ...defaultSiteConfig.site,
      ...site,
      theme: {
        ...defaultSiteConfig.site.theme,
        ...site.theme,
      },
      navigation: {
        ...defaultSiteConfig.site.navigation,
        ...site.navigation,
      },
      features: {
        ...defaultSiteConfig.site.features,
        ...site.features,
      },
      terminology: {
        ...defaultSiteConfig.site.terminology,
        ...site.terminology,
      },
      links: {
        ...defaultSiteConfig.site.links,
        ...site.links,
      },
    },
  };
}

function hexToRGBTriple(value: string): string | null {
  const match = /^#?([0-9a-f]{6})$/i.exec(value.trim());
  if (!match) return null;
  const hex = match[1];
  return [
    Number.parseInt(hex.slice(0, 2), 16),
    Number.parseInt(hex.slice(2, 4), 16),
    Number.parseInt(hex.slice(4, 6), 16),
  ].join(' ');
}

function titleCase(value: string): string {
  return value
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
