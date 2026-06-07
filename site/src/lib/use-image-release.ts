import { useEffect, useMemo, useState } from 'react';
import type { ArchPayload, ImageRecord, ReleaseEntry } from './catalog-schema';

type UseImageReleaseArgs = {
  dataUrl?: string;
  releaseTag?: string;
  initialArchitectures?: ArchPayload[];
};

type ImageReleaseState = {
  architectures: ArchPayload[];
  release: ReleaseEntry | null;
  loading: boolean;
  error: string | null;
};

const imageRecordCache = new Map<string, Promise<ImageRecord>>();

function loadImageRecord(dataUrl: string): Promise<ImageRecord> {
  const cached = imageRecordCache.get(dataUrl);
  if (cached) return cached;

  const promise = fetch(dataUrl).then(async (response) => {
    if (!response.ok) {
      throw new Error(`Unable to load catalog image data (${response.status})`);
    }
    return (await response.json()) as ImageRecord;
  });
  imageRecordCache.set(dataUrl, promise);
  return promise;
}

export function useImageRelease({
  dataUrl,
  releaseTag,
  initialArchitectures,
}: UseImageReleaseArgs): ImageReleaseState {
  const hasInitialArchitectures = (initialArchitectures?.length ?? 0) > 0;
  const [record, setRecord] = useState<ImageRecord | null>(null);
  const [loading, setLoading] = useState(Boolean(dataUrl && !hasInitialArchitectures));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!dataUrl || hasInitialArchitectures) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);
    loadImageRecord(dataUrl)
      .then((nextRecord) => {
        if (!cancelled) setRecord(nextRecord);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Unable to load catalog image data');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [dataUrl, hasInitialArchitectures]);

  const release = useMemo(() => {
    if (!record) return null;
    return record.releases.find((candidate) => candidate.tag === releaseTag) ?? record.releases[0] ?? null;
  }, [record, releaseTag]);

  return {
    architectures: initialArchitectures ?? release?.architectures ?? [],
    release,
    loading,
    error,
  };
}
