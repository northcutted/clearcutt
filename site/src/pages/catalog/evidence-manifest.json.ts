import type { APIRoute } from 'astro';
import { loadCatalogArtifact } from '../../lib/catalog';

export const GET: APIRoute = () => {
  return new Response(loadCatalogArtifact('evidence-manifest.json'), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
};
