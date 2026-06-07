import type { APIRoute } from 'astro';
import { listImageIds, loadImage } from '../../../lib/catalog';

export function getStaticPaths() {
  return listImageIds().map((id) => ({ params: { id } }));
}

export const GET: APIRoute = ({ params }) => {
  const image = loadImage(params.id!);
  return new Response(JSON.stringify(image), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
};
