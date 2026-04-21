import JSZip from 'jszip';
import { renderDataUrl, renderSvg, type EccLevel } from '../qr/generate';

export type BundleFile = { name: string; payload: string };

function dataUrlToBytes(dataUrl: string): Uint8Array {
  const comma = dataUrl.indexOf(',');
  const b64 = dataUrl.slice(comma + 1);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function buildZip(files: BundleFile[], ecc: EccLevel = 'M'): Promise<Blob> {
  const zip = new JSZip();
  for (const f of files) {
    const [svg, pngDataUrl] = await Promise.all([
      renderSvg(f.payload, { ecc, size: 480 }),
      renderDataUrl(f.payload, { ecc, size: 480 }),
    ]);
    zip.file(`${f.name}.svg`, svg);
    zip.file(`${f.name}.png`, dataUrlToBytes(pngDataUrl));
    zip.file(`${f.name}.txt`, f.payload);
  }
  return zip.generateAsync({ type: 'blob' });
}

export function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
