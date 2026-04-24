import JSZip from 'jszip';
import { renderDataUrl, renderSvg, type EccLevel } from '../qr/generate';

export type BundleFile = { name: string; payload: string };
export type ZipAttachment = { name: string; data: Uint8Array | string | Blob };
export type ZipContentOptions = {
  svg: boolean;
  png: boolean;
  txt: boolean;
};

export const DEFAULT_ZIP_CONTENT: ZipContentOptions = {
  svg: true,
  png: true,
  txt: true,
};

function dataUrlToBytes(dataUrl: string): Uint8Array {
  const comma = dataUrl.indexOf(',');
  const b64 = dataUrl.slice(comma + 1);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function buildZip(
  files: BundleFile[],
  ecc: EccLevel = 'M',
  content: ZipContentOptions = DEFAULT_ZIP_CONTENT,
  attachments: ZipAttachment[] = [],
): Promise<Blob> {
  const zip = new JSZip();
  for (const f of files) {
    if (content.svg) {
      zip.file(`${f.name}.svg`, await renderSvg(f.payload, { ecc, size: 480 }));
    }
    if (content.png) {
      const pngDataUrl = await renderDataUrl(f.payload, { ecc, size: 480 });
      zip.file(`${f.name}.png`, dataUrlToBytes(pngDataUrl));
    }
    if (content.txt) {
      zip.file(`${f.name}.txt`, f.payload);
    }
  }
  for (const attachment of attachments) {
    zip.file(attachment.name, attachment.data);
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
