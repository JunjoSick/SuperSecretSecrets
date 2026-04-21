import { describe, expect, it } from 'vitest';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
import { encodeSecret, decodeSecret } from '../src/crypto';

/**
 * Render a QR payload to raw RGBA pixels (no DOM needed), then decode it
 * with jsQR. This simulates the browser encode → image → decode path.
 */
function renderToRGBA(text: string, ecc: 'L' | 'M' | 'Q' | 'H' = 'M') {
  const q = QRCode.create(text, { errorCorrectionLevel: ecc });
  const size = q.modules.size;
  const scale = 8;
  const margin = 4;
  const w = (size + margin * 2) * scale;
  const h = w;
  const data = new Uint8ClampedArray(w * h * 4);
  for (let i = 0; i < data.length; i += 4) {
    data[i] = data[i + 1] = data[i + 2] = 255;
    data[i + 3] = 255;
  }
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (q.modules.get(x, y)) {
        for (let dy = 0; dy < scale; dy++) {
          for (let dx = 0; dx < scale; dx++) {
            const px = ((y + margin) * scale + dy) * w + ((x + margin) * scale + dx);
            const off = px * 4;
            data[off] = data[off + 1] = data[off + 2] = 0;
          }
        }
      }
    }
  }
  return { data, w, h };
}

function decodePayloadToText(text: string): string {
  const { data, w, h } = renderToRGBA(text);
  const code = jsQR(data, w, h);
  if (!code) throw new Error('failed to decode QR');
  return code.data;
}

describe('QR roundtrip', () => {
  it('decodes individual header + share QRs back to their payloads', () => {
    const bundle = encodeSecret('roundtrip secret');
    for (const p of bundle.headerQrs) expect(decodePayloadToText(p)).toBe(p);
    for (const p of bundle.shareQrs) expect(decodePayloadToText(p)).toBe(p);
  });

  it('full pipeline: encode → QR images → decode → decrypt', () => {
    const plaintext = 'hello from the QR layer';
    const bundle = encodeSecret(plaintext, { threshold: 2, shares: 3 });
    const scannedHeaders = bundle.headerQrs.map(decodePayloadToText);
    const scannedShares = bundle.shareQrs.slice(0, 2).map(decodePayloadToText);
    const result = decodeSecret([...scannedHeaders, ...scannedShares]);
    expect(result.status).toBe('ok');
    if (result.status === 'ok') expect(result.plaintext).toBe(plaintext);
  });

  it('share QRs fit in a small-ish version at ECC-M', () => {
    const bundle = encodeSecret('tiny');
    for (const p of bundle.shareQrs) {
      const q = QRCode.create(p, { errorCorrectionLevel: 'M' });
      // Version goes 1..40; share payloads should comfortably fit well below v20.
      expect(q.version).toBeLessThanOrEqual(15);
    }
  });
});
