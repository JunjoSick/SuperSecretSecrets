import { describe, expect, it } from 'vitest';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { encodeSecret, inspectQr, decodeSecret } from '../src/crypto';
import { renderDataUrl } from '../src/qr/generate';

/**
 * Exercise the *actual* PNG-upload path that breaks in the browser:
 *   qrcode.toDataURL -> PNG bytes -> pixels -> jsQR -> inspectQr
 *
 * The earlier qr-roundtrip test bypassed PNG encode/decode by rendering
 * straight to a pixel matrix; that hid a class of bug where the PNG
 * pipeline (including color values, scaling, canvas draw) could break
 * round-trip of the payload string.
 */
async function dataUrlToPng(dataUrl: string) {
  const b64 = dataUrl.slice(dataUrl.indexOf(',') + 1);
  const buf = Buffer.from(b64, 'base64');
  const png = PNG.sync.read(buf);
  const rgba = new Uint8ClampedArray(png.data.buffer, png.data.byteOffset, png.data.byteLength);
  return { rgba, w: png.width, h: png.height };
}

async function renderAndScan(text: string, size = 480) {
  const dataUrl = await renderDataUrl(text, { ecc: 'M', size });
  const { rgba, w, h } = await dataUrlToPng(dataUrl);
  const code = jsQR(rgba, w, h, { inversionAttempts: 'attemptBoth' });
  if (!code) throw new Error('jsQR returned null');
  return code.data;
}

function denseBase45LikePayload(length: number): string {
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  return Array.from({ length }, (_, i) => alphabet[(i * 17 + i * i) % alphabet.length]!).join('');
}

describe('PNG-upload pipeline (real PNG bytes)', () => {
  it('each header + share QR roundtrips through a real PNG at ZIP size (480)', async () => {
    const bundle = encodeSecret('hello PNG world', { threshold: 3, shares: 5 });
    for (const p of bundle.headerQrs) {
      const decoded = await renderAndScan(p);
      expect(decoded).toBe(p);
      // inspectQr should not throw — this is exactly the Recover page check.
      expect(() => inspectQr(decoded)).not.toThrow();
    }
    for (const p of bundle.shareQrs) {
      const decoded = await renderAndScan(p);
      expect(decoded).toBe(p);
      expect(() => inspectQr(decoded)).not.toThrow();
    }
  });

  it('full encode → PNG → scan → decodeSecret works end-to-end', async () => {
    const plaintext = 'hello post-quantum world — ' + 'x'.repeat(400);
    const bundle = encodeSecret(plaintext, { threshold: 2, shares: 3 });
    const scannedHeaders = await Promise.all(bundle.headerQrs.map((p) => renderAndScan(p)));
    const scannedShares = await Promise.all(bundle.shareQrs.slice(0, 2).map((p) => renderAndScan(p)));
    const result = decodeSecret([...scannedHeaders, ...scannedShares]);
    expect(result.status).toBe('ok');
    if (result.status === 'ok') expect(result.plaintext).toBe(plaintext);
  });

  it('larger payload that forces a multi-chunk header still roundtrips', async () => {
    const plaintext = 'a'.repeat(3000);
    const bundle = encodeSecret(plaintext);
    expect(bundle.headerQrs.length).toBeGreaterThan(1);
    const headers = await Promise.all(bundle.headerQrs.map((p) => renderAndScan(p)));
    const shares = await Promise.all(
      bundle.shareQrs.slice(0, bundle.options.threshold).map((p) => renderAndScan(p)),
    );
    const result = decodeSecret([...headers, ...shares]);
    expect(result.status).toBe('ok');
  });

  it('dense version-32 payload scans from generated PNG at ZIP minimum size', async () => {
    const payload = denseBase45LikePayload(2189);
    const qr = QRCode.create(payload, { errorCorrectionLevel: 'M' });
    expect(qr.version).toBe(32);
    await expect(renderAndScan(payload, 480)).resolves.toBe(payload);
  });
});
