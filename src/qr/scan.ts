import jsQR from 'jsqr';

export type ScanResult = { text: string };

/**
 * Decode QR codes from a File/Blob containing an image (PNG/JPG/WebP).
 * Runs purely in the browser via <img> + offscreen canvas.
 */
export async function scanImageFile(file: File | Blob): Promise<ScanResult | null> {
  // Prefer createImageBitmap where available — it fully decodes the PNG/JPEG
  // into pixels before returning, which avoids a class of "<img> loaded but
  // drawImage silently drew nothing" bugs we hit with blob: URLs.
  if (typeof createImageBitmap === 'function') {
    try {
      const bitmap = await createImageBitmap(file);
      try {
        return scanImageBitmap(bitmap);
      } finally {
        bitmap.close?.();
      }
    } catch {
      // fall through to <img> path (e.g. SVG inputs, which some browsers refuse via createImageBitmap)
    }
  }
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    return scanImageBitmap(img);
  } finally {
    URL.revokeObjectURL(url);
  }
}

export function scanImageBitmap(img: HTMLImageElement | ImageBitmap): ScanResult | null {
  const width = 'naturalWidth' in img ? img.naturalWidth : img.width;
  const height = 'naturalHeight' in img ? img.naturalHeight : img.height;
  if (!width || !height) return null;
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) return null;
  ctx.drawImage(img, 0, 0);
  const data = ctx.getImageData(0, 0, width, height);
  // attemptBoth lets jsQR try both normal and inverted colors, which helps
  // with non-pure-black "dark" QR colors that some scanners misclassify.
  const code = jsQR(data.data, data.width, data.height, { inversionAttempts: 'attemptBoth' });
  return code ? { text: code.data } : null;
}

export function scanRawPixels(
  data: Uint8ClampedArray,
  width: number,
  height: number,
): ScanResult | null {
  const code = jsQR(data, width, height, { inversionAttempts: 'attemptBoth' });
  return code ? { text: code.data } : null;
}

function loadImage(src: string): Promise<HTMLImageElement> {
  // Intentionally no `crossOrigin` setting: blob: URLs are same-origin and
  // asking for CORS on them can cause tainted-canvas false positives in some
  // browsers. We also await decode() when available to make sure the pixels
  // are actually ready before we draw into a canvas.
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = async () => {
      try {
        if (typeof img.decode === 'function') await img.decode();
      } catch {
        // decode() throwing is rare; drawImage still often works, try anyway
      }
      resolve(img);
    };
    img.onerror = () => reject(new Error('failed to load image'));
    img.src = src;
  });
}

/**
 * Continuously scan a <video> element for QR codes. Returns a cleanup function.
 * Invokes `onResult` with each *distinct* decoded text.
 */
export function startCameraScan(
  video: HTMLVideoElement,
  onResult: (result: ScanResult) => void,
  onError?: (err: unknown) => void,
): () => void {
  let stopped = false;
  let stream: MediaStream | null = null;
  let raf = 0;
  const seen = new Set<string>();
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  (async () => {
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
        audio: false,
      });
      video.srcObject = stream;
      video.setAttribute('playsinline', 'true');
      await video.play();
      const tick = () => {
        if (stopped) return;
        if (video.readyState >= video.HAVE_CURRENT_DATA && ctx) {
          const w = video.videoWidth;
          const h = video.videoHeight;
          if (w && h) {
            canvas.width = w;
            canvas.height = h;
            ctx.drawImage(video, 0, 0, w, h);
            const img = ctx.getImageData(0, 0, w, h);
            const code = jsQR(img.data, w, h, { inversionAttempts: 'dontInvert' });
            if (code && code.data && !seen.has(code.data)) {
              seen.add(code.data);
              onResult({ text: code.data });
            }
          }
        }
        raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    } catch (err) {
      onError?.(err);
    }
  })();

  return () => {
    stopped = true;
    cancelAnimationFrame(raf);
    if (stream) for (const t of stream.getTracks()) t.stop();
    if (video.srcObject) video.srcObject = null;
  };
}
