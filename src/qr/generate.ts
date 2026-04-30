import QRCode from 'qrcode';

export type EccLevel = 'L' | 'M' | 'Q' | 'H';

export type QrRenderOptions = {
  ecc?: EccLevel;
  /** Minimum pixel size (square). Dense payloads may render larger to keep modules crisp. Default 320. */
  size?: number;
  /** Quiet-zone margin in modules. Default 4. */
  margin?: number;
  darkColor?: string;
  lightColor?: string;
};

const DEFAULTS: Required<Omit<QrRenderOptions, 'darkColor' | 'lightColor'>> & {
  darkColor: string;
  lightColor: string;
} = {
  ecc: 'M',
  size: 320,
  margin: 4,
  // Pure black + pure white maximises luminance contrast, which is what
  // jsQR (and phone camera scanners) threshold against. Tinted "dark" colors
  // can get color-managed by browser canvases into values jsQR misclassifies.
  darkColor: '#000000',
  lightColor: '#ffffff',
};

const MIN_MODULE_PIXELS = 4;

export async function renderDataUrl(text: string, opts: QrRenderOptions = {}): Promise<string> {
  const o = { ...DEFAULTS, ...opts };
  const width = renderWidth(text, o.ecc, o.margin, o.size);
  return QRCode.toDataURL(text, {
    errorCorrectionLevel: o.ecc,
    margin: o.margin,
    width,
    color: { dark: o.darkColor, light: o.lightColor },
  });
}

export async function renderSvg(text: string, opts: QrRenderOptions = {}): Promise<string> {
  const o = { ...DEFAULTS, ...opts };
  const width = renderWidth(text, o.ecc, o.margin, o.size);
  return QRCode.toString(text, {
    type: 'svg',
    errorCorrectionLevel: o.ecc,
    margin: o.margin,
    width,
    color: { dark: o.darkColor, light: o.lightColor },
  });
}

export async function renderOnCanvas(
  canvas: HTMLCanvasElement,
  text: string,
  opts: QrRenderOptions = {},
): Promise<void> {
  const o = { ...DEFAULTS, ...opts };
  const width = renderWidth(text, o.ecc, o.margin, o.size);
  await QRCode.toCanvas(canvas, text, {
    errorCorrectionLevel: o.ecc,
    margin: o.margin,
    width,
    color: { dark: o.darkColor, light: o.lightColor },
  });
}

function renderWidth(text: string, ecc: EccLevel, margin: number, minSize: number): number {
  const qr = QRCode.create(text, { errorCorrectionLevel: ecc });
  const totalModules = qr.modules.size + margin * 2;
  const scale = Math.max(MIN_MODULE_PIXELS, Math.ceil(minSize / totalModules));
  return totalModules * scale;
}
