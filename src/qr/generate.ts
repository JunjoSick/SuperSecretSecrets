import QRCode from 'qrcode';

export type EccLevel = 'L' | 'M' | 'Q' | 'H';

export type QrRenderOptions = {
  ecc?: EccLevel;
  /** Pixel size (square). Default 320. */
  size?: number;
  /** Quiet-zone margin in modules. Default 2. */
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
  margin: 2,
  // Pure black + pure white maximises luminance contrast, which is what
  // jsQR (and phone camera scanners) threshold against. Tinted "dark" colors
  // can get color-managed by browser canvases into values jsQR misclassifies.
  darkColor: '#000000',
  lightColor: '#ffffff',
};

export async function renderDataUrl(text: string, opts: QrRenderOptions = {}): Promise<string> {
  const o = { ...DEFAULTS, ...opts };
  return QRCode.toDataURL(text, {
    errorCorrectionLevel: o.ecc,
    margin: o.margin,
    width: o.size,
    color: { dark: o.darkColor, light: o.lightColor },
  });
}

export async function renderSvg(text: string, opts: QrRenderOptions = {}): Promise<string> {
  const o = { ...DEFAULTS, ...opts };
  return QRCode.toString(text, {
    type: 'svg',
    errorCorrectionLevel: o.ecc,
    margin: o.margin,
    width: o.size,
    color: { dark: o.darkColor, light: o.lightColor },
  });
}

export async function renderOnCanvas(
  canvas: HTMLCanvasElement,
  text: string,
  opts: QrRenderOptions = {},
): Promise<void> {
  const o = { ...DEFAULTS, ...opts };
  await QRCode.toCanvas(canvas, text, {
    errorCorrectionLevel: o.ecc,
    margin: o.margin,
    width: o.size,
    color: { dark: o.darkColor, light: o.lightColor },
  });
}
