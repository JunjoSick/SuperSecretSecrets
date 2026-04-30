import { useEffect, useRef, useState } from 'react';
import { renderDataUrl, renderSvg, type EccLevel } from '../qr/generate';

type Props = {
  title: string;
  subtitle?: string;
  accent?: 'header' | 'share';
  payload: string;
  ecc?: EccLevel;
  downloadBase: string;
};

export function QrCard({ title, subtitle, accent = 'share', payload, ecc = 'M', downloadBase }: Props) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const svgRef = useRef<string | null>(null);

  useEffect(() => {
    let canceled = false;
    (async () => {
      try {
        const [png, svg] = await Promise.all([
          renderDataUrl(payload, { ecc, size: 480 }),
          renderSvg(payload, { ecc, size: 480 }),
        ]);
        if (canceled) return;
        setDataUrl(png);
        svgRef.current = svg;
      } catch (e) {
        if (!canceled) setErr(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      canceled = true;
    };
  }, [payload, ecc]);

  const downloadPng = () => {
    if (!dataUrl) return;
    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = `${downloadBase}.png`;
    a.click();
  };

  const downloadSvg = () => {
    if (!svgRef.current) return;
    const blob = new Blob([svgRef.current], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${downloadBase}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="card overflow-hidden">
      <div
        className={[
          'flex items-center justify-between border-b border-white/10 px-4 py-2.5 text-[10px] font-medium uppercase tracking-[0.14em]',
          accent === 'header' ? 'bg-accent-500/10 text-accent-200' : 'bg-white/[0.035] text-ink-300',
        ].join(' ')}
      >
        <span className="min-w-0 break-words">{title}</span>
        {subtitle && (
          <span className="min-w-0 break-words text-right text-[10px] normal-case tracking-normal text-ink-300">
            {subtitle}
          </span>
        )}
      </div>
      <div className="flex flex-col items-center gap-3 p-4">
        <div className="aspect-square w-full max-w-[280px] border border-white/10 bg-white p-3">
          {dataUrl ? (
            <img src={dataUrl} alt={title} className="h-full w-full" />
          ) : err ? (
            <div className="flex h-full items-center justify-center text-sm text-red-500">
              {err}
            </div>
          ) : (
            <div className="flex h-full items-center justify-center text-xs text-ink-400">
              rendering…
            </div>
          )}
        </div>
        <div className="flex w-full items-center justify-center gap-2 no-print">
          <button onClick={downloadPng} className="btn-outline text-xs" disabled={!dataUrl}>
            PNG
          </button>
          <button onClick={downloadSvg} className="btn-outline text-xs" disabled={!svgRef.current}>
            SVG
          </button>
        </div>
      </div>
    </div>
  );
}
