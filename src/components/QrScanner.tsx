import { useCallback, useEffect, useRef, useState } from 'react';
import { scanImageFile, startCameraScan } from '../qr/scan';

type Props = {
  onPayload: (payload: string) => void;
};

export function QrScanner({ onPayload }: Props) {
  const [mode, setMode] = useState<'upload' | 'camera'>('upload');
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [cameraErr, setCameraErr] = useState<string | null>(null);
  const [cameraOn, setCameraOn] = useState(false);
  const dragRef = useRef<HTMLDivElement | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploadMsg, setUploadMsg] = useState<string | null>(null);
  const [cameraHud, setCameraHud] = useState(true);

  useEffect(() => {
    if (mode !== 'camera') return;
    const video = videoRef.current;
    if (!video) return;
    setCameraErr(null);
    setCameraOn(false);
    const stop = startCameraScan(
      video,
      (r) => {
        onPayload(r.text);
        setCameraOn(true);
      },
      (err) => {
        setCameraErr(err instanceof Error ? err.message : String(err));
      },
    );
    // A short delay to flip the indicator after the stream starts
    const t = setTimeout(() => setCameraOn(true), 400);
    return () => {
      clearTimeout(t);
      stop();
    };
  }, [mode, onPayload]);

  const handleFiles = useCallback(
    async (files: FileList | File[]) => {
      const arr = Array.from(files);
      let ok = 0;
      let fail = 0;
      for (const f of arr) {
        if (isTextPayloadFile(f)) {
          const count = await addTextPayloads(f, onPayload);
          if (count > 0) {
            ok += count;
          } else {
            fail++;
          }
          continue;
        }
        if (!f.type.startsWith('image/')) {
          fail++;
          continue;
        }
        try {
          const r = await scanImageFile(f);
          if (r) {
            onPayload(r.text);
            ok++;
          } else {
            fail++;
          }
        } catch {
          fail++;
        }
      }
      setUploadMsg(
        `Scanned ${ok} payload${ok === 1 ? '' : 's'}${fail > 0 ? ` · ${fail} file${fail === 1 ? '' : 's'} could not be read` : ''}.`,
      );
    },
    [onPayload],
  );

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
        <div className="flex items-center gap-1 text-sm">
          <TabBtn active={mode === 'upload'} onClick={() => setMode('upload')}>
            Upload images
          </TabBtn>
          <TabBtn active={mode === 'camera'} onClick={() => setMode('camera')}>
            Use camera
          </TabBtn>
        </div>
      </div>

      {mode === 'upload' && (
        <div className="p-5">
          <div
            ref={dragRef}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              handleFiles(e.dataTransfer.files);
            }}
            className={[
              'flex flex-col items-center justify-center border border-dashed px-6 py-14 text-center transition-colors',
              dragOver ? 'border-accent-300 bg-accent-500/10' : 'border-white/10 bg-white/[0.025]',
            ].join(' ')}
          >
            <div className="mono-upper mb-2">drop image / txt payload</div>
            <div className="text-sm text-ink-200">Drop QR images here, or</div>
            <label className="btn-outline mt-3 cursor-pointer">
              Choose files
              <input
                type="file"
                accept="image/*,.txt,text/plain"
                multiple
                className="hidden"
                onChange={(e) => {
                  if (e.target.files) void handleFiles(e.target.files);
                  e.currentTarget.value = '';
                }}
              />
            </label>
            {uploadMsg && <div className="mt-3 text-xs text-ink-400">{uploadMsg}</div>}
          </div>
        </div>
      )}

      {mode === 'camera' && (
        <div className="p-5">
          <div className={['viewfinder aspect-video', cameraHud ? '' : 'viewfinder-plain'].join(' ')}>
            <video
              ref={videoRef}
              className="relative z-10 h-full w-full object-cover"
              muted
              playsInline
              autoPlay
            />
            {cameraHud && (
              <>
                <div className="pointer-events-none absolute inset-6 z-20 border border-dashed border-accent-300/70">
                  <div className="absolute -left-px -top-px h-8 w-8 border-l-2 border-t-2 border-accent-300" />
                  <div className="absolute -right-px -top-px h-8 w-8 border-r-2 border-t-2 border-accent-300" />
                  <div className="absolute -bottom-px -left-px h-8 w-8 border-b-2 border-l-2 border-accent-300" />
                  <div className="absolute -bottom-px -right-px h-8 w-8 border-b-2 border-r-2 border-accent-300" />
                  <div className="absolute left-1/2 top-0 h-full border-l border-accent-300/30" />
                  <div className="absolute left-0 top-1/2 w-full border-t border-accent-300/30" />
                </div>
                <div className="pointer-events-none absolute left-4 right-4 top-4 z-20 flex justify-between text-[10px] uppercase tracking-[0.14em] text-accent-200">
                  <span>▶ CAM · live</span>
                  <span className="[animation:pulse_1.2s_infinite]">● REC</span>
                </div>
              </>
            )}
            {!cameraOn && !cameraErr && (
              <div className="absolute inset-0 z-30 flex items-center justify-center text-sm text-ink-200">
                Requesting camera…
              </div>
            )}
            {cameraErr && (
              <div className="absolute inset-0 z-30 flex items-center justify-center p-5 text-center text-sm text-red-300">
                Camera unavailable: {cameraErr}
              </div>
            )}
          </div>
          <p className="mt-2 text-xs text-ink-400">
            Point at each QR code; already-scanned codes are ignored automatically.
          </p>
          <button className="btn-ghost mt-3 text-xs" type="button" onClick={() => setCameraHud((v) => !v)}>
            {cameraHud ? 'Hide scanner overlay' : 'Show scanner overlay'}
          </button>
        </div>
      )}
    </div>
  );
}

function isTextPayloadFile(file: File): boolean {
  return file.type === 'text/plain' || file.name.toLowerCase().endsWith('.txt');
}

async function addTextPayloads(
  file: File,
  onPayload: (payload: string) => void,
): Promise<number> {
  const text = await file.text();
  const payloads = text
    .replace(/^\uFEFF/, '')
    .split(/\r?\n/)
    .filter((line) => line.length > 0);
  for (const payload of payloads) onPayload(payload);
  return payloads.length;
}

function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'border px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.14em] transition-colors',
        active
          ? 'border-accent-300/50 bg-accent-500/10 text-accent-200'
          : 'border-transparent text-ink-400 hover:border-white/10 hover:bg-white/[0.04] hover:text-ink-100',
      ].join(' ')}
    >
      {children}
    </button>
  );
}
