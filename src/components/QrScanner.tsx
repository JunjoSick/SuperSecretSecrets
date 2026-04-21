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
        `Scanned ${ok} image${ok === 1 ? '' : 's'}${fail > 0 ? ` · ${fail} could not be read` : ''}.`,
      );
    },
    [onPayload],
  );

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between border-b border-white/5 px-4 py-2.5">
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
              'flex flex-col items-center justify-center rounded-xl border border-dashed px-6 py-14 text-center transition-colors',
              dragOver ? 'border-accent-400 bg-accent-500/5' : 'border-white/10 bg-white/[0.02]',
            ].join(' ')}
          >
            <div className="text-sm text-ink-200">Drop QR images here, or</div>
            <label className="btn-outline mt-3 cursor-pointer">
              Choose files
              <input
                type="file"
                accept="image/*"
                multiple
                className="hidden"
                onChange={(e) => e.target.files && handleFiles(e.target.files)}
              />
            </label>
            {uploadMsg && <div className="mt-3 text-xs text-ink-400">{uploadMsg}</div>}
          </div>
        </div>
      )}

      {mode === 'camera' && (
        <div className="p-5">
          <div className="relative aspect-video overflow-hidden rounded-xl bg-black">
            <video
              ref={videoRef}
              className="h-full w-full object-cover"
              muted
              playsInline
              autoPlay
            />
            {!cameraOn && !cameraErr && (
              <div className="absolute inset-0 flex items-center justify-center text-sm text-ink-200">
                Requesting camera…
              </div>
            )}
            {cameraErr && (
              <div className="absolute inset-0 flex items-center justify-center p-5 text-center text-sm text-red-300">
                Camera unavailable: {cameraErr}
              </div>
            )}
          </div>
          <p className="mt-2 text-xs text-ink-400">
            Point at each QR code; already-scanned codes are ignored automatically.
          </p>
        </div>
      )}
    </div>
  );
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
        'rounded-lg px-3 py-1.5 text-xs font-medium transition-colors',
        active ? 'bg-white/10 text-ink-50' : 'text-ink-300 hover:bg-white/5 hover:text-ink-100',
      ].join(' ')}
    >
      {children}
    </button>
  );
}
