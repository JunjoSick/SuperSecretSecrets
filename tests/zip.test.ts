import { describe, expect, it } from 'vitest';
import JSZip from 'jszip';
import { buildZip } from '../src/lib/zip';

describe('ZIP builder', () => {
  it('includes binary vault attachments even when QR formats are disabled', async () => {
    const vaultBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const blob = await buildZip([], 'M', { svg: false, png: false, txt: false }, [
      { name: 'vault-test.ssssvault', data: vaultBytes },
    ]);
    const zip = await JSZip.loadAsync(await blob.arrayBuffer());
    const file = zip.file('vault-test.ssssvault');
    expect(file).not.toBeNull();
    expect(Array.from(await file!.async('uint8array'))).toEqual(Array.from(vaultBytes));
  });
});
