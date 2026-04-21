declare module 'base45' {
  const base45: {
    encode(data: Uint8Array | number[]): string;
    decode(data: string): Uint8Array;
  };
  export default base45;
}
