import { describe, expect, it } from 'vitest';
import sharp from 'sharp';
import { LogoSimilarityService } from '../src/logo-similarity.service';

async function makePattern(invert: boolean): Promise<Buffer> {
  const pixels = Buffer.alloc(8 * 8);
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      const bright = (x < 4) !== (y < 4);
      pixels[y * 8 + x] = (bright !== invert) ? 255 : 0;
    }
  }
  return sharp(pixels, { raw: { width: 8, height: 8, channels: 1 } }).png().toBuffer();
}

describe('Perceptual logo similarity', () => {
  it('distinguishes visually opposite test images and recognizes an identical image', async () => {
    const service = new LogoSimilarityService();
    const officialImage = await makePattern(false);
    const copiedImage = await makePattern(false);
    const unrelatedImage = await makePattern(true);

    const copied = await service.compareImageBuffers({
      targetImage: copiedImage,
      referenceImage: officialImage,
    });
    const unrelated = await service.compareImageBuffers({
      targetImage: unrelatedImage,
      referenceImage: officialImage,
    });

    expect(copied.similarityScore).toBe(1);
    expect(copied.isImpersonating).toBe(true);
    expect(unrelated.similarityScore).toBeLessThan(0.5);
    expect(unrelated.isImpersonating).toBe(false);
  });
});
