export interface SurfaceBounds {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface FrameSize {
  width: number;
  height: number;
}

export interface FramePoint {
  x: number;
  y: number;
}

export interface CdpFileDragData {
  items: [];
  files: string[];
  dragOperationsMask: 1;
}

export const MAX_BROWSER_DROP_FILES = 32;

export function mapScreencastPoint(
  clientX: number,
  clientY: number,
  bounds: SurfaceBounds,
  frame: FrameSize,
  clampToFrame = false,
): FramePoint | null {
  if (
    !Number.isFinite(clientX)
    || !Number.isFinite(clientY)
    || bounds.width <= 0
    || bounds.height <= 0
    || frame.width <= 0
    || frame.height <= 0
  ) return null;

  const sourceRatio = frame.width / frame.height;
  const boundsRatio = bounds.width / bounds.height;
  const renderedWidth = boundsRatio > sourceRatio ? bounds.height * sourceRatio : bounds.width;
  const renderedHeight = boundsRatio > sourceRatio ? bounds.height : bounds.width / sourceRatio;
  const left = bounds.left + (bounds.width - renderedWidth) / 2;
  const top = bounds.top + (bounds.height - renderedHeight) / 2;
  let localX = clientX - left;
  let localY = clientY - top;
  const outside = localX < 0 || localY < 0 || localX > renderedWidth || localY > renderedHeight;
  if (outside && !clampToFrame) return null;
  if (clampToFrame) {
    localX = Math.min(renderedWidth, Math.max(0, localX));
    localY = Math.min(renderedHeight, Math.max(0, localY));
  }
  return {
    x: localX * frame.width / renderedWidth,
    y: localY * frame.height / renderedHeight,
  };
}

export function isShownetSessionPath(path: string) {
  return path.toLowerCase().endsWith(".shownet");
}

export function buildCdpFileDragData(paths: string[]): CdpFileDragData {
  const files = [...new Set(paths.filter((path) => path.trim() && !isShownetSessionPath(path)))]
    .slice(0, MAX_BROWSER_DROP_FILES);
  return { items: [], files, dragOperationsMask: 1 };
}
