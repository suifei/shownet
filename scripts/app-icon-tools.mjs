import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { deflateSync, inflateSync } from "node:zlib";

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const LEGACY_APP_ICON_SHA256 = "59b582dc630a385fed04bb797d3df29525173fba7394b106bdd03ea11a139003";

export const APP_ICON_SOURCE_FILES = Object.freeze({
  source: "shownet-app-icon-source.png",
  master: "shownet-app-icon-master.png",
  androidBackground: "shownet-android-background.png",
  androidForeground: "shownet-android-foreground.png",
  androidMonochrome: "shownet-android-monochrome.png",
});
export const APP_ICON_PROVENANCE_FILE = "app-icon-provenance.json";

const DESKTOP_PNG_SIZES = new Map([
  ["32x32.png", 32],
  ["64x64.png", 64],
  ["128x128.png", 128],
  ["128x128@2x.png", 256],
  ["icon.png", 512],
  ["Square30x30Logo.png", 30],
  ["Square44x44Logo.png", 44],
  ["Square71x71Logo.png", 71],
  ["Square89x89Logo.png", 89],
  ["Square107x107Logo.png", 107],
  ["Square142x142Logo.png", 142],
  ["Square150x150Logo.png", 150],
  ["Square284x284Logo.png", 284],
  ["Square310x310Logo.png", 310],
  ["StoreLogo.png", 50],
]);

export const IOS_PNG_SIZES = new Map([
  ["ios/AppIcon-20x20@1x.png", 20],
  ["ios/AppIcon-20x20@2x-1.png", 40],
  ["ios/AppIcon-20x20@2x.png", 40],
  ["ios/AppIcon-20x20@3x.png", 60],
  ["ios/AppIcon-29x29@1x.png", 29],
  ["ios/AppIcon-29x29@2x-1.png", 58],
  ["ios/AppIcon-29x29@2x.png", 58],
  ["ios/AppIcon-29x29@3x.png", 87],
  ["ios/AppIcon-40x40@1x.png", 40],
  ["ios/AppIcon-40x40@2x-1.png", 80],
  ["ios/AppIcon-40x40@2x.png", 80],
  ["ios/AppIcon-40x40@3x.png", 120],
  ["ios/AppIcon-60x60@2x.png", 120],
  ["ios/AppIcon-60x60@3x.png", 180],
  ["ios/AppIcon-76x76@1x.png", 76],
  ["ios/AppIcon-76x76@2x.png", 152],
  ["ios/AppIcon-83.5x83.5@2x.png", 167],
  ["ios/AppIcon-512@2x.png", 1024],
]);

const ANDROID_DENSITIES = new Map([
  ["mdpi", 1],
  ["hdpi", 1.5],
  ["xhdpi", 2],
  ["xxhdpi", 3],
  ["xxxhdpi", 4],
]);

export async function validateAppIconSources(brandDirectory) {
  const paths = Object.fromEntries(Object.entries(APP_ICON_SOURCE_FILES)
    .map(([name, file]) => [name, join(brandDirectory, file)]));
  const images = {};
  for (const [name, path] of Object.entries(paths)) {
    const bytes = await readFile(path).catch((error) => {
      if (error?.code === "ENOENT") {
        throw new Error(`Missing required official app icon source: ${APP_ICON_SOURCE_FILES[name]}`);
      }
      throw error;
    });
    images[name] = inspectPng(bytes, APP_ICON_SOURCE_FILES[name]);
  }

  if (images.source.width !== images.source.height
    || images.source.width < 1024
    || images.source.width > 2048) {
    throw new Error(
      `shownet-app-icon-source.png must preserve a square 1024-2048px model response, received ${images.source.width}x${images.source.height}`,
    );
  }
  for (const name of ["master", "androidBackground", "androidForeground", "androidMonochrome"]) {
    assertDimensions(images[name], 1024, 1024, APP_ICON_SOURCE_FILES[name]);
  }

  const sourceCorners = cornerPixels(images.source);
  if (!sourceCorners.every(({ red, green, blue, alpha }) => (
    red >= 220
    && green <= 50
    && blue >= 200
    && Math.abs(red - blue) <= 40
    && alpha >= 250
  ))) {
    throw new Error("shownet-app-icon-source.png must preserve the generated magenta background");
  }

  assertTransparentCorners(images.master, "shownet-app-icon-master.png");
  assertNoChromaKey(images.master, "shownet-app-icon-master.png");
  assertUsefulCoverage(images.master, "shownet-app-icon-master.png", 0.25, 0.9);

  assertSolidColor(images.androidBackground, "shownet-android-background.png", [0x10, 0x13, 0x15, 0xff]);

  for (const [name, label] of [
    ["androidForeground", "shownet-android-foreground.png"],
    ["androidMonochrome", "shownet-android-monochrome.png"],
  ]) {
    const image = images[name];
    assertTransparentCorners(image, label);
    assertNoChromaKey(image, label);
    assertUsefulCoverage(image, label, 0.015, 0.55);
    assertAdaptiveSafeZone(image, label);
  }

  forEachVisiblePixel(images.androidMonochrome, ({ red, green, blue }) => {
    if (red !== 0xff || green !== 0xff || blue !== 0xff) {
      throw new Error("shownet-android-monochrome.png must use a white mark with alpha only");
    }
  });

  return images;
}

export async function validateGeneratedIconDirectory(iconDirectory) {
  const expectedFiles = new Set(["icon.icns", "icon.ico"]);

  for (const [file, size] of DESKTOP_PNG_SIZES) {
    expectedFiles.add(file);
    const image = inspectPng(await readFile(join(iconDirectory, file)), file);
    assertDimensions(image, size, size, file);
    if (file === "icon.png") {
      const checksum = sha256(image.buffer);
      if (checksum === LEGACY_APP_ICON_SHA256) {
        throw new Error("Generated icon set still contains the rejected red ECG artwork");
      }
    }
  }

  for (const [file, size] of IOS_PNG_SIZES) {
    expectedFiles.add(file);
    const image = inspectPng(await readFile(join(iconDirectory, file)), file);
    assertDimensions(image, size, size, file);
    if (image.colorType !== 2 || image.stats.transparentPixels !== 0 || image.stats.translucentPixels !== 0) {
      throw new Error(`${file} must be a fully opaque RGB PNG for iOS`);
    }
  }

  for (const [density, scale] of ANDROID_DENSITIES) {
    const directory = `android/mipmap-${density}`;
    const legacySize = Math.round(48 * scale);
    const adaptiveSize = Math.round(108 * scale);
    for (const file of ["ic_launcher.png", "ic_launcher_round.png"]) {
      const relativePath = `${directory}/${file}`;
      expectedFiles.add(relativePath);
      const image = inspectPng(await readFile(join(iconDirectory, relativePath)), relativePath);
      assertDimensions(image, legacySize, legacySize, relativePath);
    }
    for (const file of ["ic_launcher_background.png", "ic_launcher_foreground.png", "ic_launcher_monochrome.png"]) {
      const relativePath = `${directory}/${file}`;
      expectedFiles.add(relativePath);
      const image = inspectPng(await readFile(join(iconDirectory, relativePath)), relativePath);
      assertDimensions(image, adaptiveSize, adaptiveSize, relativePath);
      if (file !== "ic_launcher_background.png") assertTransparentCorners(image, relativePath);
    }
  }

  const adaptiveXmlPath = "android/mipmap-anydpi-v26/ic_launcher.xml";
  expectedFiles.add(adaptiveXmlPath);
  const adaptiveXml = await readFile(join(iconDirectory, adaptiveXmlPath), "utf8");
  for (const layer of ["ic_launcher_background", "ic_launcher_foreground", "ic_launcher_monochrome"]) {
    if (!adaptiveXml.includes(`@mipmap/${layer}`)) {
      throw new Error(`${adaptiveXmlPath} is missing ${layer}`);
    }
  }

  const ico = inspectIco(await readFile(join(iconDirectory, "icon.ico")), "icon.ico");
  const icoSizes = new Set(ico.entries.map(({ width, height }) => width === height ? width : -1));
  for (const size of [16, 20, 24, 32, 48, 64, 128, 256]) {
    if (!icoSizes.has(size)) throw new Error(`icon.ico is missing ${size}x${size}`);
  }

  const icns = inspectIcns(await readFile(join(iconDirectory, "icon.icns")), "icon.icns");
  const icnsTypes = new Set(icns.entries.map(({ type }) => type));
  for (const type of ["ic07", "ic08", "ic09", "ic10", "ic11", "ic12", "ic13", "ic14"]) {
    if (!icnsTypes.has(type)) throw new Error(`icon.icns is missing ${type}`);
  }

  const actualFiles = new Set(await listFiles(iconDirectory));
  for (const file of expectedFiles) {
    if (!actualFiles.has(file)) throw new Error(`Generated icon set is missing ${file}`);
  }
  for (const file of actualFiles) {
    if (file === ".DS_Store") continue;
    if (!expectedFiles.has(file)) throw new Error(`Generated icon set contains stale file ${file}`);
  }

  return { ico, icns, files: [...expectedFiles].sort() };
}

export async function validateAppIconSet(projectRoot) {
  const brandDirectory = resolve(projectRoot, "docs/assets/brand");
  const iconDirectory = resolve(projectRoot, "src-tauri/icons");
  await validateAppIconSources(brandDirectory);
  await validateAppIconProvenance(brandDirectory);
  const result = await validateGeneratedIconDirectory(iconDirectory);

  const copies = [
    ["src-tauri/icons/icon.png", "src/assets/shownet-app-icon.png"],
    ["src-tauri/icons/32x32.png", "public/favicon.png"],
    ["src-tauri/icons/ios/AppIcon-60x60@3x.png", "public/apple-touch-icon.png"],
    ["src-tauri/icons/128x128@2x.png", "docs/assets/brand/shownet-app-icon-readme.png"],
  ];
  for (const [source, destination] of copies) {
    const [sourceBytes, destinationBytes] = await Promise.all([
      readFile(resolve(projectRoot, source)),
      readFile(resolve(projectRoot, destination)),
    ]);
    if (!sourceBytes.equals(destinationBytes)) {
      throw new Error(`${destination} does not match ${source}`);
    }
  }

  return result;
}

export async function validateAppIconProvenance(brandDirectory) {
  const path = join(brandDirectory, APP_ICON_PROVENANCE_FILE);
  const text = await readFile(path, "utf8").catch((error) => {
    if (error?.code === "ENOENT") throw new Error(`Missing app icon provenance: ${APP_ICON_PROVENANCE_FILE}`);
    throw error;
  });
  if (/sk-[a-zA-Z0-9_-]{16,}/.test(text)) throw new Error("App icon provenance must not contain credentials");
  const provenance = JSON.parse(text);
  if (provenance.schemaVersion !== 1
    || provenance.asset !== "ShowNet app icon"
    || provenance.generation?.modelRequested !== "gpt-image-2"
    || !/^https:\/\//.test(provenance.generation?.endpoint ?? "")
    || provenance.credentialsStored !== false) {
    throw new Error("App icon provenance metadata is incomplete");
  }
  for (const file of Object.values(APP_ICON_SOURCE_FILES)) {
    const expected = provenance.files?.[file];
    if (!/^[0-9a-f]{64}$/.test(expected ?? "")) {
      throw new Error(`App icon provenance is missing the SHA-256 for ${file}`);
    }
    const actual = sha256(await readFile(join(brandDirectory, file)));
    if (actual !== expected) throw new Error(`App icon provenance SHA-256 does not match ${file}`);
  }
  return provenance;
}

export function augmentIco(existingBuffer, pngBuffers, label = "icon.ico") {
  const existing = inspectIco(existingBuffer, label);
  const entries = existing.entries.map((entry) => ({
    ...entry,
    data: existingBuffer.subarray(entry.offset, entry.offset + entry.bytes),
  }));

  for (const [index, pngBuffer] of pngBuffers.entries()) {
    const png = inspectPng(pngBuffer, `${label} addition ${index + 1}`);
    if (png.width !== png.height || png.width > 256) {
      throw new Error(`${label} additions must be square PNG files no larger than 256px`);
    }
    const duplicate = entries.find(({ width, height }) => width === png.width && height === png.height);
    if (duplicate) {
      duplicate.data = pngBuffer;
      duplicate.bytes = pngBuffer.length;
      duplicate.planes = 1;
      duplicate.bitDepth = 32;
      continue;
    }
    entries.push({
      width: png.width,
      height: png.height,
      colorCount: 0,
      reserved: 0,
      planes: 1,
      bitDepth: 32,
      bytes: pngBuffer.length,
      data: pngBuffer,
    });
  }

  entries.sort((left, right) => left.width - right.width || left.height - right.height);
  const headerSize = 6 + entries.length * 16;
  let dataOffset = headerSize;
  const header = Buffer.alloc(headerSize);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);
  entries.forEach((entry, index) => {
    const offset = 6 + index * 16;
    header[offset] = entry.width === 256 ? 0 : entry.width;
    header[offset + 1] = entry.height === 256 ? 0 : entry.height;
    header[offset + 2] = entry.colorCount ?? 0;
    header[offset + 3] = entry.reserved ?? 0;
    header.writeUInt16LE(entry.planes || 1, offset + 4);
    header.writeUInt16LE(entry.bitDepth || 32, offset + 6);
    header.writeUInt32LE(entry.data.length, offset + 8);
    header.writeUInt32LE(dataOffset, offset + 12);
    dataOffset += entry.data.length;
  });
  return Buffer.concat([header, ...entries.map(({ data }) => data)]);
}

export function flattenPng(buffer, background = [0x10, 0x13, 0x15], label = "PNG") {
  const image = inspectPng(buffer, label);
  const scanlines = Buffer.alloc((image.width * 3 + 1) * image.height);
  for (let y = 0; y < image.height; y += 1) {
    const rowOffset = y * (image.width * 3 + 1);
    scanlines[rowOffset] = 0;
    for (let x = 0; x < image.width; x += 1) {
      const sourceOffset = (y * image.width + x) * 4;
      const targetOffset = rowOffset + 1 + x * 3;
      const alpha = image.pixels[sourceOffset + 3] / 255;
      scanlines[targetOffset] = compositeChannel(image.pixels[sourceOffset], background[0], alpha);
      scanlines[targetOffset + 1] = compositeChannel(image.pixels[sourceOffset + 1], background[1], alpha);
      scanlines[targetOffset + 2] = compositeChannel(image.pixels[sourceOffset + 2], background[2], alpha);
    }
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(image.width, 0);
  header.writeUInt32BE(image.height, 4);
  header[8] = 8;
  header[9] = 2;
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk("IHDR", header),
    pngChunk("IDAT", deflateSync(scanlines, { level: 9 })),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

export function inspectIco(buffer, label = "ICO") {
  if (buffer.length < 6 || buffer.readUInt16LE(0) !== 0 || buffer.readUInt16LE(2) !== 1) {
    throw new Error(`${label} is not a valid ICO file`);
  }
  const count = buffer.readUInt16LE(4);
  if (count === 0 || buffer.length < 6 + count * 16) throw new Error(`${label} has an invalid directory`);
  const entries = [];
  for (let index = 0; index < count; index += 1) {
    const directoryOffset = 6 + index * 16;
    const width = buffer[directoryOffset] || 256;
    const height = buffer[directoryOffset + 1] || 256;
    const bytes = buffer.readUInt32LE(directoryOffset + 8);
    const offset = buffer.readUInt32LE(directoryOffset + 12);
    if (bytes === 0 || offset < 6 + count * 16 || offset + bytes > buffer.length) {
      throw new Error(`${label} entry ${index + 1} is outside the file`);
    }
    entries.push({
      width,
      height,
      colorCount: buffer[directoryOffset + 2],
      reserved: buffer[directoryOffset + 3],
      planes: buffer.readUInt16LE(directoryOffset + 4),
      bitDepth: buffer.readUInt16LE(directoryOffset + 6),
      bytes,
      offset,
    });
  }
  return { entries };
}

export function inspectIcns(buffer, label = "ICNS") {
  if (buffer.length < 8 || buffer.toString("ascii", 0, 4) !== "icns" || buffer.readUInt32BE(4) !== buffer.length) {
    throw new Error(`${label} is not a valid ICNS file`);
  }
  const entries = [];
  let offset = 8;
  while (offset < buffer.length) {
    if (offset + 8 > buffer.length) throw new Error(`${label} has a truncated entry`);
    const type = buffer.toString("ascii", offset, offset + 4);
    const bytes = buffer.readUInt32BE(offset + 4);
    if (bytes < 8 || offset + bytes > buffer.length) throw new Error(`${label} has an invalid ${type} entry`);
    entries.push({ type, bytes });
    offset += bytes;
  }
  return { entries };
}

export function inspectPng(buffer, label = "PNG") {
  if (buffer.length < 33 || !buffer.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    throw new Error(`${label} is not a valid PNG file`);
  }
  let offset = PNG_SIGNATURE.length;
  let header;
  let palette;
  let transparency;
  const compressed = [];
  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString("ascii", offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buffer.length) throw new Error(`${label} has a truncated ${type} chunk`);
    const data = buffer.subarray(dataStart, dataEnd);
    if (type === "IHDR") {
      header = {
        width: data.readUInt32BE(0),
        height: data.readUInt32BE(4),
        bitDepth: data[8],
        colorType: data[9],
        compression: data[10],
        filter: data[11],
        interlace: data[12],
      };
    } else if (type === "PLTE") {
      palette = data;
    } else if (type === "tRNS") {
      transparency = data;
    } else if (type === "IDAT") {
      compressed.push(data);
    } else if (type === "IEND") {
      break;
    }
    offset = dataEnd + 4;
  }
  if (!header || compressed.length === 0) throw new Error(`${label} is missing required PNG chunks`);
  if (header.bitDepth !== 8 || header.compression !== 0 || header.filter !== 0 || header.interlace !== 0) {
    throw new Error(`${label} must be an 8-bit, non-interlaced PNG`);
  }

  const channelsByColorType = new Map([[0, 1], [2, 3], [3, 1], [4, 2], [6, 4]]);
  const channels = channelsByColorType.get(header.colorType);
  if (!channels) throw new Error(`${label} uses unsupported PNG color type ${header.colorType}`);
  if (header.colorType === 3 && (!palette || palette.length % 3 !== 0)) {
    throw new Error(`${label} has an invalid indexed-color palette`);
  }

  const rowBytes = header.width * channels;
  const inflated = inflateSync(Buffer.concat(compressed));
  if (inflated.length !== (rowBytes + 1) * header.height) throw new Error(`${label} has invalid pixel data length`);
  const decoded = Buffer.alloc(rowBytes * header.height);
  for (let row = 0; row < header.height; row += 1) {
    const sourceOffset = row * (rowBytes + 1);
    const targetOffset = row * rowBytes;
    const filterType = inflated[sourceOffset];
    for (let column = 0; column < rowBytes; column += 1) {
      const left = column >= channels ? decoded[targetOffset + column - channels] : 0;
      const up = row > 0 ? decoded[targetOffset + column - rowBytes] : 0;
      const upperLeft = row > 0 && column >= channels
        ? decoded[targetOffset + column - rowBytes - channels]
        : 0;
      let prediction;
      if (filterType === 0) prediction = 0;
      else if (filterType === 1) prediction = left;
      else if (filterType === 2) prediction = up;
      else if (filterType === 3) prediction = Math.floor((left + up) / 2);
      else if (filterType === 4) prediction = paeth(left, up, upperLeft);
      else throw new Error(`${label} uses invalid PNG filter ${filterType}`);
      decoded[targetOffset + column] = (inflated[sourceOffset + 1 + column] + prediction) & 0xff;
    }
  }

  const pixels = Buffer.alloc(header.width * header.height * 4);
  for (let index = 0; index < header.width * header.height; index += 1) {
    const sourceOffset = index * channels;
    const targetOffset = index * 4;
    let red;
    let green;
    let blue;
    let alpha = 0xff;
    if (header.colorType === 0) {
      red = green = blue = decoded[sourceOffset];
      if (transparency && decoded[sourceOffset] === transparency.readUInt16BE(0)) alpha = 0;
    } else if (header.colorType === 2) {
      [red, green, blue] = decoded.subarray(sourceOffset, sourceOffset + 3);
      if (transparency
        && red === transparency.readUInt16BE(0)
        && green === transparency.readUInt16BE(2)
        && blue === transparency.readUInt16BE(4)) alpha = 0;
    } else if (header.colorType === 3) {
      const paletteIndex = decoded[sourceOffset];
      red = palette[paletteIndex * 3];
      green = palette[paletteIndex * 3 + 1];
      blue = palette[paletteIndex * 3 + 2];
      if (red === undefined || green === undefined || blue === undefined) {
        throw new Error(`${label} references a missing palette color`);
      }
      alpha = transparency?.[paletteIndex] ?? 0xff;
    } else if (header.colorType === 4) {
      red = green = blue = decoded[sourceOffset];
      alpha = decoded[sourceOffset + 1];
    } else {
      [red, green, blue, alpha] = decoded.subarray(sourceOffset, sourceOffset + 4);
    }
    pixels[targetOffset] = red;
    pixels[targetOffset + 1] = green;
    pixels[targetOffset + 2] = blue;
    pixels[targetOffset + 3] = alpha;
  }

  return {
    buffer,
    ...header,
    pixels,
    stats: pixelStats(pixels, header.width, header.height),
  };
}

function pixelStats(pixels, width, height) {
  let transparentPixels = 0;
  let translucentPixels = 0;
  let opaquePixels = 0;
  let visiblePixels = 0;
  let nearMagentaPixels = 0;
  let minX = width;
  let minY = height;
  let maxX = -1;
  let maxY = -1;
  for (let index = 0; index < width * height; index += 1) {
    const offset = index * 4;
    const red = pixels[offset];
    const green = pixels[offset + 1];
    const blue = pixels[offset + 2];
    const alpha = pixels[offset + 3];
    if (alpha === 0) transparentPixels += 1;
    else if (alpha === 0xff) opaquePixels += 1;
    else translucentPixels += 1;
    if (alpha > 8) {
      visiblePixels += 1;
      const x = index % width;
      const y = Math.floor(index / width);
      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x);
      maxY = Math.max(maxY, y);
      if (red >= 230 && green <= 40 && blue >= 220) nearMagentaPixels += 1;
    }
  }
  return {
    transparentPixels,
    translucentPixels,
    opaquePixels,
    visiblePixels,
    nearMagentaPixels,
    visibleBounds: visiblePixels > 0 ? { minX, minY, maxX, maxY } : null,
  };
}

function assertDimensions(image, width, height, label) {
  if (image.width !== width || image.height !== height) {
    throw new Error(`${label} must be ${width}x${height}, received ${image.width}x${image.height}`);
  }
}

function assertTransparentCorners(image, label) {
  if (!cornerPixels(image).every(({ alpha }) => alpha <= 8)) {
    throw new Error(`${label} must have transparent outer corners`);
  }
}

function assertNoChromaKey(image, label) {
  if (image.stats.nearMagentaPixels > 0) throw new Error(`${label} still contains magenta key pixels`);
}

function assertUsefulCoverage(image, label, minimum, maximum) {
  const coverage = image.stats.visiblePixels / (image.width * image.height);
  if (coverage < minimum || coverage > maximum) {
    throw new Error(`${label} visible coverage ${(coverage * 100).toFixed(1)}% is outside ${minimum * 100}-${maximum * 100}%`);
  }
}

function assertAdaptiveSafeZone(image, label) {
  const bounds = image.stats.visibleBounds;
  const inset = Math.floor(image.width * 0.125);
  if (!bounds
    || bounds.minX < inset
    || bounds.minY < inset
    || bounds.maxX >= image.width - inset
    || bounds.maxY >= image.height - inset) {
    throw new Error(`${label} must keep all visible pixels inside the central 75% adaptive-icon source area`);
  }
}

function assertSolidColor(image, label, expected) {
  for (let offset = 0; offset < image.pixels.length; offset += 4) {
    if (image.pixels[offset] !== expected[0]
      || image.pixels[offset + 1] !== expected[1]
      || image.pixels[offset + 2] !== expected[2]
      || image.pixels[offset + 3] !== expected[3]) {
      throw new Error(`${label} must be a solid #101315 opaque background`);
    }
  }
}

function forEachVisiblePixel(image, callback) {
  for (let offset = 0; offset < image.pixels.length; offset += 4) {
    const alpha = image.pixels[offset + 3];
    if (alpha <= 8) continue;
    callback({
      red: image.pixels[offset],
      green: image.pixels[offset + 1],
      blue: image.pixels[offset + 2],
      alpha,
    });
  }
}

function cornerPixels(image) {
  return [
    pixelAt(image, 0, 0),
    pixelAt(image, image.width - 1, 0),
    pixelAt(image, 0, image.height - 1),
    pixelAt(image, image.width - 1, image.height - 1),
  ];
}

function pixelAt(image, x, y) {
  const offset = (y * image.width + x) * 4;
  return {
    red: image.pixels[offset],
    green: image.pixels[offset + 1],
    blue: image.pixels[offset + 2],
    alpha: image.pixels[offset + 3],
  };
}

async function listFiles(root) {
  const files = [];
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".DS_Store") continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(relative(root, path).split("\\").join("/"));
    }
  }
  await visit(root);
  return files.sort();
}

function paeth(left, up, upperLeft) {
  const prediction = left + up - upperLeft;
  const leftDistance = Math.abs(prediction - left);
  const upDistance = Math.abs(prediction - up);
  const upperLeftDistance = Math.abs(prediction - upperLeft);
  if (leftDistance <= upDistance && leftDistance <= upperLeftDistance) return left;
  if (upDistance <= upperLeftDistance) return up;
  return upperLeft;
}

function compositeChannel(foreground, background, alpha) {
  return Math.round(foreground * alpha + background * (1 - alpha));
}

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type, "ascii");
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  typeBytes.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), 8 + data.length);
  return chunk;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}
