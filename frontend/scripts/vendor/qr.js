const GF_EXP = new Uint8Array(512), GF_LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  GF_EXP[i] = x;
  GF_LOG[x] = i;
  x <<= 1;
  if (x & 256) x ^= 285;
}
for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
const gmul = (a, b) => a && b ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0;
function rsDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gmul(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gmul(root, 2);
  }
  return result;
}
function rsRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++) result[i] ^= gmul(divisor[i], factor);
  }
  return result;
}
const TOTAL_CODEWORDS = [0, 26, 44, 70, 100, 134, 172];
const ECC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16];
const NUM_BLOCKS = [0, 1, 1, 1, 2, 2, 4];
const dataCodewords = (v) => TOTAL_CODEWORDS[v] - ECC_PER_BLOCK[v] * NUM_BLOCKS[v];
function buildCodewords(bytes, version) {
  const capBits = dataCodewords(version) * 8;
  const bits = [];
  const push = (val, n2) => {
    for (let i = n2 - 1; i >= 0; i--) bits.push(val >>> i & 1);
  };
  push(4, 4);
  push(bytes.length, 8);
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, capBits - bits.length));
  push(0, (8 - bits.length % 8) % 8);
  for (let pad = 236; bits.length < capBits; pad ^= 236 ^ 17) push(pad, 8);
  const data = new Uint8Array(capBits / 8);
  bits.forEach((bit, i) => {
    data[i >> 3] |= bit << 7 - (i & 7);
  });
  const n = NUM_BLOCKS[version], k = data.length / n;
  const divisor = rsDivisor(ECC_PER_BLOCK[version]);
  const blocks = [];
  for (let b = 0; b < n; b++) {
    const dat = data.slice(b * k, (b + 1) * k);
    blocks.push([...dat, ...rsRemainder(dat, divisor)]);
  }
  const out = [];
  for (let i = 0; i < blocks[0].length; i++) for (const bl of blocks) out.push(bl[i]);
  return new Uint8Array(out);
}
function makeMatrix(version, codewords) {
  const size = 17 + 4 * version;
  const grid = Array.from({ length: size }, () => new Uint8Array(size));
  const func = Array.from({ length: size }, () => new Uint8Array(size));
  const set = (x, y, dark) => {
    grid[y][x] = dark ? 1 : 0;
    func[y][x] = 1;
  };
  for (let i2 = 0; i2 < size; i2++) {
    set(6, i2, i2 % 2 === 0);
    set(i2, 6, i2 % 2 === 0);
  }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x < 0 || x >= size || y < 0 || y >= size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      set(x, y, d !== 2 && d !== 4);
    }
  };
  finder(3, 3);
  finder(size - 4, 3);
  finder(3, size - 4);
  if (version >= 2) {
    const c = size - 7;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
      set(c + dx, c + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  drawFormat(grid, func, size, 0);
  let i = 0;
  const total = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = (right + 1 & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!func[y][x] && i < total) {
          grid[y][x] = codewords[i >> 3] >>> 7 - (i & 7) & 1;
          i++;
        }
      }
    }
  }
  let best = null, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(grid, func, size, mask);
    drawFormat(grid, func, size, mask);
    const score = penalty(grid, size);
    if (score < bestScore) {
      bestScore = score;
      best = grid.map((r) => r.slice());
    }
    applyMask(grid, func, size, mask);
  }
  return { size, grid: best };
}
const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => x * y % 2 + x * y % 3 === 0,
  (x, y) => (x * y % 2 + x * y % 3) % 2 === 0,
  (x, y) => ((x + y) % 2 + x * y % 3) % 2 === 0
];
function applyMask(grid, func, size, mask) {
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++)
    if (!func[y][x] && MASKS[mask](x, y)) grid[y][x] ^= 1;
}
function drawFormat(grid, func, size, mask) {
  let rem = mask;
  for (let i = 0; i < 10; i++) rem = rem << 1 ^ (rem >>> 9) * 1335;
  const bits = (mask << 10 | rem) ^ 21522;
  const bit = (i) => bits >>> i & 1;
  const set = (x, y, dark) => {
    grid[y][x] = dark ? 1 : 0;
    func[y][x] = 1;
  };
  for (let i = 0; i <= 5; i++) set(8, i, bit(i));
  set(8, 7, bit(6));
  set(8, 8, bit(7));
  set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
  set(8, size - 8, true);
}
function penalty(grid, size) {
  let score = 0;
  const line = (get) => {
    for (let i = 0; i < size; i++) {
      let run = 1;
      for (let j = 1; j < size; j++) {
        if (get(i, j) === get(i, j - 1)) {
          run++;
          if (j === size - 1 && run >= 5) score += run - 2;
        } else {
          if (run >= 5) score += run - 2;
          run = 1;
        }
      }
      for (let j = 0; j + 11 <= size; j++) {
        const w = [];
        for (let k = 0; k < 11; k++) w.push(get(i, j + k));
        const s = w.join("");
        if (s === "10111010000" || s === "00001011101") score += 40;
      }
    }
  };
  line((i, j) => grid[i][j]);
  line((i, j) => grid[j][i]);
  for (let y = 0; y + 1 < size; y++) for (let x = 0; x + 1 < size; x++) {
    const c = grid[y][x];
    if (c === grid[y][x + 1] && c === grid[y + 1][x] && c === grid[y + 1][x + 1]) score += 3;
  }
  let dark = 0;
  for (const row of grid) for (const c of row) dark += c;
  score += 10 * Math.floor(Math.abs(dark * 100 / (size * size) - 50) / 5);
  return score;
}
export function qrModules(text) {
  const bytes = new TextEncoder().encode(text);
  let version = 0;
  for (let v = 1; v <= 6; v++) if (bytes.length <= dataCodewords(v) - 2) {
    version = v;
    break;
  }
  if (!version) throw new Error("qr: payload too long");
  return makeMatrix(version, buildCodewords(bytes, version));
}
export function qrSVG(text, { module = 4, margin = 4 } = {}) {
  const { size, grid } = qrModules(text);
  const dim = (size + margin * 2) * module;
  let rects = "";
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++)
    if (grid[y][x]) rects += `<rect x="${(x + margin) * module}" y="${(y + margin) * module}" width="${module}" height="${module}"/>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${dim}" height="${dim}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${dim}" height="${dim}" fill="#fff"/><g fill="#000">${rects}</g></svg>`;
}
export function qrCanvas(text, { module = 8, margin = 4 } = {}) {
  const { size, grid } = qrModules(text);
  const dim = (size + margin * 2) * module;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = dim;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, dim, dim);
  ctx.fillStyle = "#000";
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++)
    if (grid[y][x]) ctx.fillRect((x + margin) * module, (y + margin) * module, module, module);
  return canvas;
}
