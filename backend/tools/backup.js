const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const SRC = process.env.ELUSIVE_DB || path.join(__dirname, '../elusive.db');
const DEST_DIR = process.argv[2] || path.join(__dirname, '../backups');
const KEEP = Number(process.env.BACKUP_KEEP || 14);
const DRY_RUN = process.argv.includes('--dry-run');
const FORCE = process.argv.includes('--force');

if (!path.isAbsolute(DEST_DIR) || !/backups/i.test(DEST_DIR)) {
  if (!FORCE) {
    console.error('refusing to prune outside an absolute .../backups path (use --force to override)');
    process.exit(1);
  }
}

fs.mkdirSync(DEST_DIR, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const dest = path.join(DEST_DIR, `elusive-${stamp}.db`);

const db = new Database(SRC, { readonly: true });
db.backup(dest)
  .then(() => {
    db.close();
    const files = fs.readdirSync(DEST_DIR).filter((f) => /^elusive-.*\.db$/.test(f)).sort();
    const drop = files.slice(0, Math.max(0, files.length - KEEP));
    if (DRY_RUN) {
      console.log(`[dry-run] would prune ${drop.length} backup(s) (keeping ${Math.min(files.length, KEEP)})`);
      for (const f of drop) console.error(`[dry-run] would delete ${path.join(DEST_DIR, f)}`);
      console.log(`backup ok -> ${dest} (dry-run, nothing pruned)`);
      return;
    }
    for (const f of drop) {
      console.error(`pruning ${path.join(DEST_DIR, f)}`);
      fs.rmSync(path.join(DEST_DIR, f));
    }
    console.log(`backup ok -> ${dest} (kept ${Math.min(files.length, KEEP)}, pruned ${drop.length})`);
  })
  .catch((e) => { console.error('backup failed:', e.message); process.exit(1); });
