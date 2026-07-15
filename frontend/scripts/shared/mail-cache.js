const DB_NAME = "elusive_cache";
const STORE = "messages";
let dbPromise;

function openDb() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return dbPromise;
}
function reqToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
export async function getCachedMessage(id) {
  try {
    const store = (await openDb()).transaction(STORE, "readonly").objectStore(STORE);
    return (await reqToPromise(store.get(id))) || null;
  } catch {
    return null;
  }
}
export async function putCachedMessage(id, plaintext) {
  try {
    const store = (await openDb()).transaction(STORE, "readwrite").objectStore(STORE);
    await reqToPromise(store.put(plaintext, id));
  } catch {}
}
export function clearCache() {
  dbPromise = null;
  try {
    indexedDB.deleteDatabase(DB_NAME);
  } catch {}
}
