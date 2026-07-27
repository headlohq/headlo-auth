// Thin IndexedDB wrapper for HeadloProviderV2 — stores the DPoP CryptoKeyPair
// with extractable: false. Verified to work across Chrome / Safari (incl. iOS) /
// Firefox / Brave via the /abs-spike page (see claude/headlo-auth-abs-build-sequencing.md
// gap #1, verified 2026-07-26).
//
// Deliberately minimal — this is used by dpop.ts only. If we need a general
// IndexedDB layer for other things later, extract to a shared package. For now,
// three functions is the whole API.

const DB_NAME    = 'headlo_auth_v2'
const STORE_NAME = 'dpop_keys'
const DB_VERSION = 1

// Open (or create) the headlo_auth_v2 database. Cached at module scope after
// first open so we don't churn on repeated calls. IndexedDB's own connection
// pooling handles concurrent transactions.
let dbPromise: Promise<IDBDatabase> | null = null

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise
  dbPromise = new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB unavailable — cannot use HeadloProviderV2'))
      return
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror   = () => reject(req.error ?? new Error('IndexedDB open failed'))
  })
  return dbPromise
}

// Store a value under a string key. Overwrites if the key already exists.
export async function idbPut<T>(key: string, value: T): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    tx.objectStore(STORE_NAME).put(value, key)
    tx.oncomplete = () => resolve()
    tx.onerror    = () => reject(tx.error ?? new Error('IndexedDB put failed'))
  })
}

// Retrieve a value by string key. Returns undefined if the key isn't set.
export async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const req = tx.objectStore(STORE_NAME).get(key)
    req.onsuccess = () => resolve(req.result as T | undefined)
    req.onerror   = () => reject(req.error ?? new Error('IndexedDB get failed'))
  })
}

// Delete a value by string key. No-op if the key isn't set.
export async function idbDelete(key: string): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    tx.objectStore(STORE_NAME).delete(key)
    tx.oncomplete = () => resolve()
    tx.onerror    = () => reject(tx.error ?? new Error('IndexedDB delete failed'))
  })
}
