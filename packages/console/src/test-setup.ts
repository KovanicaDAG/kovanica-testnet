// Node can expose a broken `localStorage` global unless `--localstorage-file`
// is set, which hides jsdom's storage. Tests get an in-memory stand-in.
const existing = globalThis.localStorage as Storage | undefined;
if (!existing || typeof existing.clear !== "function") {
  const store = new Map<string, string>();
  const memory: Storage = {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => {
      store.set(key, value);
    },
    removeItem: (key) => {
      store.delete(key);
    },
    clear: () => {
      store.clear();
    },
    key: (index) => [...store.keys()][index] ?? null,
    get length() {
      return store.size;
    },
  };
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: memory,
  });
}
