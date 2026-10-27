import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";

// @noble/ed25519 v2 asks the caller for SHA-512. Sync keeps key creation
// and signing free of a dynamic import in the browser.
ed.etc.sha512Sync = (...messages: Uint8Array[]) => sha512(ed.etc.concatBytes(...messages));
