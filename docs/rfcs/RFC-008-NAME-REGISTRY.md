# RFC-008 — Name Registry Contract (kovanica-name-registry)

- **Status:** Accepted / Active (M1 Implementation Target)
- **Crate Scope:** `kovanica-name-registry`, `kovanica-execution`, `kovanica-common`, `kovanica-comms-core`
- **Primary References:**
  - Contract crate: [`crates/kovanica-name-registry/src/lib.rs`](file:///crates/kovanica-name-registry/src/lib.rs)
  - Common ABI: [`crates/kovanica-common/src/lib.rs`](file:///crates/kovanica-common/src/lib.rs)
  - TypeScript bindings: `packages/comms/src/registry.ts`
  - Related RFCs:
    - [`RFC-001-ARCHITECTURE-AND-SYSTEM-OVERVIEW.md`](file:///docs/rfcs/RFC-001-ARCHITECTURE-AND-SYSTEM-OVERVIEW.md)
    - [`RFC-004-EXECUTION-ENGINE-AND-WASMI-HOST-ENVIRONMENT.md`](file:///docs/rfcs/RFC-004-EXECUTION-ENGINE-AND-WASMI-HOST-ENVIRONMENT.md)
    - [`RFC-007-RPC-AND-KEYSTORE-SPECIFICATION.md`](file:///docs/rfcs/RFC-007-RPC-AND-KEYSTORE-SPECIFICATION.md)

---

## 1. Sažetak (Executive Summary)

RFC-008 specificira ugovor registra imena (`kovanica-name-registry`) na Kovanica blockchainu. Ugovor uspostavlja pravilo prvog dolaska (first-come, first-served) i vlasničkog ažuriranja (owner-updatable) kratkih imena (DNS/ENS ekvivalent) koja mapiraju ime u adresu vlasnika računa, sirovi Ed25519 javni ključ novčanika i do 8 mrežnih relejnih adresa (`relay_endpoints`).

Ugovor se izvršava deterministički unutar Wasmi okruženja preko standardnog transakcijskog toka `Call` (definiranog u RFC-004), bez mutacija konsenzusnih pravila ili struktura u `kovanica-execution` (ledger-safe). Registar je namjerno dizajniran s otpornošću na globalno listanje i enumeraciju korisnika (enumeration resistance).

---

## 2. Podatkovni model i struktura zapisa (`NameEntry`)

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameEntry {
    /// Adresa vlasnika računa koji ima pravo izmjene ili prijenosa imena.
    pub owner: Address,
    /// Sirovi 32-bajtni Ed25519 javni ključ novčanika (wallet key).
    pub pubkey: [u8; 32],
    /// Popis do 8 relejnih HTTP(S) adresa za slanje šifriranih poruka.
    pub relay_endpoints: Vec<String>,
}
```

- `pubkey` je sirovi javni ključ. Identifikator komunikacije (`comms_id`) izvodi se na strani klijenta:
  $$\text{comms\_id} = \text{BLAKE3}(\text{"kvnc/comms/id"} \parallel \text{pubkey})$$
- Ugovor ne čuva polje isteka (nema najma / expiry u M1 fazi).
- Ugovor ne čuva obrnuti indeks (reverse index `pubkey -> name` je zabranjen radi privatnosti).

---

## 3. Organizacija pohrane ugovora (Storage Layout)

Sukladno konvenciji iz [`RFC-004`](file:///docs/rfcs/RFC-004-EXECUTION-ENGINE-AND-WASMI-HOST-ENVIRONMENT.md):
- **Sirovi ključ (Raw key):** `b"kvnc/v1/name/" ‖ utf8(normalised_name)`
- **Vrijednost (Value):** `bincode(NameEntry)`
- **Izvedeni ključ tablice:** `table_key = BLAKE3(raw_key)`
- Upisi su izolirani adresom ugovora: `(contract_address, table_key)` u `redb` bazi.

Ne postoji globalni brojač niti jedinstveno stanje: svaki naziv je samostalan zapis.

---

## 4. Metode i ulazne točke (Entry Points)

| Metoda | Bincode argumenti | Uspjeh | Moguće greške (`ContractError`) |
|---|---|---|---|
| `register` | `(String name, [u8;32] pubkey, Vec<String> relay_endpoints)` | `()` | `InvalidInput`, `AlreadyExists` |
| `resolve` | `(String name,)` | `NameEntry` | `InvalidInput`, `NotFound` |
| `update_endpoints` | `(String name, Vec<String> relay_endpoints)` | `()` | `InvalidInput`, `NotFound`, `Unauthorized` |
| `transfer` | `(String name, [u8;32] new_owner)` | `()` | `InvalidInput`, `NotFound`, `Unauthorized` |

### 4.1 Pravila validacije imena (Grammar)
1. **Normalizacija:** ASCII-lowercase nad UTF-8 unosom. Nema Unicode case-foldinga ili NFC/NFKC transformacija.
2. **Gramatička pravila:**
   - Duljina mora biti između 3 i 32 bajta/znaka (`3..=32`).
   - Svi znakovi moraju pripadati skupu `[a-z0-9-]`.
   - Ime ne smije počinjati niti završavati s crticom `-`.
   - Ime ne smije sadržavati uzastopne crtice `--`.

### 4.2 Ograničenja relejnih adresa
- Najviše 8 adresa po imenu (`<= 8`).
- Svaka adresa najviše 256 bajtova.
- Shema mora biti eksplicitno `http://` ili `https://`.

---

## 5. Sigurnost i otpornost na pretraživanje (Enumeration Resistance)

Registar ne podržava listanje imena. Korisnik mora unaprijed znati točan naziv koji želi riješiti (`resolve("alice")`). Time se sprječava masovno struganje (scraping) korisničkih profila s lanca.

---

## 6. Točne reference u kodu

- Implementacija ugovora: [`crates/kovanica-name-registry/src/lib.rs`](file:///crates/kovanica-name-registry/src/lib.rs)
- Wasmi integracija: [`crates/kovanica-execution/src/contracts.rs`](file:///crates/kovanica-execution/src/contracts.rs)
- Kovanica Common Error tipovi: [`crates/kovanica-common/src/lib.rs`](file:///crates/kovanica-common/src/lib.rs)
