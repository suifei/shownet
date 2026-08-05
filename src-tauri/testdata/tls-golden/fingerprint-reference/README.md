# Fingerprint reference inventory

This directory is the **low-cost lookup table** for JA3/JA4 work: which GitHub repos and tools claim support for which browser families/majors, so implementers can capture goldens **without installing every browser**.

It is **not** a golden store. Captured fingerprints still live only in `../entries/*.json` under the honesty rules in `../README.md`.

## Files

| File | Role |
|------|------|
| `sources-inventory.json` | Machine-checkable list of external sources (min 3) |
| `sources-inventory.schema.json` | Structural contract for the inventory |
| `version-matrix.json` | Which ShowNet preset majors have entry stubs / capture status |

## Honesty (must stay true in the JSON)

- `tool-matched` ≠ `browser-matched`
- No invented JA3 strings
- Catalog `documentedJa3` is never a golden

## Refresh path

```bash
# Structural validation only (no network / no tools)
npm run tls-golden:validate

# Validate inventory + list pending multi-version stubs
npm run tls-golden:capture:dry

# Prefer tool capture for one Chrome major (skips honestly if tool missing)
node scripts/tls-golden-capture.mjs --preset chrome150 --platform desktop-windows
```

See `scripts/tls-golden-capture.mjs` and the parent README §4.

## Source classes in the inventory

| `mayAuthoriseAlignment` | Meaning |
|-------------------------|---------|
| `tool-matched` | A successful tool capture *may* later authorise tool-matched (never browser-matched) |
| `none` | Spec/docs only (JA3/JA4 standards); never fills goldens |

Low-cost (`captureCost: low-tool`) entries are preferred for bulk Chrome majors without browser installers.
