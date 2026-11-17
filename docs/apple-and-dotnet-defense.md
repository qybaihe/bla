# Apple PropertyList & .NET Managed Assembly Defense

## 1. Apple `.plist` Internal Subset Budget Trap (`src/shields/formats/apple-plist.ts`)

In `REA/src/artifacts/apple/PropertyListDecodeBudget.ts:80`:
```ts
if (token.doctype) {
  if (token.internalSubset)
    throw fail("expansion", `XML plist internal entity expansion exceeds ${budget}`);
}
```
REA rejects any XML `.plist` whose `<!DOCTYPE plist ...>` tag contains a `[` bracket (`internalSubset = true`), even when the internal subset `[]` is completely empty and defines zero XML entities!

`protectAppleXmlPlist` injects `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" []>`, which is 100% valid XML 1.0 for Apple's `PropertyListSerialization` while causing REA's `preflightPropertyListDecode` to immediately abort.

Binary plists (`bplist00`/`bplist01`) are never appended to past EOF: their fixed 32-byte trailer must stay the final 32 bytes, and inserting decoys after it makes every parser read the decoy text as the trailer. The shield inserts its depth guard and canary records immediately before that trailer, so the object table, offset table, and trailer remain valid. Inputs shorter than 40 bytes (8-byte header + 32-byte trailer) are refused.

## 2. .NET Managed Metadata Representation Amplification (`src/shields/formats/dotnet-managed.ts`)

In `REA/src/dotnet/ManagedDecodeBudget.ts`, every metadata table row reserves `256` bytes and every UTF-8 string reserves `encodedBytes * 6 + 2` bytes against a 64 MiB ceiling, while `managed-pinvoke-import` entries trigger mandatory native ABI reconstruction obligations.
