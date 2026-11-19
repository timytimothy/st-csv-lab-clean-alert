#!/usr/bin/env python3
"""
Pendekatan: BUANG NOISE YANG SUDAH DIKETAHUI, bukan whitelist field.
Semua field lain dipertahankan apa adanya (nilai tidak diubah sama sekali),
sehingga sumber log yang belum tervalidasi tetap terlihat lengkap.

Yang dibuang:
  - blok `fields` (duplikat `_source`), kecuali field yang TIDAK ada di `_source`
    (mis. runtime field) -> tetap ditampilkan di bagian "EXTRA FROM fields"
  - `signal.*` (salinan legacy dari kibana.alert.*)
  - investigation guide: setiap key `note`, `setup`
  - `kibana.alert.rule.parameters.*` (duplikat kibana.alert.rule.*), KECUALI `query`
  - `kibana.alert.ancestors` (artefak agregasi) -> diganti jumlah entri
  - metadata index: `_index`, `_id`, `_version`, `_score`
  - nilai kosong: null, "", [], {}

Pemakaian:
  python3 clean_alert.py <file.json> [<file2.json> ...]
Input boleh: 1 dokumen alert, array dokumen, NDJSON, atau objek {"hits":{"hits":[...]}}.
"""
import json
import sys

DROP_PREFIXES = ("signal.",)
DROP_LEAF_NAMES = {"note", "setup"}
META_KEYS = {"_index", "_id", "_version", "_score", "_ignored", "sort", "highlight"}
PARAMS_PREFIX = "kibana.alert.rule.parameters."
PARAMS_KEEP = {"query"}
MULTIFIELD_SUFFIXES = (".text", ".keyword", ".caseless")

def is_empty(v):
    return v is None or v == "" or v == [] or v == {}

def flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict) and v:
                out.update(flatten(v, key))
            else:
                out[key] = v
    return out

def should_drop(key):
    if key.startswith(DROP_PREFIXES):
        return "signal.* (legacy)"
    leaf = key.rsplit(".", 1)[-1]
    if leaf in DROP_LEAF_NAMES:
        return "investigation guide/setup"
    if key.startswith(PARAMS_PREFIX):
        sub = key[len(PARAMS_PREFIX):]
        if sub.split(".")[0] not in PARAMS_KEEP:
            return "rule.parameters (duplikat)"
    if key == "kibana.alert.ancestors" or key.startswith("kibana.alert.ancestors."):
        return "ancestors"
    return None

def unwrap(v):
    if isinstance(v, list) and len(v) == 1:
        return v[0]
    return v

def load_docs(path):
    raw = open(path, encoding="utf-8").read()
    try:
        data = json.loads(raw)
        docs = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        docs = [json.loads(l) for l in raw.splitlines() if l.strip()]
    flat = []
    for d in docs:
        if isinstance(d, dict) and isinstance(d.get("hits"), dict):
            flat.extend(d["hits"].get("hits", []))
        else:
            flat.append(d)
    return raw, flat

def clean_doc(doc):
    src = doc.get("_source")
    fields = doc.get("fields") or {}
    if src is None:
        src = {k: v for k, v in doc.items() if k not in META_KEYS and k != "fields"}
        if not src and fields:  # ekspor yang hanya berisi `fields`
            src = {k: unwrap(v) for k, v in fields.items()
                   if not (k.endswith(MULTIFIELD_SUFFIXES)
                           and k.rsplit(".", 1)[0] in fields)}
            fields = {}

    flat = flatten(src)
    kept, dropped = {}, {}
    ancestors_n = None
    for k, v in flat.items():
        if k == "kibana.alert.ancestors" and isinstance(v, list):
            ancestors_n = len(v)
        reason = should_drop(k)
        if reason:
            dropped[reason] = dropped.get(reason, 0) + 1
            continue
        if is_empty(v):
            dropped["nilai kosong"] = dropped.get("nilai kosong", 0) + 1
            continue
        kept[k] = v

    # field di `fields` yang tidak ada padanannya di _source
    extra = {}
    src_keys = set(flat.keys())
    for k, v in fields.items():
        if should_drop(k) or is_empty(v):
            continue
        base = k
        for suf in MULTIFIELD_SUFFIXES:
            if base.endswith(suf):
                base = base[: -len(suf)]
        if base in src_keys or any(sk.startswith(base + ".") for sk in src_keys):
            continue
        # cocokkan juga dengan prefix list-of-object di _source (mis. kibana.alert.rule.threat.*)
        if any(base.startswith(sk + ".") for sk in src_keys):
            continue
        extra[k] = unwrap(v)
    return kept, extra, dropped, ancestors_n

def fmt(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))

def main(paths):
    for path in paths:
        raw, docs = load_docs(path)
        out_lines = [f"### FILE: {path} | {len(docs)} dokumen alert"]
        for i, doc in enumerate(docs, 1):
            kept, extra, dropped, anc = clean_doc(doc)
            out_lines.append(f"## ALERT {i}")
            for k in sorted(kept):
                out_lines.append(f"{k} = {fmt(kept[k])}")
            if extra:
                out_lines.append("## EXTRA FROM fields (tidak ada di _source)")
                for k in sorted(extra):
                    out_lines.append(f"{k} = {fmt(extra[k])}")
            if anc is not None:
                out_lines.append(f"## kibana.alert.ancestors: {anc} entri (dibuang, artefak agregasi)")
            if dropped:
                out_lines.append("## DIBUANG: " + ", ".join(f"{r}={n}" for r, n in dropped.items()))
        text = "\n".join(out_lines)
        print(text)
        print(f"## UKURAN: asli {len(raw):,} karakter -> ringkas {len(text):,} karakter "
              f"({100 - 100 * len(text) / max(len(raw), 1):.0f}% lebih kecil)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Use: python3 clean_alert.py <file.json> [...]")
    main(sys.argv[1:])
