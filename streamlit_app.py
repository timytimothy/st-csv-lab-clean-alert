"""
streamlit_app.py - Antarmuka web untuk clean_alert.py.
Tempel JSON alert di kotak teks, klik tombol, hasil ringkas muncul.
clean_alert.py harus berada di folder yang sama dan tidak perlu diubah.
"""
import json

import streamlit as st

from clean_alert import clean_doc, fmt

st.set_page_config(page_title="Alert Cleaner", layout="wide")
st.title("Alert Cleaner (Elastic Security)")
st.caption(
    "Tempel JSON alert (1 dokumen, array, NDJSON, atau hasil {\"hits\":{\"hits\":[...]}}) "
    "lalu klik Ringkas."
)


def parse_docs(raw: str):
    """Sama seperti load_docs() di clean_alert.py, tetapi dari teks, bukan file."""
    try:
        data = json.loads(raw)
        docs = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        docs = [json.loads(line) for line in raw.splitlines() if line.strip()]
    flat = []
    for d in docs:
        if isinstance(d, dict) and isinstance(d.get("hits"), dict):
            flat.extend(d["hits"].get("hits", []))
        else:
            flat.append(d)
    return flat


def build_text(raw: str) -> str:
    docs = parse_docs(raw)
    out = [f"### {len(docs)} dokumen alert"]
    for i, doc in enumerate(docs, 1):
        kept, extra, dropped, anc = clean_doc(doc)
        out.append(f"## ALERT {i}")
        for k in sorted(kept):
            out.append(f"{k} = {fmt(kept[k])}")
        if extra:
            out.append("## EXTRA FROM fields (tidak ada di _source)")
            for k in sorted(extra):
                out.append(f"{k} = {fmt(extra[k])}")
        if anc is not None:
            out.append(f"## kibana.alert.ancestors: {anc} entri (dibuang, artefak agregasi)")
        if dropped:
            out.append("## DIBUANG: " + ", ".join(f"{r}={n}" for r, n in dropped.items()))
    text = "\n".join(out)
    saved = 100 - 100 * len(text) / max(len(raw), 1)
    text += f"\n## UKURAN: asli {len(raw):,} karakter -> ringkas {len(text):,} karakter ({saved:.0f}% lebih kecil)"
    return text


raw = st.text_area("JSON alert", height=300, placeholder="Tempel JSON di sini...")

with st.expander("Atau unggah file .json"):
    uploaded = st.file_uploader("File alert", type=["json", "ndjson", "txt"])
    if uploaded is not None:
        raw = uploaded.read().decode("utf-8")

if st.button("Ringkas", type="primary"):
    if not raw.strip():
        st.warning("Isi JSON terlebih dahulu.")
    else:
        try:
            result = build_text(raw)
        except Exception as e:
            st.error(f"Gagal memproses: {e}")
        else:
            st.subheader("Hasil")
            st.code(result, language=None)  # ada tombol copy di pojok kanan atas
            st.download_button("Unduh .txt", result, file_name="alert_ringkas.txt")
