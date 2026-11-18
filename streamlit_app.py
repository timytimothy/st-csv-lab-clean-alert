"""
streamlit_app.py - Web interface for clean_alert.py.
Paste the alert JSON into the text box, click Summarize, and the cleaned result appears.
clean_alert.py must be in the same folder and does not need to be modified.
"""
import json

import streamlit as st
import streamlit.components.v1 as components

from clean_alert import clean_doc, fmt

# English labels for the drop reasons defined in clean_alert.py
REASON_EN = {
    "signal.* (legacy)": "signal.* (legacy)",
    "investigation guide/setup": "investigation guide/setup",
    "rule.parameters (duplikat)": "rule.parameters (duplicate)",
    "ancestors": "ancestors",
    "nilai kosong": "empty values",
}

st.set_page_config(page_title="Alert Cleaner", layout="wide")
st.title("Alert Cleaner (Elastic Security)")
st.caption(
    "Paste alert JSON (single document, array, NDJSON, or a {\"hits\":{\"hits\":[...]}} response), "
    "then click Summarize."
)


def parse_docs(raw: str):
    """Same as load_docs() in clean_alert.py, but reads from text instead of a file."""
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
    out = [f"### {len(docs)} alert document(s)"]
    for i, doc in enumerate(docs, 1):
        kept, extra, dropped, anc = clean_doc(doc)
        out.append(f"## ALERT {i}")
        for k in sorted(kept):
            out.append(f"{k} = {fmt(kept[k])}")
        if extra:
            out.append("## EXTRA FROM fields (not present in _source)")
            for k in sorted(extra):
                out.append(f"{k} = {fmt(extra[k])}")
        if anc is not None:
            out.append(f"## kibana.alert.ancestors: {anc} entries (dropped, aggregation artifact)")
        if dropped:
            out.append(
                "## DROPPED: "
                + ", ".join(f"{REASON_EN.get(r, r)}={n}" for r, n in dropped.items())
            )
    text = "\n".join(out)
    saved = 100 - 100 * len(text) / max(len(raw), 1)
    text += (
        f"\n## SIZE: original {len(raw):,} characters -> summarized {len(text):,} characters "
        f"({saved:.0f}% smaller)"
    )
    return text


def copy_button(text: str):
    """Render a button that copies `text` to the clipboard."""
    payload = json.dumps(text).replace("</", "<\\/")
    components.html(
        f"""
        <button id="copy-btn" style="
            font-family: sans-serif; font-size: 14px; padding: 8px 16px;
            border: 1px solid #ccc; border-radius: 8px; background: #fff;
            cursor: pointer;">Copy to clipboard</button>
        <script>
        const text = {payload};
        const btn = document.getElementById("copy-btn");
        function done(ok) {{
            btn.textContent = ok ? "Copied!" : "Copy failed - select and copy manually";
            setTimeout(() => btn.textContent = "Copy to clipboard", 2000);
        }}
        btn.addEventListener("click", async () => {{
            try {{
                await navigator.clipboard.writeText(text);
                done(true);
            }} catch (e) {{
                const ta = document.createElement("textarea");
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                let ok = false;
                try {{ ok = document.execCommand("copy"); }} catch (_) {{}}
                document.body.removeChild(ta);
                done(ok);
            }}
        }});
        </script>
        """,
        height=50,
    )


raw = st.text_area("Alert JSON", height=300, placeholder="Paste JSON here...")

with st.expander("Or upload a .json file"):
    uploaded = st.file_uploader("Alert file", type=["json", "ndjson", "txt"])
    if uploaded is not None:
        raw = uploaded.read().decode("utf-8")

if st.button("Summarize", type="primary"):
    if not raw.strip():
        st.warning("Please provide some JSON first.")
    else:
        try:
            st.session_state["result"] = build_text(raw)
        except Exception as e:
            st.session_state.pop("result", None)
            st.error(f"Failed to process input: {e}")

result = st.session_state.get("result")
if result:
    st.subheader("Result")
    col1, col2, _ = st.columns([1, 1, 4])
    with col1:
        copy_button(result)
    with col2:
        st.download_button("Download .txt", result, file_name="alert_summary.txt")
    st.code(result, language=None)
