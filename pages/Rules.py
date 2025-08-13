import streamlit as st
from utils import format_permission_name, format_feature_name

st.set_page_config(page_title="Rules • APK Analysis Tool", page_icon="⚖️", layout="wide")


def inject_css():
    st.markdown(
        """
        <style>
        .rule-card { border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:1rem 1.25rem; margin-bottom:1rem; }
        .group-title { font-weight:800; font-size:1.05rem; margin:.25rem 0 .5rem 0; }
        .chip { display:inline-block; padding:.15rem .5rem; border-radius:999px; background:var(--secondaryBackgroundColor); margin-right:.35rem; font-size:.8rem; }
        .small { color:#94a3b8; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main():
    inject_css()

    st.markdown("<span class='chip'>Reference</span>", unsafe_allow_html=True)
    st.title("⚖️ Analysis Rules")
    st.caption("All validations and heuristics applied to your APKs.")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("<div class='rule-card'>", unsafe_allow_html=True)
        st.markdown("<div class='group-title'>Security Flags</div>", unsafe_allow_html=True)
        st.write("• Risky permissions: INTERNET; WRITE/READ/MANAGE_EXTERNAL_STORAGE")
        st.write("• Target SDK must be API 29")
        st.write("• Architecture should include 'armeabi-v7a'")
        st.write("• OpenGL ES expected version 2.0")
        st.write("• Unity export: main activity with android:exported='true' required for Unity apps")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='rule-card'>", unsafe_allow_html=True)
        st.markdown("<div class='group-title'>Permission Heuristics</div>", unsafe_allow_html=True)
        st.write("• Risk tiers based on sensitive permissions (contacts, calendar, location, audio, camera, phone, SMS, storage, overlays, settings)")
        st.write("• Implied permissions: WRITE_EXTERNAL_STORAGE ⇒ READ_EXTERNAL_STORAGE; ACCESS_FINE_LOCATION ⇒ ACCESS_COARSE_LOCATION")
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("<div class='rule-card'>", unsafe_allow_html=True)
        st.markdown("<div class='group-title'>Signature Validation</div>", unsafe_allow_html=True)
        st.write("• Certificate fields captured: subject/CN, validity period, algorithm")
        st.write("• Fingerprints: SHA‑256, SHA‑1, MD5 (colon‑formatted)")
        st.write("• Expected signer/date/SHA‑256 compared; mismatches flagged")
        st.write("• Signature schemes: v1/v2/v3/v3.1/v4 status")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='rule-card'>", unsafe_allow_html=True)
        st.markdown("<div class='group-title'>Feature Mapping</div>", unsafe_allow_html=True)
        st.write("• Permissions ⇒ Features mapping (camera, GPS/network location, microphone, bluetooth, wifi)")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.caption("Note: These rules are derived from `app.py`, `apk_analyzer.py`, `signature_analyzer.py`, and `utils.py`.")


if __name__ == "__main__":
    main()


