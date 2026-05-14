"""
app.py — Streamlit UI for Chaos-Based Hybrid Cryptography System
Run with:  streamlit run app.py
"""

import io
import base64
import json
import hashlib

import numpy as np
import streamlit as st
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from PIL import Image

# ── page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="ChaosLock — Hybrid Cryptography",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── custom CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap');

    html, body, [class*="css"] { font-family: 'Exo 2', sans-serif; }

    /* Dark cyber background */
    .stApp { background: #080c14; color: #c8d8f0; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #0d1424;
        border-right: 1px solid #1e3a5f;
    }

    /* Headers */
    h1 { font-family: 'Exo 2', sans-serif; font-weight: 800;
         background: linear-gradient(90deg, #00c8ff, #7b61ff);
         -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    h2 { color: #00c8ff; font-weight: 600; border-bottom: 1px solid #1e3a5f; padding-bottom: 6px; }
    h3 { color: #7b61ff; }

    /* Metric cards */
    [data-testid="metric-container"] {
        background: #0d1424;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 10px;
    }

    /* Code blocks */
    code, pre { font-family: 'Share Tech Mono', monospace !important;
                background: #0d1424 !important; color: #00e5a0 !important; }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #00c8ff22, #7b61ff22);
        border: 1px solid #00c8ff66;
        color: #00c8ff;
        border-radius: 6px;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 1px;
        transition: all .2s;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #00c8ff44, #7b61ff44);
        border-color: #00c8ff;
        color: #fff;
    }

    /* Text areas / inputs */
    textarea, input[type="text"] {
        background: #0d1424 !important;
        border: 1px solid #1e3a5f !important;
        color: #c8d8f0 !important;
        font-family: 'Share Tech Mono', monospace !important;
    }

    /* Info / success boxes */
    .stAlert { border-radius: 6px; }

    /* Horizontal divider */
    hr { border-color: #1e3a5f; }

    /* Tab labels */
    .stTabs [data-baseweb="tab"] { color: #7b8da8; font-family: 'Exo 2', sans-serif; }
    .stTabs [aria-selected="true"] { color: #00c8ff !important; border-bottom: 2px solid #00c8ff; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── project imports (after sys-path is correct) ───────────────────────────────
from chaos import logistic_map, apply_chaos_mask
from text_crypto import encrypt_text, decrypt_text, payload_to_json
from image_crypto import (
    encrypt_image,
    decrypt_image,
    chaos_image_from_payload,
    pil_to_array,
)
from rsa_util import generate_rsa_keypair, export_keys
from Crypto.PublicKey import RSA


# ── session state: one RSA key-pair per session ───────────────────────────────
if "rsa_keys" not in st.session_state:
    with st.spinner("🔑 Generating RSA-2048 key pair …"):
        priv, pub = generate_rsa_keypair()
        st.session_state.rsa_keys = (priv, pub)

PRIVATE_KEY, PUBLIC_KEY = st.session_state.rsa_keys


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🔐 ChaosLock")
    st.markdown("*Chaos-Based Hybrid Cryptography*")
    st.markdown("---")

    page = st.radio(
        "Navigate",
        ["🏠 Home", "📝 Text Encryption", "🖼️ Image Encryption", "🌐 Network Demo", "📊 Visualisation"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("### ⚙️ Chaos Parameters")
    chaos_r = st.slider("r (Logistic Map)", 3.7, 4.0, 3.99, 0.001,
                        help="Control parameter — values near 4.0 give fully chaotic behaviour")
    chaos_x0 = st.slider("x₀ (Initial Seed)", 0.01, 0.99, 0.5, 0.01,
                          help="Initial condition; tiny changes give completely different sequences")

    st.markdown("---")
    priv_pem, pub_pem = export_keys(PRIVATE_KEY, PUBLIC_KEY)
    with st.expander("🔑 Session RSA Keys"):
        st.code(pub_pem.decode()[:300] + "\n…", language="text")
        pub_fingerprint = hashlib.sha256(pub_pem).hexdigest()
        st.caption(f"Public key fingerprint (SHA-256): {pub_fingerprint[:16]}…{pub_fingerprint[-16:]}")

        st.download_button(
            "⬇️ Download public key (PEM)",
            data=pub_pem,
            file_name="public_key.pem",
            mime="application/x-pem-file",
            key="download_public_key_pem",
        )
        st.download_button(
            "⬇️ Download private key (PEM)",
            data=priv_pem,
            file_name="private_key.pem",
            mime="application/x-pem-file",
            key="download_private_key_pem",
        )

        st.markdown("---")
        st.markdown("**Import private key (optional)**")
        st.caption("Use this to decrypt payloads generated in a previous session.")
        key_upload = st.file_uploader(
            "Upload RSA private key (PEM)",
            type=["pem", "key"],
            key="upload_private_key_pem",
        )
        if key_upload is not None:
            try:
                imported_priv = RSA.import_key(key_upload.getvalue())
                imported_pub = imported_priv.publickey()
                st.session_state.rsa_keys = (imported_priv, imported_pub)
                st.success("✅ Private key imported for this session.")
                st.info("If you were viewing another page, re-open it to use the imported key.")
                st.rerun()
            except Exception as e:
                st.error(f"Invalid private key file: {e}")

        if st.button("♻️ Generate new RSA keypair", key="regen_rsa_keys"):
            with st.spinner("Generating RSA-2048 key pair …"):
                priv, pub = generate_rsa_keypair()
                st.session_state.rsa_keys = (priv, pub)
            st.success("✅ New keypair generated.")
            st.rerun()
    st.caption("Keys are freshly generated each session and never stored.")


# ═══════════════════════════════════════════════════════════════════════════════
# HOME PAGE
# ═══════════════════════════════════════════════════════════════════════════════
if page == "🏠 Home":
    st.title("ChaosLock")
    st.subheader("Chaos-Based Hybrid Encryption for Text & Images")

    st.markdown(
        """
        This system combines three independent security layers to protect data in transit:

        | Layer | Technique | Role |
        |-------|-----------|------|
        | 1 | Logistic-Map Chaos Masking | Makes data statistically random before encryption |
        | 2 | AES-256-CBC | Symmetric bulk encryption (fast, strong) |
        | 3 | RSA-2048-OAEP | Asymmetric key exchange (secure AES key delivery) |
        """
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 📝 Text Encryption Flow")
        st.code(
            "Plaintext\n  ↓ Chaos XOR Mask\nScrambled\n  ↓ AES-256-CBC\nCiphertext\n"
            "  ↓ RSA-2048 (AES key)\nSecure Payload",
            language="text",
        )
    with col2:
        st.markdown("### 🖼️ Image Encryption Flow")
        st.code(
            "Original Image\n  ↓ Chaos Pixel XOR\nScrambled Image\n  ↓ AES-256-CBC\n"
            "Encrypted Bytes\n  ↓ RSA-2048 (AES key)\nSecure Payload",
            language="text",
        )

    st.markdown("---")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("AES Key Size", "256 bit")
    c2.metric("RSA Key Size", "2048 bit")
    c3.metric("Chaos Layers", "1 (XOR)")
    c4.metric("Total Layers", "3")

    st.markdown("---")
    st.markdown("### 🌍 Real-World Applications")
    apps = [
        "🏥 Medical image protection",
        "🏦 Banking & fintech",
        "🪖 Military communications",
        "☁️ Cloud data security",
        "📡 IoT device messaging",
        "💬 Secure chat systems",
    ]
    for i in range(0, len(apps), 3):
        cols = st.columns(3)
        for j, col in enumerate(cols):
            if i + j < len(apps):
                col.success(apps[i + j])


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT ENCRYPTION PAGE
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "📝 Text Encryption":
    st.title("📝 Text Encryption")

    st.markdown("### Step 1 — Enter your message")
    message = st.text_area("Plaintext message", height=120,
                            placeholder="Type anything here …")

    if st.button("🔒 ENCRYPT", disabled=not message.strip()):
        with st.spinner("Encrypting …"):
            payload = encrypt_text(message, PUBLIC_KEY, r=chaos_r, x0=chaos_x0)
            st.session_state.text_payload = payload
            st.session_state.text_original = message
        st.success("✅ Encryption complete!")

    if "text_payload" in st.session_state:
        payload = st.session_state.text_payload
        st.markdown("---")
        st.markdown("### Step 2 — Encrypted Layers")

        tab1, tab2, tab3 = st.tabs(["Layer 1 — Chaos Masked", "Layer 2 — AES Ciphertext", "Layer 3 — RSA-Encrypted Key"])

        with tab1:
            masked_bytes = base64.b64decode(payload["chaos_masked_b64"])
            st.markdown("**Chaos-masked bytes** (hex preview):")
            st.code(masked_bytes.hex()[:200] + " …", language="text")

        with tab2:
            ct_bytes = base64.b64decode(payload["ciphertext_b64"])
            st.markdown("**AES-256-CBC ciphertext** (base64):")
            st.code(payload["ciphertext_b64"][:200] + " …", language="text")
            st.caption(f"Ciphertext size: {len(ct_bytes)} bytes")

        with tab3:
            st.markdown("**RSA-2048 encrypted AES key** (base64):")
            st.code(payload["enc_aes_key_b64"], language="text")

        st.markdown("#### Full JSON Payload")
        st.json(payload)

        st.markdown("---")
        st.markdown("### Step 3 — Download Payload + Key")
        st.caption(
            "To make decryption feel more realistic, download the encrypted payload and the RSA private key. "
            "Then upload them below to decrypt."
        )

        payload_json_bytes = payload_to_json(payload).encode("utf-8")
        suggested_payload_name = "encrypted_text_payload.json"
        if payload.get("created_at"):
            ts = payload["created_at"].replace(":", "-").replace("Z", "")
            suggested_payload_name = f"encrypted_text_payload_{ts}.json"

        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "⬇️ Download encrypted payload (.json)",
                data=payload_json_bytes,
                file_name=suggested_payload_name,
                mime="application/json",
                key="download_text_payload_json",
            )
        with d2:
            priv_pem_for_text, _pub_pem_for_text = export_keys(PRIVATE_KEY, PUBLIC_KEY)
            st.download_button(
                "⬇️ Download RSA private key (.pem)",
                data=priv_pem_for_text,
                file_name="private_key.pem",
                mime="application/x-pem-file",
                key="download_text_private_key_pem",
            )

        st.markdown("---")
        st.markdown("### Step 4 — Decrypt by Uploading Files")
        st.caption("Upload the payload JSON and the matching RSA private key PEM to recover the original message.")

        up_payload = st.file_uploader(
            "Upload encrypted payload (JSON)",
            type=["json"],
            key="text_payload_upload",
        )
        up_priv = st.file_uploader(
            "Upload RSA private key (PEM)",
            type=["pem", "key"],
            key="text_private_key_upload",
        )

        uploaded_payload = None
        if up_payload is not None:
            try:
                uploaded_payload = json.loads(up_payload.getvalue().decode("utf-8"))
                required = {"iv_b64", "ciphertext_b64", "enc_aes_key_b64", "chaos_r", "chaos_x0"}
                missing = sorted(required.difference(uploaded_payload.keys()))
                if missing:
                    st.error(f"Invalid payload file — missing keys: {', '.join(missing)}")
                    uploaded_payload = None
            except Exception as e:
                st.error(f"Could not read JSON payload: {e}")

        uploaded_priv = None
        if up_priv is not None:
            try:
                uploaded_priv = RSA.import_key(up_priv.getvalue())
            except Exception as e:
                st.error(f"Invalid private key file: {e}")

        can_decrypt = uploaded_payload is not None and uploaded_priv is not None
        if st.button("🔓 DECRYPT (from uploads)", disabled=not can_decrypt, key="decrypt_text_from_uploads"):
            with st.spinner("Decrypting uploaded payload …"):
                try:
                    recovered = decrypt_text(uploaded_payload, uploaded_priv)
                    st.session_state.text_recovered_uploaded = recovered
                    st.success("✅ Decryption successful!")
                except Exception as e:
                    st.error(f"Decryption failed: {e}")

        if "text_recovered_uploaded" in st.session_state:
            st.markdown("**Recovered message:**")
            st.info(st.session_state.text_recovered_uploaded)

            if "text_original" in st.session_state:
                match = st.session_state.text_recovered_uploaded == st.session_state.text_original
                if match:
                    st.success("✅ Original and recovered messages match.")
                else:
                    st.warning("Recovered text doesn't match the last message encrypted in this session.")


# ═══════════════════════════════════════════════════════════════════════════════
# IMAGE ENCRYPTION PAGE
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "🖼️ Image Encryption":
    st.title("🖼️ Image Encryption")

    uploaded = st.file_uploader("Upload an image", type=["png", "jpg", "jpeg", "bmp", "webp"])

    st.markdown("---")
    st.markdown("### 🔓 Decrypt an Encrypted Image (Payload Upload)")
    st.caption(
        "Upload a previously downloaded encrypted payload (.json) to decrypt and display the image. "
        "Note: decryption works only with the matching RSA private key (this app generates a new key each session)."
    )

    encrypted_upload = st.file_uploader(
        "Upload encrypted payload (JSON)",
        type=["json"],
        key="encrypted_image_payload_uploader",
    )

    uploaded_payload = None
    if encrypted_upload is not None:
        try:
            uploaded_payload = json.loads(encrypted_upload.getvalue().decode("utf-8"))
            required = {"iv_b64", "ciphertext_b64", "enc_aes_key_b64", "chaos_r", "chaos_x0", "chaos_img_b64"}
            missing = sorted(required.difference(uploaded_payload.keys()))
            if missing:
                st.error(f"Invalid payload file — missing keys: {', '.join(missing)}")
                uploaded_payload = None
        except Exception as e:
            st.error(f"Could not read JSON payload: {e}")
            uploaded_payload = None

    if uploaded_payload is not None:
        col_u1, col_u2 = st.columns(2)
        with col_u1:
            st.markdown("#### Encrypted (Chaos-Scrambled Preview)")
            try:
                uploaded_chaos = chaos_image_from_payload(uploaded_payload)
                st.image(uploaded_chaos, use_container_width=True)
            except Exception:
                st.info("Payload loaded, but preview image could not be rendered.")

        with col_u2:
            st.markdown("#### Decrypted Result")
            if st.button("🔓 DECRYPT UPLOADED PAYLOAD", key="decrypt_uploaded_payload"):
                with st.spinner("Decrypting uploaded payload …"):
                    try:
                        recovered_from_upload = decrypt_image(uploaded_payload, PRIVATE_KEY)
                        st.session_state.img_recovered_from_upload = recovered_from_upload
                        st.success("✅ Decryption successful!")
                    except Exception as e:
                        st.error(f"Decryption failed: {e}")

            if "img_recovered_from_upload" in st.session_state:
                st.image(st.session_state.img_recovered_from_upload, use_container_width=True)

    if uploaded:
        img = Image.open(uploaded).convert("RGB")
        arr_orig = pil_to_array(img)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Original Image")
            st.image(img, use_container_width=True)
            st.caption(f"Size: {img.width}×{img.height} px | Mode: RGB")

        if st.button("🔒 ENCRYPT IMAGE"):
            with st.spinner("Encrypting image …"):
                payload = encrypt_image(img, PUBLIC_KEY, r=chaos_r, x0=chaos_x0)
                st.session_state.img_payload = payload
                st.session_state.img_original = img
            st.success("✅ Image encryption complete!")

        if "img_payload" in st.session_state:
            payload = st.session_state.img_payload

            st.markdown("---")
            st.markdown("### ⬇️ Download Encrypted Image")
            st.caption("Downloads the full encrypted payload (JSON). You can upload this file above to decrypt.")

            suggested_name = "encrypted_image_payload.json"
            if getattr(uploaded, "name", None):
                base = uploaded.name.rsplit(".", 1)[0]
                suggested_name = f"{base}.encrypted.json"

            st.download_button(
                "⬇️ Download encrypted payload (.json)",
                data=json.dumps(payload, indent=2).encode("utf-8"),
                file_name=suggested_name,
                mime="application/json",
                key="download_encrypted_payload",
            )

            # Chaos scrambled image
            chaos_pil = chaos_image_from_payload(payload)
            with col2:
                st.markdown("#### Chaos-Scrambled Image")
                st.image(chaos_pil, use_container_width=True)
                st.caption("After Layer 1 (chaos XOR) — visually unrecognisable")

            st.markdown("---")
            st.markdown("#### AES Ciphertext (hex preview)")
            ct_bytes = base64.b64decode(payload["ciphertext_b64"])
            st.code(ct_bytes.hex()[:300] + " …", language="text")
            st.caption(f"Total AES-encrypted bytes: {len(ct_bytes):,}")

            # Histogram comparison
            st.markdown("---")
            st.markdown("#### 📊 Histogram Analysis")
            arr_chaos = pil_to_array(chaos_pil)

            fig, axes = plt.subplots(1, 2, figsize=(12, 3),
                                      facecolor="#080c14", tight_layout=True)
            colors = {"Original": "#00c8ff", "Chaos Encrypted": "#7b61ff"}
            for ax, (label, arr) in zip(
                axes,
                [("Original", arr_orig), ("Chaos Encrypted", arr_chaos)],
            ):
                ax.set_facecolor("#0d1424")
                for ch, col in zip(range(3), ["#ff4c6e", "#00e5a0", "#4c9eff"]):
                    ax.hist(arr[:, :, ch].ravel(), bins=64, alpha=0.7, color=col,
                            histtype="stepfilled", linewidth=0)
                ax.set_title(label, color="#c8d8f0", fontsize=11)
                ax.tick_params(colors="#556070")
                for spine in ax.spines.values():
                    spine.set_edgecolor("#1e3a5f")
            st.pyplot(fig)
            st.caption(
                "The encrypted histogram is nearly flat — indicating high entropy (randomness), "
                "a hallmark of strong encryption."
            )

            # NPCR / UACI (common image-encryption metrics)
            st.markdown("---")
            st.markdown("#### 🔬 NPCR / UACI (Image Encryption Metrics)")

            def npcr_uaci(a: np.ndarray, b: np.ndarray) -> tuple[float, float]:
                if a.shape != b.shape:
                    raise ValueError("Shape mismatch")
                a16 = a.astype(np.int16)
                b16 = b.astype(np.int16)
                diff = np.abs(a16 - b16)
                npcr = float(np.mean(diff != 0) * 100.0)
                uaci = float(np.mean(diff) / 255.0 * 100.0)
                return npcr, uaci

            try:
                npcr_val, uaci_val = npcr_uaci(arr_orig, arr_chaos)
                m1, m2 = st.columns(2)
                m1.metric("NPCR", f"{npcr_val:.2f}%", help="% of pixel values that changed after encryption")
                m2.metric("UACI", f"{uaci_val:.2f}%", help="Average intensity difference after encryption")
            except Exception as e:
                st.info(f"NPCR/UACI not available: {e}")

            # Adjacent pixel correlation (horizontal/vertical/diagonal)
            st.markdown("---")
            st.markdown("#### 📐 Adjacent Pixel Correlation")

            def corr_adjacent(arr: np.ndarray, direction: str) -> float:
                a = arr.astype(np.float64)
                if a.ndim == 3:
                    a = a.mean(axis=2)  # grayscale for correlation metric
                if direction == "H":
                    x = a[:, :-1].ravel()
                    y = a[:, 1:].ravel()
                elif direction == "V":
                    x = a[:-1, :].ravel()
                    y = a[1:, :].ravel()
                elif direction == "D":
                    x = a[:-1, :-1].ravel()
                    y = a[1:, 1:].ravel()
                else:
                    raise ValueError("direction must be H, V, or D")
                if x.size < 2:
                    return float("nan")
                return float(np.corrcoef(x, y)[0, 1])

            try:
                c_orig_h, c_orig_v, c_orig_d = (
                    corr_adjacent(arr_orig, "H"),
                    corr_adjacent(arr_orig, "V"),
                    corr_adjacent(arr_orig, "D"),
                )
                c_enc_h, c_enc_v, c_enc_d = (
                    corr_adjacent(arr_chaos, "H"),
                    corr_adjacent(arr_chaos, "V"),
                    corr_adjacent(arr_chaos, "D"),
                )
                cc1, cc2, cc3 = st.columns(3)
                cc1.metric("Correlation (H)", f"{c_orig_h:.4f} → {c_enc_h:.4f}")
                cc2.metric("Correlation (V)", f"{c_orig_v:.4f} → {c_enc_v:.4f}")
                cc3.metric("Correlation (D)", f"{c_orig_d:.4f} → {c_enc_d:.4f}")
                st.caption("Good encryption reduces adjacent-pixel correlation toward 0.")
            except Exception as e:
                st.info(f"Correlation metrics not available: {e}")

            # Entropy
            def shannon_entropy(arr):
                flat = arr.ravel()
                hist, _ = np.histogram(flat, bins=256, range=(0, 255))
                hist = hist[hist > 0].astype(float)
                p = hist / hist.sum()
                return float(-np.sum(p * np.log2(p)))

            e_orig = shannon_entropy(arr_orig)
            e_enc = shannon_entropy(arr_chaos)
            c1, c2 = st.columns(2)
            c1.metric("Original Entropy", f"{e_orig:.4f} bits/symbol")
            c2.metric("Encrypted Entropy", f"{e_enc:.4f} bits/symbol",
                      delta=f"+{e_enc - e_orig:.4f}")

            # Decrypt
            st.markdown("---")
            if st.button("🔓 DECRYPT IMAGE"):
                with st.spinner("Decrypting …"):
                    recovered_img = decrypt_image(payload, PRIVATE_KEY)
                    st.session_state.img_recovered = recovered_img
                st.success("✅ Image decrypted successfully!")

            if "img_recovered" in st.session_state:
                st.markdown("#### Recovered Image")
                st.image(st.session_state.img_recovered, use_container_width=True)
                st.success("✅ Image perfectly recovered from the encrypted payload.")


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK DEMO PAGE
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "🌐 Network Demo":
    st.title("🌐 Network Demo")
    st.caption(
        "This simulates sending encrypted payloads over a network and demonstrates two security properties: "
        "(1) tamper detection via HMAC integrity checks, and (2) replay detection via nonce reuse."
    )

    if "seen_nonces" not in st.session_state:
        st.session_state.seen_nonces = set()

    source = st.selectbox(
        "Choose a payload to transmit",
        ["Text payload (latest)", "Image payload (latest)", "Upload payload JSON"],
    )

    payload = None
    payload_kind = None

    if source == "Text payload (latest)":
        payload = st.session_state.get("text_payload")
        payload_kind = "text"
        if payload is None:
            st.info("No text payload yet. Go to 📝 Text Encryption and click ENCRYPT.")

    elif source == "Image payload (latest)":
        payload = st.session_state.get("img_payload")
        payload_kind = "image"
        if payload is None:
            st.info("No image payload yet. Go to 🖼️ Image Encryption and click ENCRYPT IMAGE.")

    else:
        up = st.file_uploader("Upload any payload JSON", type=["json"], key="netdemo_payload_upload")
        if up is not None:
            try:
                payload = json.loads(up.getvalue().decode("utf-8"))
                # Guess kind by fields
                payload_kind = "image" if "shape" in payload else "text"
            except Exception as e:
                st.error(f"Could not read JSON payload: {e}")

    if payload is not None:
        st.markdown("---")
        st.markdown("### 📦 Payload")
        st.json(payload)

        nonce_b64 = payload.get("nonce_b64")
        if nonce_b64:
            st.caption(f"Nonce (for replay detection): {nonce_b64[:12]}…")
        else:
            st.warning("This payload has no nonce; replay detection will be limited.")

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("📨 SEND", key="netdemo_send"):
                # Receiver checks replay
                if nonce_b64 and nonce_b64 in st.session_state.seen_nonces:
                    st.error("🚫 Replay detected: this nonce has already been received.")
                else:
                    if nonce_b64:
                        st.session_state.seen_nonces.add(nonce_b64)
                    st.session_state.net_last_received = payload
                    st.success("✅ Payload delivered to receiver.")

        with c2:
            if st.button("🧪 TAMPER (flip 1 byte)", key="netdemo_tamper"):
                tampered = dict(payload)
                try:
                    ct = base64.b64decode(tampered["ciphertext_b64"])
                    if len(ct) == 0:
                        raise ValueError("Empty ciphertext")
                    mutated = bytes([ct[0] ^ 0x01]) + ct[1:]
                    tampered["ciphertext_b64"] = base64.b64encode(mutated).decode()
                    st.session_state.net_last_received = tampered
                    st.warning("⚠️ Sent a tampered payload to receiver.")
                except Exception as e:
                    st.error(f"Could not tamper payload: {e}")

        with c3:
            if st.button("♻️ REPLAY LAST", key="netdemo_replay"):
                last = st.session_state.get("net_last_received")
                if last is None:
                    st.info("Nothing received yet. Click SEND first.")
                else:
                    n = last.get("nonce_b64")
                    if n and n in st.session_state.seen_nonces:
                        st.error("🚫 Replay detected: this nonce has already been received.")
                    else:
                        if n:
                            st.session_state.seen_nonces.add(n)
                        st.success("✅ Replay accepted (nonce not seen).")

        st.markdown("---")
        st.markdown("### 🖥️ Receiver: Decrypt")
        received = st.session_state.get("net_last_received")
        if received is None:
            st.info("Receiver has no payload yet.")
        else:
            if st.button("🔓 Receiver Decrypt", key="netdemo_receiver_decrypt"):
                with st.spinner("Receiver decrypting …"):
                    try:
                        if payload_kind == "image":
                            out = decrypt_image(received, PRIVATE_KEY)
                            st.image(out, use_container_width=True)
                            st.success("✅ Receiver decrypted the image.")
                        else:
                            out = decrypt_text(received, PRIVATE_KEY)
                            st.success("✅ Receiver decrypted the text.")
                            st.info(out)
                    except Exception as e:
                        st.error(f"Receiver decrypt failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# VISUALISATION PAGE
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "📊 Visualisation":
    st.title("📊 Visualisation")

    # ── Chaotic Signal ──────────────────────────────────────────────────────
    st.markdown("### Logistic-Map Chaotic Signal")
    n_points = st.slider("Number of iterations", 50, 500, 200, 10)
    seq = logistic_map(chaos_r, chaos_x0, n_points)

    fig, ax = plt.subplots(figsize=(12, 3), facecolor="#080c14")
    ax.set_facecolor("#0d1424")
    ax.plot(seq, color="#00c8ff", linewidth=0.8)
    ax.fill_between(range(n_points), seq, alpha=0.15, color="#00c8ff")
    ax.set_xlabel("Iteration n", color="#556070")
    ax.set_ylabel("x(n)", color="#556070")
    ax.tick_params(colors="#556070")
    for spine in ax.spines.values():
        spine.set_edgecolor("#1e3a5f")
    ax.set_title(f"Logistic Map: r={chaos_r}, x₀={chaos_x0}", color="#c8d8f0")
    st.pyplot(fig)

    # ── Bifurcation Diagram ─────────────────────────────────────────────────
    st.markdown("### Bifurcation Diagram")
    st.caption("Shows how the system transitions from periodic to chaotic behaviour as *r* increases.")
    with st.spinner("Computing bifurcation …"):
        r_vals = np.linspace(2.5, 4.0, 800)
        bif_r, bif_x = [], []
        for r in r_vals:
            x = 0.5
            for _ in range(300):   # transient
                x = r * x * (1 - x)
            for _ in range(100):   # capture
                x = r * x * (1 - x)
                bif_r.append(r)
                bif_x.append(x)

    fig2, ax2 = plt.subplots(figsize=(12, 4), facecolor="#080c14")
    ax2.set_facecolor("#0d1424")
    ax2.scatter(bif_r, bif_x, s=0.05, c="#7b61ff", alpha=0.5)
    ax2.axvline(chaos_r, color="#00e5a0", linewidth=1.2, linestyle="--",
                label=f"Current r = {chaos_r:.3f}")
    ax2.set_xlabel("r", color="#556070")
    ax2.set_ylabel("x(n)", color="#556070")
    ax2.tick_params(colors="#556070")
    for spine in ax2.spines.values():
        spine.set_edgecolor("#1e3a5f")
    ax2.legend(facecolor="#0d1424", labelcolor="#c8d8f0", edgecolor="#1e3a5f")
    st.pyplot(fig2)

    # ── Byte Distribution ───────────────────────────────────────────────────
    st.markdown("### Chaos Byte Distribution")
    st.caption("A well-designed chaos sequence produces a nearly uniform byte distribution (0–255).")
    sample = (logistic_map(chaos_r, chaos_x0, 10_000) * 255).astype(np.uint8)

    fig3, ax3 = plt.subplots(figsize=(12, 3), facecolor="#080c14")
    ax3.set_facecolor("#0d1424")
    ax3.hist(sample, bins=64, color="#00c8ff", alpha=0.8, edgecolor="none")
    ax3.axhline(10_000 / 64, color="#ff4c6e", linewidth=1.2, linestyle="--",
                label="Ideal uniform")
    ax3.set_xlabel("Byte value", color="#556070")
    ax3.set_ylabel("Count", color="#556070")
    ax3.tick_params(colors="#556070")
    for spine in ax3.spines.values():
        spine.set_edgecolor("#1e3a5f")
    ax3.legend(facecolor="#0d1424", labelcolor="#c8d8f0", edgecolor="#1e3a5f")
    ax3.set_title("Distribution of 10,000 chaos-generated bytes", color="#c8d8f0")
    st.pyplot(fig3)

    # ── Encryption Workflow Diagram ─────────────────────────────────────────
    st.markdown("### Encryption Workflow")
    fig4, ax4 = plt.subplots(figsize=(10, 5), facecolor="#080c14")
    ax4.set_facecolor("#080c14")
    ax4.axis("off")

    steps = [
        ("Plaintext /\nImage", "#00c8ff"),
        ("Chaos\nMasking", "#7b61ff"),
        ("AES-256\nEncrypt", "#00e5a0"),
        ("RSA-2048\nKey Wrap", "#ff9f43"),
        ("Secure\nPayload", "#ff4c6e"),
    ]
    for i, (label, color) in enumerate(steps):
        x = 0.1 + i * 0.2
        rect = mpatches.FancyBboxPatch(
            (x - 0.08, 0.3), 0.16, 0.4,
            boxstyle="round,pad=0.02",
            facecolor=color + "33",
            edgecolor=color,
            linewidth=1.5,
        )
        ax4.add_patch(rect)
        ax4.text(x, 0.5, label, ha="center", va="center",
                 color=color, fontsize=9, fontweight="bold")
        if i < len(steps) - 1:
            ax4.annotate(
                "", xy=(x + 0.12, 0.5), xytext=(x + 0.08, 0.5),
                arrowprops=dict(arrowstyle="->", color="#556070", lw=1.5),
            )

    ax4.text(0.5, 0.05, "← Decryption reverses all steps →",
             ha="center", va="bottom", color="#556070", fontsize=9, style="italic")
    st.pyplot(fig4)
