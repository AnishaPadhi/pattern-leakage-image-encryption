"""
Pattern Leakage in Image Encryption — Interactive Prototype
-----------------------------------------------------------
Educational dashboard comparing:
  1) Plain image pixel blocks
  2) Deterministic AES-ECB (insecure demonstration only)
  3) AES-GCM (randomized authenticated encryption)

This is a teaching prototype, not a production security audit.
Never use ECB for real data. For real image protection, use a reviewed
authenticated-encryption design such as AES-GCM and protect the key.
"""

import io
import math
from collections import Counter

import numpy as np
import streamlit as st
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


st.set_page_config(
    page_title="PatternLeak | Image Encryption Lab",
    page_icon="🔐",
    layout="wide",
)

st.markdown(
    """
    <style>
    .main {background: #0b1020;}
    .block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
    .hero {
        padding: 1.4rem 1.6rem; border-radius: 18px;
        background: linear-gradient(120deg, #16213e, #243b67);
        border: 1px solid #354b76; margin-bottom: 1.1rem;
    }
    .hero h1 {margin: 0; color: #f4f7ff;}
    .hero p {color: #c8d5f0; margin: .45rem 0 0 0;}
    .metric-card {
        padding: 1rem; border: 1px solid #293650;
        border-radius: 14px; background: #111a2e;
    }
    .small-note {font-size: .88rem; color: #aebbd3;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <h1>🔐 PatternLeak — Image Encryption Lab</h1>
      <p>Explore repeated-block leakage, compare encryption approaches, and inspect measurable indicators.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.warning(
    "Educational demonstration only. AES-ECB is intentionally included to illustrate "
    "pattern leakage and must not be used to protect real images. AES-GCM is the "
    "authenticated-encryption example."
)


def prepare_image(uploaded_file, max_side=512):
    """Load image safely, convert to RGB, and resize for a quick demo."""
    image = Image.open(uploaded_file).convert("RGB")
    original_size = image.size
    image.thumbnail((max_side, max_side))
    return image, original_size


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(data, 16)
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_gcm_encrypt(data: bytes, key: bytes):
    nonce = AESGCM.generate_key  # keep key generation separate from nonce generation
    from os import urandom
    iv = urandom(12)
    encrypted = AESGCM(key).encrypt(iv, data, None)
    return iv, encrypted


def duplicate_block_ratio(data: bytes, block_size: int = 16) -> float:
    """Fraction of complete blocks that are duplicates of an earlier block."""
    usable = len(data) - (len(data) % block_size)
    if usable < block_size:
        return 0.0
    blocks = [data[i:i + block_size] for i in range(0, usable, block_size)]
    counts = Counter(blocks)
    repeated = sum(count - 1 for count in counts.values() if count > 1)
    return repeated / len(blocks)


def shannon_entropy(data: bytes) -> float:
    """Byte-wise Shannon entropy, in bits per byte (maximum is 8)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0] / len(data)
    return float(-np.sum(probabilities * np.log2(probabilities)))


def bytes_as_image(data: bytes, width: int, height: int, channels: int = 3):
    """Visualize the first width*height*channels bytes as RGB pixels."""
    needed = width * height * channels
    arr = np.frombuffer(data[:needed], dtype=np.uint8)
    if arr.size < needed:
        arr = np.pad(arr, (0, needed - arr.size), mode="constant")
    arr = arr.reshape((height, width, channels))
    return Image.fromarray(arr, mode="RGB")


def format_pct(value):
    return f"{value * 100:.2f}%"


with st.sidebar:
    st.header("Experiment setup")
    uploaded = st.file_uploader(
        "Upload a test image",
        type=["png", "jpg", "jpeg", "bmp", "webp"],
        help="Use a sample image or a non-sensitive image you have permission to test.",
    )
    max_side = st.slider("Preview maximum side (pixels)", 128, 768, 384, 64)
    st.caption("The app processes a resized RGB copy for a faster demonstration.")
    st.divider()
    st.markdown("**Encryption methods**")
    st.markdown("- AES-ECB: deterministic comparison baseline")
    st.markdown("- AES-GCM: randomized authenticated encryption")
    st.markdown("- Repeated 16-byte blocks: simple leakage indicator")


if uploaded is None:
    st.info("Upload an image in the sidebar to start the experiment.")
    st.subheader("What this prototype demonstrates")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("### 01 · Visual patterns")
        st.write("Compare the original image with a visualization of encrypted pixel bytes.")
    with c2:
        st.markdown("### 02 · Leakage metrics")
        st.write("Measure repeated 16-byte blocks and byte-wise Shannon entropy.")
    with c3:
        st.markdown("### 03 · Safer design")
        st.write("See how a randomized AES-GCM encryption result differs from deterministic ECB.")
    st.stop()


try:
    image, original_size = prepare_image(uploaded, max_side=max_side)
except Exception as exc:
    st.error(f"Could not read this image: {exc}")
    st.stop()

rgb = np.asarray(image, dtype=np.uint8)
raw = rgb.tobytes()
width, height = image.size

# Fixed demonstration key for reproducible ECB visualization.
# AES-GCM uses a fresh random key and nonce for this session's experiment.
ecb_key = b"PatternLeakDemo!"  # exactly 16 bytes
gcm_key = AESGCM.generate_key(bit_length=128)

ecb_ciphertext = aes_ecb_encrypt(raw, ecb_key)
gcm_nonce, gcm_ciphertext = aes_gcm_encrypt(raw, gcm_key)

# ECB byte visualization aligns to the image byte count; padding is ignored.
ecb_preview = bytes_as_image(ecb_ciphertext, width, height)
# GCM ciphertext includes a 16-byte authentication tag; visualize ciphertext only.
gcm_preview = bytes_as_image(gcm_ciphertext[:-16], width, height)

plain_dup = duplicate_block_ratio(raw)
ecb_dup = duplicate_block_ratio(ecb_ciphertext)
gcm_dup = duplicate_block_ratio(gcm_ciphertext[:-16])

plain_entropy = shannon_entropy(raw)
ecb_entropy = shannon_entropy(ecb_ciphertext)
gcm_entropy = shannon_entropy(gcm_ciphertext[:-16])

st.caption(
    f"File: **{uploaded.name}** · Original dimensions: **{original_size[0]} × "
    f"{original_size[1]}** · Processed dimensions: **{width} × {height}**"
)

tab_overview, tab_metrics, tab_method, tab_notes = st.tabs(
    ["🖼️ Visual comparison", "📊 Leakage metrics", "🧪 Method details", "📝 Project notes"]
)

with tab_overview:
    st.subheader("Image and encrypted-byte visualizations")
    st.caption(
        "Encrypted-byte previews are diagnostic visualizations, not image files that can be opened as normal photos."
    )
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**Original image**")
        st.image(image, use_container_width=True)
        st.caption("Structured visual information is visible.")
    with col2:
        st.markdown("**AES-ECB (insecure baseline)**")
        st.image(ecb_preview, use_container_width=True)
        st.caption("ECB encrypts identical blocks identically under the same key.")
    with col3:
        st.markdown("**AES-GCM (randomized)**")
        st.image(gcm_preview, use_container_width=True)
        st.caption("Fresh key and nonce produce a ciphertext with no intended visual structure.")

    st.markdown("#### Interpretation")
    if ecb_dup > gcm_dup:
        st.success(
            "In this sample, the ECB ciphertext has a higher repeated-block ratio than the "
            "GCM ciphertext. This is evidence of repeated-block leakage in this experiment."
        )
    else:
        st.info(
            "The measured repeated-block ratios are close for this sample. Results depend on "
            "the image content and size; this single metric is not a complete security proof."
        )

with tab_metrics:
    st.subheader("Quantitative indicators")
    st.caption(
        "Duplicate-block ratio counts repeated complete 16-byte blocks. Byte entropy estimates "
        "how evenly byte values are distributed; neither metric alone proves security."
    )

    m1, m2, m3 = st.columns(3)
    m1.metric("Plain repeated-block ratio", format_pct(plain_dup))
    m2.metric("ECB repeated-block ratio", format_pct(ecb_dup), delta=f"{(ecb_dup-plain_dup)*100:+.2f} pp")
    m3.metric("GCM repeated-block ratio", format_pct(gcm_dup), delta=f"{(gcm_dup-plain_dup)*100:+.2f} pp")

    st.markdown("#### Byte-wise Shannon entropy")
    e1, e2, e3 = st.columns(3)
    e1.metric("Plain image", f"{plain_entropy:.3f} / 8 bits")
    e2.metric("AES-ECB", f"{ecb_entropy:.3f} / 8 bits")
    e3.metric("AES-GCM", f"{gcm_entropy:.3f} / 8 bits")

    st.markdown("#### Summary table")
    st.dataframe(
        {
            "Stage": ["Original pixel bytes", "AES-ECB ciphertext", "AES-GCM ciphertext"],
            "Bytes analyzed": [len(raw), len(ecb_ciphertext), len(gcm_ciphertext) - 16],
            "Repeated-block ratio": [format_pct(plain_dup), format_pct(ecb_dup), format_pct(gcm_dup)],
            "Byte entropy (bits)": [round(plain_entropy, 4), round(ecb_entropy, 4), round(gcm_entropy, 4)],
        },
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Download metrics as CSV",
        data=(
            "stage,bytes_analyzed,repeated_block_ratio,byte_entropy_bits\n"
            f"original,{len(raw)},{plain_dup:.8f},{plain_entropy:.8f}\n"
            f"aes_ecb,{len(ecb_ciphertext)},{ecb_dup:.8f},{ecb_entropy:.8f}\n"
            f"aes_gcm,{len(gcm_ciphertext)-16},{gcm_dup:.8f},{gcm_entropy:.8f}\n"
        ),
        file_name="pattern_leakage_metrics.csv",
        mime="text/csv",
    )

with tab_method:
    st.subheader("How the experiment works")
    st.markdown(
        """
        1. **Preprocessing:** the uploaded image is converted to RGB and resized for this demo.
        2. **Baseline:** the RGB byte stream is encrypted with AES-ECB to demonstrate why deterministic block encryption leaks repeated-block relationships.
        3. **Protected example:** the same byte stream is encrypted using AES-GCM with a fresh random 128-bit key and 96-bit nonce.
        4. **Evaluation:** the dashboard computes repeated-block ratio and byte-wise entropy for each byte stream.
        5. **Important limitation:** these indicators are useful for classroom demonstration, but they do not replace cryptanalysis, threat modeling, or a formal security review.
        """
    )
    with st.expander("AES-GCM parameters used"):
        st.write("Algorithm: AES-GCM")
        st.write("Key size: 128 bits")
        st.write("Nonce size: 96 bits (12 bytes)")
        st.write("Authentication tag: 128 bits (16 bytes)")
        st.write("Additional authenticated data (AAD): none in this prototype")
    with st.expander("Why ECB can leak patterns"):
        st.write(
            "ECB encrypts each block independently. Identical plaintext blocks produce identical "
            "ciphertext blocks under the same key, which can preserve relationships in structured "
            "data. AES-GCM uses a nonce and authenticated encryption, and is the safer example here."
        )

with tab_notes:
    st.subheader("Suggested project presentation points")
    st.markdown(
        """
        **Problem statement:** Image encryption should conceal visual information and avoid leaking
        structural patterns that may reveal details about the original image.

        **Objective:** Build a prototype that compares a deterministic block-encryption baseline
        with randomized authenticated encryption using visual and statistical indicators.

        **Expected observation:** ECB may preserve repeated-block relationships; AES-GCM ciphertext
        should appear noise-like and also provides integrity authentication.

        **Future work:**
        - Compare multiple images and image types.
        - Add histograms and adjacent-pixel correlation analysis.
        - Test key/nonce handling and authenticated decryption.
        - Evaluate against a clearly defined threat model and relevant research papers.

        **Research caution:** Do not claim the dashboard proves an encryption method is secure.
        Report the tested images, parameters, metrics, and limitations.
        """
    )

st.divider()
st.caption(
    "PatternLeak prototype · Runs locally · Uploaded image bytes are processed by this app session. "
    "For deployment, review hosting, logging, and data-retention settings before using private images."
)
