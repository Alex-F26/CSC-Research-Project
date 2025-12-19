from Linkers import cve_cwe_linker
from Linkers import cwe_capec_linker
from Linkers import capec_taxonomy_linker
from Linkers import attack_defend_linker

import streamlit as st
import pandas as pd
import time

import streamlit as st
from fpdf import FPDF


# -------------------------------
# Persistent storage
# -------------------------------
if "results" not in st.session_state:
    st.session_state["results"] = {}

st.title("CVE-CWE-CAPEC-ATT&CK-D3FEND")

cveID_text = st.text_input("Enter CVE ID (e.g CVE-2024-5217)")
uploaded_files = st.file_uploader(
    "Upload one or more CSV files containing CVE IDs in the First Column", 
    accept_multiple_files=True, 
    type="csv"
)

# -------------------------------
# CSV PROCESSING
# -------------------------------
if uploaded_files:
    process_clicked = st.button("Process CSVs")
    if process_clicked:
        placeholder_text = st.empty()
        stage1, stage2, stage3, stage4, stage5 = st.columns(5)

        for uploaded_file in uploaded_files:
            df = pd.read_csv(uploaded_file)
            if "cveID" not in df.columns:
                st.error(f"{uploaded_file.name} must contain a 'cveID' column")
                continue

            for cveID in df["cveID"]:
                if cveID in st.session_state["results"]:
                    continue  # Skip if already processed

                # Stage animation
                # stage1 cve
                placeholder_text.info(f"Linking CVE {cveID} → CWE...")
                cweID = cve_cwe_linker.get_cve_cwe_mapping(cveID)
                # stage2 cwe
                placeholder_text.info(f"Linking CWE → CAPEC...")
                capec = cwe_capec_linker.get_cwe_capec_mapping(cweID)
                # stage3 capec
                placeholder_text.info(f"Linking CAPEC → ATT&CK...")
                attack = capec_taxonomy_linker.get_capec_attack_mapping(
                    [c["capec_id"] for c in capec]
                )
                # stage4 attack
                attack_ids = [a["id"] for a in attack if a.get("type") == "ATT&CK" and a.get("id")]
                placeholder_text.info(f"Linking ATT&CK → D3FEND...")
                defend = attack_defend_linker.get_attack_defend_mapping(attack_ids)
                # stage5 defend
                
                # Save results
                st.session_state["results"][cveID] = {
                    "cwe": cweID,
                    "capec": capec,
                    "attack": attack,
                    "d3fend": defend
                }

        placeholder_text.success("All CVEs processed successfully!")

# -------------------------------
# TEXT INPUT
# -------------------------------
if cveID_text:

    st.title(f"Linked Information")

    # CVE → CWE
    cweID = cve_cwe_linker.get_cve_cwe_mapping(cveID_text)

    # CWE → CAPEC
    capec = cwe_capec_linker.get_cwe_capec_mapping(cweID)

    # CAPEC → ATT&CK
    attack = capec_taxonomy_linker.get_capec_attack_mapping(
        [c["capec_id"] for c in capec]
    )

    attack_ids = [
        a["id"] for a in attack if a.get("type") == "ATT&CK" and a.get("id")
    ]

    defend = attack_defend_linker.get_attack_defend_mapping(attack_ids)

    st.session_state["results"][cveID_text] = {
        "cwe": cweID,
        "capec": capec,
        "attack": attack,
        "d3fend": defend
    }


# -------------------------------
# DROPDOWN VIEWER
# -------------------------------
if st.session_state["results"]:

# -------------------------------
# PDF DOWNLOAD BUTTON
# -------------------------------
    def safe_text(text):
        if not text:
            return ""
        return str(text).replace("—", "-").replace("–", "-")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "CVE-CWE-CAPEC-ATT&CK-D3FEND Mappings", ln=True, align="C")
    pdf.ln(10)

    indent = "    "  # 4 spaces for list indentation

    for cve, data in st.session_state["results"].items():
        # CVE
        pdf.set_font("Arial", "B", 12)
        pdf.multi_cell(0, 8, f"---------------------------------------------------------------------------------------------------------------------------------")
        pdf.multi_cell(0, 8, f"CVE: {safe_text(cve)}")
        
        
        # CWEs
        pdf.set_font("Arial", "B", 12)
        pdf.multi_cell(0, 6, "CWEs:")
        pdf.set_font("Arial", "", 12)
        pdf.multi_cell(0, 6, indent + ', '.join([safe_text(c) for c in data['cwe']]))

        # CAPECs
        pdf.set_font("Arial", "B", 12)
        pdf.multi_cell(0, 6, "CAPECs:")
        pdf.set_font("Arial", "", 12)
        capecs_text = ', '.join([safe_text(c['capec_id']) for c in data['capec']])
        pdf.multi_cell(0, 6, indent + capecs_text)

        # ATT&CK
        pdf.set_font("Arial", "B", 12)
        pdf.multi_cell(0, 6, "ATT&CK:")
        pdf.set_font("Arial", "", 12)
        attacks_text = ', '.join([safe_text(a.get('id', '')) for a in data['attack'] if a.get('type') == 'ATT&CK'])
        pdf.multi_cell(0, 6, indent + attacks_text)

        # D3FEND
        pdf.set_font("Arial", "B", 12)
        pdf.multi_cell(0, 6, "D3FEND:")
        pdf.set_font("Arial", "", 12)
        d3fend_text = ', '.join([safe_text(d.get('d3fend_id', '')) for d in data['d3fend']])
        pdf.multi_cell(0, 6, indent + d3fend_text)

        # OWASP
        owasp_text = ', '.join([safe_text(t.get('name', '')) for t in data['attack'] if t.get('type') == 'OWASP'])
        if owasp_text:
            pdf.set_font("Arial", "B", 12)
            pdf.multi_cell(0, 6, "OWASP:")
            pdf.set_font("Arial", "", 12)
            pdf.multi_cell(0, 6, indent + owasp_text)

        # WASC
        wasc_text = ', '.join([safe_text(t.get('id', '')) for t in data['attack'] if t.get('type') == 'WASC'])
        if wasc_text:
            pdf.set_font("Arial", "B", 12)
            pdf.multi_cell(0, 6, "WASC (Deprecated):")
            pdf.set_font("Arial", "", 12)
            pdf.multi_cell(0, 6, indent + wasc_text)

        pdf.ln(5)



    pdf_output = pdf.output(dest='S').encode('latin1', 'replace')
    st.download_button(
        label="Download All Mappings as PDF",
        data=pdf_output,
        file_name="cve_mappings.pdf",
        mime="application/pdf"
    )


    st.header("CVE ID")
    selected_cve = st.selectbox(
        "Select CVE",
        list(st.session_state["results"].keys())
    )
    cve_data = st.session_state["results"][selected_cve]

    st.subheader("Associated CWEs")
    selected_cwe = st.selectbox(
        "Select CWE",
        cve_data["cwe"]
    )

    st.subheader("Associated CAPECs")
    filtered_capecs = [
        c for c in cve_data["capec"]
        if c.get("cwe_id") == selected_cwe
    ]

    if not filtered_capecs:
        st.warning("No CAPECs found for this CWE.")
        st.stop()

    capec_options = []
    capec_lookup = {}
    for c in filtered_capecs:
        capec_id = c["capec_id"]
        taxonomy_entries = [
            t for t in cve_data["attack"] if t.get("capec_id") == capec_id
        ]
        name = taxonomy_entries[0]["name"] if taxonomy_entries else "Unknown CAPEC name"
        label = f"CAPEC-{capec_id} — {name}"
        capec_options.append(label)
        capec_lookup[label] = c

    selected_capec_label = st.selectbox("Select CAPEC", capec_options)
    selected_capec = capec_lookup[selected_capec_label]

    st.subheader("Associated Taxonomies")
    taxonomy_for_capec = [
        t for t in cve_data["attack"] if t.get("capec_id") == selected_capec.get("capec_id")
    ]
    if not taxonomy_for_capec:
        st.warning("No taxonomies found for this CAPEC.")
        st.stop()

    taxonomy_options = []
    for t in taxonomy_for_capec:
        if t["type"] == "OWASP":
            label = f"{t['type']} — {t['name']}"
        else:
            label = f"{t['type']} {t.get('id', 'UNKNOWN')} — {t.get('name', '')}"
        taxonomy_options.append(label)

    selected_taxonomy_label = st.selectbox(
        "Select Taxonomy (ATT&CK / OWASP / WASC)",
        taxonomy_options
    )
    selected_taxonomy = taxonomy_for_capec[taxonomy_options.index(selected_taxonomy_label)]

    if selected_taxonomy["type"] == "ATT&CK":
        st.subheader("Associated D3FEND Techniques")
        d3fend_for_attack = [
            d for d in cve_data["d3fend"] if d.get("id") == selected_taxonomy.get("id")
        ]
        if not d3fend_for_attack:
            st.warning("No D3FEND techniques found for this ATT&CK technique.")
        else:
            d3fend_options = [
                f"{d.get('d3fend_id', 'UNKNOWN')} — {d.get('d3fend_name', '')}"
                for d in d3fend_for_attack
            ]
            st.selectbox("Select D3FEND Technique", d3fend_options)
    else:
        st.info("D3FEND mappings are only available for ATT&CK techniques.")

