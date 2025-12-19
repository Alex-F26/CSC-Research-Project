# CVE-CWE-CAPEC-ATT&CK-D3FEND Mapper

A Streamlit web application to link CVEs to CWEs, CAPECs, MITRE ATT&CK techniques, D3FEND mitigations, OWASP threats, and the now-deprecated WASC entries. Users can either input a single CVE or upload CSV files with multiple CVEs and generate a PDF report of the linked categories.

Features:
  Single CVE Lookup: Enter a CVE ID to see all linked CWEs, CAPECs, ATT&CK techniques, and D3FEND mappings.
  CSV Upload: Upload multiple CSV files containing CVE IDs for batch processing.
  Interactive Viewer: Select CVEs, associated CWEs, CAPECs, and taxonomies via dropdowns.
  PDF Export: Download a comprehensive PDF report of all mappings.
  Persistent Session: Previously processed CVEs remain in session storage.

Installation:

  Clone this repository:
    git clone https://github.com/Alex-F26/cve-mapper.git
    cd cve-mapper

Create and activate a virtual environment:
  python -m venv venv
# Windows
  venv\Scripts\activate
# macOS/Linux
  source venv/bin/activate


  Install dependencies:

  pip install -r requirements.txt

  Ensure the Linkers package with modules cve_cwe_linker, cwe_capec_linker, capec_taxonomy_linker, and attack_defend_linker is available in your project directory.

Usage:
  Run the Streamlit app:
  streamlit run app.py

Single CVE Lookup:
  Enter a CVE ID in the text box.
  View linked CWEs, CAPECs, ATT&CK techniques, D3FEND mitigations, OWASP, and WASC entries.

CSV Batch Processing:
  Upload one or more CSV files containing a cveID column.
  Click Process CSVs.
  View results and download a PDF report using the Download All Mappings as PDF button.

Interactive Selection:
 Select a CVE from the dropdown.
 Select associated CWE.
 Select associated CAPEC.
 View linked taxonomies (ATT&CK / OWASP / WASC).
 For ATT&CK, view linked D3FEND techniques.

File Format for CSV Upload:
 Your CSV files must have at least the following in the first column:
 
 cveID
 CVE-2023-12345
 CVE-2022-54321

 (Basically just make sure that your csv file has your CVE ID's in the first column and you're good to go!)

Dependencies:
  Streamlit
  pandas
  fpdf
  Python 3.8+
  Linkers package with your CVE/CWE/CAPEC/ATT&CK/D3FEND mapping modules

Notes:
  D3FEND mappings are only available for MITRE ATT&CK techniques.
  The PDF generation automatically wraps long lists to avoid cutting off content.
  OWASP and WASC are included if present in the taxonomy mappings.

License:
 MIT License 
