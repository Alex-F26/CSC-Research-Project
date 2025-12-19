import nvdlib
import streamlit as st
import csv

testCSV = "csv/test.csv"
cwe_capec = "csv/CWE_CAPEC.csv"

#Searches for CVE details from the NVD API and extracts associated CWEs.        
try:
    def get_cve_cwe_mapping(cve_id):
        cwe_ids = []

        with open("csv/test.csv", "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if row[0] == cve_id:
                    cwe_ids = row[1].split("::")
                    return cwe_ids

        search_nvd(cve_id)
        return get_cve_cwe_mapping(cve_id)

    
    def search_nvd(cve_id):
        with open(testCSV, "a", newline ='') as csvfile:
            cwe_id_array = []
            writer = csv.writer(csvfile)

            results = nvdlib.searchCVE(cveId=cve_id, key="8cbbf53c-1ffc-4864-bee6-ef32e8c52b6f", delay=0.6)
            
            if results:
                cve_entry = results[0]

                if cve_entry.weaknesses:
                    for weakness_entry in cve_entry.weaknesses:
                        for desc in weakness_entry.description:
                            id = desc.value.split(':')[0].strip()
                            cwe_id_array.append(id)
                    cwe_id = '::'.join(cwe_id_array)
                    writer.writerow([cve_entry.id, cwe_id])
                    print(cwe_id)   
                    
                else:
                    st.write("No direct CWE mapping found in the NVD entry.")
                    writer.writerow([cve_entry.id, "No direct CWE mapping found in the NVD entry."])
            else:
                st.write(f"CVE ID {cve_id} not found or no results returned.")
                writer.writerow([f"CVE ID {cve_id} not found or no results returned."])
        
except Exception as e:
        st.write(f"An error occurred: {e}")
        

#TO DO

#LOGISTICS
#   Option 1: Create a visual of ALL CVE's with their CWE'S and potential chaining 
#       Should load all CVE files and write all ID's when prompted
#       Organize CVE's under identical CWE's
#       Should allow user to search for a CVE or CWE and get full mapping/chain

#   Option 2: Create a visual of only imported CVE's (USE KNOWN EXPLOTED VULNERABILITIES .CSV)
#       Should parse through downloaded XML / JSON file to find the CVE ID's 
#       Organize CVE's under identical CWE's  / Organize CVE's as they are found with their chains

#   Option 3: Do both option 1 & 2 as features available

#REPORTING
#   Both options mentioned above should allow the user to generate a report
#       User should have the option to filter through what they want on the report
#           (e.g do they only want CVE's and CWE's? Only from CWE to CAPEC mappings?)
#       Report should include short summaries of what the chained categories consist of
#           (e.g ATT&CK ID [2025-sfd57]: This ID refers to SQL injection attacks)

#CHAINING LOGISTICS
#   CVE to CWE is completed 
#   CWE to CAPEC is completed
#   CAPEC to ATT&CK might have a list already created
#   ATT&CK to D3FEND TBD (MAY NEED TO BE CAPEC TO D3FEND)


# cwe array = 1, 2 ,3
# each cwe id in the cwe array will have an internal array with cve's, so
# array[1] = cve1, cve2, cve3
    # to print array index name:
        # def print_variable_name(variable):
        #     for name, value in locals().items():
        #         if value is variable:
        #             print(f"The variable name is: {name}")
        #             return
        #     for name, value in globals().items():
        #         if value is variable:
        #             print(f"The variable name is: {name}")
        #             return

        # my_variable = 42
        # print_variable_name(my_variable)