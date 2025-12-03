import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import json
import hashlib

# Page configuration
st.set_page_config(
    page_title="Cyber Compliance Management System",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state for data persistence
if 'risks' not in st.session_state:
    st.session_state.risks = [
        {
            'risk_id': 'R1',
            'description': 'Weak Passwords',
            'likelihood': 'High',
            'impact': 'High',
            'risk_level': 'Critical',
            'mitigation': 'Enforce MFA, strong password policy'
        },
        {
            'risk_id': 'R2',
            'description': 'Phishing Attack',
            'likelihood': 'Medium',
            'impact': 'High',
            'risk_level': 'High',
            'mitigation': 'Employee training, email filtering'
        },
        {
            'risk_id': 'R3',
            'description': 'Ransomware',
            'likelihood': 'Medium',
            'impact': 'Critical',
            'risk_level': 'Critical',
            'mitigation': 'Regular backups, endpoint protection'
        }
    ]

if 'compliance_mapping' not in st.session_state:
    st.session_state.compliance_mapping = [
        {
            'control': 'Data Encryption',
            'law': 'IT Act 2000',
            'description': 'Protects sensitive data in transit and at rest',
            'status': 'Compliant'
        },
        {
            'control': 'Log Retention',
            'law': 'CERT-In Guidelines',
            'description': 'Maintain logs for 180 days',
            'status': 'Compliant'
        },
        {
            'control': 'User Consent',
            'law': 'DPDP Act 2023',
            'description': 'Required for data collection and processing',
            'status': 'In Progress'
        },
        {
            'control': 'Incident Reporting',
            'law': 'CERT-In Guidelines',
            'description': 'Report incidents within 6 hours',
            'status': 'Compliant'
        }
    ]

if 'incidents' not in st.session_state:
    st.session_state.incidents = [
        {
            'incident_id': 'INC001',
            'date': '2024-11-20',
            'type': 'Phishing Attempt',
            'severity': 'Medium',
            'status': 'Resolved',
            'description': 'Employee reported suspicious email'
        },
        {
            'incident_id': 'INC002',
            'date': '2024-11-22',
            'type': 'Unauthorized Access Attempt',
            'severity': 'High',
            'status': 'Investigating',
            'description': 'Multiple failed login attempts detected'
        }
    ]

if 'audit_logs' not in st.session_state:
    st.session_state.audit_logs = []

if 'policies' not in st.session_state:
    st.session_state.policies = [
        {
            'policy_name': 'Information Security Policy',
            'version': '1.2',
            'last_updated': '2024-10-15',
            'status': 'Active'
        },
        {
            'policy_name': 'Password Policy',
            'version': '2.0',
            'last_updated': '2024-11-01',
            'status': 'Active'
        },
        {
            'policy_name': 'Data Protection Policy',
            'version': '1.0',
            'last_updated': '2024-09-20',
            'status': 'Active'
        },
        {
            'policy_name': 'Remote Work Policy',
            'version': '1.1',
            'last_updated': '2024-08-10',
            'status': 'Under Review'
        }
    ]

# Function to log activities
def log_activity(action, details):
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'action': action,
        'details': details
    }
    st.session_state.audit_logs.append(log_entry)

# Sidebar navigation
st.sidebar.title("🔒 Cyber Compliance System")
st.sidebar.markdown("**ABC Tech Solutions Pvt Ltd**")
st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Risk Management", "Compliance Mapping", 
     "Incident Response", "Security Policies", "Audit Logs"]
)

# Dashboard
if menu == "Dashboard":
    st.title("📊 Cyber Compliance Dashboard")
    st.markdown("### ABC Tech Solutions Pvt Ltd - Compliance Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Risks", len(st.session_state.risks))
        critical_risks = sum(1 for r in st.session_state.risks if r['risk_level'] == 'Critical')
        st.metric("Critical Risks", critical_risks, delta=f"-{critical_risks}" if critical_risks > 0 else "0")
    
    with col2:
        compliant = sum(1 for c in st.session_state.compliance_mapping if c['status'] == 'Compliant')
        total_controls = len(st.session_state.compliance_mapping)
        compliance_rate = (compliant / total_controls * 100) if total_controls > 0 else 0
        st.metric("Compliance Rate", f"{compliance_rate:.1f}%")
        st.metric("Compliant Controls", f"{compliant}/{total_controls}")
    
    with col3:
        open_incidents = sum(1 for i in st.session_state.incidents if i['status'] != 'Resolved')
        st.metric("Open Incidents", open_incidents)
        st.metric("Total Incidents", len(st.session_state.incidents))
    
    with col4:
        active_policies = sum(1 for p in st.session_state.policies if p['status'] == 'Active')
        st.metric("Active Policies", active_policies)
        st.metric("Total Policies", len(st.session_state.policies))
    
    st.markdown("---")
    
    # Indian Cyber Laws Compliance
    st.subheader("🇮🇳 Indian Cyber Laws Compliance Status")
    
    laws_data = {
        'Law/Standard': [
            'Information Technology Act, 2000',
            'CERT-In Guidelines (2022)',
            'Digital Personal Data Protection Act, 2023'
        ],
        'Key Requirements': [
            'Unauthorized access prevention, Data protection',
            'Log retention (180 days), 6-hour incident reporting',
            'User consent, Data protection rights'
        ],
        'Compliance Status': ['✅ Compliant', '✅ Compliant', '⚠️ In Progress']
    }
    
    st.dataframe(pd.DataFrame(laws_data), use_container_width=True, hide_index=True)
    
    # Recent Activity
    st.markdown("---")
    st.subheader("📋 Recent Activity")
    
    if st.session_state.audit_logs:
        recent_logs = st.session_state.audit_logs[-5:][::-1]
        for log in recent_logs:
            st.text(f"[{log['timestamp']}] {log['action']}: {log['details']}")
    else:
        st.info("No recent activity recorded.")

# Risk Management
elif menu == "Risk Management":
    st.title("⚠️ Risk Management System")
    
    tab1, tab2 = st.tabs(["View Risks", "Add/Update Risk"])
    
    with tab1:
        st.subheader("Risk Register")
        
        if st.session_state.risks:
            df_risks = pd.DataFrame(st.session_state.risks)
            
            # UPDATED: Text color forced to black
            def highlight_risk(row):
                if row['risk_level'] == 'Critical':
                    bg = 'background-color: #ffcccc;'
                elif row['risk_level'] == 'High':
                    bg = 'background-color: #ffe6cc;'
                elif row['risk_level'] == 'Medium':
                    bg = 'background-color: #ffffcc;'
                else:
                    bg = 'background-color: #ccffcc;'
                return [bg + 'color: black;'] * len(row)
            
            st.dataframe(
                df_risks.style.apply(highlight_risk, axis=1),
                use_container_width=True,
                hide_index=True
            )
            
            # Risk Level Distribution
            st.subheader("Risk Distribution")
            risk_counts = df_risks['risk_level'].value_counts()
            st.bar_chart(risk_counts)
        else:
            st.info("No risks recorded.")
    
    with tab2:
        st.subheader("Add New Risk")
        
        with st.form("risk_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                risk_id = st.text_input("Risk ID", placeholder="e.g., R4")
                description = st.text_area("Description", placeholder="Describe the risk")
                likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
            
            with col2:
                impact = st.selectbox("Impact", ["Low", "Medium", "High", "Critical"])
                risk_level = st.selectbox("Risk Level", ["Low", "Medium", "High", "Critical"])
                mitigation = st.text_area("Mitigation Strategy", placeholder="How to mitigate this risk")
            
            submit = st.form_submit_button("Add Risk")
            
            if submit:
                if risk_id and description and mitigation:
                    new_risk = {
                        'risk_id': risk_id,
                        'description': description,
                        'likelihood': likelihood,
                        'impact': impact,
                        'risk_level': risk_level,
                        'mitigation': mitigation
                    }
                    st.session_state.risks.append(new_risk)
                    log_activity("Risk Added", f"New risk {risk_id} added to register")
                    st.success(f"Risk {risk_id} added successfully!")
                    st.rerun()
                else:
                    st.error("Please fill all required fields.")

# Compliance Mapping
elif menu == "Compliance Mapping":
    st.title("📃 Legal Compliance Mapping")
    
    tab1, tab2 = st.tabs(["View Compliance Controls", "Add/Update Control"])
    
    with tab1:
        st.subheader("Compliance Control Matrix")
        
        if st.session_state.compliance_mapping:
            df_compliance = pd.DataFrame(st.session_state.compliance_mapping)
            
            # UPDATED: Text color forced to black
            def highlight_status(row):
                if row['status'] == 'Compliant':
                    bg = 'background-color: #ccffcc;'
                elif row['status'] == 'In Progress':
                    bg = 'background-color: #ffffcc;'
                else:
                    bg = 'background-color: #ffcccc;'
                return [bg + 'color: black;'] * len(row)
            
            st.dataframe(
                df_compliance.style.apply(highlight_status, axis=1),
                use_container_width=True,
                hide_index=True
            )
            
            st.subheader("Compliance Status Overview")
            status_counts = df_compliance['status'].value_counts()
            st.bar_chart(status_counts)
        else:
            st.info("No compliance controls recorded.")
    
    with tab2:
        st.subheader("Add New Compliance Control")
        
        with st.form("compliance_form"):
            control = st.text_input("Control Name", placeholder="e.g., Two-Factor Authentication")
            law = st.selectbox("Applicable Law/Standard", 
                             ["IT Act 2000", "CERT-In Guidelines", "DPDP Act 2023", "ISO 27001", "Other"])
            description = st.text_area("Description", placeholder="Describe the control requirement")
            status = st.selectbox("Compliance Status", ["Compliant", "In Progress", "Non-Compliant", "Not Applicable"])
            
            submit = st.form_submit_button("Add Control")
            
            if submit:
                if control and description:
                    new_control = {
                        'control': control,
                        'law': law,
                        'description': description,
                        'status': status
                    }
                    st.session_state.compliance_mapping.append(new_control)
                    log_activity("Compliance Control Added", f"New control '{control}' added")
                    st.success("Compliance control added successfully!")
                    st.rerun()
                else:
                    st.error("Please fill all required fields.")

# Incident Response
elif menu == "Incident Response":
    st.title("🚨 Incident Response Management")
    
    tab1, tab2 = st.tabs(["View Incidents", "Report New Incident"])
    
    with tab1:
        st.subheader("Incident Register")
        
        if st.session_state.incidents:
            df_incidents = pd.DataFrame(st.session_state.incidents)
            
            # UPDATED: Text color forced to black
            def highlight_severity(row):
                if row['severity'] == 'Critical':
                    bg = 'background-color: #ff9999;'
                elif row['severity'] == 'High':
                    bg = 'background-color: #ffcc99;'
                elif row['severity'] == 'Medium':
                    bg = 'background-color: #ffff99;'
                else:
                    bg = 'background-color: #ccffcc;'
                return [bg + 'color: black;'] * len(row)
            
            st.dataframe(
                df_incidents.style.apply(highlight_severity, axis=1),
                use_container_width=True,
                hide_index=True
            )
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("By Severity")
                severity_counts = df_incidents['severity'].value_counts()
                st.bar_chart(severity_counts)
            
            with col2:
                st.subheader("By Status")
                status_counts = df_incidents['status'].value_counts()
                st.bar_chart(status_counts)
        else:
            st.info("No incidents recorded.")
        
        st.markdown("---")
        st.subheader("📃 Incident Response Process (As per CERT-In)")
        st.markdown("""
        1. **Detection** - Identify and verify the incident
        2. **Containment** - Isolate affected systems
        3. **Eradication** - Remove the threat
        4. **Recovery** - Restore systems to normal operation
        5. **Post-Incident Review** - Document and learn
        
        ⚠️ CERT-In Requirement: Report incidents within **6 hours**
        """)
    
    with tab2:
        st.subheader("Report New Incident")
        
        with st.form("incident_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                incident_id = st.text_input("Incident ID", placeholder="e.g., INC003")
                date = st.date_input("Date", datetime.now())
                incident_type = st.selectbox("Type", 
                    ["Phishing Attempt", "Malware", "Unauthorized Access Attempt", 
                     "Data Breach", "DDoS Attack", "Ransomware", "Other"])
            
            with col2:
                severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
                status = st.selectbox("Status", ["New", "Investigating", "Contained", "Resolved"])
                description = st.text_area("Description", placeholder="Detailed description of the incident")
            
            submit = st.form_submit_button("Report Incident")
            
            if submit:
                if incident_id and description:
                    new_incident = {
                        'incident_id': incident_id,
                        'date': date.strftime('%Y-%m-%d'),
                        'type': incident_type,
                        'severity': severity,
                        'status': status,
                        'description': description
                    }
                    st.session_state.incidents.append(new_incident)
                    log_activity("Incident Reported", f"New incident {incident_id} reported - {incident_type}")
                    st.success(f"Incident {incident_id} reported successfully!")
                    st.warning("⚠️ Remember: CERT-In requires incident reporting within 6 hours!")
                    st.rerun()
                else:
                    st.error("Please fill all required fields.")

# Security Policies
elif menu == "Security Policies":
    st.title("📄 Security Policies Management")
    
    tab1, tab2 = st.tabs(["View Policies", "Add/Update Policy"])
    
    with tab1:
        st.subheader("Active Security Policies")
        
        if st.session_state.policies:
            df_policies = pd.DataFrame(st.session_state.policies)
            
            # UPDATED: Text color forced to black
            def highlight_policy_status(row):
                if row['status'] == 'Active':
                    bg = 'background-color: #ccffcc;'
                elif row['status'] == 'Under Review':
                    bg = 'background-color: #ffffcc;'
                else:
                    bg = 'background-color: #ffcccc;'
                return [bg + 'color: black;'] * len(row)
            
            st.dataframe(
                df_policies.style.apply(highlight_policy_status, axis=1),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No policies recorded.")
        
        st.markdown("---")
        st.subheader("📃 Standard Policy Templates")
        
        with st.expander("Information Security Policy"):
            st.markdown("""
            **Purpose**: Establish standards for protecting company information assets
            
            **Key Components**:
            - Data classification
            - Access control requirements
            - Encryption standards
            - Incident reporting procedures
            """)
        
        with st.expander("Password Policy"):
            st.markdown("""
            **Purpose**: Define password requirements and management
            
            **Requirements**:
            - Minimum 12 characters
            - Combination of uppercase, lowercase, numbers, special characters
            - Change every 90 days
            - No password reuse (last 5 passwords)
            - Multi-factor authentication mandatory
            """)
        
        with st.expander("Data Protection Policy"):
            st.markdown("""
            **Purpose**: Ensure compliance with DPDP Act 2023
            
            **Key Requirements**:
            - User consent for data collection
            - Data minimization
            - Purpose limitation
            - Data retention limits
            - Right to erasure
            """)
    
    with tab2:
        st.subheader("Add New Policy")
        
        with st.form("policy_form"):
            policy_name = st.text_input("Policy Name", placeholder="e.g., BYOD Policy")
            version = st.text_input("Version", placeholder="e.g., 1.0")
            last_updated = st.date_input("Last Updated", datetime.now())
            status = st.selectbox("Status", ["Active", "Under Review", "Archived"])
            
            submit = st.form_submit_button("Add Policy")
            
            if submit:
                if policy_name and version:
                    new_policy = {
                        'policy_name': policy_name,
                        'version': version,
                        'last_updated': last_updated.strftime('%Y-%m-%d'),
                        'status': status
                    }
                    st.session_state.policies.append(new_policy)
                    log_activity("Policy Added", f"New policy '{policy_name}' version {version} added")
                    st.success("Policy added successfully!")
                    st.rerun()
                else:
                    st.error("Please fill all required fields.")

# Audit Logs
elif menu == "Audit Logs":
    st.title("📝 System Audit Logs")
    
    st.markdown("""
    ### CERT-In Compliance
    As per CERT-In Guidelines 2022, organizations must:
    - Maintain logs for 180 days
    - Enable security logs on all systems
    - Synchronize system time with NTP
    - Monitor and review logs regularly
    """)
    
    st.markdown("---")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader("Activity Log")
    with col2:
        if st.button("Clear Logs", type="secondary"):
            st.session_state.audit_logs = []
            st.success("Logs cleared!")
            st.rerun()
    
    if st.session_state.audit_logs:
        df_logs = pd.DataFrame(st.session_state.audit_logs[::-1])
        
        st.dataframe(
            df_logs,
            use_container_width=True,
            hide_index=True
        )
        
        st.markdown("---")
        if st.button("Export Logs (CSV)"):

            csv = df_logs.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No audit logs available. System activities will be logged here.")
        st.markdown("""
        **Sample activities that get logged:**
        - Risk additions or updates
        - Compliance control changes
        - Incident reports
        - Policy updates
        - Data modifications
        """)

