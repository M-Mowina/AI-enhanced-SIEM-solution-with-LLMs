import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import re
from datetime import datetime
import os
import io
import base64
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import requests
from dotenv import load_dotenv
from torchvision.models import resnet50
import torch.nn as nn
from torchvision import transforms
import numpy as np
from PIL import Image
import splunklib.client as client
import splunklib.results as results
import time
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import chromadb

# Google Gemini imports
import google.generativeai as genai

# STIX2 imports for MITRE ATT&CK parsing
from stix2 import MemoryStore, Filter, AttackPattern, Relationship

# Load environment variables
load_dotenv("app.env")

# Splunk API configuration

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Page config
st.set_page_config(
    page_title="Log Analyzer",
    page_icon="📊",
    layout="wide"
)

# Add new sidebar options
data_source = st.sidebar.radio(
    "Select Tool",
    ["Log Analysis", "Phishing Detection", "Malware Analysis"]
)
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "127.0.0.1")
SPLUNK_PORT = int(os.environ.get("SPLUNK_PORT", 8089))
SPLUNK_USERNAME = os.environ.get("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "changeme") # IMPORTANT: Update this in app.env
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN") # Optional, not used in current connect_to_splunk
VT_API_KEY = os.environ.get('VT_API_KEY')

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    st.error("GEMINI_API_KEY environment variable not set. Get your key from Google AI Studio (https://makersuite.google.com/).")
    st.stop() # Stop the app if API key is missing

# Configure Google Gemini
genai.configure(api_key=GEMINI_API_KEY)
llm = genai.GenerativeModel('gemini-2.0-flash') # For text generation
embedding_model = 'embedding-001' # For embeddings

# ChromaDB Settings
CHROMA_DB_PATH = "./chroma_db"
chroma_client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
SECURITY_COLLECTION_NAME = "security_knowledge"
security_collection = chroma_client.get_or_create_collection(SECURITY_COLLECTION_NAME)

# MITRE ATT&CK Data File Path
MITRE_STIX_JSON_PATH = "enterprise-attack.json" # Ensure this file is in the same directory as this script


# --- Splunk Connection & Query Functions ---
def connect_to_splunk():
    """Connects to Splunk and returns a Service object."""
    connection_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
    st.info(f"Attempting to connect to Splunk at {connection_url}...")
    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            scheme="https",
            verify=False # IMPORTANT: For testing with self-signed certs. Use True with a proper CA bundle in production!
        )
        st.success("Successfully connected to Splunk.")
        return service
    except Exception as e:
        st.error(f"Error connecting to Splunk: {e}")
        return None

def run_splunk_query(service, query, output_mode="json"):
    """
    Runs a Splunk search query and returns the results.
    """
    st.info(f"Attempting to run Splunk query:\n```\n{query}\n```")
    try:
        kwargs = {
            "output_mode": output_mode,
            "app": "search"
        }
        job = service.jobs.create(query, **kwargs)

        st.info(f"Splunk Job ID: {job.sid}")
        # Wait for the job to complete
        max_wait_time = 120 # seconds, e.g., 2 minutes. Adjust as needed.
        start_time = time.time()

        status_placeholder = st.empty()
        while not job.is_ready():
            time.sleep(0.5)
            status_placeholder.info(f"Job {job.sid} status: {job.content.get('dispatchState')}")
            
            if time.time() - start_time > max_wait_time:
                status_placeholder.warning(f"Job {job.sid} timed out after {max_wait_time} seconds. Current status: {job.content.get('dispatchState')}")
                job.cancel()
                return []

        if job.is_done():
            status_placeholder.success(f"Splunk search job {job.sid} is DONE. Final dispatch state: {job.content.get('dispatchState')}")
            if job.messages:
                st.warning(f"Job {job.sid} messages: {job.messages}")

            reader = results.ResultsReader(job.results())
            events = []
            for item in reader:
                events.append(item)
                st.success(f"event: {item}")
                

            job.cancel()
            st.info(f"Successfully retrieved {len(events)} events from Splunk for Job ID {job.sid}.")
            return events
        else:
            status_placeholder.error(f"Splunk search job {job.sid} did not complete successfully. Final status: {job.content.get('dispatchState')}")
            if job.messages:
                st.warning(f"Job {job.sid} messages: {job.messages}")
            job.cancel()
            return []
    except Exception as e:
        st.error(f"Error running Splunk query: {e}")
        return []
    
# --- Embedding & ChromaDB Functions ---
def get_embedding(text):
    """Generates an embedding for the given text using the specified Gemini embedding model."""
    try:
        response = genai.embed_content(model=embedding_model, content=text, task_type="RETRIEVAL_DOCUMENT")
        return response['embedding']
    except Exception as e:
        st.warning(f"Error generating embedding for text (first 50 chars): '{text[:50]}...': {e}")
        return None

@st.cache_data(show_spinner=False) # Cache the loaded data for performance
def load_mitre_attack_data_cached(stix_json_path=MITRE_STIX_JSON_PATH):
    """
    Loads MITRE ATT&CK techniques AND their associated mitigations from a STIX 2.x JSON file.
    Cached to avoid reloading on every Streamlit rerun.
    """
    st.info(f"Loading MITRE ATT&CK data from {stix_json_path} using stix2...")
    try:
        stix_store = MemoryStore()
        stix_store.load_from_file(stix_json_path)
        
        all_mitigations_raw = stix_store.query(Filter("type", "=", "course-of-action"))
        mitigations_map = {}
        mitigation_data_points = []

        for miti_sdo in all_mitigations_raw:
            chroma_mitigation_id = miti_sdo.id
            display_mitigation_id = miti_sdo.id
            
            for ext_ref in miti_sdo.external_references:
                if ext_ref.get('source_name') == 'mitre-attack' and 'external_id' in ext_ref:
                    if ext_ref['external_id'].startswith('M'):
                        display_mitigation_id = ext_ref['external_id']
                        break
                    elif ext_ref['external_id'].startswith('T') and not display_mitigation_id.startswith('M'):
                        display_mitigation_id = ext_ref['external_id']
                        
            mitigation_description = miti_sdo.description if hasattr(miti_sdo, 'description') else "No description available."
            
            full_mitigation_text = (
                f"MITRE ATT&CK Mitigation: {miti_sdo.name} (ID: {display_mitigation_id})\n"
                f"Description: {mitigation_description}"
            )
            
            mitigation_data_points.append({
                "id": chroma_mitigation_id,
                "text": full_mitigation_text,
                "metadata": {
                    "type": "mitre_attack_mitigation",
                    "mitigation_stix_id": miti_sdo.id,
                    "mitigation_id_external": display_mitigation_id,
                    "mitigation_name": miti_sdo.name,
                    "source_file": stix_json_path
                }
            })
            mitigations_map[miti_sdo.id] = {
                "name": miti_sdo.name,
                "id_external": display_mitigation_id,
                "description": mitigation_description
            }

        techniques = stix_store.query(Filter("type", "=", "attack-pattern"))
        attack_data_points = []

        for tech in techniques:
            mitre_id = None
            for ext_ref in tech.external_references:
                if ext_ref.get('source_name') == 'mitre-attack' and 'external_id' in ext_ref:
                    if ext_ref['external_id'].startswith('T'):
                        mitre_id = ext_ref['external_id']
                        break
            if not mitre_id:
                continue

            description = tech.description if hasattr(tech, 'description') else "No description available."
            
            tactics_names = []
            if hasattr(tech, 'x_mitre_tactic_refs'):
                for tactic_ref_id in tech.x_mitre_tactic_refs:
                    tactic_sdo = stix_store.get(tactic_ref_id)
                    if tactic_sdo and tactic_sdo.type == 'tactic':
                        tactics_names.append(tactic_sdo.name)
            tactics_str = ', '.join(tactics_names) if tactics_names else 'N/A'
            
            full_tech_text = (
                f"MITRE ATT&CK Technique: {tech.name} (ID: {mitre_id})\n"
                f"Tactics: {tactics_str}\n"
                f"Description: {description}\n"
                f"URL: {tech.external_references[0]['url'] if tech.external_references else 'N/A'}"
            )
            
            attack_data_points.append({
                "id": mitre_id,
                "text": full_tech_text,
                "metadata": {
                    "type": "mitre_attack_technique",
                    "technique_id": mitre_id,
                    "technique_name": tech.name,
                    "tactics": tactics_str,
                    "is_subtechnique": tech.x_mitre_is_subtechnique if hasattr(tech, 'x_mitre_is_subtechnique') else False,
                    "source_file": stix_json_path
                }
            })
        
        st.success(f"Loaded {len(attack_data_points)} MITRE ATT&CK techniques and {len(mitigation_data_points)} mitigations.")
        return attack_data_points + mitigation_data_points

    except FileNotFoundError:
        st.error(f"Error: MITRE ATT&CK STIX JSON file not found at '{stix_json_path}'")
        st.markdown("Please download 'enterprise-attack.json' from [https://attack.mitre.org/resources/attack-data-and-tools/](https://attack.mitre.org/resources/attack-data-and-tools/) and place it in the script's directory.")
        return []
    except Exception as e:
        st.error(f"Error loading MITRE ATT&CK data: {e}")
        return []

def populate_security_knowledge_base(data_points):
    """Populates the ChromaDB collection with security knowledge data points, avoiding duplicates."""
    with st.spinner("Populating security knowledge base..."):
        existing_ids_result = security_collection.get(include=[])
        existing_ids = set(existing_ids_result.get('ids', []))

        docs_to_add = []
        embeddings_to_add = []
        metadatas_to_add = []
        ids_to_add = []

        for dp in data_points:
            unique_id = dp.get("id")
            if not unique_id:
                unique_id = f"custom_knowledge_{hash(dp['text'])}"

            if unique_id in existing_ids:
                continue

            embedding = get_embedding(dp["text"])
            if embedding is not None:
                docs_to_add.append(dp["text"])
                embeddings_to_add.append(embedding)
                metadatas_to_add.append(dp.get("metadata", {}))
                ids_to_add.append(unique_id)
            else:
                st.warning(f"Skipping document due to embedding failure: {dp['text'][:50]}...")

        if docs_to_add:
            try:
                security_collection.add(
                    documents=docs_to_add,
                    embeddings=embeddings_to_add,
                    metadatas=metadatas_to_add,
                    ids=ids_to_add
                )
                st.success(f"Populated vector store with {len(docs_to_add)} new security knowledge documents.")
            except Exception as e:
                st.error(f"Error adding documents to ChromaDB: {e}")
        else:
            st.info("No new unique documents to add to the vector store.")

def search_security_knowledge_base(query_text, n_results=5, filter_metadata=None):
    """
    Searches the ChromaDB knowledge base for relevant documents.
    """
    query_embedding = get_embedding(query_text)
    if query_embedding is not None:
        results = security_collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            include=['documents', 'distances', 'metadatas'],
            where=filter_metadata
        )
        return results
    return None

# --- AI Report Generation Function ---
def generate_incident_report(splunk_logs, relevant_knowledge, mitre_mappings, incident_summary=""):
    """
    Generates a comprehensive security incident report using Gemini.
    """
    mitre_details_str = ""
    if mitre_mappings:
        mitre_details_str = "\n**Potential MITRE ATT&CK Mappings:**\n"
        for mapping in mitre_mappings:
            mitre_details_str += f"* **Technique:** {mapping.get('technique_name', 'N/A')} ({mapping.get('technique_id', 'N/A')})\n"
            if mapping.get('tactics') and mapping['tactics'] != 'N/A':
                mitre_details_str += f"  **Tactics:** {mapping['tactics']}\n"
            description_text = str(mapping.get('description', 'No description.')).strip()
            clean_description = description_text.split("Description: ")[1].split("\nURL:")[0].strip() if "Description: " in description_text else description_text
            mitre_details_str += f"  **Description:** {clean_description[:200]}...\n"
            mitre_details_str += f"  **Confidence (similarity score):** {mapping.get('distance_score', 0.0):.4f}\n"

    prompt = f"""
You are an AI-driven SOC analyst assistant. Your task is to generate a concise and informative incident report based on the provided Splunk logs, potential MITRE ATT&CK mappings, and recommended mitigations.

---
**Splunk Logs (Raw Data for Context):**
{splunk_logs}

---
**Potential MITRE ATT&CK Mappings (Most Relevant First):**
{mitre_details_str if mitre_details_str else "No specific MITRE ATT&CK mappings found or provided. Analyze logs for common adversary behaviors."}

---
**Recommended Mitigations (from Knowledge Base):**
{relevant_knowledge if relevant_knowledge else "No specific mitigation recommendations found. Consider general security best practices."}

---
**Incident Summary (if provided by human analyst):**
{incident_summary if incident_summary else "No specific summary provided, analyze logs for key details."}

---
**Instructions for Report Generation:**
1.  **Incident Title:** Create a clear and descriptive title for the incident.
2.  **Date/Time of Detection:** Extract the earliest and latest timestamps from the logs. Provide a range if multiple times.
3.  **Affected Systems/Users:** Identify specific hosts, IP addresses, or users mentioned in the logs.
4.  **Description of Incident:** Summarize the observed events chronologically. **Crucially, explain how the observed behavior aligns with the most relevant MITRE ATT&CK Tactics and Techniques, referencing their IDs and names from the provided mappings.**
5.  **Attack Vector/Technique (MITRE ATT&CK IDs and names):** Explicitly list the *most relevant* MITRE ATT&CK Tactics and Techniques identified (e.g., "T1078 - Valid Accounts, T1110 - Brute Force").
6.  **Impact:** Briefly describe the potential impact of this incident (e.g., data breach, service disruption, account compromise, unauthorized access).
7.  **Recommended Actions/Remediation:** Based on the identified MITRE techniques and the **"Recommended Mitigations"** section, suggest immediate and long-term actions for containment, eradication, and recovery. If no specific mitigations are found, provide general best practices based on the MITRE techniques.
8.  **Status:** (e.g., New Incident, In Progress, Contained, Resolved) - Default to "New Incident" if unsure.
9.  **Analyst Notes:** Any other observations, open questions, or next steps for further investigation.

Please present the report in a clear, markdown-formatted structure, focusing on actionable intelligence.
"""
    try:
        response = llm.generate_content(prompt)
        return response.text
    except Exception as e:
        st.error(f"Error generating incident report with Gemini: {e}")
        return "Failed to generate incident report."

# --- Main Orchestration Logic ---
def ai_soc_analyst_assistant_app(splunk_query, incident_summary=""):
    st.markdown("### Running AI SOC Analyst Assistant")
    
    splunk_service = connect_to_splunk()

    if not splunk_service:
        return "Failed to connect to Splunk. Cannot proceed."

    st.markdown("---")
    with st.spinner("Retrieving data from Splunk... This may take a moment."):
        raw_splunk_events = run_splunk_query(splunk_service, splunk_query)

    if not raw_splunk_events:
        st.warning("No relevant Splunk logs found for the given query.")
        return generate_incident_report("No logs retrieved.", "No relevant knowledge.", [], incident_summary)

    combined_log_text = " ".join([event.get('_raw', '') for event in raw_splunk_events])

    relevant_knowledge_text = "" 

    st.markdown("---")
    with st.spinner("Searching for relevant MITRE ATT&CK techniques..."):
        mitre_search_results = search_security_knowledge_base(
            combined_log_text, 
            n_results=5, 
            filter_metadata={"type": "mitre_attack_technique"}
        )
        
    mitre_mappings = []
    if mitre_search_results and mitre_search_results['documents']:
        for i in range(len(mitre_search_results['documents'][0])):
            doc = mitre_search_results['documents'][0][i]
            meta = mitre_search_results['metadatas'][0][i]
            dist = mitre_search_results['distances'][0][i]

            similarity_score = 1 - (dist**2 / 2) 
            
            if similarity_score > 0.7:
                mitre_mappings.append({
                    "technique_id": meta.get('technique_id'),
                    "technique_name": meta.get('technique_name'),
                    "tactics": meta.get('tactics'),
                    "description": doc,
                    "distance_score": similarity_score
                })
        st.info(f"Found {len(mitre_mappings)} potential MITRE ATT&CK technique mappings.")
    else:
        st.info("No close MITRE ATT&CK technique mappings found in the knowledge base.")

    st.markdown("---")
    with st.spinner("Searching for relevant MITRE ATT&CK mitigations..."):
        mitigations_text_to_query = ""
        if mitre_mappings:
            mitigations_text_to_query = " ".join([m['description'] for m in mitre_mappings])
        else:
            mitigations_text_to_query = combined_log_text

        relevant_mitigations_results = search_security_knowledge_base(
            mitigations_text_to_query,
            n_results=3,
            filter_metadata={"type": "mitre_attack_mitigation"}
        )
        
    if relevant_mitigations_results and relevant_mitigations_results['documents']:
        relevant_knowledge_text = "\n**Recommended Mitigations (from MITRE ATT&CK):**\n"
        for i in range(len(relevant_mitigations_results['documents'][0])):
            doc = relevant_mitigations_results['documents'][0][i]
            meta = relevant_mitigations_results['metadatas'][0][i]
            dist = relevant_mitigations_results['distances'][0][i]
            similarity_score = 1 - (dist**2 / 2)

            if similarity_score > 0.6:
                mitigation_name = meta.get('mitigation_name', 'N/A')
                mitigation_id_for_display = meta.get('mitigation_id_external', meta.get('mitigation_stix_id', 'N/A'))
                
                description_start_index = doc.find("Description: ")
                description_end_index = doc.find("Mitigates Technique STIX ID:") # This field may not exist for pure mitigations
                clean_description = "No description available."
                if description_start_index != -1:
                    if description_end_index != -1 and description_end_index > description_start_index:
                        clean_description = doc[description_start_index + len("Description: "):description_end_index].strip()
                    else:
                        clean_description = doc[description_start_index + len("Description: "):].strip()
                
                relevant_knowledge_text += (
                    f"* **Mitigation:** {mitigation_name} (ID: {mitigation_id_for_display})\n"
                    f"  **Description:** {clean_description[:200]}...\n"
                    f"  **Similarity Score:** {similarity_score:.4f}\n"
                )
        st.info(f"Found relevant mitigations in the knowledge base.")
    else:
        st.info("No specific mitigation recommendations found in the knowledge base.")
    
    st.markdown("---")
    with st.spinner("Generating incident report with Gemini..."):
        report = generate_incident_report(
            "\n".join([event.get('_raw', '') for event in raw_splunk_events]),
            relevant_knowledge_text,
            mitre_mappings,
            incident_summary
        )
    return report


# Initialize session state for storing analysis results
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None

# Add class names for malware detection
class_names = ['Adialer.C',
 'Agent.FYI',
 'Allaple.A',
 'Allaple.L',
 'Alueron.gen!J',
 'Autorun.K',
 'C2LOP.P',
 'C2LOP.gen!g',
 'Dialplatform.B',
 'Dontovo.A',
 'Fakerean',
 'Instantaccess',
 'Lolyda.AA1',
 'Lolyda.AA2',
 'Lolyda.AA3',
 'Lolyda.AT',
 'Malex.gen!J',
 'Obfuscator.AD',
 'Rbot!gen',
 'Skintrim.N',
 'Swizzor.gen!E',
 'Swizzor.gen!I',
 'VB.AT',
 'Wintrim.BX',
 'Yuner.A']

fixed_transform = transforms.Compose([
    transforms.Resize((256, 256)),       # Forces square shape (may distort)
    transforms.Grayscale(num_output_channels=1),  # Ensure single channel
    transforms.ToTensor(),               # Converts to [0, 1] range
])

def load_malware_model(model_path):
    """Load the malware detection model"""
    model_load_path = model_path
    loaded_model = resnet50(weights=None)
    loaded_model.conv1 = nn.Conv2d(1, 64, kernel_size=(7, 7), stride=(2, 2), padding=(3, 3), bias=False)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    state_dict = torch.load(model_load_path, map_location=device)
    loaded_model.load_state_dict(state_dict)
    loaded_model.to(device)
    loaded_model.eval()
    return loaded_model

def load_model(model_path="utils"):
    """Load the phishing detection model"""
    try:
        # Load tokenizer and model from local directory
        tokenizer = DistilBertTokenizer.from_pretrained("Mowina/distilbert-phishing-model")
        model = DistilBertForSequenceClassification.from_pretrained("Mowina/distilbert-phishing-model")
        model.eval()
        return model, tokenizer
    except Exception as e:
        st.error(f"""
        Error loading the phishing detection model: {str(e)}
        
        Please ensure:
        1. The model files exist in the utils/phishing_model directory
        2. The model files are not corrupted
        3. You have the correct permissions to access the files
        """)
        return None, None

def detect_log_type(log_lines):
    """Detect if the log is a web server log or SSH log"""
    sample_lines = log_lines[:5]
    
    web_pattern = re.compile(
        r'(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>.*?)\s+HTTP\s*[\d\.]+"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
        r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s+(?P<response_time>\d+)'
    )
    
    ssh_pattern = re.compile(
        r'(?P<weekday>\w+)\s+(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<year>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+'
        r'(?P<action>Failed|Accepted)\s+password for\s+(invalid user\s+)?(?P<user>\w+)\s+from\s+(?P<ip>[\d\.]+)\s+port\s+(?P<port>\d+)\s+ssh2'
    )
    
    for line in sample_lines:
        if web_pattern.search(line):
            return 'web'
        if ssh_pattern.search(line):
            return 'ssh'
    
    return 'unknown'

def parse_web_logs(log_lines):
    """Parse web server logs"""
    log_pattern = re.compile(
        r'(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>.*?)\s+HTTP\s*[\d\.]+"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
        r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s+(?P<response_time>\d+)'
    )
    
    parsed_logs = []
    for line in log_lines:
        match = log_pattern.search(line)
        if match:
            log_data = match.groupdict()
            try:
                log_data['timestamp'] = datetime.strptime(log_data['timestamp'], '%d/%b/%Y:%H:%M:%S')
                product_id = re.search(r'productId=([^&]+)', log_data['path'])
                log_data['product_id'] = product_id.group(1) if product_id else None
                category = re.search(r'categoryId=([^&]+)', log_data['path'])
                log_data['category'] = category.group(1) if category else None
                log_data['response_time'] = int(log_data['response_time'])
                parsed_logs.append(log_data)
            except Exception as e:
                st.warning(f"Error parsing log line: {str(e)}")
                continue
    
    df = pd.DataFrame(parsed_logs)
    if df.empty:
        st.error("No valid log entries found in the file")
    else:
        st.success(f"Successfully parsed {len(df)} log entries")
        st.write(f"Found {df['ip'].nunique()} unique IP addresses")
    return df

def parse_ssh_logs(log_lines):
    """Parse SSH logs"""
    log_pattern = re.compile(
        r'(?P<weekday>\w+)\s+(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<year>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+'
        r'(?P<action>Failed|Accepted)\s+password for\s+(invalid user\s+)?(?P<user>\w+)\s+from\s+(?P<ip>[\d\.]+)\s+port\s+(?P<port>\d+)\s+ssh2'
    )
    
    parsed_logs = []
    for line in log_lines:
        match = log_pattern.search(line)
        if match:
            log_data = match.groupdict()
            try:
                log_data['timestamp'] = datetime.strptime(
                    f"{log_data['month']} {log_data['day']} {log_data['time']}", "%b %d %H:%M:%S"
                ).replace(year=2025)
                parsed_logs.append(log_data)
            except Exception as e:
                st.warning(f"Error parsing log line: {str(e)}")
                continue
    
    df = pd.DataFrame(parsed_logs)
    if df.empty:
        st.error("No valid log entries found in the file")
    else:
        st.success(f"Successfully parsed {len(df)} log entries")
        st.write(f"Found {df['ip'].nunique()} unique IP addresses")
    return df

def scan_ip_with_virustotal(ip):
    """Scan IP using VirusTotal API and return key summary info only"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}
        
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(f"{VT_URL}{ip}", headers=headers)
        response.raise_for_status()
        data = response.json()
        
        attr = data.get("data", {}).get("attributes", {})
        
        # Format the last analysis date
        last_analysis_date = attr.get("last_analysis_date", "N/A")
        if last_analysis_date != "N/A":
            last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')

        return {
            "ip": ip,
            "last_analysis_stats": attr.get("last_analysis_stats", {}),
            "reputation": attr.get("reputation", 0),
            "country": attr.get("country", "N/A"),
            "as_owner": attr.get("as_owner", "N/A"),
            "network": attr.get("network", "N/A"),
            "tags": attr.get("tags", []),
            "last_analysis_date": last_analysis_date
        }

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def create_web_analysis(df):
    """Create enhanced analysis for web logs"""
    if df.empty:
        st.error("No data available for analysis")
        return
    
    # Create summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Requests", len(df))
    with col2:
        st.metric("Unique Visitors", df['ip'].nunique())
    with col3:
        st.metric("Avg Response Time", f"{df['response_time'].mean():.2f}ms")
    with col4:
        success_rate = (len(df[df['status'] == '200']) / len(df) * 100) if len(df) > 0 else 0
        st.metric("Success Rate", f"{success_rate:.1f}%")
    
    # Create visualizations
    st.subheader("Request Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.line(
            df.groupby(df['timestamp'].dt.date).size().reset_index(name='requests'),
            x='timestamp',
            y='requests',
            title='Web Server Requests Over Time'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = px.pie(
            df,
            names='status',
            title='Distribution of HTTP Status Codes'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Top Visitors")
    fig = px.bar(
        df['ip'].value_counts().head(10).reset_index(),
        x='ip',
        y='count',
        title='Top 10 Visitors by IP Address'
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Move IP scanning and threat intelligence to the end
    st.subheader("IP Threat Intelligence")
    st.info("Scanning top IPs for threat intelligence... This may take a few moments.")
    
    # Get top 10 IPs
    top_ips = df['ip'].value_counts().head(10)
    ip_scan_results = {}
    
    with st.spinner('Scanning IPs with VirusTotal...'):
        for ip in top_ips.index:
            scan_result = scan_ip_with_virustotal(ip)
            if 'error' not in scan_result:
                ip_scan_results[ip] = {
                    'count': int(top_ips[ip]),
                    'malicious': int(scan_result.get('last_analysis_stats', {}).get('malicious', 0)),
                    'suspicious': int(scan_result.get('last_analysis_stats', {}).get('suspicious', 0)),
                    'reputation': int(scan_result.get('reputation', 0)),
                    'country': scan_result.get('country', 'N/A'),
                    'as_owner': scan_result.get('as_owner', 'N/A'),
                    'tags': scan_result.get('tags', [])
                }
            else:
                st.warning(f"Error scanning IP {ip}: {scan_result['error']}")
    
    if ip_scan_results:
        for ip, data in ip_scan_results.items():
            with st.expander(f"IP: {ip} ({data['count']} requests)"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Malicious Score", data['malicious'])
                with col2:
                    st.metric("Suspicious Score", data['suspicious'])
                with col3:
                    st.metric("Reputation", data['reputation'])
                st.write(f"Country: {data['country']}")
                st.write(f"AS Owner: {data['as_owner']}")
                if data['tags']:
                    st.write("Tags:", ", ".join(data['tags']))
    else:
        st.warning("No IP threat intelligence data available")

def create_ssh_analysis(df):
    """Create enhanced analysis for SSH logs"""
    if df.empty:
        st.error("No data available for analysis")
        return
    
    # Create summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Attempts", len(df))
    with col2:
        st.metric("Successful Logins", len(df[df['action'] == 'Accepted']))
    with col3:
        st.metric("Failed Logins", len(df[df['action'] == 'Failed']))
    with col4:
        success_rate = (len(df[df['action'] == 'Accepted']) / len(df) * 100) if len(df) > 0 else 0
        st.metric("Success Rate", f"{success_rate:.1f}%")
    
    # Create visualizations
    st.subheader("Login Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.line(
            df.groupby(df['timestamp'].dt.date).size().reset_index(name='attempts'),
            x='timestamp',
            y='attempts',
            title='SSH Login Attempts Over Time'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = px.pie(
            df,
            names='action',
            title='Distribution of Login Attempts (Success vs Failed)'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Create heatmap
    st.subheader("Login Attempts by Time")
    heatmap_df = df.copy()
    heatmap_df['hour'] = heatmap_df['timestamp'].dt.hour
    heatmap_df['day'] = heatmap_df['timestamp'].dt.day_name()
    heatmap_data = heatmap_df.groupby(['day', 'hour']).size().reset_index(name='attempts')
    
    fig = px.density_heatmap(
        heatmap_data,
        x='hour',
        y='day',
        z='attempts',
        title='Login Attempts by Day and Hour'
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Move IP scanning and threat intelligence to the end
    st.subheader("IP Threat Intelligence")
    st.info("Scanning top IPs for threat intelligence... This may take a few moments.")
    
    # Get top 10 IPs
    top_ips = df['ip'].value_counts().head(10)
    ip_scan_results = {}
    
    with st.spinner('Scanning IPs with VirusTotal...'):
        for ip in top_ips.index:
            scan_result = scan_ip_with_virustotal(ip)
            if 'error' not in scan_result:
                ip_scan_results[ip] = {
                    'count': int(top_ips[ip]),
                    'malicious': int(scan_result.get('last_analysis_stats', {}).get('malicious', 0)),
                    'suspicious': int(scan_result.get('last_analysis_stats', {}).get('suspicious', 0)),
                    'reputation': int(scan_result.get('reputation', 0)),
                    'country': scan_result.get('country', 'N/A'),
                    'as_owner': scan_result.get('as_owner', 'N/A'),
                    'tags': scan_result.get('tags', [])
                }
            else:
                st.warning(f"Error scanning IP {ip}: {scan_result['error']}")
    
    if ip_scan_results:
        for ip, data in ip_scan_results.items():
            with st.expander(f"IP: {ip} ({data['count']} attempts)"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Malicious Score", data['malicious'])
                with col2:
                    st.metric("Suspicious Score", data['suspicious'])
                with col3:
                    st.metric("Reputation", data['reputation'])
                st.write(f"Country: {data['country']}")
                st.write(f"AS Owner: {data['as_owner']}")
                if data['tags']:
                    st.write("Tags:", ", ".join(data['tags']))
    else:
        st.warning("No IP threat intelligence data available")


def display_web_visualizations(visualizations):
    """Display web log visualizations"""
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total_requests = visualizations['requests_over_time']['requests'].sum()
        st.metric("Total Requests", int(total_requests))
    with col2:
        unique_ips = len(visualizations['top_ips'])
        st.metric("Unique Visitors", unique_ips)
    with col3:
        avg_requests = total_requests / len(visualizations['requests_over_time'])
        st.metric("Avg Requests/Hour", f"{avg_requests:.1f}")
    with col4:
        success_count = visualizations['status_codes'][visualizations['status_codes']['status'] == '200']['count'].sum()
        success_rate = (success_count / total_requests * 100) if total_requests > 0 else 0
        st.metric("Success Rate", f"{success_rate:.1f}%")
    
    # Request Analysis
    st.subheader("Request Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.line(
            visualizations['requests_over_time'],
            x='_time',
            y='requests',
            title='Web Server Requests Over Time'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = px.pie(
            visualizations['status_codes'],
            names='status',
            values='count',
            title='Distribution of HTTP Status Codes'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Top Visitors
    st.subheader("Top Visitors")
    fig = px.bar(
        visualizations['top_ips'],
        x='ip',
        y='count',
        title='Top 10 Visitors by IP Address'
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # IP Threat Intelligence
    st.subheader("IP Threat Intelligence")
    if 'top_ips' in visualizations and not visualizations['top_ips'].empty:
        for _, row in visualizations['top_ips'].iterrows():
            ip = row['ip']
            count = row['count']
            
            # Add loading spinner while fetching VirusTotal data
            with st.spinner(f'Fetching threat intelligence for {ip}...'):
                scan_result = scan_ip_with_virustotal(ip)
                
                if 'error' not in scan_result:
                    with st.expander(f"IP: {ip} ({count} requests)"):
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            malicious = scan_result.get('last_analysis_stats', {}).get('malicious', 0)
                            st.metric("Malicious Score", malicious)
                        with col2:
                            suspicious = scan_result.get('last_analysis_stats', {}).get('suspicious', 0)
                            st.metric("Suspicious Score", suspicious)
                        with col3:
                            reputation = scan_result.get('reputation', 0)
                            st.metric("Reputation", reputation)
                        
                        # Add more detailed information
                        st.write("### Location Information")
                        st.write(f"Country: {scan_result.get('country', 'N/A')}")
                        st.write(f"AS Owner: {scan_result.get('as_owner', 'N/A')}")
                        st.write(f"Network: {scan_result.get('network', 'N/A')}")
                        
                        if scan_result.get('tags'):
                            st.write("### Associated Tags")
                            st.write(", ".join(scan_result['tags']))
                        
                        st.write("### Last Analysis")
                        st.write(f"Date: {scan_result.get('last_analysis_date', 'N/A')}")
                else:
                    st.warning(f"Could not fetch threat intelligence for {ip}: {scan_result['error']}")
    else:
        st.warning("No IP data available for threat intelligence analysis")

def display_ssh_visualizations(visualizations):
    """Display SSH log visualizations"""
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total_attempts = visualizations['attempts_over_time']['attempts'].sum()
        st.metric("Total Attempts", int(total_attempts))
    with col2:
        successful = visualizations['action_distribution'][visualizations['action_distribution']['action'] == 'Accepted']['count'].sum()
        st.metric("Successful Logins", int(successful))
    with col3:
        failed = visualizations['action_distribution'][visualizations['action_distribution']['action'] == 'Failed']['count'].sum()
        st.metric("Failed Logins", int(failed))
    with col4:
        success_rate = (successful / total_attempts * 100) if total_attempts > 0 else 0
        st.metric("Success Rate", f"{success_rate:.1f}%")
    
    # Login Analysis
    st.subheader("Login Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.line(
            visualizations['attempts_over_time'],
            x='_time',
            y='attempts',
            title='SSH Login Attempts Over Time'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = px.pie(
            visualizations['action_distribution'],
            names='action',
            values='count',
            title='Distribution of Login Attempts (Success vs Failed)'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Login Attempts Heatmap
    st.subheader("Login Attempts by Time")
    fig = px.density_heatmap(
        visualizations['attempts_heatmap'],
        x='hour',
        y='day',
        z='count',
        title='Login Attempts by Day and Hour'
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # IP Threat Intelligence
    st.subheader("IP Threat Intelligence")
    if 'top_ips' in visualizations and not visualizations['top_ips'].empty:
        for _, row in visualizations['top_ips'].iterrows():
            ip = row['ip']
            count = row['count']
            
            # Add loading spinner while fetching VirusTotal data
            with st.spinner(f'Fetching threat intelligence for {ip}...'):
                scan_result = scan_ip_with_virustotal(ip)
                
                if 'error' not in scan_result:
                    with st.expander(f"IP: {ip} ({count} attempts)"):
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            malicious = scan_result.get('last_analysis_stats', {}).get('malicious', 0)
                            st.metric("Malicious Score", malicious)
                        with col2:
                            suspicious = scan_result.get('last_analysis_stats', {}).get('suspicious', 0)
                            st.metric("Suspicious Score", suspicious)
                        with col3:
                            reputation = scan_result.get('reputation', 0)
                            st.metric("Reputation", reputation)
                        
                        # Add more detailed information
                        st.write("### Location Information")
                        st.write(f"Country: {scan_result.get('country', 'N/A')}")
                        st.write(f"AS Owner: {scan_result.get('as_owner', 'N/A')}")
                        st.write(f"Network: {scan_result.get('network', 'N/A')}")
                        
                        if scan_result.get('tags'):
                            st.write("### Associated Tags")
                            st.write(", ".join(scan_result['tags']))
                        
                        st.write("### Last Analysis")
                        st.write(f"Date: {scan_result.get('last_analysis_date', 'N/A')}")
                else:
                    st.warning(f"Could not fetch threat intelligence for {ip}: {scan_result['error']}")
    else:
        st.warning("No IP data available for threat intelligence analysis")

def malware_to_image(file_path, width=256):
    """Convert malware binary to grayscale image (MalImg method)."""
    with open(file_path, 'rb') as f:
        bytez = np.frombuffer(f.read(), dtype=np.uint8)
    
    # Reshape to width=256 (height varies)
    height = max(1, len(bytez) // width)
    img = Image.fromarray(bytez[:width * height].reshape((height, width)))
    return img

def predict_malware(file_path, class_names=class_names, model=None):
    """
    Predict the class of a malware binary.

    Args:
        model: Trained PyTorch model.
        file_path: Path to malware binary.
        class_names: List of class names.

    Returns:
        Predicted class (str) and confidence (float).
    """
    if model is None:
        model = load_malware_model("utils/malware_resnet_model.pth")
    
    # Convert malware to image
    img = malware_to_image(file_path)

    # Preprocess and add batch dimension
    img_tensor = fixed_transform(img).unsqueeze(0)  # Shape: [1, 1, 256, 256]

    # Move the input tensor to the same device as the model
    img_tensor = img_tensor.to(next(model.parameters()).device)

    # Predict
    model.eval()
    with torch.no_grad():
        outputs = model(img_tensor)
        probs = torch.nn.functional.softmax(outputs, dim=1)
        conf, pred_idx = torch.max(probs, dim=1)

    return class_names[pred_idx.item()], conf.item()

def predict(text, model, tokenizer, device=None):
    """
    Make a prediction for the given text.
    
    Args:
        text (str): Input text to classify
        model: Loaded DistilBERT model
        tokenizer: Loaded DistilBERT tokenizer
        device (str, optional): Device to run inference on ('cuda' or 'cpu')
        
    Returns:
        dict: Prediction results containing:
            - prediction: 0 for legitimate, 1 for phishing
            - confidence: Confidence score for the prediction
    """
    # Set device
    if device is None:
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    # Move model to device
    model = model.to(device)
    
    # Tokenize input
    inputs = tokenizer(
        text,
        padding=True,
        truncation=True,
        max_length=512,
        return_tensors="pt"
    )
    
    # Move inputs to device
    inputs = {k: v.to(device) for k, v in inputs.items()}
    
    # Make prediction
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.softmax(logits, dim=1)
        
    # Get prediction and confidence
    prediction = torch.argmax(probabilities, dim=1).item()
    confidence = probabilities[0][prediction].item()
    
    return {
        "prediction": prediction,  # 0: legitimate, 1: phishing
        "confidence": confidence
    }

# Main app logic
st.title("🤖 SIEM AI Assistant")

if data_source == "Log Analysis":
    st.header("Log Analyzer")
    st.markdown("""
    This application analyzes web server and SSH logs, providing insights and visualizations.
    You can either upload log files or connect directly to Splunk.
    """)
    
    # Log analysis source selection
    analysis_source = st.radio(
        "Select Data Source",
        ["Upload Log File", "Splunk"]
    )
    
    if analysis_source == "Upload Log File":
        st.subheader("Upload Log File")
        uploaded_file = st.file_uploader("Choose a log file", type=['log', 'txt'])
        
        if uploaded_file is not None:
            log_lines = uploaded_file.read().decode('utf-8').splitlines()
            log_type = detect_log_type(log_lines)
            
            if log_type == 'unknown':
                st.error("Could not detect log type. Please ensure the file contains valid web server or SSH logs.")
            else:
                st.success(f"Detected log type: {log_type.upper()}")
                
                if log_type == 'web':
                    df = parse_web_logs(log_lines)
                    create_web_analysis(df)
                else:  # ssh
                    df = parse_ssh_logs(log_lines)
                    create_ssh_analysis(df)

    else:  # Splunk Integration
        st.header("Splunk")
        
        if 'knowledge_base_initialized' not in st.session_state:
            st.session_state.knowledge_base_initialized = False
        if not st.session_state.knowledge_base_initialized:
            st.sidebar.markdown("### Knowledge Base Setup")
            with st.sidebar:
                with st.spinner("Initializing/Populating Security Knowledge Base (MITRE ATT&CK)..."):
                    total_docs_in_db = security_collection.count()
                    needs_mitre_population = False
                    
                    if total_docs_in_db == 0:
                        needs_mitre_population = True
                        st.info("ChromaDB collection is empty. Populating MITRE ATT&CK data.")
                    else:
                        try:
                            tech_ids = security_collection.get(where={"type": "mitre_attack_technique"}, include=[])['ids']
                            miti_ids = security_collection.get(where={"type": "mitre_attack_mitigation"}, include=[])['ids']
                            tech_count = len(tech_ids)
                            miti_count = len(miti_ids)
                            
                            if tech_count < 500 or miti_count < 50: # Adjust thresholds based on your ATT&CK version
                                needs_mitre_population = True
                                st.warning(f"Insufficient MITRE ATT&CK data found (techniques: {tech_count}, mitigations: {miti_count}). Repopulating...")
                            else:
                                st.success(f"MITRE ATT&CK data (techniques: {tech_count}, mitigations: {miti_count}) already present.")
                        except Exception as e:
                            st.warning(f"Error checking for existing MITRE data: {e}. Assuming MITRE data needs population.")
                            needs_mitre_population = True

                    if needs_mitre_population:
                        st.info("Clearing existing ChromaDB collection to repopulate with fresh MITRE data...")
                        try:
                            chroma_client.delete_collection(SECURITY_COLLECTION_NAME)
                        except Exception as e:
                            st.warning(f"Warning: Could not delete collection (might not exist or be empty): {e}")
                        
                        # Recreate the collection after deletion
                        # Removed 'global security_collection' as it's not needed here
                        security_collection = chroma_client.get_or_create_collection(SECURITY_COLLECTION_NAME) 

                        mitre_all_data_points = load_mitre_attack_data_cached(stix_json_path=MITRE_STIX_JSON_PATH)
                        if mitre_all_data_points:
                            populate_security_knowledge_base(mitre_all_data_points)
                        else:
                            st.error("MITRE ATT&CK data could not be loaded from file. AI mapping might be less effective.")
                    
                    st.info(f"Total unique documents in knowledge base: {security_collection.count()}")
                    st.session_state.knowledge_base_initialized = True
        st.markdown("---")
        splunk_query_input = st.text_area(
            "Enter your Splunk Search Query:",
            value='search index="main" source="archive.zip:*" host="DESKTOP-48V92VC" "Severity Level"="Medium" | head 10',
            height=150,
            help="Provide a Splunk query to retrieve relevant logs for incident analysis."
        )

        incident_summary_input = st.text_area(
            "Optional: Provide a summary of the incident/context for the AI:",
            value="Simulated multiple failed SSH login attempts, a successful login, an attempted SQL Injection, and an encoded PowerShell command on an endpoint.",
            height=100,
            help="Add any additional context or observations to help the AI generate a more accurate report."
        )

        if st.button("Generate Incident Report", type="primary"):
            if not splunk_query_input.strip():
                st.warning("Please enter a Splunk search query.")
            else:
                st.markdown("## Generated Incident Report")
                with st.spinner("Generating report... This might take a few minutes depending on Splunk query complexity and AI processing."):
                    report = ai_soc_analyst_assistant_app(splunk_query_input, incident_summary_input)
                    st.markdown(report)
        else:
            st.info("Enter your Splunk query and summary, then click 'Generate Incident Report'.")

        st.markdown("---")
        st.caption("Developed by Gemini AI for SOC Analyst Automation.")


elif data_source == "Phishing Detection":
    st.header("Phishing Detection")
    st.markdown("""
    This tool analyzes text content to detect potential phishing attempts.
    Enter the text you want to analyze below.
    """)
    
    # Text input for phishing analysis
    text_input = st.text_area(
        "Enter text to analyze",
        height=200,
        help="Enter the text content you want to check for phishing attempts"
    )
    
    if st.button("Analyze for Phishing"):
        if not text_input:
            st.error("Please enter some text to analyze")
        else:
            try:
                with st.spinner("Loading phishing detection model..."):
                    model, tokenizer = load_model()
                    if model is None or tokenizer is None:
                        st.error("Failed to load the phishing detection model. Please check the error message above.")
                        st.stop()
                
                with st.spinner("Analyzing text..."):
                    result = predict(text_input, model, tokenizer)
                
                # Display results
                st.subheader("Analysis Results")
                col1, col2 = st.columns(2)
                
                with col1:
                    is_phishing = bool(result['prediction'])
                    confidence = result['confidence']
                    
                    if is_phishing:
                        st.error("⚠️ Potential Phishing Detected")
                    else:
                        st.success("✅ Likely Legitimate")
                    
                    st.metric("Confidence", f"{confidence:.1%}")
                
                with col2:
                    st.write("### Details")
                    st.write(f"Prediction: {'Phishing' if is_phishing else 'Legitimate'}")
                    st.write(f"Confidence Score: {confidence:.1%}")
                    
                    if is_phishing:
                        st.warning("""
                        **Recommendations:**
                        - Do not click any links in this content
                        - Do not provide any personal information
                        - Report this content to your security team
                        """)
            
            except Exception as e:
                st.error(f"Error during analysis: {str(e)}")
                st.info("""
                If you're seeing a model loading error, please check:
                1. The model files exist in utils/phishing_model
                2. The model files are not corrupted
                3. You have the correct permissions to access the files
                """)

else:  # Malware Analysis
    st.header("Malware Analysis")
    st.markdown("""
    This tool analyzes binary files to detect potential malware.
    Upload a file to analyze its characteristics.
    """)
    
    # File upload for malware analysis
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=['exe', 'dll', 'bin'],
        help="Upload a binary file for malware analysis"
    )
    
    if uploaded_file is not None:
        if st.button("Analyze File"):
            try:
                # Save the uploaded file temporarily
                file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
                with open(file_path, 'wb') as f:
                    f.write(uploaded_file.getvalue())
                
                with st.spinner("Loading malware detection model..."):
                    model = load_malware_model("utils/malware_resnet_model.pth")
                
                with st.spinner("Analyzing file..."):
                    predicted_class, confidence = predict_malware(file_path)
                
                # Display results
                st.subheader("Analysis Results")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric("Detected Class", predicted_class)
                    st.metric("Confidence", f"{confidence:.1%}")
                
                with col2:
                    st.write("### File Information")
                    st.write(f"Filename: {uploaded_file.name}")
                    st.write(f"File Size: {uploaded_file.size / 1024:.1f} KB")
                    
                    if confidence > 0.7:
                        st.error("""
                        ⚠️ **High Confidence Malware Detection**
                        - This file appears to be malicious
                        - Do not execute this file
                        - Report to your security team
                        """)
                    elif confidence > 0.4:
                        st.warning("""
                        ⚠️ **Suspicious File Detected**
                        - Exercise caution with this file
                        - Verify the source
                        - Consider additional scanning
                        """)
                    else:
                        st.success("""
                        ✅ **Likely Safe**
                        - No strong indicators of malware
                        - Still exercise caution with unknown files
                        """)
                
                # Clean up the temporary file
                os.remove(file_path)
            
            except Exception as e:
                st.error(f"Error during analysis: {str(e)}")
                # Clean up the temporary file in case of error
                if os.path.exists(file_path):
                    os.remove(file_path) 