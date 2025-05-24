from flask import Flask, render_template, request, jsonify, send_file
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
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import requests
from dotenv import load_dotenv
from torchvision.models import resnet50
import torch.nn as nn
from torchvision import transforms
import numpy as np
from PIL import Image

load_dotenv()  # Load environment variables

app = Flask(__name__)

# VirusTotal API configuration
VT_API_KEY = os.getenv('VT_API_KEY')
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def load_malware_model(model_path):
    # Define the path to the saved model state dictionary
    model_load_path = model_path

    # Load the pre-trained ResNet50 model (weights are not loaded yet)
    loaded_model = resnet50(weights=None) # Start with no weights, we'll load our own

    # Modify the first convolutional layer to accept 1 input channel
    loaded_model.conv1 = nn.Conv2d(1, 64, kernel_size=(7, 7), stride=(2, 2), padding=(3, 3), bias=False)

    # Define the device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load the saved state dictionary
    state_dict = torch.load(model_load_path, map_location=device) # Map to the desired device

    # Load the state dictionary into the model
    loaded_model.load_state_dict(state_dict)

    # Move the model to the device
    loaded_model.to(device)

    # Set the model to evaluation mode
    loaded_model.eval()
    return loaded_model

fixed_transform = transforms.Compose([
    transforms.Resize((256, 256)),       # Forces square shape (may distort)
    transforms.Grayscale(num_output_channels=1),  # Ensure single channel
    transforms.ToTensor(),               # Converts to [0, 1] range
])

def malware_to_image(file_path, width=256):
    """Convert malware binary to grayscale image (MalImg method)."""
    with open(file_path, 'rb') as f:
        bytez = np.frombuffer(f.read(), dtype=np.uint8)
    
    # Reshape to width=256 (height varies)
    height = max(1, len(bytez) // width)
    img = Image.fromarray(bytez[:width * height].reshape((height, width)))
    return img

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

def predict_malware(file_path, class_names = class_names, model = load_malware_model("utils/malware_resnet_model.pth")):
    """
    Predict the class of a malware binary.

    Args:
        model: Trained PyTorch model.
        file_path: Path to malware binary.
        class_names: List of class names (e.g., ["Trojan", "Ransomware", ...]).

    Returns:
        Predicted class (str) and confidence (float).
    """
    # Convert malware to image
    img = malware_to_image(file_path)

    # Preprocess and add batch dimension
    img_tensor = fixed_transform(img).unsqueeze(0)  # Shape: [1, 1, 256, 256]

    # Move the input tensor to the same device as the model
    img_tensor = img_tensor.to(next(model.parameters()).device) # Get the device from model parameters


    # Predict
    model.eval()
    with torch.no_grad():
        outputs = model(img_tensor)
        probs = torch.nn.functional.softmax(outputs, dim=1)
        conf, pred_idx = torch.max(probs, dim=1)

    return class_names[pred_idx.item()], conf.item()

def load_model(model_path="utils/phishing_model"):
    """
    Load the DistilBERT model and tokenizer from the specified path.
    
    Args:
        model_path (str): Path to the directory containing the model files
        
    Returns:
        tuple: (model, tokenizer)
    """
    # Load tokenizer
    tokenizer = DistilBertTokenizer.from_pretrained(model_path)
    
    # Load model
    model = DistilBertForSequenceClassification.from_pretrained(model_path)
    
    # Set model to evaluation mode
    model.eval()
    
    return model, tokenizer

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

def detect_log_type(log_lines):
    """Detect if the log is a web server log or SSH log"""
    # Check first few lines for patterns
    sample_lines = log_lines[:5]
    
    # Web server log pattern
    web_pattern = re.compile(
        r'(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>.*?)\s+HTTP\s*[\d\.]+"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
        r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s+(?P<response_time>\d+)'
    )
    
    # SSH log pattern
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
            log_data['timestamp'] = datetime.strptime(log_data['timestamp'], '%d/%b/%Y:%H:%M:%S')
            product_id = re.search(r'productId=([^&]+)', log_data['path'])
            log_data['product_id'] = product_id.group(1) if product_id else None
            category = re.search(r'categoryId=([^&]+)', log_data['path'])
            log_data['category'] = category.group(1) if category else None
            log_data['response_time'] = int(log_data['response_time'])
            parsed_logs.append(log_data)
    
    return pd.DataFrame(parsed_logs)

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
            log_data['timestamp'] = datetime.strptime(
                f"{log_data['month']} {log_data['day']} {log_data['time']}", "%b %d %H:%M:%S"
            ).replace(year=2025)
            parsed_logs.append(log_data)
    
    return pd.DataFrame(parsed_logs)

def create_web_analysis(df):
    """Create enhanced analysis for web logs for SOC"""
    # Get top 10 IPs for scanning
    top_ips = df['ip'].value_counts().head(10)
    ip_scan_results = {}
    
    # Scan each IP with VirusTotal
    for ip in top_ips.index:
        scan_result = scan_ip_with_virustotal(ip)
        if 'error' not in scan_result:
            ip_scan_results[ip] = {
                'count': int(top_ips[ip]),  # Convert to native Python int
                'malicious': int(scan_result.get('last_analysis_stats', {}).get('malicious', 0)),
                'suspicious': int(scan_result.get('last_analysis_stats', {}).get('suspicious', 0)),
                'reputation': int(scan_result.get('reputation', 0)),
                'country': scan_result.get('country', 'N/A'),
                'as_owner': scan_result.get('as_owner', 'N/A'),
                'tags': scan_result.get('tags', [])
            }
    
    analysis = {
        'summary': {
            'total_requests': int(len(df)),
            'unique_visitors': int(df['ip'].nunique()),
            'avg_response_time': float(df['response_time'].mean()),
            'success_rate': float((len(df[df['status'] == '200']) / len(df) * 100) if len(df) > 0 else 0),
            'suspicious_user_agents': {k: int(v) for k, v in df['user_agent'].value_counts().head(10).to_dict().items()},
            'top_error_ips': {k: int(v) for k, v in df[df['status'].str.startswith(('4', '5'))]['ip'].value_counts().head(10).to_dict().items()},
            'scanner_like_ips': {k: int(v) for k, v in df.groupby('ip')['path'].nunique().sort_values(ascending=False).head(10).to_dict().items()},
            'ip_scan_results': ip_scan_results
        },
        'plots': {
            'requests_over_time': create_plot(px.line(
                df.groupby(df['timestamp'].dt.date).size().reset_index(name='requests'),
                x='timestamp',
                y='requests',
                labels={'timestamp': 'Date', 'requests': 'Number of Requests'},
                title='Web Server Requests Over Time'
            )),
            'status_codes': create_plot(px.pie(
                df,
                names='status',
                title='Distribution of HTTP Status Codes'
            )),
            'top_visitors': create_plot(px.bar(
                df['ip'].value_counts().head(10).reset_index(),
                x='ip',
                y='count',
                labels={'ip': 'IP Address', 'count': 'Number of Requests'},
                title='Top 10 Visitors by IP Address'
            )),
            'requests_by_hour': create_plot(px.bar(
                df['timestamp'].dt.hour.value_counts().sort_index().reset_index(),
                x='timestamp',
                y='count',
                labels={'timestamp': 'Hour of Day', 'count': 'Number of Requests'},
                title='Requests by Hour of Day'
            )),
            'most_requested_paths': create_plot(px.bar(
                df['path'].value_counts().head(10).reset_index(),
                x='count',
                y='path',
                orientation='h',
                labels={'path': 'Endpoint', 'count': 'Hits'},
                title='Top 10 Requested Paths'
            ).update_layout(
                height=400,  # Adjust height to fit all endpoints comfortably
                width=900,   # Increase width to expand the chart to the right
                margin=dict(l=150)  # Optional: Increase left margin if endpoint names are long
            ))
        }
    }
    return analysis
    
def create_ssh_analysis(df):
    """Create enhanced analysis for SSH logs for SOC"""
    # Get top 10 IPs for scanning
    top_ips = df['ip'].value_counts().head(10)
    ip_scan_results = {}
    
    # Scan each IP with VirusTotal
    for ip in top_ips.index:
        scan_result = scan_ip_with_virustotal(ip)
        if 'error' not in scan_result:
            ip_scan_results[ip] = {
                'count': int(top_ips[ip]),  # Convert to native Python int
                'malicious': int(scan_result.get('last_analysis_stats', {}).get('malicious', 0)),
                'suspicious': int(scan_result.get('last_analysis_stats', {}).get('suspicious', 0)),
                'reputation': int(scan_result.get('reputation', 0)),
                'country': scan_result.get('country', 'N/A'),
                'as_owner': scan_result.get('as_owner', 'N/A'),
                'tags': scan_result.get('tags', [])
            }
    
    heatmap_df = df.copy()
    heatmap_df['hour'] = heatmap_df['timestamp'].dt.hour
    heatmap_df['day'] = heatmap_df['timestamp'].dt.day_name()
    heatmap_data = heatmap_df.groupby(['day', 'hour']).size().reset_index(name='attempts')

    analysis = {
        'summary': {
            'total_attempts': int(len(df)),
            'successful_logins': int(len(df[df['action'] == 'Accepted'])),
            'failed_logins': int(len(df[df['action'] == 'Failed'])),
            'success_rate': float((len(df[df['action'] == 'Accepted']) / len(df) * 100) if len(df) > 0 else 0),
            'unique_ips': int(df['ip'].nunique()),
            'unique_users': int(df['user'].nunique()),
            'targeted_users': {k: int(v) for k, v in df['user'].value_counts().head(10).to_dict().items()},
            'failed_ips': {k: int(v) for k, v in df[df['action'] == 'Failed']['ip'].value_counts().head(10).to_dict().items()},
            'ip_scan_results': ip_scan_results
        },
        'plots': {
            'login_attempts_over_time': create_plot(px.line(
                df.groupby(df['timestamp'].dt.date).size().reset_index(name='attempts'),
                x='timestamp',
                y='attempts',
                labels={'timestamp': 'Date', 'attempts': 'Number of Attempts'},
                title='SSH Login Attempts Over Time'
            )),
            'success_vs_failed': create_plot(px.pie(
                df,
                names='action',
                title='Distribution of Login Attempts (Success vs Failed)'
            )),
            'top_ips': create_plot(px.bar(
                df['ip'].value_counts().head(10).reset_index(),
                x='ip',
                y='count',
                labels={'ip': 'IP Address', 'count': 'Number of Attempts'},
                title='Top 10 IP Addresses Attempting to Log In'
            )),
            'attempts_by_hour': create_plot(px.bar(
                df['timestamp'].dt.hour.value_counts().sort_index().reset_index(),
                x='timestamp',
                y='count',
                labels={'timestamp': 'Hour of Day', 'count': 'Number of Attempts'},
                title='Login Attempts by Hour of Day'
            )),
            'login_attempts_heatmap': create_plot(px.density_heatmap(
                heatmap_data, x='hour', y='day', z='attempts',
                title='Login Attempts by Day and Hour'
            ))
        }
    }
    return analysis

def create_plot(fig):
    """Convert plotly figure to JSON"""
    return json.loads(fig.to_json())

def scan_ip_with_virustotal(ip):
    """Scan IP using VirusTotal API and return key summary info only"""
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(f"{VT_URL}{ip}", headers=headers)
        response.raise_for_status()
        data = response.json()
        
        attr = data.get("data", {}).get("attributes", {})

        return {
            "ip": ip,
            "last_analysis_stats": attr.get("last_analysis_stats", {}),
            "reputation": attr.get("reputation", 0),
            "country": attr.get("country", "N/A"),
            "as_owner": attr.get("as_owner", "N/A"),
            "network": attr.get("network", "N/A"),
            "tags": attr.get("tags", []),
            "last_analysis_date": attr.get("last_analysis_date", "N/A"),
        }

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Read the log file
    log_lines = file.read().decode('utf-8').splitlines()
    
    # Detect log type
    log_type = detect_log_type(log_lines)
    if log_type == 'unknown':
        return jsonify({'error': 'Could not detect log type'}), 400
    
    # Parse logs based on type
    if log_type == 'web':
        df = parse_web_logs(log_lines)
        analysis = create_web_analysis(df)
    else:  # ssh
        df = parse_ssh_logs(log_lines)
        analysis = create_ssh_analysis(df)
    
    return jsonify({
        'log_type': log_type,
        'analysis': analysis
    })

@app.route('/ip_details/<ip>')
def ip_details(ip):
    """Get detailed information about a specific IP address"""
    scan_result = scan_ip_with_virustotal(ip)
    if 'error' in scan_result:
        return jsonify({'error': scan_result['error']}), 400
    
    return jsonify({
        'ip': ip,
        'last_analysis_stats': scan_result.get('last_analysis_stats', {}),
        'reputation': scan_result.get('reputation', 0),
        'country': scan_result.get('country', 'N/A'),
        'as_owner': scan_result.get('as_owner', 'N/A'),
        'network': scan_result.get('network', 'N/A'),
        'tags': scan_result.get('tags', []),
        'last_analysis_date': scan_result.get('last_analysis_date', 'N/A')
    })

@app.route('/analyze_malware', methods=['POST'])
def analyze_malware():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Save the file temporarily
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    try:
        # Predict malware class
        predicted_class, confidence = predict_malware(file_path)
        
        # Clean up the temporary file
        os.remove(file_path)
        
        return jsonify({
            'filename': file.filename,
            'predicted_class': predicted_class,
            'confidence': confidence
        })
    except Exception as e:
        # Clean up the temporary file in case of error
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'error': str(e)}), 500

@app.route('/analyze_phishing', methods=['POST'])
def analyze_phishing():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'error': 'No text provided'}), 400
    
    text = data['text']
    
    try:
        # Load the model and tokenizer
        model, tokenizer = load_model()
        
        # Make prediction
        result = predict(text, model, tokenizer)
        
        return jsonify({
            'text': text,
            'is_phishing': bool(result['prediction']),  # Convert to boolean
            'confidence': result['confidence']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 