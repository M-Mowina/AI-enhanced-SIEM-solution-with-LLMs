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

app = Flask(__name__)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
    analysis = {
        'summary': {
            'total_requests': len(df),
            'unique_visitors': df['ip'].nunique(),
            'avg_response_time': df['response_time'].mean(),
            'success_rate': (len(df[df['status'] == '200']) / len(df) * 100) if len(df) > 0 else 0,
            'suspicious_user_agents': df['user_agent'].value_counts().head(10).to_dict(),
            'top_error_ips': df[df['status'].str.startswith(('4', '5'))]['ip'].value_counts().head(10).to_dict(),
            'scanner_like_ips': df.groupby('ip')['path'].nunique().sort_values(ascending=False).head(10).to_dict()
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
                x='index',
                y='ip',
                labels={'index': 'IP Address', 'ip': 'Number of Requests'},
                title='Top 10 Visitors by IP Address'
            )),
            'requests_by_hour': create_plot(px.bar(
                df['timestamp'].dt.hour.value_counts().sort_index().reset_index(),
                x='index',
                y='timestamp',
                labels={'index': 'Hour of Day', 'timestamp': 'Number of Requests'},
                title='Requests by Hour of Day'
            )),
            'most_requested_paths': create_plot(px.bar(
                df['path'].value_counts().head(10).reset_index(),
                x='path',
                y='index',
                orientation='h',
                labels={'index': 'Endpoint', 'path': 'Hits'},
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
    heatmap_df = df.copy()
    heatmap_df['hour'] = heatmap_df['timestamp'].dt.hour
    heatmap_df['day'] = heatmap_df['timestamp'].dt.day_name()
    heatmap_data = heatmap_df.groupby(['day', 'hour']).size().reset_index(name='attempts')

    analysis = {
        'summary': {
            'total_attempts': len(df),
            'successful_logins': len(df[df['action'] == 'Accepted']),
            'failed_logins': len(df[df['action'] == 'Failed']),
            'success_rate': (len(df[df['action'] == 'Accepted']) / len(df) * 100) if len(df) > 0 else 0,
            'unique_ips': df['ip'].nunique(),
            'unique_users': df['user'].nunique(),
            'targeted_users': df['user'].value_counts().head(10).to_dict(),
            'failed_ips': df[df['action'] == 'Failed']['ip'].value_counts().head(10).to_dict()
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
                x='index',
                y='ip',
                labels={'index': 'IP Address', 'ip': 'Number of Attempts'},
                title='Top 10 IP Addresses Attempting to Log In'
            )),
            'attempts_by_hour': create_plot(px.bar(
                df['timestamp'].dt.hour.value_counts().sort_index().reset_index(),
                x='index',
                y='timestamp',
                labels={'index': 'Hour of Day', 'timestamp': 'Number of Attempts'},
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

if __name__ == '__main__':
    app.run(debug=True) 