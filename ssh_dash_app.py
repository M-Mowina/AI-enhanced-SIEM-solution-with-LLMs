import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
import re

# Initialize the Dash app
app = dash.Dash(__name__)

# Read and parse the log file
def parse_logs():
    with open(r'data\tutorialdata\mailsv\secure.log', 'r') as file:
        log_lines = file.readlines()

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

    df = pd.DataFrame(parsed_logs)
    df.drop(columns=['month', 'day', 'time'], inplace=True)
    return df

# Parse the logs and create the DataFrame
df = parse_logs()

# Calculate summary statistics
total_attempts = len(df)
successful_logins = len(df[df['action'] == 'Accepted'])
failed_logins = len(df[df['action'] == 'Failed'])
success_rate = (successful_logins / total_attempts * 100) if total_attempts > 0 else 0
unique_ips = df['ip'].nunique()
unique_users = df['user'].nunique()

# Create the layout
app.layout = html.Div([
    html.H1('SSH Log Analysis Dashboard', style={'textAlign': 'center', 'color': '#2c3e50'}),
    
    # Summary Statistics Cards
    html.Div([
        html.Div([
            html.H3('Total Attempts'),
            html.H2(f'{total_attempts:,}')
        ], className='stat-card'),
        html.Div([
            html.H3('Success Rate'),
            html.H2(f'{success_rate:.1f}%')
        ], className='stat-card'),
        html.Div([
            html.H3('Unique IPs'),
            html.H2(f'{unique_ips:,}')
        ], className='stat-card'),
        html.Div([
            html.H3('Unique Users'),
            html.H2(f'{unique_users:,}')
        ], className='stat-card'),
    ], className='stats-container'),

    # Login Attempts Over Time
    html.Div([
        html.H2('Login Attempts Over Time'),
        dcc.Graph(
            figure=px.line(
                df.groupby(df['timestamp'].dt.date).size().reset_index(),
                x='timestamp',
                y=0,
                labels={'timestamp': 'Date', '0': 'Number of Attempts'},
                title='SSH Login Attempts Over Time'
            )
        )
    ], className='graph-container'),

    # Success vs Failed Login Attempts
    html.Div([
        html.H2('Login Attempt Distribution'),
        dcc.Graph(
            figure=px.pie(
                df,
                names='action',
                title='Distribution of Login Attempts (Success vs Failed)'
            )
        )
    ], className='graph-container'),

    # Top IP Addresses
    html.Div([
        html.H2('Top IP Addresses'),
        dcc.Graph(
            figure=px.bar(
                df['ip'].value_counts().head(10).reset_index(),
                x='index',
                y='ip',
                labels={'index': 'IP Address', 'ip': 'Number of Attempts'},
                title='Top 10 IP Addresses Attempting to Log In'
            )
        )
    ], className='graph-container'),

    # Most Targeted Users
    html.Div([
        html.H2('Most Targeted Users'),
        dcc.Graph(
            figure=px.bar(
                df['user'].value_counts().head(10).reset_index(),
                x='index',
                y='user',
                labels={'index': 'Username', 'user': 'Number of Attempts'},
                title='Top 10 Most Targeted Users'
            )
        )
    ], className='graph-container'),

    # Login Attempts by Hour
    html.Div([
        html.H2('Login Attempts by Hour'),
        dcc.Graph(
            figure=px.bar(
                df['timestamp'].dt.hour.value_counts().sort_index().reset_index(),
                x='index',
                y='timestamp',
                labels={'index': 'Hour of Day', 'timestamp': 'Number of Attempts'},
                title='Login Attempts by Hour of Day'
            )
        )
    ], className='graph-container'),

    # Success Rate by User
    html.Div([
        html.H2('Success Rate by User'),
        dcc.Graph(
            figure=px.bar(
                df.groupby('user')['action'].apply(
                    lambda x: (x == 'Accepted').mean() * 100
                ).sort_values(ascending=False).head(10).reset_index(),
                x='user',
                y='action',
                labels={'user': 'Username', 'action': 'Success Rate (%)'},
                title='Top 10 Users by Login Success Rate'
            )
        )
    ], className='graph-container'),
], style={'padding': '20px'})

# Add custom CSS
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>SSH Log Analysis</title>
        {%favicon%}
        {%css%}
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f5f6fa;
                margin: 0;
                padding: 20px;
            }
            .stats-container {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .stat-card {
                background-color: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
            }
            .stat-card h3 {
                margin: 0;
                color: #7f8c8d;
                font-size: 1em;
            }
            .stat-card h2 {
                margin: 10px 0 0 0;
                color: #2c3e50;
                font-size: 2em;
            }
            .graph-container {
                background-color: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }
            .graph-container h2 {
                color: #2c3e50;
                margin-top: 0;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

if __name__ == '__main__':
    app.run_server(debug=True) 