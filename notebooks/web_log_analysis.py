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
    with open(r'data\tutorialdata\www1\access.log', 'r') as file:
        log_lines = file.readlines()

    # Define the log pattern
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
            # Parse timestamp
            log_data['timestamp'] = datetime.strptime(log_data['timestamp'], '%d/%b/%Y:%H:%M:%S')
            # Extract product ID if present
            product_id = re.search(r'productId=([^&]+)', log_data['path'])
            log_data['product_id'] = product_id.group(1) if product_id else None
            # Extract category if present
            category = re.search(r'categoryId=([^&]+)', log_data['path'])
            log_data['category'] = category.group(1) if category else None
            log_data['response_time'] = int(log_data['response_time'])
            parsed_logs.append(log_data)

    df = pd.DataFrame(parsed_logs)
    return df

# Parse the logs and create the DataFrame
df = parse_logs()

# Calculate summary statistics
total_requests = len(df)
unique_visitors = df['ip'].nunique()
avg_response_time = df['response_time'].mean()
success_rate = (len(df[df['status'] == '200']) / total_requests * 100) if total_requests > 0 else 0

# Create the layout
app.layout = html.Div([
    html.H1('Web Server Log Analysis Dashboard', style={'textAlign': 'center', 'color': '#2c3e50'}),
    
    # Summary Statistics Cards
    html.Div([
        html.Div([
            html.H3('Total Requests'),
            html.H2(f'{total_requests:,}')
        ], className='stat-card'),
        html.Div([
            html.H3('Unique Visitors'),
            html.H2(f'{unique_visitors:,}')
        ], className='stat-card'),
        html.Div([
            html.H3('Success Rate'),
            html.H2(f'{success_rate:.1f}%')
        ], className='stat-card'),
        html.Div([
            html.H3('Avg Response Time'),
            html.H2(f'{avg_response_time:.0f}ms')
        ], className='stat-card'),
    ], className='stats-container'),

    # Requests Over Time
    html.Div([
        html.H2('Requests Over Time'),
        dcc.Graph(
            figure=px.line(
                df.groupby(df['timestamp'].dt.date).size().reset_index(),
                x='timestamp',
                y=0,
                labels={'timestamp': 'Date', '0': 'Number of Requests'},
                title='Web Server Requests Over Time'
            )
        )
    ], className='graph-container'),

    # HTTP Status Codes
    html.Div([
        html.H2('HTTP Status Codes'),
        dcc.Graph(
            figure=px.pie(
                df,
                names='status',
                title='Distribution of HTTP Status Codes'
            )
        )
    ], className='graph-container'),

    # Top IP Addresses
    html.Div([
        html.H2('Top Visitors'),
        dcc.Graph(
            figure=px.bar(
                df['ip'].value_counts().head(10).reset_index(),
                x='index',
                y='ip',
                labels={'index': 'IP Address', 'ip': 'Number of Requests'},
                title='Top 10 Visitors by IP Address'
            )
        )
    ], className='graph-container'),

    # Most Accessed Categories
    html.Div([
        html.H2('Most Accessed Categories'),
        dcc.Graph(
            figure=px.bar(
                df['category'].value_counts().head(10).reset_index(),
                x='index',
                y='category',
                labels={'index': 'Category', 'category': 'Number of Requests'},
                title='Top 10 Most Accessed Categories'
            )
        )
    ], className='graph-container'),

    # Most Popular Products
    html.Div([
        html.H2('Most Popular Products'),
        dcc.Graph(
            figure=px.bar(
                df['product_id'].value_counts().head(10).reset_index(),
                x='index',
                y='product_id',
                labels={'index': 'Product ID', 'product_id': 'Number of Views'},
                title='Top 10 Most Viewed Products'
            )
        )
    ], className='graph-container'),

    # Requests by Hour
    html.Div([
        html.H2('Requests by Hour'),
        dcc.Graph(
            figure=px.bar(
                df['timestamp'].dt.hour.value_counts().sort_index().reset_index(),
                x='index',
                y='timestamp',
                labels={'index': 'Hour of Day', 'timestamp': 'Number of Requests'},
                title='Requests by Hour of Day'
            )
        )
    ], className='graph-container'),

    # Response Time Distribution
    html.Div([
        html.H2('Response Time Distribution'),
        dcc.Graph(
            figure=px.histogram(
                df,
                x='response_time',
                nbins=50,
                labels={'response_time': 'Response Time (ms)'},
                title='Distribution of Response Times'
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
        <title>Web Server Log Analysis</title>
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