# AI-enhanced SIEM Solution

An advanced Security Information and Event Management (SIEM) solution that leverages Large Language Models (LLMs) and Exploratory Data Analysis (EDA) to analyze, summarize, and explore security attacks using log data.

## Features

- **Log Analysis**: Process and analyze security logs using advanced NLP techniques
- **Attack Detection**: Identify potential security threats and attacks using machine learning
- **Visualization**: Interactive dashboards for security metrics and attack patterns
- **LLM Integration**: Leverage transformer models for log summarization and threat analysis

## Prerequisites

- Python 3.8 or higher
- CUDA-compatible GPU (recommended for LLM operations)
- Sufficient RAM (16GB minimum recommended)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/AI-enhanced-SIEM-solution.git
cd AI-enhanced-SIEM-solution
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Download required NLTK data:
```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Access the dashboard at `http://localhost:8050`

## Project Structure

```
AI-enhanced-SIEM-solution/
├── app.py                 # Main application entry point
├── requirements.txt       # Project dependencies
├── data/                  # Data directory
├── models/               # ML models and configurations
├── utils/                # Utility functions
└── notebooks/            # Jupyter notebooks for analysis
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Dash and Plotly for visualization
- Powered by PyTorch and Transformers for ML capabilities
- Uses various open-source security tools and libraries
