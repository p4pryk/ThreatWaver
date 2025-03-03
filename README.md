# ThreatWeaver

ThreatWeaver is an advanced web application that leverages artificial intelligence for automated threat modeling and security analysis. It allows users to upload architecture diagrams and detailed application descriptions, which are then analyzed using the STRIDE and MITRE ATT&CK frameworks, generating clear threat models along with recommendations for mitigation measures.

![image](https://github.com/user-attachments/assets/b6c35673-a590-4a1d-9b57-8fce4da00f49)


## Features

- **AI-Powered Diagram Analysis**: Upload architecture diagrams and get automatic descriptions.
- **Dual Framework Support**: Generate threat models using both STRIDE and MITRE ATT&CK frameworks.
- **Detailed Security Analysis**: Obtain specific threat scenarios, potential impacts, and mitigation strategies.
- **Export Options**: Export results in both JSON and CSV formats for further analysis and documentation.

## Getting Started

### Prerequisites

- Python 3.8+
- Flask
- Azure OpenAI API access

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/p4pryk/threatweaver.git
   cd threatweaver
   ```

2. Install dependencies:
   ```bash
   pip install flask openai
   ```

3. Configure your Azure OpenAI API settings in the application:
   ```python
   AZURE_API_ENDPOINT = "your-azure-endpoint"
   AZURE_API_KEY = "your-api-key"
   AZURE_DEPLOYMENT_NAME = "your-deployment-name"
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Access the application in your browser at: `http://localhost:5000`

## Usage

1. **Upload a Diagram**: Select an architecture diagram file and click "Upload" to get an automatic description.
2. **Enter Application Details**: Provide security details about your application.
3. **Generate Models**: Click either "Generate STRIDE Model" or "Generate MITRE Model" to create a threat analysis.
4. **Review Results**: Examine the generated threats and security suggestions.
5. **Export Data**: Use the export buttons to save results as JSON or CSV files.

## Security Framework Details

### STRIDE Model
The STRIDE model categorizes threats into six categories:
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

### MITRE ATT&CK Framework
The MITRE ATT&CK framework is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides detailed information about:
- Tactics (the why of an attack)
- Techniques (the how of an attack)
- Specific procedures used by threat actors

## Acknowledgements

- Azure OpenAI for providing the AI capabilities
- Bootstrap for the frontend framework
- Flask for the web application framework
