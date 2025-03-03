import os
import json
import base64
import logging
from flask import Flask, request, render_template_string, jsonify, flash, redirect, url_for
from openai import AzureOpenAI

# === CONFIGURE LOGGING ===
logging.basicConfig(level=logging.INFO)

# === INITIALIZE AZURE OPENAI ENDPOINTS ===
AZURE_API_ENDPOINT = ""
AZURE_API_KEY = ""
AZURE_API_VERSION = "2024-12-01-preview"
AZURE_DEPLOYMENT_NAME = "gpt-4o"

# === INITIALIZE FLASK APP ===
app = Flask(__name__)
app.secret_key = 'ENTER_YOUR_KEY'


# =================== Threat Modeling Functions ===================

def create_image_analysis_prompt():
    return (
        """
        Analyze the provided architecture diagram for security threat modeling by detailing the key components, their interactions, and potential security implications. Focus specifically on the following areas:

        - System components and relationships: Describe the components, their purpose, and how they interrelate.
        - Data flows and trust boundaries: Examine the flow of information between components, including transitions across trust boundaries.
        - External interfaces and integration points: Identify external-facing components and their connectivity to third-party systems.
        - Security controls: Highlight only the security mechanisms explicitly shown in the diagram.

        # Steps

        1. Identify and list all primary system components visible in the diagram.
        2. Explain the relationships between these components, emphasizing notable trust relationships.
        3. Trace and describe the data flows between components, specifying crossing of trust boundaries if applicable.
        4. Document the external-facing interfaces and describe their integration points (e.g., APIs, third-party services, external networks).
        5. Clearly identify all security controls present in the diagram (e.g., firewalls, encryption mechanisms, IDS/IPS).
        6. Conclude by mentioning any visible security gaps or areas requiring further clarification or enhancement.

        # Notes

        - Base your explanation entirely on the visible elements of the diagram. Avoid unfounded assumptions about unrepresented components or controls.
        - Avoid redundant descriptions; keep the analysis concise and relevant.
        - Include recommendations (if any) explicitly tied to gaps or implications visible in the diagram.
        - Provide a clear, structured explanation without any introductory phrases.
        - Only include information that is directly visible in the diagram.
        - Don't use Markdown in outputs. Use only plain text.
        """
    )

def analyze_image_azure(client, deployment_name, image_data, prompt):
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=[
                {"role": "user", "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_data}"}}
                ]}
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        logging.error(f"Error during image analysis: {str(e)}")
        return None

def create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
Prepare a comprehensive STRIDE threat model analysis for the provided application details. Follow these detailed steps:

For each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), identify 3 to 4 credible threat scenarios. For each scenario, include:

Threat Type: Specify the STRIDE category.
Scenario: Describe a specific and realistic example of how the threat might occur in the context of the application.
Potential Impact: Detail the consequences if the threat is successfully exploited.
Mitigations: List specific security controls, best practices, and technical solutions to prevent or reduce the risk of this threat.
Generate the output in JSON format with the following structure:

"threat": An array of objects, each representing a threat scenario with keys "Threat Type", "Scenario", "Potential Impact", and "Mitigations".
"security_suggestions": An array of actionable recommendations directly addressing the identified risks.

Example of expected JSON response format:
{{
"threat": [
{{
"Threat Type": "Spoofing",
"Scenario": "Example Scenario 1",
"Potential Impact": "Example Potential Impact 1",
"Mitigations": "Example Mitigations 1"
}}
],
"security_suggestions": [
"Example improvement suggestion 1"
]
}}

Adapt threat scenarios to the specifics of the application type and provided details. Include considerations for both internal network scenarios and internet-facing components, where applicable.
For any components or features not explicitly mentioned in the application details, use reasonable industry norms and best practices as assumptions.
Use the following application details:

APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {', '.join(authentication) if authentication else 'None'}
INTERNET FACING: {internet_facing}
DATA CONFIDENTIALITY: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
"""
    return prompt

def create_mitre_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
Using the MITRE ATT&CK framework, prepare a detailed threat model analysis for the provided application details. For each relevant MITRE tactic, identify applicable threat techniques and provide specific scenarios in which these techniques could be exploited. For each identified threat, include:

- Tactic: The MITRE tactic related to the threat.
- Technique: The specific MITRE technique.
- Scenario: A realistic example of how the threat might occur in the context of the application.
- Potential Impact: A description of the consequences if the threat is successfully exploited.
- Mitigations: Recommended security controls, best practices, or technical solutions to mitigate the threat.

Generate the output in JSON format with the following structure:

"threat": An array of objects, each representing a threat scenario with keys "Tactic", "Technique", "Scenario", "Potential Impact", and "Mitigations".
"security_suggestions": An array of actionable recommendations addressing the identified risks.

Example of expected JSON response format:
{{
"threat": [
{{
"Tactic": "Initial Access",
"Technique": "Technique Number (Technique Name) example: T1190 (Exploit Public-Facing Application)",
"Scenario": "Example Scenario 1",
"Potential Impact": "Example Potential Impact 1",
"Mitigations": "Example Mitigations 1"
}}
],
"security_suggestions": [
"Example improvement suggestion 1"
]
}}

Adapt threat scenarios to the specifics of the application type and provided details. Consider both internal network threats and internet-facing threats.
For any components or features not explicitly mentioned in the application details, use reasonable industry norms and best practices as assumptions.
Use the following application details:

APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {', '.join(authentication) if authentication else 'None'}
INTERNET FACING: {internet_facing}
DATA CONFIDENTIALITY: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
"""
    return prompt

def generate_threat_model(prompt):
    client = AzureOpenAI(
        azure_endpoint=AZURE_API_ENDPOINT,
        api_key=AZURE_API_KEY,
        api_version=AZURE_API_VERSION,
    )
    response = client.chat.completions.create(
        model=AZURE_DEPLOYMENT_NAME,
        messages=[
            {"role": "system", "content": """You are an expert cybersecurity threat modeling assistant specializing in application security. 
            You have extensive knowledge of secure coding practices, threat intelligence, and security frameworks including STRIDE and MITRE ATT&CK. 
            
            When creating threat models:
            1. Analyze the application context thoroughly before suggesting threats
            2. Identify realistic, specific and actionable threats rather than generic risks
            3. Adapt threats to match the specific technology stack, deployment model, and sensitivity level described
            4. Ensure all threats include concrete impact descriptions and practical mitigation measures
            5. Format output as clean, valid JSON that follows the structure requested in the prompt
            6. Focus on quality over quantity - prioritize meaningful threats over exhaustive lists
            7. Provide security suggestions that address the most critical risks first
            8. Use modern, industry-standard terminology and reference relevant security standards when appropriate
            9. Stay within the specified framework (STRIDE or MITRE ATT&CK) as indicated in the prompt
            
            The output must be valid, parseable JSON without additional text, markdown formatting, or explanations.
            """},
            {"role": "user", "content": prompt}
        ]
    )
    try:
        content = response.choices[0].message.content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.endswith("```"):
            content = content[:-3]
        return json.loads(content)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse API response. Raw response: {content}")
        raise Exception(f"Failed to parse response: {str(e)}")
    except Exception as e:
        raise Exception(f"Error processing response: {str(e)}")

# =================== Helper Functions for Flask Routes ===================

def render_form():
    return render_template_string(FORM_TEMPLATE)

def handle_upload():
    file = request.files.get("diagram")
    if not file or file.filename == "":
        return jsonify({"error": "No file uploaded"}), 400

    file_bytes = file.read()
    image_data = base64.b64encode(file_bytes).decode("utf-8")
    image_prompt = create_image_analysis_prompt()

    client = AzureOpenAI(
        azure_endpoint=AZURE_API_ENDPOINT,
        api_key=AZURE_API_KEY,
        api_version=AZURE_API_VERSION,
    )
    analysis_result = analyze_image_azure(client, AZURE_DEPLOYMENT_NAME, image_data, image_prompt)
    if analysis_result:
        return jsonify({"analysis": analysis_result})
    else:
        return jsonify({"error": "Failed to analyze the image"}), 500

def handle_stride_model():
    try:
        description = request.form.get("description", "").strip()
        app_type = request.form.get("app_type", "Web Application")
        data_confidentiality = request.form.get("data_confidentiality", "Not Confidential")
        public_private = request.form.get("public_private", "Public")
        authentication = request.form.get("authentication", "None")

        if not description:
            flash("Please fill in the Application Description.", "warning")
            return redirect(url_for("index"))

        auth_methods = [authentication] if authentication and authentication != "None" else []
        prompt = create_threat_model_prompt(
            app_type=app_type,
            authentication=auth_methods,
            internet_facing=public_private,
            sensitive_data=data_confidentiality,
            app_input=description
        )
        threat_model_response = generate_threat_model(prompt)
        for threat in threat_model_response.get("threat", []):
            if "Technique" in threat:
                del threat["Technique"]
        return jsonify(threat_model_response)
    except Exception as e:
        logging.exception("Error generating STRIDE model")
        return jsonify({"error": str(e)}), 500

def handle_mitre_model():
    try:
        description = request.form.get("description", "").strip()
        app_type = request.form.get("app_type", "Web Application")
        data_confidentiality = request.form.get("data_confidentiality", "Not Confidential")
        public_private = request.form.get("public_private", "Public")
        authentication = request.form.get("authentication", "None")

        if not description:
            flash("Please fill in the Application Description.", "warning")
            return redirect(url_for("index"))

        auth_methods = [authentication] if authentication and authentication != "None" else []
        prompt = create_mitre_model_prompt(
            app_type=app_type,
            authentication=auth_methods,
            internet_facing=public_private,
            sensitive_data=data_confidentiality,
            app_input=description
        )
        mitre_model_response = generate_threat_model(prompt)
        return jsonify(mitre_model_response)
    except Exception as e:
        logging.exception("Error generating MITRE model")
        return jsonify({"error": str(e)}), 500

# =================== HTML Template with new buttons (Export to JSON and Export to CSV) ===================

FORM_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ThreatWeaver</title>
  <!-- Bootstrap CSS (using 4.5.2 for compatibility) -->
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  <!-- Google Font: Fira Code -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Fira+Code&display=swap">
  <style>
    html, body {
      height: 100%;
      margin: 0;
      background-color: #1e1e1e;
      color: #ccc;
      font-family: 'Fira Code', monospace;
      font-size: 14px;
    }
    /* Klasa dla słowa Weaver, z wyjątkiem navbaru */
    .weaver {
      color: #007acc;
    }
    .navbar-custom {
      background-color: #007acc;
    }
    .navbar-custom .navbar-brand {
      color: #fff;
      font-weight: bold;
      font-size: 1rem;
    }
    .container {
      margin-top: 2rem;
      background-color: #252526;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.5);
    }
    h1, h4 {
      color: #fff;
    }
    /* Ustawienie etykiet w kolorze niebieskim */
    .form-label {
      font-weight: 600;
      color: #007acc;
    }
    .form-control, .form-select, .btn {
      border-radius: 4px;
    }
    .form-control {
      background-color: #1e1e1e;
      color: #ccc;
      border: 1px solid #333;
    }
    .btn-primary, .btn-mitre, .btn-upload {
      background-color: #007acc;
      border: none;
      font-weight: bold;
      color: #fff; /* Białe napisy */
    }
    .btn-primary:hover, .btn-mitre:hover, .btn-upload:hover {
      background-color: #005f9e;
    }
    .spinner-border {
      width: 1rem;
      height: 1rem;
      border-width: .2em;
    }
    /* Adjust input-group for file upload to have both elements in one row */
    .input-group .form-control {
      border-top-right-radius: 0;
      border-bottom-right-radius: 0;
    }
    .input-group .btn {
      border-top-left-radius: 0;
      border-bottom-left-radius: 0;
    }
    /* Add margin between buttons in btn-group */
    .btn-group > .btn + .btn {
      margin-left: 10px;
    }
    /* Style for result tables */
    .result-table {
      background-color: #1e1e1e;
      color: #ccc;
      width: 100%;
      border-collapse: collapse;
    }
    .result-table th, .result-table td {
      border: 1px solid #333;
      padding: 8px;
    }
    /* Nagłówki kolumn w tabelach w kolorze niebieskim */
    .result-table th {
      color: #007acc;
    }
    .result-heading {
      margin-top: 2rem;
    }
    .list-group-item {
      background-color: #1e1e1e;
      color: #ccc;
      border: 1px solid #333;
    }
    /* Spinner styling inline under the buttons */
    .overlay-spinner {
      display: none;
      margin-top: 1rem;
      text-align: center;
    }
    .overlay-spinner > div {
      display: inline-flex;
      align-items: center;
    }
    .overlay-spinner .spinner-border {
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <!-- Navbar: tytuł bez dodatkowej stylizacji "Weaver" -->
  <nav class="navbar navbar-expand-lg navbar-custom">
    <a class="navbar-brand" href="#">ThreatWeaver</a>
  </nav>
  <div class="container">
    <div class="mb-4 text-center">
      <!-- Główny nagłówek z częścią "Weaver" w kolorze niebieskim -->
      <h1>Threat<span class="weaver">Weaver</span></h1>
      <p>
        Threat<span class="weaver">Weaver</span> is an advanced web application that leverages artificial intelligence for automated threat modeling and security analysis. It allows users to upload architecture diagrams and detailed application descriptions, which are then analyzed using the STRIDE and MITRE ATT&CK frameworks, generating clear threat models along with recommendations for mitigation measures.
      </p>
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
            {{ message }}
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    <form method="POST" action="{{ url_for('analyze') }}" enctype="multipart/form-data" id="threatForm">
      <div class="row">
        <!-- Left Column: Application Diagram and Description -->
        <div class="col-md-6">
          <div class="form-group mb-3">
            <label for="diagram" class="form-label">Application Diagram</label>
            <div class="input-group">
              <input type="file" class="form-control" id="diagram" name="diagram" accept="image/*">
              <div class="input-group-append">
                <button type="button" class="btn btn-upload" id="uploadBtn">Upload</button>
              </div>
            </div>
            <small id="spinner" class="form-text" style="display: none;">
              <span class="spinner-border" role="status" aria-hidden="true"></span>
              Generating description...
            </small>
          </div>
          <div class="form-group mb-3">
            <label for="description" class="form-label">Application Description</label>
            <textarea class="form-control" id="description" name="description" rows="10" placeholder="Enter application description or it will be auto-populated if a diagram is uploaded..."></textarea>
            <small class="form-text">If a diagram is uploaded, the analysis result will be populated here.</small>
          </div>
        </div>
        <!-- Right Column: Security Details -->
        <div class="col-md-6">
          <h4 class="mb-3">Security Details</h4>
          <div class="form-group mb-3">
            <label for="app_type" class="form-label">Application Type</label>
            <select class="form-control" id="app_type" name="app_type">
              <option value="Web Application" selected>Web Application</option>
              <option value="Other">Other</option>
            </select>
          </div>
          <div class="form-group mb-3">
            <label for="data_confidentiality" class="form-label">Data Confidentiality</label>
            <select class="form-control" id="data_confidentiality" name="data_confidentiality">
              <option value="Not Confidential" selected>Not Confidential</option>
              <option value="Confidential">Confidential</option>
              <option value="Secret">Secret</option>
            </select>
          </div>
          <div class="form-group mb-3">
            <label for="public_private" class="form-label">Is the application public or private?</label>
            <select class="form-control" id="public_private" name="public_private">
              <option value="Public" selected>Public</option>
              <option value="Private">Private</option>
            </select>
          </div>
          <div class="form-group mb-3">
            <label for="authentication" class="form-label">Authentication Mechanisms</label>
            <select class="form-control" id="authentication" name="authentication">
              <option value="None" selected>None</option>
              <option value="OAuth2">OAuth2</option>
              <option value="SAML">SAML</option>
              <option value="JWT">JWT</option>
              <option value="Basic Authentication">Basic Authentication</option>
            </select>
          </div>
        </div>
      </div>
      <!-- Button group with margin between buttons -->
      <div class="btn-group mt-3" role="group">
        <button type="submit" name="action" value="stride" class="btn btn-primary">Generate STRIDE Model</button>
        <button type="submit" name="action" value="mitre" class="btn btn-primary">Generate MITRE Model</button>
      </div>
      <!-- Spinner inline under the buttons -->
      <div id="overlay-spinner" class="overlay-spinner" style="display: none;">
        <div>
          <div class="spinner-border" role="status"></div>
          <span>Generating Threat Model...</span>
        </div>
      </div>
    </form>
    <!-- Container for displaying results -->
    <div id="result-container" class="result-heading"></div>
    <!-- Buttons for Copy and Export -->
    <div id="result-actions" class="mt-3" style="display: none;">
      <button id="copyBtn" class="btn btn-primary">Copy Results</button>
      <!-- Zmieniona nazwa przycisku na Export to JSON -->
      <button id="exportJsonBtn" class="btn btn-primary ml-2">Export to JSON</button>
      <!-- Nowy przycisk Export to CSV -->
      <button id="exportCsvBtn" class="btn btn-primary ml-2">Export to CSV</button>
    </div>
  </div>
  
  <!-- JavaScript dependencies (jQuery and Bootstrap JS from 4.5.2) -->
  <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    let currentAction = ""; // Global variable to store current action ("stride" or "mitre")
    let lastResult = null; // Będziemy przechowywać ostatni wynik z serwera
    
    // Upload button handler
    document.getElementById('uploadBtn').addEventListener('click', function() {
      const fileInput = document.getElementById('diagram');
      const uploadBtn = document.getElementById('uploadBtn');
      const spinner = document.getElementById('spinner');

      if (!fileInput.files.length) {
        alert("Please select a diagram file.");
        return;
      }
      uploadBtn.disabled = true;
      spinner.style.display = 'inline';

      const file = fileInput.files[0];
      const formData = new FormData();
      formData.append('diagram', file);

      fetch('{{ url_for("upload_diagram") }}', {
        method: 'POST',
        body: formData
      })
      .then(response => {
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
          return response.json();
        } else {
          return response.text().then(text => {
            console.error("Non-JSON response received:", text);
            throw new Error("Non-JSON response received. Check console for details.");
          });
        }
      })
      .then(data => {
        if(data.error) {
          console.error("Error generating STRIDE model:", data.error);
          alert("Error: " + data.error);
        } else {
          document.getElementById('description').value = data.analysis;
        }
      })
      .catch(error => {
        console.error("Fetch error:", error);
        alert("An error occurred while uploading the file. Check console for details.");
      })
      .finally(() => {
        uploadBtn.disabled = false;
        spinner.style.display = 'none';
      });
    });

    // Form submission handler using e.submitter to determine which button was pressed
    document.getElementById('threatForm').addEventListener('submit', function(e) {
      e.preventDefault();
      const description = document.getElementById('description').value.trim();
      if (!description) {
        alert("Please fill in the Application Description.");
        return;
      }
      currentAction = e.submitter.value;
      const formData = new FormData(this);
      formData.append('action', currentAction);
      // Disable buttons and show spinner inline under the buttons
      document.querySelectorAll('.btn-group > .btn').forEach(btn => btn.disabled = true);
      document.getElementById('overlay-spinner').style.display = 'flex';
      
      fetch('{{ url_for("analyze") }}', {
        method: 'POST',
        body: formData
      })
      .then(response => {
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
          return response.json();
        } else {
          return response.text().then(text => {
            console.error("Non-JSON response received:", text);
            throw new Error("Non-JSON response received. Check console for details.");
          });
        }
      })
      .then(data => {
        if(data.error) {
          console.error("Error generating model:", data.error);
          alert("Error: " + data.error);
        } else {
          displayResults(data);
          // Zapamiętujemy ostatni wynik
          lastResult = data;
        }
      })
      .catch(error => {
        console.error("Fetch error:", error);
        alert("An error occurred while generating the model. Check console for details.");
      })
      .finally(() => {
        // Re-enable buttons and hide spinner
        document.querySelectorAll('.btn-group > .btn').forEach(btn => btn.disabled = false);
        document.getElementById('overlay-spinner').style.display = 'none';
      });
    });

    function displayResults(result) {
      let html = "";
      if (result.threat && result.threat.length > 0) {
        html += "<h4 class='mt-4'>Generated Threat Model</h4>";
        // Dla STRIDE (currentAction=="stride") pomijamy kolumnę "Technique"
        if (currentAction === "stride") {
          html += "<table class='table result-table'>";
          html += "<thead><tr><th>Threat Type</th><th>Scenario</th><th>Potential Impact</th><th>Mitigations</th></tr></thead>";
          html += "<tbody>";
          result.threat.forEach(function(threat) {
            html += `<tr>
                      <td>${threat["Threat Type"] || "N/A"}</td>
                      <td>${threat["Scenario"]}</td>
                      <td>${threat["Potential Impact"]}</td>
                      <td>${threat["Mitigations"] || "N/A"}</td>
                     </tr>`;
          });
          html += "</tbody></table>";
        } else {
          // Dla MITRE, oczekujemy kolumn: Tactic, Technique, Scenario, Potential Impact, Mitigations
          html += "<table class='table result-table'>";
          html += "<thead><tr><th>Tactic</th><th>Technique</th><th>Scenario</th><th>Potential Impact</th><th>Mitigations</th></tr></thead>";
          html += "<tbody>";
          result.threat.forEach(function(threat) {
            html += `<tr>
                      <td>${threat["Tactic"] || threat["Threat Type"] || "N/A"}</td>
                      <td>${threat["Technique"] || "N/A"}</td>
                      <td>${threat["Scenario"]}</td>
                      <td>${threat["Potential Impact"]}</td>
                      <td>${threat["Mitigations"] || "N/A"}</td>
                     </tr>`;
          });
          html += "</tbody></table>";
        }
      }
      if (result.security_suggestions && result.security_suggestions.length > 0) {
        html += "<h4 class='mt-4'>Security Suggestions</h4>";
        html += "<ul class='list-group'>";
        result.security_suggestions.forEach(function(suggestion) {
          html += `<li class="list-group-item">${suggestion}</li>`;
        });
        html += "</ul>";
      }
      document.getElementById("result-container").innerHTML = html;
      // Pokazujemy przyciski do kopiowania i eksportu
      document.getElementById("result-actions").style.display = "block";
    }

    // Copy Results button handler
    document.getElementById('copyBtn').addEventListener('click', function() {
      const resultsHtml = document.getElementById("result-container").innerText;
      navigator.clipboard.writeText(resultsHtml).then(() => {
        alert("Results copied to clipboard!");
      }).catch(err => {
        console.error("Error copying to clipboard:", err);
        alert("Failed to copy results.");
      });
    });

    // Export to JSON button handler
    document.getElementById('exportJsonBtn').addEventListener('click', function() {
      if(!lastResult) {
        alert("No data available to export.");
        return;
      }
      // Zapisujemy obiekt lastResult jako JSON w pliku
      const jsonStr = JSON.stringify(lastResult, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "threat_model_results.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });

    // Export to CSV button handler
    document.getElementById('exportCsvBtn').addEventListener('click', function() {
      if(!lastResult) {
        alert("No data available to export.");
        return;
      }
      // Budujemy CSV z sekcji "threat" i "security_suggestions"
      const csvContent = buildCsvContent(lastResult);
      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "threat_model_results.csv";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });

    function buildCsvContent(data) {
      // Uproszczone: tworzymy dwie sekcje w jednym pliku CSV
      // 1. THREAT
      // 2. SECURITY_SUGGESTIONS
      let csv = "Threat Model Data\\n";
      if(data.threat && data.threat.length > 0){
        // Pobieramy wszystkie klucze z pierwszego obiektu, żeby zbudować nagłówki
        const keys = Object.keys(data.threat[0]);
        csv += keys.join(",") + "\\n";
        data.threat.forEach(item => {
          // Escapujemy ewentualne przecinki lub cudzysłowy
          const row = keys.map(k => `"${(item[k] || "").toString().replace(/"/g, '""')}"`).join(",");
          csv += row + "\\n";
        });
      } else {
        csv += "No threat data found\\n";
      }

      csv += "\\nSecurity Suggestions\\n";
      if(data.security_suggestions && data.security_suggestions.length > 0) {
        csv += "Suggestion\\n";
        data.security_suggestions.forEach(sugg => {
          csv += `"${sugg.replace(/"/g, '""')}"\\n`;
        });
      } else {
        csv += "No security suggestions found\\n";
      }

      return csv;
    }
  </script>
</body>
</html>
"""

# =================== Flask Routes ===================

@app.route("/", methods=["GET"])
def index():
    return render_form()

@app.route("/upload_diagram", methods=["POST"])
def upload_diagram():
    return handle_upload()

@app.route("/analyze", methods=["POST"])
def analyze():
    action = request.form.get("action")
    if action == "stride":
        return handle_stride_model()
    elif action == "mitre":
        return handle_mitre_model()
    else:
        flash("Invalid action.", "warning")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
