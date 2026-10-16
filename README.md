# VulnSight — Vulnerability Assessment Suite

**Discover. Assess. Secure.**

VulnSight is a Python-based desktop vulnerability assessment tool designed to help security learners, administrators, and authorized security testers identify potential security weaknesses in network hosts and web applications. It combines network discovery, service enumeration, CVE correlation, passive web security checks, risk scoring, and security report generation in a graphical interface.

> **Disclaimer:** VulnSight is intended for educational and authorized security testing only. Scan only systems, networks, and applications you own or have explicit permission to assess.

## Features

### 1. Network Discovery
- Scan individual IP addresses, hostnames, URLs, and CIDR network ranges.
- Discover reachable hosts on a target network.
- Identify accessible network services and ports.

### 2. Port Scanning and Service Enumeration
- Discover open TCP ports using Nmap when available.
- Support optional UDP scanning.
- Identify services and collect available service information.
- Provide a built-in Python-based fallback scanner when supported Nmap functionality is unavailable.

### 3. CVE Correlation
- Correlate discovered service information with known Common Vulnerabilities and Exposures (CVEs).
- Retrieve vulnerability information through the National Vulnerability Database (NVD) REST API.
- Use CIRCL as a fallback vulnerability information source.
- Cache vulnerability data locally using SQLite to reduce repeated requests.

*Note: CVE matches indicate potential vulnerabilities and should be validated against the actual software version, configuration, and environment.*

### 4. Web Application Security Checks
Perform safe, passive checks for common security configuration issues, including:

- Missing or weak HTTP security headers.
- Cookie security flags.
- TLS/HTTPS configuration indicators.
- HTTP-to-HTTPS redirect behavior.
- Directory listing exposure.
- Form security indicators.
- Server banner information.
- Availability of `robots.txt` and `security.txt`.

These checks provide indicators for further investigation; they do not constitute a complete web application penetration test.

### 5. Risk Assessment
- Calculate a risk score from collected scan findings.
- Organize results to help prioritize investigation.
- Present findings through the graphical interface.

### 6. Security Reporting
Generate reports in multiple formats:

- PDF
- HTML
- CSV
- JSON

Reports can be used for documentation, security reviews, and tracking assessment results.

### 7. Graphical User Interface
The desktop interface is designed with `ttkbootstrap` and includes sections for:

- Dashboard
- Scan configuration
- Scan results
- Reports
- Settings
- About

Background threads help keep the interface responsive during scanning operations.

### 8. Optional Integrations
- Nmap for enhanced network scanning.
- OpenVAS/Greenbone availability detection for environments where those tools are installed.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application |
| Tkinter / ttkbootstrap | Desktop graphical interface |
| Nmap / python-nmap | Network discovery and port scanning |
| Requests | HTTP requests and vulnerability API access |
| Beautiful Soup | HTML parsing |
| SQLite | Local vulnerability cache |
| ReportLab | PDF report generation |
| Jinja2 | HTML report templates |
| Matplotlib | Data visualization |
| PyYAML | Configuration management |
| Python Dateutil | Date and time utilities |

## Prerequisites

- Python 3.12 or later is recommended.
- Python 3.10 or later may work, depending on the components used.
- Nmap is optional but recommended for enhanced network scanning.
- Internet access is needed for online vulnerability database queries.
- A Windows or Linux environment capable of running Python desktop applications.

## Installation

### Windows

1. Download or clone the project repository.
2. Open PowerShell or Command Prompt in the project directory.
3. Run the setup script:

```powershell
.\setup.bat
```

If the setup script does not run, create a virtual environment manually:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual environment activation, use Command Prompt and run:

```bat
.venv\Scripts\activate.bat
```

### Linux

Run the setup script from the project directory:

```bash
chmod +x setup.sh
./setup.sh
```

Alternatively, install the dependencies manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install Nmap separately using your Linux distribution's package manager if you want to use its scanning capabilities.

## Dependency Check

After installing the dependencies, run:

```bash
python check_dependencies.py
```

This script checks the Python version, required dependencies, and optional Nmap availability.

## Running VulnSight

From the project directory, activate the virtual environment and run:

```bash
python main.py
```

The application entry point loads the VulnSight desktop interface.

**Important:** The complete project structure must be present for the application to start successfully. This includes the GUI, scanner, CVE, reporting, database, and utility modules referenced by the application.

## Typical Workflow

1. Launch VulnSight.
2. Confirm that you are authorized to scan the intended target.
3. Enter a permitted IP address, hostname, URL, or network range.
4. Configure the available scan options.
5. Start the assessment.
6. Review discovered hosts, services, potential vulnerabilities, and web security findings.
7. Examine the risk score and prioritize findings for validation.
8. Generate a report in the required format.
9. Remediate verified issues and conduct a follow-up assessment.

## Project Structure

The intended project structure is organized into the following components:

```text
VulnSight/
├── main.py
├── requirements.txt
├── check_dependencies.py
├── setup.bat
├── setup.sh
├── README.md
├── gui/
│   └── main_window.py
├── scanner/
├── cve/
├── reports/
├── database/
├── utils/
├── config/
│   └── default_config.yaml
├── templates/
│   └── report_template.html
├── assets/
├── logs/
├── exports/
└── docs/
```

Some directories may be created during setup or generated as part of the application's operation. Ensure that the required source modules and configuration files are included in your repository.

## Security and Responsible Use

VulnSight is intended to support defensive security assessments.

- Obtain explicit authorization before scanning a target.
- Do not scan public IP addresses, third-party infrastructure, or networks without permission.
- Start with a small, controlled test environment.
- Review scan configurations before launching a scan.
- Protect generated reports because they may contain sensitive infrastructure information.
- Validate findings before treating them as confirmed vulnerabilities.
- Respect applicable laws, organizational policies, and service terms.

VulnSight is an assessment aid and should not be treated as a replacement for professional security testing or manual validation.

## Limitations

- Vulnerability correlation depends on the accuracy of detected service information and available CVE data.
- Online vulnerability lookups depend on external services and network connectivity.
- Nmap-based features require Nmap to be installed and available in the system path.
- Passive web checks identify selected security indicators and may not discover every application vulnerability.
- Risk scores are prioritization aids, not guarantees of exploitability or business impact.
- Optional integrations may require separate installation and configuration.

## Future Enhancements

Potential areas for future development include:

- Improved vulnerability validation and deduplication.
- Enhanced scan history and comparison between assessments.
- Additional report customization.
- Improved visualization of findings and risk trends.
- More vulnerability data sources and integrations.
- Additional security checks for authorized testing environments.

## Contributing

Contributions, bug reports, documentation improvements, and feature suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make your changes and test them.
4. Submit a pull request describing the changes.

Please do not include real credentials, API keys, private target information, or sensitive scan reports in commits.

## License

Choose and add an appropriate open-source license before distributing this project. Until a license is included, do not assume that others have permission to reuse, modify, or redistribute the code.

---

**VulnSight — Discover. Assess. Secure.**

*A desktop vulnerability assessment project built with Python for authorized security testing and learning.*
