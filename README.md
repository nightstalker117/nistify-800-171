# NISTify 800-171

**NIST SP 800-171 Compliance Scanner & Assessment Tool**

Automated network compliance scanner supporting both **Rev 2** (110 controls, 14 families) and **Rev 3** (132 controls, 17 families) of NIST SP 800-171. Scans networks and endpoints, evaluates compliance findings, calculates SPRS scores, and generates multi-format reports including POA&M documents.

> Version: 2.0.0 | License: GPL-3.0 | Windows Compatible | Author: Nightstalker

---

## Features

- Automated network discovery and port scanning via nmap
- Support for NIST SP 800-171 **Rev 2** (14 control families) and **Rev 3** (17 control families)
- SPRS score calculation and risk analysis
- Network topology discovery and visualization
- Multi-format reporting: HTML, JSON, plain text, Excel (POA&M), and nmap-format scan report
- Structured verbose screen output (`--verbose`) with phase-by-phase progress and per-control results
- Interactive version selection at startup

---

## Requirements

### System Dependencies

- **Python 3.8+**
- **nmap** (must be installed separately and available in PATH)
  - Windows: Download from [https://nmap.org/download.html](https://nmap.org/download.html)
  - Linux: `sudo apt-get install nmap`
  - macOS: `brew install nmap`

### Python Dependencies

```
pip install -r requirements.txt
```

| Package | Purpose |
|---|---|
| `python-nmap` | Python interface for nmap network scanning |
| `openpyxl` | Excel POA&M report generation |
| `networkx` | Network topology graph construction |
| `matplotlib` | Network topology diagram rendering |

---

## Installation

```bash
git clone https://github.com/nightstalker/nistify800-171.git
cd nistify800-171
pip install -r requirements.txt
```

> **Note:** Port scanning requires elevated privileges — run as Administrator on Windows or with `sudo` on Linux/macOS.

---

## Usage

```bash
python nistify_sp-800-171.py <network_range> [options]
```

On launch, you will be prompted to select the NIST SP 800-171 revision (Rev 2 or Rev 3).

### Arguments

| Argument | Description | Default |
|---|---|---|
| `networks` | One or more network ranges in CIDR notation | Required |
| `--output-dir` | Directory for generated reports | `nistify_reports` |
| `--no-topology` | Skip network topology generation | Off |
| `--verbose`, `-v` | Enable structured verbose screen output | Off |

### Examples

```bash
# Scan a single subnet
python nistify_sp-800-171.py 192.168.1.0/24

# Scan multiple ranges with verbose output
python nistify_sp-800-171.py 10.0.0.0/8 192.168.0.0/16 --verbose

# Scan and skip topology diagram
python nistify_sp-800-171.py 172.16.0.0/12 --no-topology

# Scan with custom output directory and verbose output
python nistify_sp-800-171.py 192.168.1.0/24 --output-dir ./results -v
```

---

## Output

All reports are saved to the `--output-dir` directory (default: `nistify_reports/`):

| File | Description |
|---|---|
| `nistify_compliance_report_<timestamp>.html` | Interactive HTML report with executive summary |
| `nistify_compliance_report_<timestamp>.json` | Machine-readable JSON findings |
| `nistify_compliance_report_<timestamp>.txt` | Plain text compliance report |
| `nistify_poam_<timestamp>.xlsx` | Plan of Action & Milestones (POA&M) Excel document |
| `nistify_scan_<timestamp>.nmap` | Nmap-format scan report for all scanned hosts |
| `nistify_network_topology.png` | Network topology diagram (unless `--no-topology`) |

A log file `nistify800-171r2.log` is written to the working directory.

---

## Verbose Output

Running with `--verbose` (or `-v`) enables structured, phase-by-phase screen output in addition to the standard log messages. No extra packages are required. The output is organized into the following sections:

| Phase | What is displayed |
|---|---|
| **Scan Configuration** | Selected standard, control count, network ranges, output directory, topology setting |
| **Network Discovery** | Per-range header, list of all discovered hosts, deep-scan progress per host |
| **Host Results** | Hostname, OS, open ports, running services, MAC address and vendor |
| **Network Topology** | Phase header before topology graph construction |
| **Compliance Assessment** | Per-host header with a tabular control checklist — Control ID, name, status (`[PASS]` / `[FAIL]` / `[MANUAL REVIEW]`), and severity; failing controls show their finding inline |
| **Per-host Summary** | Total controls checked, pass/fail/manual counts |
| **SPRS Score** | Full score breakdown — score, compliance rate, compliant/non-compliant counts, high/medium/low finding counts |
| **Report Generation** | Progress indicator and full file path for each report as it is written |

Example (truncated):

```
================================================================================
  NISTIFY 800-171  —  SCAN CONFIGURATION
================================================================================
  Standard            : NIST SP 800-171 Rev 2
  Controls            : 110
  Networks            : 192.168.1.0/24
  Output Dir          : nistify_reports
  Topology            : Enabled
  Verbose             : Enabled

================================================================================
  NETWORK DISCOVERY  |  Range: 192.168.1.0/24
================================================================================
  [>] Running host discovery (ping sweep)...
  [+] Found 3 active host(s):
      192.168.1.1  (up)
      192.168.1.10  (up)
      192.168.1.50  (up)

  [>] Deep scanning: 192.168.1.1
  [+] 192.168.1.1 scan complete:
    Hostname            : router.local
    OS                  : Linux 4.15
    Open Ports          : 22, 80, 443
    Services            : 22/ssh OpenSSH 8.2, 80/http nginx, 443/https nginx
    MAC                 : AA:BB:CC:11:22:33 (Cisco)

--------------------------------------------------------------------------------
  COMPLIANCE ASSESSMENT  |  router.local  (192.168.1.1)  [Rev 2]
--------------------------------------------------------------------------------
Control ID    Control Name                          Status            Severity
------------------------------------------------------------------------------
3.1.2         Transaction and Function Control      [FAIL]            [HIGH]
                Finding: Potentially insecure services detected: SSH (port 22)
3.4.7         Nonessential Functionality            [PASS]            [LOW]
3.13.1        Boundary Protection                   [FAIL]            [HIGH]
                Finding: External-facing services detected: ssh, http, https
3.1.1         Access Control Policy and Proc...     [MANUAL REVIEW]   [MED]
...

  Assessment summary: 110 controls  |  Pass: 1  Fail: 2  Manual: 107

================================================================================
  SPRS SCORE RESULTS
================================================================================
  SPRS Score          : 80 / 110
  Compliance Rate     : 0.91%
  High Findings       : 2
  Medium Findings     : 0
  Low Findings        : 0
```

---

## SPRS Score Calculation

The tool calculates a **Supplier Performance Risk System (SPRS)** score based on compliance findings:

| Severity | Point Deduction |
|---|---|
| High | -15 per finding |
| Medium | -10 per finding |
| Low | -5 per finding |

Controls that cannot be assessed via network scan alone are flagged as `MANUAL_REVIEW_REQUIRED` and must be verified manually.

---

## NIST SP 800-171 Control Families Covered

**Rev 2 (14 families):** Access Control, Awareness & Training, Audit & Accountability, Configuration Management, Identification & Authentication, Incident Response, Maintenance, Media Protection, Personnel Security, Physical Protection, Risk Assessment, Security Assessment, System & Communications Protection, System & Information Integrity

**Rev 3 (17 families):** All Rev 2 families plus Planning, Supply Chain Risk Management, and Program Management

---

## Disclaimer

This tool performs automated network scanning. **Always obtain proper written authorization before scanning any network.** Many NIST SP 800-171 controls cannot be fully assessed via network scan alone — use this tool as part of a broader compliance program that includes manual review, policy assessment, and qualified professional evaluation.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
