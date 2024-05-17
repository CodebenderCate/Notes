# Security Operations
## 1.1 Explain the importance of system and network architecture concepts in security operations.

- **Log ingestion**: Collecting logs from various sources for analysis.
- **Time synchronization**: Ensuring all systems use the same time reference to correlate logs accurately.
- **Operating system (OS) concepts**: Understanding OS structures like Windows Registry, system hardening, and file structures.
- **Infrastructure concepts**: Serverless computing, virtualization, containerization.
Network architecture: On-premises, cloud, hybrid, network segmentation, Zero Trust, SDN.
- **Identity and Access Management (IAM)**: MFA, SSO, federation, privileged access management.
- **Encryption**: PKI for secure communication, SSL inspection.
- **Sensitive data protection**: Data loss prevention (DLP), PII, CHD.

## 1.2 Given a scenario, analyze indicators of potentially malicious activity.

- **Network-related indicators**: Bandwidth consumption, beaconing, irregular peer-to-peer communication, rogue devices, scans/sweeps, unusual traffic spikes, activity on unexpected ports.
- **Host-related indicators**: Processor/memory consumption, drive capacity consumption, unauthorized software, malicious processes, unauthorized changes/privileges, data exfiltration.
- **Application-related indicators**: Anomalous activity, introduction of new accounts, unexpected output/outbound communication, service interruption.

## 1.3 Given a scenario, use appropriate tools or techniques to determine malicious activity.

### Tools:
- Packet capture (Wireshark, tcpdump)
- Log analysis/correlation (SIEM, SOAR)
- Endpoint security (EDR)
- DNS and IP reputation tools (WHOIS, AbuseIPDB)
- File analysis (Strings, VirusTotal)
- Sandboxing (Joe Sandbox, Cuckoo Sandbox)
- Common techniques: Pattern recognition, interpreting suspicious commands, email analysis, file analysis, user behavior analysis.

## 1.4 Compare and contrast threat-intelligence and threat-hunting concepts.

- **Threat actors**: APT, hacktivists, organized crime, nation-state, script kiddie, insider threat.
- Tactics, techniques, and procedures (TTP)
- **Collection methods and sources**: Open source (social media, blogs, CERT), closed source (paid feeds, information sharing organizations, internal sources).
- **Threat hunting**: IoC collection, analysis, application, configurations/misconfigurations, isolated networks, business-critical assets and processes, active defense, honeypot.

## 1.5 Explain the importance of efficiency and process improvement in security operations.

- **Standardize processes**: Identify tasks suitable for automation.
- **Streamline operations**: Use automation and orchestration to minimize human engagement.
- **Technology and tool integration**: API, webhooks, plugins.
- **Single pane of glass**: Unified interface for managing security operations.

# 2. Vulnerability Management
## 2.1 Given a scenario, implement vulnerability scanning methods and concepts.

- **Asset discovery**: Map scans, device fingerprinting.
- **Special considerations**: Scheduling, operations, performance, sensitivity levels, segmentation, regulatory requirements.
- **Types of scanning**: Internal vs. external, agent vs. agentless, credentialed vs. non-credentialed, passive vs. active, static vs. dynamic.

## 2.2 Given a scenario, analyze output from vulnerability assessment tools.

### Tools:
- Network scanning (Nmap, Maltego)
- Web application scanners (Burp Suite, ZAP, Arachni, Nikto)
- Vulnerability scanners (Nessus, OpenVAS)
- Debuggers (Immunity debugger, GDB)
- Cloud infrastructure assessment tools (Scout Suite, Prowler, Pacu)

## 2.3 Given a scenario, analyze data to prioritize vulnerabilities.

- **Metrics**: CVSS interpretation (attack vectors, complexity, privileges required, user interaction, scope, impact on confidentiality, integrity, availability).
- **Validation**: True/false positives, true/false negatives.
- **Context awareness**: Internal, external, isolated. Exploitability/weaponization, asset value, zero-day vulnerabilities.

## 2.4 Given a scenario, recommend controls to mitigate attacks and software vulnerabilities.

- **Vulnerabilities**: Cross-site scripting, overflow vulnerabilities, injection flaws, cryptographic failures, broken access control, insecure design, security misconfiguration, end-of-life components.
- **Controls**: Compensating controls, control types (managerial, operational, technical, preventative, detective, responsive, corrective), patching and configuration management.

## 2.5 Explain concepts related to vulnerability response, handling, and management.

- **Handling and management**: Identification, patching, configuration management, risk management principles (accept, transfer, avoid, mitigate), policies, governance, service-level objectives (SLOs), prioritization, escalation, attack surface management.

# 3. Incident Response and Management
## 3.1 Explain concepts related to attack methodology frameworks.

- **Frameworks**: Cyber kill chains, Diamond Model of Intrusion Analysis, MITRE ATT&CK, Open Source Security Testing Methodology Manual (OSSTMM), OWASP Testing Guide.

## 3.2 Given a scenario, perform incident response activities.

- **Detection and analysis**: IoC, evidence acquisition, chain of custody, validating data integrity, preservation, legal hold, data and log analysis.
- **Containment, eradication, and recovery**: Scope, impact, isolation, remediation, re-imaging, compensating controls.

## 3.3 Explain the preparation and post-incident activity phases of the incident management life cycle.

- **Preparation**: Incident response plan, tools, playbooks, tabletop exercises, training, business continuity (BC), disaster recovery (DR).
- **Post-incident**: Forensic analysis, root cause analysis, lessons learned.

# 4. Reporting and Communication
## 4.1 Explain the importance of vulnerability management reporting and communication.

- **Vulnerability management reporting**: Vulnerabilities, affected hosts, risk score, mitigation, recurrence, prioritization.
- **Compliance reports, action plans**: Configuration management, patching, compensating controls, awareness, education, training, changing business requirements.
- **Inhibitors to remediation**: Memorandum of understanding (MOU), service-level agreement (SLA), organizational governance, business process interruption, degrading functionality, legacy systems, proprietary systems.
- **Metrics and KPIs**: Trends, top 10, critical vulnerabilities, zero-days, SLOs.

## 4.2 Explain the importance of incident response reporting and communication.

- **Incident response reporting**: Stakeholder communication, incident declaration, escalation, executive summary, recommendations, timeline, impact, scope, evidence.
- **Communications**: Legal, public relations, customer communication, media, regulatory reporting, law enforcement.
- **Root cause analysis, lessons learned, metrics, and KPIs**: Mean time to detect, mean time to respond, mean time to remediate, alert volume.
