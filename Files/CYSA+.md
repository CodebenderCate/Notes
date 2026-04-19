<div align="center" dir="auto">
<img src="https://github.com/CodebenderCate/codebendercate/blob/main/Images/Cysa+.jpg" width="400 height="100"/>
</div>

# <div align="center" dir="auto">My Notes for CYSA+ (2024)</div>

## Domain 1: Security Operations (33%)

### 1.1 Explain the Importance of System and Network Architecture Concepts in Security Operations
- **Log Ingestion**
  - Time synchronization
  - Logging levels
- **Operating System (OS) Concepts**
  - Windows Registry
  - System hardening
  - File structure
    - Configuration file locations
  - System processes
  - Hardware architecture
- **Infrastructure Concepts**
  - Serverless
  - Virtualization
  - Containerization
- **Network Architecture**
  - On-premises
  - Cloud
  - Hybrid
  - Network segmentation
  - Zero trust
  - Secure access secure edge (SASE)
  - Software-defined networking (SDN)
- **Identity and Access Management**
  - Multifactor authentication (MFA)
  - Single sign-on (SSO)
  - Federation
  - Privileged access management (PAM)
  - Passwordless
  - Cloud access security broker (CASB)
- **Encryption**
  - Public key infrastructure (PKI)
  - Secure sockets layer (SSL) inspection
- **Sensitive Data Protection**
  - Data loss prevention (DLP)
  - Personally identifiable information (PII)
  - Cardholder data (CHD)

### 1.2 Given a Scenario, Analyze Indicators of Potentially Malicious Activity
- **Network-related**
  - Bandwidth consumption
  - Beaconing
  - Irregular peer-to-peer communication
  - Rogue devices on the network
  - Scans/sweeps
  - Unusual traffic spikes
  - Activity on unexpected ports
- **Host-related**
  - Processor consumption
  - Memory consumption
  - Drive capacity consumption
  - Unauthorized software
  - Malicious processes
  - Unauthorized changes
  - Unauthorized privileges
  - Data exfiltration
  - Abnormal OS process behavior
  - File system changes or anomalies
  - Registry changes or anomalies
  - Unauthorized scheduled tasks
- **Application-related**
  - Anomalous activity
  - Introduction of new accounts
  - Unexpected output
  - Unexpected outbound communication
  - Service interruption
  - Application logs
- **Other**
  - Social engineering attacks
  - Obfuscated links

### 1.3 Given a Scenario, Use Appropriate Tools or Techniques to Determine Malicious Activity
- **Tools**
  - Packet capture
    - Wireshark
    - tcpdump
  - Log analysis/correlation
    - Security information and event management (SIEM)
    - Security orchestration, automation, and response (SOAR)
  - Endpoint security
    - Endpoint detection and response (EDR)
  - Domain name service (DNS) and Internet Protocol (IP) reputation
    - WHOIS
    - AbuseIPDB
  - File analysis
    - Strings
    - VirusTotal
  - Sandboxing
    - Joe Sandbox
    - Cuckoo Sandbox
- **Common Techniques**
  - Pattern recognition
    - Command and control
  - Interpreting suspicious commands
  - Email analysis
    - Header
    - Impersonation
    - DomainKeys Identified Mail (DKIM)
    - Domain-based Message Authentication, Reporting, and Conformance (DMARC)
    - Sender Policy Framework (SPF)
    - Embedded links
  - File analysis
    - Hashing
  - User behavior analysis
    - Abnormal account activity
    - Impossible travel
- **Programming Languages/Scripting**
  - JavaScript Object Notation (JSON)
  - Extensible Markup Language (XML)
  - Python
  - PowerShell
  - Shell script
  - Regular expressions

### 1.4 Compare and Contrast Threat-Intelligence and Threat-Hunting Concepts
- **Threat Actors**
  - Advanced persistent threat (APT)
  - Hacktivists
  - Organized crime
  - Nation-state
  - Script kiddie
  - Insider threat
    - Intentional
    - Unintentional
  - Supply chain
- **Tactics, Techniques, and Procedures (TTP)**
- **Confidence Levels**
  - Timeliness
  - Relevancy
  - Accuracy
- **Collection Methods and Sources**
  - Open source
    - Social media
    - Blogs/forums
    - Government bulletins
    - Computer emergency response team (CERT)
    - Cybersecurity incident response team (CSIRT)
    - Deep/dark web
  - Closed source
    - Paid feeds
    - Information sharing organizations
    - Internal sources
- **Threat Intelligence Sharing**
  - Incident response
  - Vulnerability management
  - Risk management
  - Security engineering
  - Detection and monitoring
- **Threat Hunting**
  - Indicators of compromise (IoC)
    - Collection
    - Analysis
    - Application
  - Focus areas
    - Configurations/misconfigurations
    - Isolated networks
    - Business-critical assets and processes
  - Active defense
  - Honeypot

### 1.5 Explain the Importance of Efficiency and Process Improvement in Security Operations
- **Standardize Processes**
  - Identification of tasks suitable for automation
    - Repeatable/do not require human interaction
  - Team coordination to manage and facilitate automation
- **Streamline Operations**
  - Automation and orchestration
    - Security orchestration, automation, and response (SOAR)
  - Orchestrating threat intelligence data
    - Data enrichment
    - Threat feed combination
  - Minimize human engagement
- **Technology and Tool Integration**
  - Application programming interface (API)
  - Webhooks
  - Plugins
- **Single Pane of Glass**

## Domain 2: Vulnerability Management (30%)

### 2.1 Given a Scenario, Implement Vulnerability Scanning Methods and Concepts
- **Asset Discovery**
  - Map scans
  - Device fingerprinting
- **Special Considerations**
  - Scheduling
  - Operations
  - Performance
  - Sensitivity levels
  - Segmentation
  - Regulatory requirements
- **Internal vs. External Scanning**
- **Agent vs. Agentless**
- **Credentialed vs. Non-Credentialed**
- **Passive vs. Active**
- **Static vs. Dynamic**
  - Reverse engineering
  - Fuzzing
- **Critical Infrastructure**
  - Operational technology (OT)
  - Industrial control systems (ICS)
  - Supervisory control and data acquisition (SCADA)
- **Security Baseline Scanning**
- **Industry Frameworks**
  - Payment Card Industry Data Security Standard (PCI DSS)
  - Center for Internet Security (CIS) benchmarks
  - Open Web Application Security Project (OWASP)
  - International Organization for Standardization (ISO) 27000 series

### 2.2 Given a Scenario, Analyze Output from Vulnerability Assessment Tools
- **Tools**
  - Network scanning and mapping
    - Angry IP Scanner
    - Maltego
  - Web application scanners
    - Burp Suite
    - Zed Attack Proxy (ZAP)
    - Arachni
    - Nikto
  - Vulnerability scanners
    - Nessus
    - OpenVAS
  - Debuggers
    - Immunity debugger
    - GNU debugger (GDB)
  - Multipurpose
    - Nmap
    - Metasploit framework (MSF)
    - Recon-ng
  - Cloud infrastructure assessment tools
    - Scout Suite
    - Prowler
    - Pacu

### 2.3 Given a Scenario, Analyze Data to Prioritize Vulnerabilities
- **Common Vulnerability Scoring System (CVSS) Interpretation**
  - Attack vectors
  - Attack complexity
  - Privileges required
  - User interaction
  - Scope
  - Impact
    - Confidentiality
    - Integrity
    - Availability
- **Validation**
  - True/false positives
  - True/false negatives
- **Context Awareness**
  - Internal
  - External
  - Isolated
- **Exploitability/Weaponization**
- **Asset Value**
- **Zero-Day**

### 2.4 Given a Scenario, Recommend Controls to Mitigate Attacks and Software Vulnerabilities
- **Cross-Site Scripting**
  - Reflected
  - Persistent
- **Overflow Vulnerabilities**
  - Buffer
  - Integer
  - Heap
  - Stack
- **Data Poisoning**
- **Broken Access Control**
- **Cryptographic Failures**
- **Injection Flaws**
- **Cross-Site Request Forgery**
- **Directory Traversal**
- **Insecure Design**
- **Security Misconfiguration**
- **End-of-Life or Outdated Components**
- **Identification and Authentication Failures**
- **Server-Side Request Forgery**
- **Remote Code Execution**
- **Privilege Escalation**
- **Local File Inclusion (LFI)/Remote File Inclusion (RFI)**

### 2.5 Explain Concepts Related to Vulnerability Response, Handling, and Management
- **Compensating Control**
- **Control Types**
  - Managerial
  - Operational
  - Technical
  - Preventative
  - Detective
  - Responsive
  - Corrective
- **Patching and Configuration Management**
  - Testing
  - Implementation
  - Rollback
  - Validation
- **Maintenance Windows**
- **Exceptions**
- **Risk Management Principles**
  - Accept
  - Transfer
  - Avoid
  - Mitigate
- **Policies, Governance, and Service-Level Objectives (SLOs)**
- **Prioritization and Escalation**
  - Attack Surface Management
    - Edge discovery
    - Passive discovery
    - Security controls testing
    - Penetration testing and adversary emulation
    - Bug bounty
    - Attack surface reduction
  - **Secure Coding Best Practices**
    - Input validation
    - Output encoding
    - Session management
    - Authentication
    - Data protection
    - Parameterized queries
  - **Secure Software Development Life Cycle (SDLC)**
  - **Threat Modeling**

## Domain 3: Incident Response & Management (20%)

### 3.1 Explain Concepts Related to Attack Methodology Frameworks
- **Cyber Kill Chains**
- **Diamond Model of Intrusion Analysis**
- **MITRE ATT&CK**
- **Open Source Security Testing Methodology Manual (OSSTMM)**
- **OWASP Testing Guide**

### 3.2 Given a Scenario, Perform Incident Response Activities
- **Detection and Analysis**
  - Indicators of compromise (IoC)
  - Evidence acquisition
    - Chain of custody
    - Validating data integrity
    - Preservation
    - Legal hold
  - Data and log analysis
- **Containment, Eradication, and Recovery**
  - Scope
  - Impact
  - Isolation
  - Remediation
  - Re-imaging
  - Compensating controls

### 3.3 Explain the Preparation and Post-Incident Activity Phases of the Incident Management Life Cycle
- **Preparation**
  - Incident response plan
  - Tools
  - Playbooks
  - Tabletop exercises
  - Training
  - Business continuity (BC) and disaster recovery (DR)
- **Post-Incident Activity**
  - Forensic analysis
  - Root cause analysis
  - Lessons learned

## Domain 4: Reporting & Communication (17%)

### 4.1 Explain the Importance of Vulnerability Management Reporting and Communication
- **Vulnerability Management Reporting**
  - Vulnerabilities
  - Affected hosts
  - Risk score
  - Mitigation
  - Recurrence
  - Prioritization
- **Compliance Reports**
- **Action Plans**
  - Configuration management
  - Patching
  - Compensating controls
  - Awareness, education, and training
  - Changing business requirements
- **Inhibitors to Remediation**
  - Memorandum of understanding (MOU)
  - Service-level agreement (SLA)
  - Organizational governance
  - Business process interruption
  - Degrading functionality
  - Legacy systems
  - Proprietary systems
- **Metrics and Key Performance Indicators (KPIs)**
  - Trends
  - Top 10
  - Critical vulnerabilities and zero-days
  - Service-level objectives (SLOs)
- **Stakeholder Identification and Communication**

### 4.2 Explain the Importance of Incident Response Reporting and Communication
- **Stakeholder Identification and Communication**
- **Incident Declaration and Escalation**
- **Incident Response Reporting**
  - Executive summary
  - Who, what, when, where, and why
  - Recommendations
  - Timeline
  - Impact
  - Scope
  - Evidence
- **Communications**
  - Legal
  - Public relations
    - Customer communication
    - Media
  - Regulatory reporting
  - Law enforcement
- **Root Cause Analysis**
- **Lessons Learned**
- **Metrics and KPIs**
  - Mean time to detect
  - Mean time to respond
  - Mean time to remediate
  - Alert volume

## Acronyms

- **ACL**: Access Control List
- **API**: Application Programming Interface
- **APT**: Advanced Persistent Threat
- **ARP**: Address Resolution Protocol
- **AV**: Antivirus
- **BC**: Business Continuity
- **BCP**: Business Continuity Plan
- **BGP**: Border Gateway Protocol
- **BIA**: Business Impact Analysis
- **C2**: Command and Control
- **CA**: Certificate Authority
- **CASB**: Cloud Access Security Broker
- **CDN**: Content Delivery Network
- **CERT**: Computer Emergency Response Team
- **CHD**: Cardholder Data
- **CI/CD**: Continuous Integration and Continuous Delivery
- **CIS**: Center for Internet Security
- **COBIT**: Control Objectives for Information and Related Technologies
- **CSIRT**: Cybersecurity Incident Response Team
- **CSRF**: Cross-site Request Forgery
- **CVE**: Common Vulnerabilities and Exposures
- **CVSS**: Common Vulnerability Scoring System
- **DDoS**: Distributed Denial of Service
- **DoS**: Denial of Service
- **DKIM**: DomainKeys Identified Mail
- **DLP**: Data Loss Prevention
- **DMARC**: Domain-based Message Authentication, Reporting, and Conformance
- **DNS**: Domain Name Service
- **DR**: Disaster Recovery
- **EDR**: Endpoint Detection and Response
- **FIM**: File Integrity Monitoring
- **FTP**: File Transfer Protocol
- **GDB**: GNU Debugger
- **GPO**: Group Policy Objects
- **HIDS**: Host-based Intrusion Detection System
- **HIPS**: Host-based Intrusion Prevention System
- **HTTP**: Hypertext Transfer Protocol
- **HTTPS**: Hypertext Transfer Protocol Secure
- **IaaS**: Infrastructure as a Service
- **ICMP**: Internet Control Message Protocol
- **ICS**: Industrial Control Systems
- **IDS**: Intrusion Detection System
- **IoC**: Indicators of Compromise
- **IP**: Internet Protocol
- **IPS**: Intrusion Prevention System
- **IR**: Incident Response
- **ISO**: International Organization for Standardization
- **IT**: Information Technology
- **ITIL**: Information Technology Infrastructure Library
- **JSON**: JavaScript Object Notation
- **KPI**: Key Performance Indicator
- **LAN**: Local Area Network
- **LDAPS**: Lightweight Directory Access Protocol
- **LFI**: Local File Inclusion
- **LOI**: Letter of Intent
- **MAC**: Media Access Control
- **MFA**: Multifactor Authentication
- **MOU**: Memorandum of Understanding
- **MSF**: Metasploit Framework
- **MSP**: Managed Service Provider
- **MSSP**: Managed Security Service Provider
- **MTTD**: Mean Time to Detect
- **MTTR**: Mean Time to Repair
- **NAC**: Network Access Control
- **NDA**: Non-disclosure Agreement
- **NGFW**: Next-generation Firewall
- **NIDS**: Network-based Intrusion Detection System
- **NTP**: Network Time Protocol
- **OpenVAS**: Open Vulnerability Assessment Scanner
- **OS**: Operating System
- **OSSTMM**: Open Source Security Testing Methodology Manual
- **OT**: Operational Technology
- **OWASP**: Open Web Application Security Project
- **PAM**: Privileged Access Management
- **PCI DSS**: Payment Card Industry Data Security Standard
- **PHP**: Hypertext Preprocessor
- **PID**: Process Identifier
- **PII**: Personally Identifiable Information
- **PKI**: Public Key Infrastructure
- **PLC**: Programmable Logic Controller
- **POC**: Proof of Concept
- **RCE**: Remote Code Execution
- **RDP**: Remote Desktop Protocol
- **REST**: Representational State Transfer
- **RFI**: Remote File Inclusion
- **RXSS**: Reflected Cross-site Scripting
- **SaaS**: Software as a Service
- **SAML**: Security Assertion Markup Language
- **SASE**: Secure Access Secure Edge
- **SCADA**: Supervisory Control and Data Acquisition
- **SDLC**: Software Development Life Cycle
- **SDN**: Software-defined Networking
- **SFTP**: Secure File Transfer Protocol
- **SIEM**: Security Information and Event Management
- **SLA**: Service-level Agreement
- **SLO**: Service-level Objective
- **SOAR**: Security Orchestration, Automation, and Response
- **SMB**: Server Message Block
- **SMTP**: Simple Mail Transfer Protocol
- **SNMP**: Simple Network Management Protocol
- **SOC**: Security Operations Center
- **SPF**: Sender Policy Framework
- **SQL**: Structured Query Language
- **SSL**: Secure Sockets Layer
- **SSO**: Single Sign-on
- **SSRF**: Server-side Request Forgery
- **STIX**: Structured Threat Information Expression
- **SWG**: Secure Web Gateway
- **TCP**: Transmission Control Protocol
- **TFTP**: Trivial File Transfer Protocol
- **TLS**: Transport Layer Security
- **TRACE**: Trade Reporting and Compliance Engine
- **TTP**: Tactics, Techniques, and Procedures
- **UEBA**: User and Entity Behavior Analytics
- **URI**: Uniform Resource Identifier
- **URL**: Uniform Resource Locator
- **USB**: Universal Serial Bus
- **VLAN**: Virtual LAN
- **VM**: Virtual Machine
- **VPN**: Virtual Private Network
- **WAF**: Web Application Firewall
- **WAN**: Wide Area Network
- **XDR**: Extended Detection Response
- **XML**: Extensible Markup Language
- **XSS**: Cross-site Scripting
- **XXE**: XML External Entity
- **ZAP**: Zed Attack Proxy
- **ZTNA**: Zero Trust Network Access

## Official Resources
1. [CompTIA CySA+ Certification Exam Objectives](https://www.comptia.org/certifications/cybersecurity-analyst#examdetails) - The official exam objectives provide a detailed breakdown of the topics covered in the exam.
2. [CompTIA CySA+ Study Guide](https://store.comptia.org/comptia-cysa-study-guide-exam-cs0-003/p/COMPTIA-CYS0-003) - The official study guide from CompTIA.

## Study Guides and Books
1. **CompTIA CySA+ Study Guide: Exam CS0-003** by Mike Chapple and David Seidl
2. **CompTIA CySA+ Cybersecurity Analyst Certification All-in-One Exam Guide, Second Edition (Exam CS0-003)** by Brent Chapman and Fernando Maymi

## Online Courses
1. [CompTIA CySA+ (CS0-003) Complete Course & Practice Exam](https://www.udemy.com/course/comptia-cysa-complete-course-practice-exam/) - A comprehensive course on Udemy.
2. [CompTIA CySA+ (CS0-003) on Pluralsight](https://www.pluralsight.com/paths/comptia-cysa-cybersecurity-analyst) - Courses on Pluralsight tailored to the CySA+ certification.

## Practice Exams
1. [CompTIA CySA+ Practice Exams](https://www.examcompass.com/comptia/cysa-plus-certification/free-cysa-practice-tests) - Free practice tests to help you prepare.
2. [Boson Practice Exams for CompTIA CySA+](https://www.boson.com/practice-exam/cysa-003-comptia) - High-quality practice exams from Boson.

## Websites and Forums
1. [CompTIA CySA+ Exam subreddit](https://www.reddit.com/r/CompTIA/) - Join discussions and find resources shared by other exam candidates.
2. [Cybrary](https://www.cybrary.it/course/comptia-cysa-plus/) - Offers free and premium training for CySA+.

## Additional Resources
1. [MITRE ATT&CK Framework](https://attack.mitre.org/) - A comprehensive knowledge base of adversary tactics and techniques.
2. [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Resources for web security testing.
3. [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
4. [OWASP Top 10](https://owasp.org/www-project-top-ten/)
5. [ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html)

