# PentestAI-AD: Automated Active Directory Pentesting with Artificial Intelligence

## Technical Specification Document v1.0

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Architecture](#2-project-architecture)
3. [AD Pentest Pipeline](#3-ad-pentest-pipeline)
4. [Artificial Intelligence Engine](#4-artificial-intelligence-engine)
5. [Vulnerability Prioritization System](#5-vulnerability-prioritization-system)
6. [Web Interface & Dashboard](#6-web-interface--dashboard)
7. [Automated Report Generation](#7-automated-report-generation)
8. [Technical Project Structure](#8-technical-project-structure)
9. [Technology Stack](#9-technology-stack)
10. [Expected Results](#10-expected-results)
11. [PFE Report Structure](#11-pfe-report-structure)
12. [Presentation Structure](#12-presentation-structure)

---

## 1. Executive Summary

### Project Overview

**Project Name:** PentestAI-AD  
**Type:** PFE / Internship Project - Cybersecurity Automation  
**Domain:** Active Directory Security Assessment & Penetration Testing  
**Core Functionality:** Automated AD pentesting platform with AI-powered analysis, attack path visualization, and professional report generation

### Problem Statement

Traditional Active Directory pentesting is:
- **Time-consuming**: Manual enumeration takes 40-60 hours per engagement
- **Error-prone**: Human fatigue leads to missed vulnerabilities
- **Inconsistent**: Results vary based on pentester experience
- **Hard to document**: Report writing is tedious and repetitive

### Solution

An AI-driven platform that:
1. Automates reconnaissance and enumeration phases
2. Analyzes collected data for vulnerabilities
3. Uses LLM to explain findings and recommend exploitation paths
4. Visualizes attack paths to Domain Admin
5. Generates professional pentest reports automatically

---

## 2. Project Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PentestAI-AD Platform                           │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Frontend Layer                               │  │
│  │         React Dashboard  ·  D3.js Graph  ·  Chat UI              │  │
│  └──────────────────────────────┬───────────────────────────────────┘  │
│                                 │ REST API / WebSocket                  │  │
│  ┌──────────────────────────────▼───────────────────────────────────┐  │
│  │                      Backend Layer (FastAPI)                      │  │
│  │  /api/scan  /api/findings  /api/graph  /api/report  /api/chat    │  │
│  └──────┬─────────────┬──────────────┬──────────────┬──────────────┘  │
│         │             │              │              │                   │
│  ┌──────▼──────┐ ┌───▼────────┐ ┌──▼──────┐ ┌────▼─────────┐        │
│  │   Pentest   │ │  Analysis  │ │   AI    │ │   Reporting  │        │
│  │   Engine    │ │   Engine   │ │ Engine  │ │   Engine     │        │
│  │             │ │            │ │         │ │              │        │
│  │ Recon       │ │ Vuln       │ │ Claude  │ │ PDF/HTML     │        │
│  │ Enum        │ │ Scoring    │ │ LangCh. │ │ Generator    │  │
│  │ Exploit     │ │ Path Anal. │ │ Chat    │ │              │        │
│  └──────┬──────┘ └───┬────────┘ └──┬──────┘ └────┬─────────┘        │
│         │            │             │              │                   │
│  ┌──────▼────────────▼─────────────▼──────────────▼─────────────┐   │
│  │                      Data Layer                                │   │
│  │    PostgreSQL (findings)  ·  Neo4j (AD graph)  ·  Redis       │   │
│  │    File Store (evidence screenshots, raw output)              │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │              Lab Network (isolated, authorized)                │    │
│  │   Kali Linux (attacker)  ←→  Windows Server 2019 (DC01)      │    │
│  │                          ←→  Windows 10 (THEPUNISHER)         │    │
│  │                          ←→  Windows 10 (DATAMAN)             │    │
│  └───────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Module Architecture

#### Core Modules

| Module | Responsibility | Key Components |
|--------|---------------|----------------|
| **Pentest Engine** | Execute scanning and enumeration | Responder, LDAP enum, SMB enum, Kerberos enum |
| **Analysis Engine** | Detect vulnerabilities and attack paths | Vuln detectors, Path analyzer, ACL analyzer |
| **AI Engine** | Natural language processing and recommendations | LLM integration, Chat interface, Report generation |
| **Reporting Engine** | Generate professional reports | PDF generator, HTML exporter, Template engine |
| **Data Layer** | Store and retrieve findings | PostgreSQL, Neo4j, Redis, File storage |

### 2.3 Technology Stack

#### Backend
- **Language:** Python 3.11+
- **Framework:** FastAPI (async, high performance)
- **ORM:** SQLAlchemy + Pydantic
- **Authentication:** JWT tokens

#### Frontend
- **Framework:** React 18 + TypeScript
- **State Management:** Zustand
- **Graph Visualization:** D3.js / React Force Graph
- **UI Components:** Tailwind CSS + Shadcn/ui
- **HTTP Client:** Axios + React Query

#### Database
- **Relational:** PostgreSQL 15 (findings, users, scan history)
- **Graph:** Neo4j 5.x (AD relationships, attack paths)
- **Cache:** Redis (session, real-time status)
- **File Storage:** Local filesystem / MinIO (screenshots, raw data)

#### Security Tools Integration
- **Responder:** LLMNR/NBT-NS poisoning
- **Impacket:** SMB, LDAP, Kerberos attacks
- **BloodHound/SharpHound:** AD graph collection
- **LDAP3:** LDAP enumeration
- **CrackMapExec/NetExec:** Multi-protocol exploitation
- **Nmap:** Network scanning

#### AI Components
- **LLM:** Ollama with Llama3/Mistral (local) or OpenAI API
- **LangChain:** Prompt management and chain execution
- **Vector Store:** ChromaDB (for knowledge base)

### 2.4 API Architecture

```
Base URL: http://localhost:8000/api/v1

Authentication:
  POST   /auth/login          - User login
  POST   /auth/register       - User registration
  POST   /auth/refresh        - Refresh JWT token

Scans:
  POST   /scans               - Start new pentest scan
  GET    /scans               - List all scans
  GET    /scans/{id}          - Get scan details
  DELETE /scans/{id}          - Delete scan
  POST   /scans/{id}/stop     - Stop running scan

Findings:
  GET    /findings            - List all findings
  GET    /findings/{id}       - Get finding details
  GET    /findings/scan/{id}  - Get findings for specific scan
  PUT    /findings/{id}       - Update finding status

Attack Paths:
  GET    /paths               - Get attack paths
  GET    /paths/to-da         - Get paths to Domain Admin
  GET    /paths/critical      - Get critical attack paths

Graph:
  GET    /graph/nodes         - Get AD nodes
  GET    /graph/edges         - Get AD relationships
  GET    /graph/export        - Export BloodHound JSON

AI Chat:
  POST   /chat                - Send message to AI assistant
  GET    /chat/history/{scan_id} - Get chat history

Reports:
  POST   /reports/generate    - Generate report
  GET    /reports/{id}        - Get report
  GET    /reports/{id}/download - Download report file
  GET    /reports/templates   - List available templates

Dashboard:
  GET    /dashboard/stats     - Get dashboard statistics
  GET    /dashboard/risk-score - Get overall risk score
```

### 2.5 Data Flow

```
1. User initiates scan
   └─> Backend creates scan record in PostgreSQL
       └─> Pentest Engine executes tools sequentially
           ├─> Responder (LLMNR poisoning) → Raw data
           ├─> LDAP enumeration → User/Group data
           ├─> SharpHound → Graph data
           └─> Custom scripts → Vulnerability checks
       
2. Analysis Engine processes raw data
   ├─> Parse tool outputs
   ├─> Detect vulnerabilities
   ├─> Calculate risk scores
   ├─> Build attack paths in Neo4j
   └─> Store findings in PostgreSQL

3. AI Engine analyzes findings
   ├─> Generate vulnerability descriptions
   ├─> Explain exploitation steps
   ├─> Recommend remediation
   └─> Create report sections

4. User accesses results via Dashboard
   ├─> View statistics
   ├─> Explore AD graph
   ├─> Chat with AI assistant
   └─> Download report
```

---

## 3. AD Pentest Pipeline

### 3.1 Phase 1: Reconnaissance

#### Network Discovery
```python
# Pseudo-code: Network reconnaissance module
class NetworkReconnaissance:
    """Discover AD infrastructure"""
    
    def run_nmap_scan(self, target_cidr: str) -> ScanResult:
        """Perform network scan to discover hosts"""
        # Nmap scan types:
        # - SYN scan (-sS) for fast discovery
        # - Service version detection (-sV)
        # - OS detection (-O)
        # - Script scan for AD-specific services
        
        nmap_command = [
            'nmap', '-p53,88,389,445,636,3268,3389,5985',
            '-sV', '--script=ldap-rootdse,bloodhound-jssh',
            '-oA', 'nmap_results', target_cidr
        ]
        return self.execute_scan(nmap_command)
    
    def identify_domain_controllers(self) -> List[DCInfo]:
        """Identify Domain Controllers via DNS/LDAP"""
        # Query DNS for _ldap._tcp.dc._msdcs.{domain}
        # Check port 88 (Kerberos), 389 (LDAP)
        # Verify with nltest /dclist:{domain}
        pass
    
    def get_domain_info(self) -> DomainInfo:
        """Gather basic domain information"""
        # LDAP query to RootDSE
        # Get domain naming context
        # Retrieve domain SID
        pass
```

#### LLMNR/NBT-NS Poisoning (Responder)
```python
# Pseudo-code: Responder module
class ResponderModule:
    """LLMNR/NBT-NS poisoning for credential capture"""
    
    def start_poisoning(self, interface: str, domain: str) -> Process:
        """Start Responder in analysis mode"""
        # Command: python Responder.py -I eth0 -wrf
        # Options:
        #   -w : Write hashes to database
        #   -r : Analyze answers from NBT-NS
        #   -f : Fingerprint hosts
        
        cmd = [
            'python', 'Responder.py',
            '-I', interface,
            '-wrf',  # Analysis mode
            '--lm',  # Downgrade LM hash
            '--ntlmv2',  # Capture NTLMv2
        ]
        return self.spawn_process(cmd)
    
    def parse_responder_db(self, db_path: str) -> List[CapturedHash]:
        """Parse Responder SQLite database"""
        # Read SQLite database
        # Extract: username, hash, challenge, timestamp
        # Return list of captured credentials
        pass
    
    def crack_hashes(self, hashes: List[CapturedHash]) -> List[CrackedCred]:
        """Crack captured hashes with Hashcat"""
        # Extract NTLM hashes to file
        # Run hashcat with wordlist
        # Return cracked passwords
        pass
```

### 3.2 Phase 2: Enumeration

#### LDAP Enumeration
```python
# Pseudo-code: LDAP enumeration module
class LDAPEnumeration:
    """Enumerate AD objects via LDAP"""
    
    def __init__(self, ldap_url: str, username: str, password: str):
        self.ldap_url = ldap_url
        self.username = username
        self.password = password
        self.conn = None
    
    def connect(self) -> bool:
        """Establish LDAP connection"""
        # Use ldap3 library
        # Support: Simple auth, NTLM, GSSAPI
        # Auto-detect TLS requirements
        pass
    
    def enumerate_users(self) -> List[ADUser]:
        """Enumerate all users"""
        # LDAP filter: (objectClass=user)
        # Attributes: sAMAccountName, mail, memberOf,
        #             userAccountControl, pwdLastSet,
        #             lastLogon, description, etc.
        
        query = "(&(objectClass=user)(!(objectClass=computer)))"
        return self.search(query, attributes=['*'])
    
    def enumerate_groups(self) -> List[ADGroup]:
        """Enumerate all groups"""
        # LDAP filter: (objectClass=group)
        # Attributes: cn, description, member, memberOf
        pass
    
    def enumerate_computers(self) -> List[ADComputer]:
        """Enumerate all computers"""
        # LDAP filter: (objectClass=computer)
        # Attributes: dNSHostName, operatingSystem,
        #             servicePrincipalName, etc.
        pass
    
    def enumerate_ous(self) -> List[ADOU]:
        """Enumerate Organizational Units"""
        # LDAP filter: (objectClass=organizationalUnit)
        pass
    
    def enumerate_gpos(self) -> List[GPO]:
        """Enumerate Group Policy Objects"""
        # LDAP filter: (objectClass=groupPolicyContainer)
        # Get: gPCFileSysPath, displayName, whenChanged
        pass
    
    def get_user_details(self, username: str) -> UserDetails:
        """Get detailed user information"""
        # Include: all groups, ACLs, SPNs, delegated permissions
        pass
    
    def check_account_policy(self) -> AccountPolicy:
        """Get domain account policies"""
        # Min password length, password history,
        # lockout threshold, etc.
        pass
```

#### Kerberos Enumeration
```python
# Pseudo-code: Kerberos enumeration module
class KerberosEnumeration:
    """Kerberos-based enumeration"""
    
    def get_kerberos_tickets(self) -> List<KerberosTicket]:
        """List available TGTs and TGS"""
        # Use mimikatz: kerberos::list
        # Or Rubeus: .\Rubeus.exe dump
        pass
    
    def enumerate_spn_accounts(self) -> List[SPNAccount]:
        """Find accounts with SPNs (Kerberoasting)"""
        # LDAP filter: (servicePrincipalName=*)
        # Extract: servicePrincipalName, sAMAccountName
        pass
    
    def request_tgs(self, spn: str) -> TGSResponse:
        """Request TGS for SPN (Kerberoasting prep)"""
        # Use GetUserSPNs.py or Rubeus
        # Request TGS without cracking
        pass
    
    def check_asrep_roastable(self) -> List[ASREPTarget]:
        """Find AS-REP roastable accounts"""
        # LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304)
        # Check: DONT_REQ_PREAUTH flag
        pass
    
    def enumerate_delegation(self) -> DelegationInfo:
        """Find delegation configurations"""
        # Unconstrained: userAccountControl bit 524288
        # Constrained: msDS-AllowedToDelegateTo
        # RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity
        pass
```

#### BloodHound/SharpHound Collection
```python
# Pseudo-code: BloodHound collector module
class BloodHoundCollector:
    """Collect AD data for BloodHound analysis"""
    
    def run_sharphound(self, collection_method: str = 'All') -> BloodHoundData:
        """Execute SharpHound collector"""
        # Collection methods:
        # - Default: Sessions, LocalGroups, Trusts, ACLs, ObjectProps
        # - All: All collection methods
        # - Session: Session collection only
        # - ACL: ACL collection only
        
        cmd = [
            'SharpHound.exe',
            '--CollectionMethods', collection_method,
            '--Domain', self.domain,
            '--OutputDirectory', self.output_dir,
            '--ZipFilename', 'bloodhound_data'
        ]
        return self.execute(cmd)
    
    def parse_bloodhound_json(self, json_path: str) -> GraphData:
        """Parse BloodHound JSON exports"""
        # Parse: computers.json, users.json, groups.json,
        #         domains.json, ou.json, gpos.json,
        #         containers.json, edges.json
        pass
    
    def import_to_neo4j(self, graph_data: GraphData) -> bool:
        """Import data to Neo4j"""
        # Use bloodhound-python or neo4j driver
        # Create nodes and relationships
        pass
```

### 3.3 Phase 4: Vulnerability Analysis

#### Kerberoasting Detection
```python
# Pseudo-code: Kerberoasting vulnerability detector
class KerberoastingDetector:
    """Detect Kerberoasting vulnerability"""
    
    def detect(self, spn_accounts: List[SPNAccount]) -> Finding:
        """Identify Kerberoasting vulnerable accounts"""
        
        vulnerable = []
        for account in spn_accounts:
            # Check if account is privileged
            if self.is_privileged(account):
                vulnerable.append({
                    'username': account.samaccountname,
                    'spn': account.serviceprincipalname,
                    'risk': 'HIGH'
                })
        
        return Finding(
            vuln_type='KERBEROASTING',
            severity='HIGH',
            title='Kerberoasting Attack Possible',
            description=f'Found {len(vulnerable)} accounts with SPNs',
            evidence=vulnerable,
            affected_assets=[a['username'] for a in vulnerable],
            remediation='Use managed service accounts (gMSA) or rotate SPN passwords'
        )
    
    def is_privileged(self, account: ADUser) -> bool:
        """Check if account has privileged status"""
        # Check memberOf for Domain Admins, Enterprise Admins
        # Check if in "Protected Users" group
        # Check userAccountControl for sensitive flags
        pass
```

#### AS-REP Roasting Detection
```python
class ASREPRoastingDetector:
    """Detect AS-REP Roasting vulnerability"""
    
    def detect(self, users: List[ADUser]) -> Finding:
        """Find accounts with DONT_REQ_PREAUTH"""
        
        vulnerable = []
        for user in users:
            if self.has_asrep_vulnerability(user):
                vulnerable.append(user.samaccountname)
        
        return Finding(
            vuln_type='AS_REP_ROASTING',
            severity='CRITICAL',
            title='AS-REP Roasting Vulnerability',
            description='Pre-authentication disabled for user accounts',
            evidence=vulnerable,
            remediation='Enable require pre-authentication'
        )
    
    def has_asrep_vulnerability(self, user: ADUser) -> bool:
        """Check if user has AS-REP vulnerability"""
        # Check userAccountControl bit 4194304 (DONT_REQ_PREAUTH)
        # Or check: userAccountControl & 0x400000
        pass
```

#### ACL Abuse Detection
```python
# Pseudo-code: ACL vulnerability detector
class ACLDetector:
    """Detect dangerous ACL configurations"""
    
    # Dangerous ACE types to detect
    DANGEROUS_ACLS = {
        'WriteOwner': 'Can change object owner',
        'WriteDacl': 'Can modify ACLs',
        'GenericAll': 'Full control',
        'GenericWrite': 'Can modify object',
        'WriteProperty': 'Can write properties',
        'Self': 'Can add self to group',
        'ForceChangePassword': 'Can reset password',
        'AddMember': 'Can add members to group',
    }
    
    def detect_dangerous_aces(self, acls: List[ACL]) -> List[Finding]:
        """Find dangerous ACL configurations"""
        
        findings = []
        
        for ace in acls:
            if ace.ace_type in self.DANGEROUS_ACLS:
                # Check if principal is low-privileged
                if self.is_interesting_principal(ace.principal):
                    findings.append(Finding(
                        vuln_type='DANGEROUS_ACL',
                        severity=self.calculate_severity(ace),
                        title=f'Dangerous ACL: {ace.ace_type}',
                        description=self.DANGEROUS_ACLS[ace.ace_type],
                        evidence={
                            'principal': ace.principal,
                            'target': ace.target,
                            'ace_type': ace.ace_type
                        },
                        remediation=self.get_remediation(ace)
                    ))
        
        return findings
    
    def detect_privilege_escalation_paths(self, graph: ADGraph) -> List[AttackPath]:
        """Find paths to Domain Admin using ACL abuse"""
        
        paths = []
        
        # BFS from low-priv users to Domain Admin
        for user in graph.get_users():
            for path in self.bfs_to_da(user, graph):
                if self.path_uses_acl(path):
                    paths.append(path)
        
        return paths
```

#### Delegation Vulnerabilities
```python
# Pseudo-code: Delegation vulnerability detectors
class DelegationDetector:
    """Detect delegation-related vulnerabilities"""
    
    def detect_unconstrained_delegation(self) -> Finding:
        """Find unconstrained delegation enabled"""
        # LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=524288)
        pass
    
    def detect_constrained_delegation(self) -> Finding:
        """Find constrained delegation enabled"""
        # Check msDS-AllowedToDelegateTo
        pass
    
    def detect_rbcd(self) -> Finding:
        """Find Resource-Based Constrained Delegation"""
        # Check msDS-AllowedToActOnBehalfOfOtherIdentity
        pass
    
    def detect_delegation_privesc(self, graph: ADGraph) -> List[AttackPath]:
        """Find privilege escalation via delegation"""
        # Find: RBCD → DC → DCSync
        # Find: Constrained Del → Service → Code Exec
        pass
```

#### ADCS Vulnerabilities (ESC1-ESC8)
```python
# Pseudo-code: ADCS vulnerability detectors
class ADCSDetector:
    """Detect Active Directory Certificate Services vulnerabilities"""
    
    def detect_esc1(self) -> Finding:
        """ESC1: Enrollment agent allows arbitrary principal"""
        # Check CA template for:
        # - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        # - CT_FLAG_AUTHORITY_FLAG_ALLOW_ENROLLEE_SUPPLY_SUBJECT
        # - Enrollment agent certificate
        pass
    
    def detect_esc2(self) -> Finding:
        """ESC2: Dangerous EKUs"""
        # Certificate has: Any Purpose EKU or no EKU
        pass
    
    def detect_esc3(self) -> Finding:
        """ESC3: Enrollment Agent Template"""
        # Template allows enrollment agent
        pass
    
    def detect_esc5(self) -> Finding:
        """ESC5: Dangerous ACL on CA server"""
        # Low-priv user can modify CA settings
        pass
    
    def detect_esc8(self) -> Finding:
        """ESC8: HTTP enrollment relay"""
        # Check for HTTP enrollment endpoint
        pass
```

#### Pass-the-Hash Detection
```python
# Pseudo-code: PtH detection
class PtHDetector:
    """Detect Pass-the-Hash opportunities"""
    
    def detect_weak_credentials(self, users: List[ADUser]) -> List[Finding]:
        """Find accounts with weak/empty passwords"""
        # Check: pwdLastSet = 0 (never changed)
        # Check: password not required
        # Check: reversible encryption enabled
        pass
    
    def detect_lm_hashable(self) -> Finding:
        """Find accounts with LM hash available"""
        # Check: userAccountControl bit 2 (ENCRYPTED_TEXT_PWD_ALLOWED)
        pass
```

### 3.4 Phase 5: Attack Path Analysis

```python
# Pseudo-code: Attack path analysis module
class AttackPathAnalyzer:
    """Analyze and visualize attack paths to Domain Admin"""
    
    def __init__(self, neo4j_driver):
        self.graph = neo4j_driver
    
    def find_all_paths_to_da(self, max_hops: int = 10) -> List[AttackPath]:
        """Find all paths to Domain Admin"""
        
        query = """
        MATCH path = (start:User)-[r:MemberOf|HasSession|AdminTo|
                      CanRDP|ExecuteDCOM|AllowedToDelegate|
                      WriteDacl|GenericAll*1..{max_hops}]->(da:Group)
        WHERE da.name CONTAINS 'Domain Admin'
        RETURN path, length(path) as hops
        ORDER BY hops
        LIMIT 100
        """
        
        return self.graph.run(query)
    
    def find_shortest_path(self, start_node: str, end_node: str) -> AttackPath:
        """Find shortest attack path between nodes"""
        
        query = """
        MATCH path = shortestPath(
            (start)-[r*]->(end)
        )
        WHERE start.name = $start AND end.name = $end
        RETURN path
        """
        
        return self.graph.run(query, start=start_node, end=end_node)
    
    def find_critical_paths(self) -> List[AttackPath]:
        """Find most critical attack paths"""
        
        # Paths that:
        # 1. Start from internet-exposed services
        # 2. Use high-severity vulnerabilities
        # 3. Have short hops to DA
        # 4. Don't require credential reuse
        
        query = """
        MATCH path = (u:User)-[r*1..5]->(da:Group)
        WHERE da.name CONTAINS 'Domain Admin'
        WITH path, 
             [n IN nodes(path) | n.critical] as criticals,
             length(path) as hops
        WHERE reduce(c = 0, x IN criticals | c + x) > 0
        RETURN path, hops
        ORDER BY hops
        """
        
        return self.graph.run(query)
    
    def calculate_path_risk(self, path: AttackPath) -> float:
        """Calculate risk score for attack path"""
        
        # Factors:
        # - Number of hops (shorter = higher risk)
        # - Severity of each step
        # - Exploitability of each step
        # - Asset criticality
        
        score = 0.0
        for step in path.steps:
            score += step.severity * step.exploitability
        
        # Normalize by path length
        return score / len(path.steps)
```

---

## 4. Artificial Intelligence Engine

### 4.1 AI Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI Engine Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   Input     │    │   Prompt    │    │   Output    │        │
│  │  Processing │───▶│  Management │───▶│  Formatting │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│         │                  │                  │                 │
│         ▼                  ▼                  ▼                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    LangChain Framework                   │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │   │
│  │  │   Chains    │  │   Agents    │  │  Memory     │     │   │
│  │  │  (LCEL)     │  │  (Tools)    │  │ (Context)   │     │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    LLM Provider                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │   │
│  │  │   Ollama    │  │  OpenAI     │  │  Anthropic  │     │   │
│  │  │  (Local)    │  │   (API)     │  │   (API)     │     │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 AI Use Cases

#### 1. Vulnerability Analysis & Explanation
```python
# Pseudo-code: AI vulnerability analyzer
class AIVulnerabilityAnalyzer:
    """Use LLM to analyze and explain vulnerabilities"""
    
    def __init__(self, llm: BaseChatModel):
        self.llm = llm
        self.prompt_template = PromptTemplate(
            input_variables=["vuln_data", "context"],
            template=VULN_ANALYSIS_PROMPT
        )
    
    def analyze_vulnerability(self, finding: Finding) -> AnalysisResult:
        """Generate detailed analysis of a vulnerability"""
        
        prompt = self.prompt_template.format(
            vuln_data=json.dumps(finding.to_dict()),
            context=self.get_domain_context(finding)
        )
        
        response = self.llm.invoke(prompt)
        
        return AnalysisResult(
            summary=response.summary,
            impact=response.impact,
            exploitation_steps=response.steps,
            remediation=response.remediation,
            references=response.references
        )
    
    def get_domain_context(self, finding: Finding) -> str:
        """Get relevant domain context for analysis"""
        # Include: AD structure, user roles, asset criticality
        pass
```

#### 2. Exploitation Path Recommendation
```python
# Pseudo-code: AI exploitation path recommender
class AIExploitationAdvisor:
    """AI-powered exploitation path recommendations"""
    
    def recommend_exploitation_order(self, findings: List[Finding], 
                                     attack_paths: List[AttackPath]) -> ExploitationPlan:
        """Recommend logical exploitation order"""
        
        prompt = """
        You are a senior penetration tester. Given the following findings 
        and attack paths, recommend the optimal exploitation order.
        
        Findings:
        {findings}
        
        Attack Paths:
        {paths}
        
        Consider:
        1. Difficulty of exploitation
        2. Potential impact
        3. Prerequisites (what needs to be done first)
        4. Risk of detection/disruption
        
        Provide a numbered list of recommended actions with explanations.
        """
        
        response = self.llm.invoke(prompt)
        return self.parse_exploitation_plan(response)
```

#### 3. Remediation Recommendations
```python
# Pseudo-code: AI remediation advisor
class AIRemediationAdvisor:
    """AI-powered remediation recommendations"""
    
    def generate_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Generate detailed remediation plan"""
        
        prompt = """
        Generate a detailed remediation plan for:
        
        Vulnerability: {vuln_type}
        Severity: {severity}
        Affected Assets: {assets}
        
        Include:
        1. Immediate actions (what to do now)
        2. Short-term fixes (1-4 weeks)
        3. Long-term improvements (1-3 months)
        4. Verification steps
        5. Priority order if multiple issues
        
        Use specific Active Directory commands and configurations.
        """
        
        response = self.llm.invoke(prompt)
        return self.parse_remediation_plan(response)
```

#### 4. Report Generation Assistant
```python
# Pseudo-code: AI report generator
class AIReportGenerator:
    """AI-powered pentest report generation"""
    
    def generate_executive_summary(self, scan_data: ScanData) -> str:
        """Generate executive summary"""
        
        prompt = """
        Generate a professional executive summary for a pentest report.
        
        Scan Results:
        - Total findings: {count}
        - Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}
        - Key vulnerabilities: {top_vulns}
        
        The summary should:
        1. Be 2-3 paragraphs
        2. Focus on business impact
        3. Avoid technical jargon
        4. Include risk rating
        5. Recommend next steps
        """
        
        return self.llm.invoke(prompt)
    
    def generate_technical_details(self, finding: Finding) -> str:
        """Generate technical details section"""
        
        prompt = """
        Write technical details for a pentest finding:
        
        {finding_details}
        
        Include:
        1. Technical description
        2. Proof of concept
        3. Impact analysis
        4. References (CVE, MITRE ATT&CK)
        """
        
        return self.llm.invoke(prompt)
```

#### 5. Chat Assistant
```python
# Pseudo-code: AI chat assistant
class AIChatAssistant:
    """Interactive pentest assistant"""
    
    def __init__(self, llm: BaseChatModel):
        self.llm = llm
        self.tools = self.create_tools()
        self.agent = Agent(
            llm=self.llm,
            tools=self.tools,
            prompt=CHAT_SYSTEM_PROMPT
        )
    
    def create_tools(self) -> List[Tool]:
        """Create available tools for the agent"""
        
        return [
            Tool(
                name="get_findings",
                func=self.get_findings,
                description="Get list of vulnerabilities found"
            ),
            Tool(
                name="get_attack_paths",
                func=self.get_attack_paths,
                description="Get attack paths to Domain Admin"
            ),
            Tool(
                name="get_graph_data",
                func=self.get_graph_data,
                description="Get AD graph visualization data"
            ),
            Tool(
                name="explain_vulnerability",
                func=self.explain_vulnerability,
                description="Explain a specific vulnerability"
            ),
            Tool(
                name="get_recommendations",
                func=self.get_recommendations,
                description="Get remediation recommendations"
            ),
        ]
    
    def chat(self, message: str, context: ChatContext) -> str:
        """Process chat message and return response"""
        
        response = self.agent.invoke(
            input=message,
            context=context
        )
        
        return response
```

### 4.3 Prompt Engineering

```python
# System prompts for different AI tasks

VULN_ANALYSIS_SYSTEM_PROMPT = """You are an expert cybersecurity analyst 
specializing in Active Directory security. Your role is to analyze pentest 
findings and provide detailed, accurate explanations.

When analyzing vulnerabilities:
1. Explain the technical mechanism clearly
2. Provide real-world impact scenarios
3. Reference relevant CVEs and attack techniques
4. Suggest specific remediation steps
5. Consider false positives and validation needs

Always prioritize accuracy and actionable advice."""

EXPLOITATION_ADVISOR_PROMPT = """You are a senior penetration tester with 
10+ years of experience in Active Directory security testing. Your role is 
to guide less experienced testers through complex exploitation scenarios.

When recommending exploitation:
1. Consider the attack path complexity
2. Prioritize stealth and minimal detection
3. Account for dependencies between steps
4. Provide specific commands and techniques
5. Include verification steps after exploitation"""

REPORT_GENERATION_PROMPT = """You are a technical writer specializing in 
cybersecurity reports. Your role is to create professional, accurate pentest 
reports that communicate findings clearly to both technical and executive 
audiences.

For executive summaries:
- Use business-focused language
- Avoid excessive technical jargon
- Focus on risk and impact
- Include clear recommendations

For technical sections:
- Be precise and detailed
- Include proof of concept
- Reference standards (MITRE ATT&CK, CWE)
- Provide actionable remediation"""
```

---

## 5. Vulnerability Prioritization System

### 5.1 Risk Scoring Algorithm

```python
# Pseudo-code: Risk scoring system
class RiskScoringEngine:
    """Calculate risk scores for vulnerabilities"""
    
    # Weight factors
    WEIGHTS = {
        'severity': 0.35,        # CVSS base score
        'exploitability': 0.20,  # Ease of exploitation
        'impact': 0.25,          # Business impact
        'proximity': 0.10,       # Distance to Domain Admin
        'remediation': 0.10,     # Ease of fixing
    }
    
    def calculate_risk_score(self, finding: Finding, 
                            context: ScanContext) -> RiskScore:
        """Calculate overall risk score"""
        
        # 1. Base severity score (CVSS-like)
        severity_score = self.get_severity_score(finding.severity)
        
        # 2. Exploitability score
        exploitability = self.assess_exploitability(finding)
        
        # 3. Business impact
        impact = self.assess_business_impact(finding, context)
        
        # 4. Proximity to Domain Admin
        proximity = self.assess_da_proximity(finding, context)
        
        # 5. Remediation difficulty
        remediation = self.assess_remediation_difficulty(finding)
        
        # Calculate weighted score
        final_score = (
            severity_score * self.WEIGHTS['severity'] +
            exploitability * self.WEIGHTS['exploitability'] +
            impact * self.WEIGHTS['impact'] +
            proximity * self.WEIGHTS['proximity'] +
            remediation * self.WEIGHTS['remediation']
        )
        
        return RiskScore(
            value=final_score,
            rating=self.get_rating(final_score),
            breakdown={
                'severity': severity_score,
                'exploitability': exploitability,
                'impact': impact,
                'proximity': proximity,
                'remediation': remediation
            }
        )
    
    def get_severity_score(self, severity: str) -> float:
        """Convert severity to numeric score"""
        mapping = {
            'CRITICAL': 10.0,
            'HIGH': 8.0,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 0.5
        }
        return mapping.get(severity.upper(), 5.0)
    
    def assess_exploitability(self, finding: Finding) -> float:
        """Assess how easy the vulnerability is to exploit"""
        
        # Factors:
        # - Public exploits available (higher score)
        # - Tool support (Metasploit, etc.)
        # - No authentication required
        # - Network accessibility
        
        score = 5.0
        
        if finding.has_public_exploit:
            score += 3.0
        
        if finding.in_metasploit:
            score += 2.0
        
        if not finding.requires_auth:
            score += 2.0
        
        if finding.exposed_to_internet:
            score += 3.0
        
        return min(score, 10.0)
    
    def assess_business_impact(self, finding: Finding, 
                               context: ScanContext) -> float:
        """Assess business impact of exploitation"""
        
        # Consider:
        # - Data sensitivity
        # - Regulatory compliance
        # - Service availability
        # - Financial impact
        
        score = 5.0
        
        # Check affected asset criticality
        for asset in finding.affected_assets:
            criticality = context.get_asset_criticality(asset)
            score += criticality * 0.5
        
        return min(score, 10.0)
    
    def assess_da_proximity(self, finding: Finding, 
                           context: ScanContext) -> float:
        """Assess proximity to Domain Admin"""
        
        # Check if finding enables path to DA
        paths = context.get_attack_paths_to_da(finding)
        
        if not paths:
            return 0.0
        
        # Shorter path = higher score
        shortest = min(p.length for p in paths)
        
        # Convert to 0-10 scale (1 hop = 10, 5+ hops = 2)
        return max(10 - (shortest * 2), 2)
    
    def assess_remediation_difficulty(self, finding: Finding) -> float:
        """Assess how difficult it is to fix"""
        
        # Higher score = harder to fix
        # Invert for final calculation
        
        difficulty = finding.remediation_difficulty
        
        # Convert to 0-10 (10 = very hard)
        return difficulty
    
    def get_rating(self, score: float) -> str:
        """Convert numeric score to rating"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 5.0:
            return 'MEDIUM'
        elif score >= 3.0:
            return 'LOW'
        else:
            return 'INFO'
```

### 5.2 Priority Matrix

| Severity | Exploitability | Proximity to DA | Priority |
|----------|---------------|-----------------|----------|
| CRITICAL | High | Direct | P1 - Immediate |
| CRITICAL | Medium | Direct | P1 - Immediate |
| HIGH | High | Direct | P2 - This Week |
| HIGH | High | Indirect | P2 - This Week |
| CRITICAL | Low | Any | P3 - This Month |
| HIGH | Medium | Direct | P3 - This Month |
| MEDIUM | High | Direct | P3 - This Month |
| HIGH | Low | Any | P4 - Next Quarter |
| MEDIUM | Medium | Any | P4 - Next Quarter |
| LOW | Any | Any | P5 - Planned |

---

## 6. Web Interface & Dashboard

### 6.1 Dashboard Pages

#### 1. Home/Dashboard
```
┌─────────────────────────────────────────────────────────────────┐
│  PentestAI-AD                              [User] [Settings]   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐           │
│  │   CRITICAL   │ │    HIGH      │ │    MEDIUM    │           │
│  │      12      │ │      25      │ │      43      │           │
│  └──────────────┘ └──────────────┘ └──────────────┘           │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Risk Score Gauge (0-100)                     │  │
│  │                       ████████░░ 78                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────┐ ┌─────────────────────────────┐  │
│  │   Vulnerabilities by    │ │   Attack Paths to DA        │  │
│  │       Category          │ │                             │  │
│  │                         │ │   [Interactive Graph]       │  │
│  │   [Pie Chart]          │ │                             │  │
│  └─────────────────────────┘ └─────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │   Recent Scans                                            │  │
│  │   ─────────────────────────────────────────────────────  │  │
│  │   Scan #23  |  2024-01-15  |  80 findings  |  Completed  │  │
│  │   Scan #22  |  2024-01-10  |  45 findings  |  Completed  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

#### 2. Findings List
```
┌─────────────────────────────────────────────────────────────────┐
│  Findings                                    [Filter] [Export]  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [Search: _______________] [Severity: All ▼] [Status: All ▼]   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ ☑ │ KERBEROASTING        │ CRITICAL │ SRV01, SRV02    │  │
│  │ ☑ │ AS-REP Roasting      │ CRITICAL │ USER01          │  │
│  │ ☑ │ Unconstrained Del.   │ HIGH     │ DC01            │  │
│  │ ☑ │ Weak Password        │ HIGH     │ 15 accounts     │  │
│  │ ☑ │ Dangerous ACL        │ MEDIUM   │ GROUP01         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Showing 1-5 of 80 findings                    [<] 1 2 3 ... [>]│
└─────────────────────────────────────────────────────────────────┘
```

#### 3. Finding Details
```
┌─────────────────────────────────────────────────────────────────┐
│  Finding Details                              [Edit] [Delete]   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Title:    Kerberoasting Attack Possible                        │
│  ID:       FIND-001                                             │
│  Severity: CRITICAL                                             │
│  Status:   Open                                                 │
│  Score:    9.2/10                                               │
│                                                                  │
│  ───────────────────────────────────────────────────────────    │
│                                                                  │
│  Description                                                     │
│  ─────────────                                                   │
│  Multiple service accounts have SPNs configured and are         │
│  vulnerable to Kerberoasting attack. These accounts can be      │
│  targeted to obtain TGS tickets that can be cracked offline.    │
│                                                                  │
│  Affected Assets                                                 │
│  ───────────────                                                 │
│  • svc_backup (SPN: MSSQL/backup.db.local)                     │
│  • svc_sql (SPN: MSSQL/sql.db.local)                           │
│  • svc_web (SPN: HTTP/web.db.local)                            │
│                                                                  │
│  AI Analysis                                                     │
│  ───────────                                                     │
│  [Expand for AI-generated explanation]                          │
│                                                                  │
│  Proof of Concept                                                │
│  ────────────────                                                │
│  GetUserSPNs.py -dc-ip 10.10.10.10 -domain db.local            │
│                                                                  │
│  Remediation                                                     │
│  ───────────                                                     │
│  [Expand for AI recommendations]                                │
│                                                                  │
│  References                                                      │
│  ───────────                                                     │
│  • MITRE ATT&CK: T1558.003                                      │
│  • MITRE ATT&CK: T1003.001                                      │
└─────────────────────────────────────────────────────────────────┘
```

#### 4. Attack Graph
```
┌─────────────────────────────────────────────────────────────────┐
│  Attack Path Visualization                    [Filter] [Zoom]  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [Legend: ●User ○Computer ■Group ◇DA]                          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                                                          │  │
│  │      ┌──────┐                                            │  │
│  │      │ USER │──────┐                                     │  │
│  │      └──────┘      │                                     │  │
│  │                     ▼                                     │  │
│  │              ┌──────────┐                                 │  │
│  │              │  GROUP1  │                                 │  │
│  │              └──────────┘                                 │  │
│  │                     │                                     │  │
│  │                     ▼                                     │  │
│  │              ┌──────────┐                                 │  │
│  │              │ COMPUTER │                                 │  │
│  │              └──────────┘                                 │  │
│  │                     │                                     │  │
│  │                     ▼                                     │  │
│  │              ┌──────────┐                                 │  │
│  │              │    DA    │                                 │  │
│  │              └──────────┘                                 │  │
│  │                                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Path Details: 4 hops to Domain Admin                           │
│  1. USER01 → MemberOf → IT_Admins                               │
│  2. IT_Admins → AdminTo → WORKSTATION01                         │
│  3. WORKSTATION01 → CanRDP → SERVER01                           │
│  4. SERVER01 → AdminTo → Domain Admins                          │
└─────────────────────────────────────────────────────────────────┘
```

#### 5. AI Chat
```
┌─────────────────────────────────────────────────────────────────┐
│  AI Pentest Assistant                              [Clear]      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ User: How should I prioritize exploitation?              │  │
│  │                                                          │  │
│  │ AI: Based on the findings, I recommend this order:      │  │
│  │                                                          │  │
│  │ 1. Kerberoasting (CRITICAL) - Quick win, no noise       │  │
│  │ 2. AS-REP Roasting (CRITICAL) - Easy credential access  │  │
│  │ 3. Unconstrained Delegation (HIGH) - If DC accessible    │  │
│  │ 4. ACL Abuse (MEDIUM) - Requires more setup              │  │
│  │                                                          │  │
│  │ Would you like detailed steps for any of these?         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Type your message...                          [Send]     │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

#### 6. Report Generation
```
┌─────────────────────────────────────────────────────────────────┐
│  Generate Report                                  [Preview]     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Report Type:                                                   │
│  [●] Full Report  [ ] Executive Summary  [ ] Technical Only    │
│                                                                  │
│  Template:                                                      │
│  [Default ▼]                                                    │
│                                                                  │
│  Include Sections:                                              │
│  ☑ Executive Summary                                           │
│  ☑ Methodology                                                 │
│  ☑ Scope                                                       │
│  ☑ Findings (All / Critical+High / Custom)                    │
│  ☑ Attack Paths                                                │
│  ☑ Remediation Plan                                            │
│  ☑ Appendices                                                  │
│                                                                  │
│  Format:                                                        │
│  [●] PDF  [ ] HTML  [ ] Markdown                               │
│                                                                  │
│  [──────────────────── Generate Report ─────────────────────]  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Frontend Components

```typescript
// Frontend component structure
src/
├── components/
│   ├── dashboard/
│   │   ├── RiskGauge.tsx
│   │   ├── FindingStats.tsx
│   │   ├── RecentScans.tsx
│   │   └── CategoryChart.tsx
│   ├── findings/
│   │   ├── FindingList.tsx
│   │   ├── FindingCard.tsx
│   │   ├── FindingDetail.tsx
│   │   └── FindingFilters.tsx
│   ├── graph/
│   │   ├── ADGraph.tsx
│   │   ├── GraphControls.tsx
│   │   └── PathHighlight.tsx
│   ├── chat/
│   │   ├── ChatWindow.tsx
│   │   ├── MessageBubble.tsx
│   │   └── ChatInput.tsx
│   └── report/
│       ├── ReportGenerator.tsx
│       ├── ReportPreview.tsx
│       └── ReportDownload.tsx
├── pages/
│   ├── Dashboard.tsx
│   ├── Findings.tsx
│   ├── Graph.tsx
│   ├── Chat.tsx
│   ├── Reports.tsx
│   └── Settings.tsx
├── hooks/
│   ├── useScans.ts
│   ├── useFindings.ts
│   ├── useGraph.ts
│   └── useChat.ts
├── services/
│   ├── api.ts
│   ├── websocket.ts
│   └── auth.ts
└── types/
    ├── finding.ts
    ├── scan.ts
    ├── graph.ts
    └── report.ts
```

---

## 7. Automated Report Generation

### 7.1 Report Structure

```python
# Pseudo-code: Report generator
class ReportGenerator:
    """Generate professional pentest reports"""
    
    def generate_report(self, scan_id: str, 
                       template: str = 'default',
                       sections: List[str] = None) -> Report:
        """Generate complete pentest report"""
        
        scan = self.get_scan(scan_id)
        findings = self.get_findings(scan_id)
        
        # Build report sections
        report = Report()
        
        if 'executive_summary' in sections:
            report.add_section(self.generate_executive_summary(
                scan, findings
            ))
        
        if 'methodology' in sections:
            report.add_section(self.generate_methodology())
        
        if 'scope' in sections:
            report.add_section(self.generate_scope(scan))
        
        if 'findings' in sections:
            report.add_section(self.generate_findings(findings))
        
        if 'attack_paths' in sections:
            report.add_section(self.generate_attack_paths(scan_id))
        
        if 'remediation' in sections:
            report.add_section(self.generate_remediation(findings))
        
        if 'appendices' in sections:
            report.add_section(self.generate_appendices(scan))
        
        return report
    
    def generate_executive_summary(self, scan: Scan, 
                                   findings: List[Finding]) -> Section:
        """Generate executive summary using AI"""
        
        # Use AI to generate summary
        ai_summary = self.ai_engine.generate_executive_summary(
            scan_data=ScanData(
                total_findings=len(findings),
                critical=len([f for f in findings if f.severity == 'CRITICAL']),
                high=len([f for f in findings if f.severity == 'HIGH']),
                medium=len([f for f in findings if f.severity == 'MEDIUM']),
                low=len([f for f in findings if f.severity == 'LOW']),
                top_vulns=self.get_top_vulnerabilities(findings, 5)
            )
        )
        
        return Section(
            title='Executive Summary',
            content=ai_summary,
            template='executive_summary'
        )
    
    def generate_findings(self, findings: List[Finding]) -> Section:
        """Generate findings section"""
        
        content = []
        
        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in findings 
                                if f.severity == severity]
            
            if severity_findings:
                content.append(f"## {severity} Severity Findings\n")
                
                for finding in severity_findings:
                    content.append(self.format_finding(finding))
        
        return Section(
            title='Vulnerability Findings',
            content='\n\n'.join(content),
            template='findings'
        )
    
    def format_finding(self, finding: Finding) -> str:
        """Format individual finding"""
        
        return f"""
### {finding.title}

**Severity:** {finding.severity}  
**Risk Score:** {finding.risk_score}/10  
**Status:** {finding.status}

#### Description
{finding.description}

#### Affected Assets
{self.format_list(finding.affected_assets)}

#### Proof of Concept
```{finding.proof_of_concept_language}
{finding.proof_of_concept}
```

#### Impact
{finding.impact}

#### Remediation
{finding.remediation}

#### References
{self.format_references(finding.references)}
"""
```

### 7.2 Report Templates

```html
<!-- Report template example (Jinja2) -->
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; }
        h2 { color: #34495e; margin-top: 30px; }
        .finding { background: #f8f9fa; padding: 15px; margin: 15px 0; }
        .critical { border-left: 4px solid #e74c3c; }
        .high { border-left: 4px solid #e67e22; }
        .medium { border-left: 4px solid #f1c40f; }
        .low { border-left: 4px solid #95a5a6; }
        .code { background: #2c3e50; color: #ecf0f1; padding: 10px; }
    </style>
</head>
<body>
    <h1>{{ report_title }}</h1>
    <p><strong>Date:</strong> {{ date }}</p>
    <p><strong>Client:</strong> {{ client }}</p>
    
    {{ content }}
    
    <footer>
        <p>Generated by PentestAI-AD Platform</p>
    </footer>
</body>
</html>
```

---

## 8. Technical Project Structure

### 8.1 Project Directory Structure

```
PentestAI-AD/
├── README.md
├── requirements.txt
├── docker-compose.yml
├── .env.example
├── Makefile
│
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI application
│   │   ├── config.py               # Configuration
│   │   ├── database.py             # Database connections
│   │   ├── security.py             # Auth & security
│   │   └── constants.py            # Constants
│   │   │
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── routes/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth.py         # Authentication endpoints
│   │   │   │   ├── scans.py        # Scan management
│   │   │   │   ├── findings.py     # Findings CRUD
│   │   │   │   ├── graph.py        # Graph data
│   │   │   │   ├── paths.py        # Attack paths
│   │   │   │   ├── chat.py         # AI chat
│   │   │   │   ├── reports.py      # Report generation
│   │   │   │   └── dashboard.py    # Dashboard stats
│   │   │   └── dependencies.py     # API dependencies
│   │   │
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── pentest/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py       # Main pentest engine
│   │   │   │   ├── reconnaissance.py
│   │   │   │   ├── enumeration.py
│   │   │   │   ├── exploitation.py
│   │   │   │   └── tools/
│   │   │   │       ├── __init__.py
│   │   │   │       ├── responder.py
│   │   │   │       ├── ldap_enum.py
│   │   │   │       ├── kerberos.py
│   │   │   │       ├── bloodhound.py
│   │   │   │       └── nmap.py
│   │   │   │
│   │   │   ├── analysis/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── vulnerability.py
│   │   │   │   ├── scoring.py
│   │   │   │   ├── path_analysis.py
│   │   │   │   └── detectors/
│   │   │   │       ├── __init__.py
│   │   │   │       ├── kerberoasting.py
│   │   │   │       ├── asrep.py
│   │   │   │       ├── acl.py
│   │   │   │       ├── delegation.py
│   │   │   │       ├── adcs.py
│   │   │   │       └── credentials.py
│   │   │   │
│   │   │   ├── ai/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py       # AI engine
│   │   │   │   ├── prompts.py      # Prompt templates
│   │   │   │   ├── chains.py       # LangChain chains
│   │   │   │   └── tools.py        # Agent tools
│   │   │   │
│   │   │   └── reporting/
│   │   │       ├── __init__.py
│   │   │       ├── generator.py
│   │   │       ├── templates.py
│   │   │       └── exporters.py
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── scan.py
│   │   │   ├── finding.py
│   │   │   ├── graph.py
│   │   │   └── report.py
│   │   │
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── scan.py
│   │   │   ├── finding.py
│   │   │   ├── graph.py
│   │   │   └── report.py
│   │   │
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── logger.py
│   │       ├── validators.py
│   │       └── helpers.py
│   │
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── api/
│   │   ├── core/
│   │   └── fixtures/
│   │
│   └── scripts/
│       ├── init_db.py
│       ├── seed_data.py
│       └── setup_neo4j.py
│
├── frontend/
│   ├── public/
│   │   ├── index.html
│   │   └── favicon.ico
│   ├── src/
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   ├── index.css
│   │   │
│   │   ├── components/
│   │   │   ├── ui/                # Reusable UI components
│   │   │   ├── dashboard/
│   │   │   ├── findings/
│   │   │   ├── graph/
│   │   │   ├── chat/
│   │   │   └── report/
│   │   │
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Findings.tsx
│   │   │   ├── Graph.tsx
│   │   │   ├── Chat.tsx
│   │   │   ├── Reports.tsx
│   │   │   └── Settings.tsx
│   │   │
│   │   ├── hooks/
│   │   │   ├── useAuth.ts
│   │   │   ├── useScans.ts
│   │   │   ├── useFindings.ts
│   │   │   ├── useGraph.ts
│   │   │   └── useChat.ts
│   │   │
│   │   ├── services/
│   │   │   ├── api.ts
│   │   │   ├── websocket.ts
│   │   │   └── auth.ts
│   │   │
│   │   ├── stores/
│   │   │   ├── authStore.ts
│   │   │   ├── scanStore.ts
│   │   │   └── uiStore.ts
│   │   │
│   │   ├── types/
│   │   │   ├── index.ts
│   │   │   ├── finding.ts
│   │   │   ├── scan.ts
│   │   │   ├── graph.ts
│   │   │   └── report.ts
│   │   │
│   │   └── utils/
│   │       ├── formatters.ts
│   │       └── validators.ts
│   │
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── .env.example
│
├── lab/
│   ├── docker-compose.yml
│   ├── scripts/
│   │   ├── setup_lab.sh
│   │   ├── provision_ad.sh
│   │   └── cleanup.sh
│   └── configs/
│       ├── domain.json
│       └── users.ldif
│
└── docs/
    ├── architecture.md
    ├── api.md
    ├── deployment.md
    └── troubleshooting.md
```

### 8.2 Database Schema

```sql
-- PostgreSQL Schema

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    target_domain VARCHAR(255) NOT NULL,
    target_ips CIDR[],
    status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    settings JSONB DEFAULT '{}'
);

-- Findings table
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    risk_score FLOAT,
    affected_assets TEXT[],
    evidence JSONB,
    proof_of_concept TEXT,
    impact TEXT,
    remediation TEXT,
    references TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Attack paths table
CREATE TABLE attack_paths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    source_node VARCHAR(255) NOT NULL,
    target_node VARCHAR(255) NOT NULL,
    path_type VARCHAR(50) NOT NULL,
    hops INTEGER NOT NULL,
    nodes JSONB NOT NULL,
    relationships JSONB NOT NULL,
    risk_score FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Reports table
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    template VARCHAR(100) DEFAULT 'default',
    sections JSONB,
    file_path VARCHAR(500),
    format VARCHAR(20) DEFAULT 'pdf',
    status VARCHAR(20) DEFAULT 'generating',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Chat history table
CREATE TABLE chat_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan tool results (raw data)
CREATE TABLE tool_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    tool_name VARCHAR(100) NOT NULL,
    raw_output TEXT,
    parsed_data JSONB,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 8.3 Neo4j Graph Schema

```cypher
// Neo4j Graph Schema

// Node types
CREATE CONSTRAINT IF NOT EXISTS FOR (n:User) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Computer) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Group) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Domain) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:OU) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:GPO) REQUIRE n.name IS UNIQUE;

// Relationship types
// MemberOf - User/Computer belongs to Group
// HasSession - Computer has logged on User
// AdminTo - User/Computer has admin rights on Computer
// CanRDP - User can RDP to Computer
// ExecuteDCOM - User can execute via DCOM
// AllowedToDelegate - User/Computer can be delegated
// WriteDacl - User can modify ACL
// GenericAll - User has full control
// GenericWrite - User can write properties
// Owns - User owns object
// Contains - OU contains objects
// HasGPO - OU linked to GPO
// AppliedTo - GPO applied to OU/Computer
```

---

## 9. Technology Stack

### 9.1 Backend Technologies

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Primary language |
| FastAPI | 0.109+ | REST API framework |
| SQLAlchemy | 2.0+ | ORM |
| Pydantic | 2.5+ | Data validation |
| Uvicorn | 0.27+ | ASGI server |
| python-jose | 3.3+ | JWT tokens |
| passlib | 1.7+ | Password hashing |
| python-multipart | 0.0+ | File uploads |

### 9.2 Security Tools

| Tool | Purpose | Integration |
|------|---------|-------------|
| Responder | LLMNR/NBT-NS poisoning | Subprocess |
| Impacket | SMB/LDAP/Kerberos | Python library |
| LDAP3 | LDAP enumeration | Python library |
| BloodHound | AD graph collection | SharpHound exe |
| Nmap | Network scanning | Subprocess |
| CrackMapExec | Multi-protocol exploitation | Subprocess |
| Hashcat | Password cracking | Subprocess |

### 9.3 AI Technologies

| Technology | Purpose |
|------------|---------|
| LangChain | LLM orchestration |
| Ollama | Local LLM |
| ChromaDB | Vector store |
| LangSmith | Monitoring |

### 9.4 Database Technologies

| Technology | Purpose |
|------------|---------|
| PostgreSQL 15 | Relational data |
| Neo4j 5.x | Graph database |
| Redis | Caching/queue |
| SQLAlchemy | ORM |

### 9.5 Frontend Technologies

| Technology | Purpose |
|------------|---------|
| React 18 | UI framework |
| TypeScript | Type safety |
| Vite | Build tool |
| Tailwind CSS | Styling |
| D3.js | Graph visualization |
| React Query | Data fetching |
| Zustand | State management |
| React Router | Navigation |

---

## 10. Expected Results

### 10.1 Functional Deliverables

| Deliverable | Description | Priority |
|-------------|-------------|----------|
| Scan Engine | Automated AD reconnaissance and enumeration | P0 |
| Vulnerability Detection | Detection of 15+ AD vulnerabilities | P0 |
| Attack Path Analysis | Graph-based attack path visualization | P0 |
| Risk Scoring | Automated risk prioritization | P0 |
| Report Generator | PDF/HTML report generation | P0 |
| AI Assistant | Chat interface for pentest guidance | P1 |
| Dashboard | Web-based monitoring interface | P1 |
| AD Graph | Interactive AD topology visualization | P1 |

### 10.2 Vulnerability Coverage

| Vulnerability | Detection Method | Severity |
|---------------|------------------|----------|
| Kerberoasting | LDAP + TGS request | CRITICAL |
| AS-REP Roasting | LDAP userAccountControl | CRITICAL |
| Unconstrained Delegation | LDAP + DC analysis | HIGH |
| Constrained Delegation | LDAP delegation check | HIGH |
| RBCD | LDAP + computer attributes | HIGH |
| Weak Passwords | Password policy + spray | HIGH |
| Dangerous ACLs | BloodHound ACL analysis | HIGH |
| ADCS ESC1-ESC8 | CA enumeration + template analysis | CRITICAL |
| Pass-the-Hash | Credential analysis | HIGH |
| Golden Ticket | KRBTGT analysis | CRITICAL |
| DCSync | Domain replication analysis | CRITICAL |
| Privilege Escalation | Attack path analysis | HIGH |

### 10.3 Performance Targets

| Metric | Target |
|--------|--------|
| Scan completion | < 2 hours for medium domain |
| API response time | < 500ms |
| Graph rendering | < 2 seconds for 1000 nodes |
| Report generation | < 30 seconds |
| AI response time | < 10 seconds |

---

## 11. PFE Report Structure

### Chapter 1: Introduction
- 1.1 Context and motivation
- 1.2 Problem statement
- 1.3 Objectives
- 1.4 Scope of work
- 1.5 Report structure

### Chapter 2: State of the Art
- 2.1 Active Directory overview
- 2.2 AD security vulnerabilities
- 2.3 Traditional pentesting methodology
- 2.4 Automation in cybersecurity
- 2.5 AI in penetration testing
- 2.6 Existing tools and platforms
- 2.7 Comparative analysis

### Chapter 3: Active Directory Security
- 3.1 AD architecture and components
- 3.2 Authentication protocols (Kerberos, NTLM)
- 3.3 AD attack vectors
- 3.4 Common vulnerabilities
- 3.5 Security best practices

### Chapter 4: Penetration Testing Methodology
- 4.1 Pentest phases (recon, enum, exploit, reporting)
- 4.2 AD-specific techniques
- 4.3 Tools and frameworks
- 4.4 Documentation standards
- 4.5 Legal and ethical considerations

### Chapter 5: Proposed Architecture
- 5.1 System architecture overview
- 5.2 Component design
- 5.3 Data flow
- 5.4 Technology stack
- 5.5 Integration approach

### Chapter 6: Implementation
- 6.1 Development environment
- 6.2 Core modules implementation
- 6.3 AI engine integration
- 6.4 Database design
- 6.5 API development
- 6.6 Frontend development

### Chapter 7: Laboratory Testing
- 7.1 Test environment setup
- 7.2 AD lab configuration
- 7.3 Test scenarios
- 7.4 Validation methodology
- 7.5 Test results

### Chapter 8: Results and Analysis
- 8.1 Vulnerability detection results
- 8.2 Attack path analysis
- 8.3 Performance metrics
- 8.4 AI effectiveness evaluation
- 8.5 Comparison with manual testing

### Chapter 9: Discussion
- 9.1 Strengths of the solution
- 9.2 Limitations and challenges
- 9.3 Comparison with objectives
- 9.4 Ethical considerations
- 9.5 Lessons learned

### Chapter 10: Conclusion and Perspectives
- 10.1 Summary of contributions
- 10.2 Future work
- 10.3 Potential improvements
- 10.4 Industry impact

### Appendices
- A: Installation guide
- B: User manual
- C: API documentation
- D: Configuration files
- E: Raw test results
- F: Code snippets
- G: Glossary

---

## 12. Presentation Structure

### Slide 1: Title Slide
- Project title
- Student name and institution
- Date
- Advisor name

### Slide 2: Context & Problem
- Current pentesting challenges
- Time consumption
- Human error risks
- Inconsistency issues

### Slide 3: Objectives
- Automate AD pentesting
- AI-powered analysis
- Attack path visualization
- Automated reporting

### Slide 4: Architecture Overview
- System diagram
- Main components
- Technology stack

### Slide 5: Pipeline
- Reconnaissance phase
- Enumeration phase
- Analysis phase
- Reporting phase

### Slide 6: Vulnerability Detection
- Kerberoasting
- AS-REP Roasting
- ACL abuse
- Delegation attacks
- ADCS vulnerabilities

### Slide 7: AI Integration
- LLM for analysis
- Prompt engineering
- Chat assistant
- Report generation

### Slide 8: Attack Path Analysis
- Graph-based visualization
- Paths to Domain Admin
- Critical path identification

### Slide 9: Demonstration
- Live demo of platform
- Show key features
- Walk through workflow

### Slide 10: Results
- Vulnerabilities found
- Performance metrics
- Comparison with manual testing

### Slide 11: Generated Report
- Sample report sections
- Executive summary
- Technical details

### Slide 12: Limitations
- Scope constraints
- Technical limitations
- Ethical boundaries

### Slide 13: Future Work
- Additional vulnerabilities
- Enhanced AI capabilities
- Integration possibilities

### Slide 14: Conclusion
- Key takeaways
- Project value
- Thank you

### Slide 15: Q&A
- Questions
- Contact information

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
- [ ] Set up development environment
- [ ] Configure PostgreSQL and Neo4j
- [ ] Create FastAPI project structure
- [ ] Implement authentication

### Phase 2: Core Engine (Week 3-5)
- [ ] Implement network reconnaissance
- [ ] Build LDAP enumeration module
- [ ] Integrate Responder
- [ ] Add SharpHound collection

### Phase 3: Analysis (Week 6-8)
- [ ] Create vulnerability detectors
- [ ] Implement risk scoring
- [ ] Build attack path analysis
- [ ] Integrate with Neo4j

### Phase 4: AI Engine (Week 9-10)
- [ ] Set up Ollama/LLM
- [ ] Implement LangChain chains
- [ ] Build chat interface
- [ ] Create report generation

### Phase 5: Frontend (Week 11-12)
- [ ] Build React dashboard
- [ ] Implement graph visualization
- [ ] Create report viewer
- [ ] Add real-time updates

### Phase 6: Testing (Week 13-14)
- [ ] Lab environment setup
- [ ] Integration testing
- [ ] Performance testing
- [ ] Documentation

---

*Document Version: 1.0*  
*Last Updated: April 2026*  
*Author: PentestAI-AD Project Team*