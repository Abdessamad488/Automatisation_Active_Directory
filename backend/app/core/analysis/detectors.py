"""
Vulnerability Detectors
"""
from typing import List, Dict, Any
from uuid import UUID
from sqlalchemy.orm import Session
from app.database import SessionLocal, get_neo4j


class KerberoastingDetector:
    """Detect Kerberoasting vulnerability"""
    
    def __init__(self, scan_id: UUID):
        self.scan_id = scan_id
        self.db = SessionLocal()
        self.neo4j = get_neo4j()
    
    async def detect(self) -> List[Dict[str, Any]]:
        """Detect Kerberoasting vulnerable accounts"""
        findings = []
        
        # Query for SPN accounts in Neo4j
        query = """
        MATCH (u:ADObject {scan_id: $scan_id})
        WHERE u.serviceprincipalname IS NOT NULL
        RETURN u
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, scan_id=str(self.scan_id))
            
            for record in result:
                user = dict(record["u"])
                
                findings.append({
                    "title": f"Kerberoasting: {user.get('name')} has SPN",
                    "description": f"User account '{user.get('name')}' has a Service Principal Name (SPN) set, making it vulnerable to Kerberoasting attack. An attacker can request a TGS ticket and crack it offline to recover the account's password.",
                    "severity": "high",
                    "target": user.get("name"),
                    "evidence": {
                        "spn": user.get("serviceprincipalname"),
                        "account": user.get("name")
                    },
                    "remediation": "If the SPN is not required, remove it. If required, ensure the account uses a strong password and consider rotating it regularly. Consider using Managed Service Accounts (MSAs).",
                    "exploitable": True
                })
        
        self.db.close()
        return findings


class ASREPRoastingDetector:
    """Detect AS-REP Roasting vulnerability"""
    
    def __init__(self, scan_id: UUID):
        self.scan_id = scan_id
        self.db = SessionLocal()
        self.neo4j = get_neo4j()
    
    async def detect(self) -> List[Dict[str, Any]]:
        """Detect AS-REP Roasting vulnerable accounts"""
        findings = []
        
        # Query for accounts without pre-authentication
        query = """
        MATCH (u:ADObject {scan_id: $scan_id})
        WHERE u.dontreqpreauth = true OR u.useraccountcontrol CONTAINS 'DONT_REQ_PREAUTH'
        RETURN u
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, scan_id=str(self.scan_id))
            
            for record in result:
                user = dict(record["u"])
                
                findings.append({
                    "title": f"AS-REP Roasting: {user.get('name')} doesn't require pre-auth",
                    "description": f"User account '{user.get('name')}' does not require Kerberos pre-authentication, making it vulnerable to AS-REP Roasting. An attacker can request AS-REP tickets and crack them offline.",
                    "severity": "high",
                    "target": user.get("name"),
                    "evidence": {
                        "preauth_required": False,
                        "account": user.get("name")
                    },
                    "remediation": "Enable 'Require Kerberos pre-authentication' for all user accounts in Active Directory.",
                    "exploitable": True
                })
        
        self.db.close()
        return findings


class ACLDetector:
    """Detect ACL misconfigurations"""
    
    def __init__(self, scan_id: UUID):
        self.scan_id = scan_id
        self.db = SessionLocal()
        self.neo4j = get_neo4j()
    
    async def detect(self) -> List[Dict[str, Any]]:
        """Detect dangerous ACL configurations"""
        findings = []
        
        # Query for dangerous ACL relationships
        dangerous_acl_queries = [
            # GenericAll on user
            ("GenericAll on User", """
                MATCH ( attacker:ADObject {scan_id: $scan_id})-[r:GenericAll]->(target:ADObject {scan_id: $scan_id, type: 'user'})
                RETURN attacker, target
            """),
            # WriteDACL
            ("WriteDACL", """
                MATCH ( attacker:ADObject {scan_id: $scan_id})-[r:WriteDACL]->(target:ADObject {scan_id: $scan_id})
                RETURN attacker, target
            """),
            # Owner on sensitive objects
            ("Owner of Sensitive Object", """
                MATCH ( attacker:ADObject {scan_id: $scan_id})-[r:Owns]->(target:ADObject {scan_id: $scan_id})
                WHERE target.sensitive = true OR target.type = 'domain'
                RETURN attacker, target
            """),
            # AddMember to privileged groups
            ("AddMember to Privileged Group", """
                MATCH ( attacker:ADObject {scan_id: $scan_id})-[r:AddMember]->(target:ADObject {scan_id: $scan_id})
                WHERE target.name CONTAINS 'Admin' OR target.name CONTAINS 'Domain Admins'
                RETURN attacker, target
            """)
        ]
        
        with self.neo4j.session() as session:
            for acl_type, query in dangerous_acl_queries:
                result = session.run(query, scan_id=str(self.scan_id))
                
                for record in result:
                    attacker = dict(record["attacker"])
                    target = dict(record["target"])
                    
                    findings.append({
                        "title": f"Dangerous ACL: {attacker.get('name')} has {acl_type} on {target.get('name')}",
                        "description": f"The account '{attacker.get('name')}' has {acl_type} permission on '{target.get('name')}'. This can be exploited to escalate privileges or gain unauthorized access.",
                        "severity": "high",
                        "target": target.get("name"),
                        "evidence": {
                            "attacker": attacker.get("name"),
                            "target": target.get("name"),
                            "permission": acl_type
                        },
                        "remediation": f"Review and remove unnecessary {acl_type} permissions. Implement the principle of least privilege.",
                        "exploitable": True
                    })
        
        self.db.close()
        return findings


class DelegationDetector:
    """Detect delegation misconfigurations"""
    
    def __init__(self, scan_id: UUID):
        self.scan_id = scan_id
        self.db = SessionLocal()
        self.neo4j = get_neo4j()
    
    async def detect(self) -> List[Dict[str, Any]]:
        """Detect delegation vulnerabilities"""
        findings = []
        
        # Query for unconstrained delegation
        unconstrained_query = """
        MATCH (c:ADObject {scan_id: $scan_id})
        WHERE c.trustedfortdelegation = true OR c.useraccountcontrol CONTAINS 'TRUSTED_FOR_DELEGATION'
        RETURN c
        """
        
        # Query for constrained delegation
        constrained_query = """
        MATCH (c:ADObject {scan_id: $scan_id})
        WHERE c.trustedtodelegateto = true OR c.useraccountcontrol CONTAINS 'TRUSTED_TO_AUTH_FOR_DELEGATION'
        RETURN c
        """
        
        with self.neo4j.session() as session:
            # Check unconstrained delegation
            result = session.run(unconstrained_query, scan_id=str(self.scan_id))
            for record in result:
                computer = dict(record["c"])
                
                findings.append({
                    "title": f"Unconstrained Delegation: {computer.get('name')}",
                    "description": f"Computer '{computer.get('name')}' has unconstrained delegation enabled. This allows any user to impersonate any other user to this computer, potentially leading to privilege escalation to Domain Admin.",
                    "severity": "critical",
                    "target": computer.get("name"),
                    "evidence": {
                        "delegation_type": "unconstrained",
                        "computer": computer.get("name")
                    },
                    "remediation": "Disable unconstrained delegation unless absolutely required. If required, ensure the computer is highly secured and monitor for suspicious activity.",
                    "exploitable": True
                })
            
            # Check constrained delegation
            result = session.run(constrained_query, scan_id=str(self.scan_id))
            for record in result:
                computer = dict(record["c"])
                
                findings.append({
                    "title": f"Constrained Delegation: {computer.get('name')}",
                    "description": f"Computer '{computer.get('name')}' has constrained delegation enabled. While safer than unconstrained, this can still be exploited via S4U2Self/S4U2Proxy attacks.",
                    "severity": "high",
                    "target": computer.get("name"),
                    "evidence": {
                        "delegation_type": "constrained",
                        "computer": computer.get("name"),
                        "allowed_services": computer.get("allowedtodelegateto")
                    },
                    "remediation": "Review delegation settings and limit to only necessary services. Consider using Resource-Based Constrained Delegation (RBCD).",
                    "exploitable": True
                })
        
        self.db.close()
        return findings


class ADCSDetector:
    """Detect Active Directory Certificate Services vulnerabilities"""
    
    def __init__(self, scan_id: UUID):
        self.scan_id = scan_id
        self.db = SessionLocal()
        self.neo4j = get_neo4j()
    
    async def detect(self) -> List[Dict[str, Any]]:
        """Detect AD CS vulnerabilities"""
        findings = []
        
        # Query for AD CS endpoints
        query = """
        MATCH (c:ADObject {scan_id: $scan_id})
        WHERE c.type = 'certificationauthority' OR c.name CONTAINS 'Certificate'
        RETURN c
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, scan_id=str(self.scan_id))
            
            for record in result:
                ca = dict(record["c"])
                
                # Check for ESC1 - Template allows requester to specify SAN
                findings.append({
                    "title": f"AD CS: Certificate Authority found - {ca.get('name')}",
                    "description": f"Active Directory Certificate Services (AD CS) is present in the environment. Certificate templates should be reviewed for security misconfigurations like ESC1, ESC2, etc.",
                    "severity": "medium",
                    "target": ca.get("name"),
                    "evidence": {
                        "ca_name": ca.get("name"),
                        "type": "certification_authority"
                    },
                    "remediation": "Review certificate templates and ensure they follow security best practices. Disable dangerous template configurations.",
                    "exploitable": False
                })
        
        self.db.close()
        return findings


class PassTheHashDetector:
    """Detect Pass-The-Hash vulnerable accounts"""
    
    def __init__(self, scan_id: UUID):
        self.scan_id = scan_id
        self.db = SessionLocal()
        self.neo4j = get_neo4j()
    
    async def detect(self) -> List[Dict[str, Any]]:
        """Detect Pass-The-Hash vulnerabilities"""
        findings = []
        
        # Query for accounts with LM hash stored (weak)
        query = """
        MATCH (u:ADObject {scan_id: $scan_id})
        WHERE u.lmhash IS NOT NULL OR u.pwdhistorylength > 0
        RETURN u
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, scan_id=str(self.scan_id))
            
            for record in result:
                user = dict(record["u"])
                
                findings.append({
                    "title": f"Potential Pass-The-Hash: {user.get('name')}",
                    "description": f"User account '{user.get('name')}' may be vulnerable to Pass-The-Hash attacks. LM hash storage or password history may allow NTLM hash reuse.",
                    "severity": "medium",
                    "target": user.get("name"),
                    "evidence": {
                        "lmhash_stored": user.get("lmhash") is not None,
                        "pwd_history": user.get("pwdhistorylength")
                    },
                    "remediation": "Disable LM hash storage via Group Policy. Implement credential guard and other Windows security features.",
                    "exploitable": False
                })
        
        self.db.close()
        return findings