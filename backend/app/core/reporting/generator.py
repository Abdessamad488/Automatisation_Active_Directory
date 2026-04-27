"""
Report Generator Module
"""
import asyncio
import json
from datetime import datetime
from typing import Dict, Any, Optional
from uuid import UUID
from pathlib import Path

from app.database import SessionLocal
from app.models.scan import Scan
from app.models.finding import Finding


class ReportGenerator:
    """Generate pentest reports in various formats"""
    
    def __init__(self, scan_id: Optional[UUID] = None):
        self.output_dir = Path("/tmp/pentest_reports")
        self.output_dir.mkdir(exist_ok=True)
        self.scan_id = scan_id
    
    async def generate(
        self,
        scan_id: UUID,
        format: str = "pdf",
        template: str = "standard"
    ) -> str:
        """Generate report for a scan"""
        
        # Gather scan data
        data = await self._gather_scan_data(scan_id)
        
        # Generate based on format
        if format == "json":
            return await self._generate_json(data, scan_id)
        elif format == "markdown":
            return await self._generate_markdown(data, scan_id)
        elif format == "html":
            return await self._generate_html(data, scan_id)
        elif format == "pdf":
            return await self._generate_pdf(data, scan_id)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def _gather_scan_data(self, scan_id: UUID) -> Dict[str, Any]:
        """Gather all data for the report"""
        db = SessionLocal()
        
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            
            # Group findings by severity and category
            by_severity = {}
            by_category = {}
            
            for f in findings:
                by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
                by_category[f.category] = by_category.get(f.category, 0) + 1
            
            return {
                "scan": {
                    "id": str(scan.id),
                    "name": scan.name,
                    "target_domain": scan.target_domain,
                    "status": scan.status,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration": self._calculate_duration(scan)
                },
                "findings": {
                    "total": len(findings),
                    "by_severity": by_severity,
                    "by_category": by_category,
                    "items": [
                        {
                            "id": str(f.id),
                            "title": f.title,
                            "description": f.description,
                            "severity": f.severity,
                            "category": f.category,
                            "status": f.status,
                            "affected_target": f.affected_target,
                            "remediation": f.remediation,
                            "risk_score": f.risk_score
                        }
                        for f in findings
                    ]
                },
                "executive_summary": self._generate_executive_summary(findings),
                "risk_assessment": self._generate_risk_assessment(findings)
            }
            
        finally:
            db.close()
    
    def _calculate_duration(self, scan: Scan) -> str:
        """Calculate scan duration"""
        if scan.started_at and scan.completed_at:
            duration = scan.completed_at - scan.started_at
            hours, remainder = divmod(int(duration.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{hours}h {minutes}m {seconds}s"
        return "N/A"
    
    def _generate_executive_summary(self, findings: list) -> Dict[str, Any]:
        """Generate executive summary"""
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        
        overall_risk = "Critical" if critical > 0 else "High" if high > 0 else "Medium" if medium > 0 else "Low"
        
        return {
            "total_findings": len(findings),
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "overall_risk": overall_risk,
            "key_findings": [
                f.title for f in findings if f.severity in ["critical", "high"]
            ][:5]
        }
    
    def _generate_risk_assessment(self, findings: list) -> Dict[str, Any]:
        """Generate risk assessment"""
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        
        total_score = sum(
            severity_weights.get(f.severity, 0)
            for f in findings
            if f.status != "false_positive"
        )
        
        return {
            "total_risk_score": total_score,
            "risk_level": "Critical" if total_score >= 50 else "High" if total_score >= 25 else "Medium" if total_score >= 10 else "Low",
            "remediation_effort": "High" if total_score >= 40 else "Medium" if total_score >= 20 else "Low"
        }
    
    async def _generate_json(self, data: Dict, scan_id: UUID) -> str:
        """Generate JSON report"""
        output_file = self.output_dir / f"report_{scan_id}.json"
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        return str(output_file)
    
    async def _generate_markdown(self, data: Dict, scan_id: UUID) -> str:
        """Generate Markdown report"""
        output_file = self.output_dir / f"report_{scan_id}.md"
        
        md_content = f"""# PentestAI-AD Security Assessment Report

## Executive Summary

- **Scan Name**: {data['scan']['name']}
- **Target Domain**: {data['scan']['target_domain']}
- **Assessment Date**: {data['scan']['created_at']}
- **Overall Risk Level**: {data['executive_summary']['overall_risk']}

### Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {data['executive_summary']['critical_count']} |
| High | {data['executive_summary']['high_count']} |
| Medium | {data['executive_summary']['medium_count']} |
| **Total** | {data['executive_summary']['total_findings']} |

## Risk Assessment

- **Total Risk Score**: {data['risk_assessment']['total_risk_score']}
- **Risk Level**: {data['risk_assessment']['risk_level']}
- **Remediation Effort**: {data['risk_assessment']['remediation_effort']}

## Findings

"""
        
        # Add findings by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        for severity in severity_order:
            severity_findings = [
                f for f in data['findings']['items']
                if f['severity'] == severity
            ]
            
            if severity_findings:
                md_content += f"### {severity.upper()} Severity\n\n"
                
                for finding in severity_findings:
                    md_content += f"""#### {finding['title']}

**Category**: {finding['category']}
**Target**: {finding['affected_target']}
**Status**: {finding['status']}

{finding['description'] or 'No description provided.'}

**Remediation**: {finding['remediation'] or 'No remediation provided.'}

---

"""
        
        with open(output_file, 'w') as f:
            f.write(md_content)
        
        return str(output_file)
    
    async def _generate_html(self, data: Dict, scan_id: UUID) -> str:
        """Generate HTML report"""
        output_file = self.output_dir / f"report_{scan_id}.html"
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {data['scan']['name']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }}
        .critical {{ border-color: #d32f2f; background: #ffebee; }}
        .high {{ border-color: #f57c00; background: #fff3e0; }}
        .medium {{ border-color: #fbc02d; background: #fffde7; }}
        .low {{ border-color: #388e3c; background: #e8f5e9; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Scan Name:</strong> {data['scan']['name']}</p>
        <p><strong>Target Domain:</strong> {data['scan']['target_domain']}</p>
        <p><strong>Assessment Date:</strong> {data['scan']['created_at']}</p>
        <p><strong>Overall Risk Level:</strong> {data['executive_summary']['overall_risk']}</p>
        
        <h3>Findings Summary</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td>Critical</td><td>{data['executive_summary']['critical_count']}</td></tr>
            <tr><td>High</td><td>{data['executive_summary']['high_count']}</td></tr>
            <tr><td>Medium</td><td>{data['executive_summary']['medium_count']}</td></tr>
        </table>
    </div>
    
    <h2>Findings</h2>
"""
        
        # Add findings
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        for severity in severity_order:
            severity_findings = [
                f for f in data['findings']['items']
                if f['severity'] == severity
            ]
            
            for finding in severity_findings:
                html_content += f"""
    <div class="finding {severity}">
        <h3>{finding['title']}</h3>
        <p><strong>Category:</strong> {finding['category']}</p>
        <p><strong>Target:</strong> {finding['affected_target']}</p>
        <p><strong>Description:</strong> {finding['description'] or 'N/A'}</p>
        <p><strong>Remediation:</strong> {finding['remediation'] or 'N/A'}</p>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return str(output_file)
    
    async def _generate_pdf(self, data: Dict, scan_id: UUID) -> str:
        """Generate PDF report (placeholder - requires additional libraries)"""
        # For PDF generation, you would use libraries like:
        # - reportlab
        # - weasyprint (HTML to PDF)
        # - fpdf
        
        # For now, generate HTML and return that path
        # In production, convert HTML to PDF
        return await self._generate_html(data, scan_id)

    async def generate_full_report(
        self,
        scan_id: UUID,
        recon_data: Dict[str, Any],
        enum_data: Dict[str, Any],
        vuln_data: Dict[str, Any],
        exploit_data: Dict[str, Any],
        ai_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate complete pentest report for Phase 7
        Includes all 7 phases data with evidence and AI analysis
        """
        
        print("[*] Generating complete pentest report...")
        
        db = SessionLocal()
        
        try:
            # Fetch scan data
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            
            # Calculate severity counts
            critical = sum(1 for f in findings if f.severity == "critical")
            high = sum(1 for f in findings if f.severity == "high")
            medium = sum(1 for f in findings if f.severity == "medium")
            low = sum(1 for f in findings if f.severity == "low")
            
            # Successful exploits
            exploits = exploit_data.get("exploits", [])
            successful_exploits = sum(1 for e in exploits if e.get("success"))
            
            # Build comprehensive markdown report
            md_content = f"""# Rapport de Pentest - {scan.target_domain if scan else 'pentestlab.local'}

**Date:** {datetime.now().strftime('%d/%m/%Y')}  
**Version:** 1.0  
**Classification:** Confidentiel

---

## 1. Résumé Exécutif

### Vue d'ensemble
Ce rapport présente les résultats d'un test d'intrusion automatisé effectué sur l'infrastructure 
Active Directory **{scan.target_domain if scan else 'pentestlab.local'}**.

### Périmètre
- **Domaine:** {scan.target_domain if scan else 'pentestlab.local'}
- **Contrôleur de domaine:** 192.168.142.128
- **Date du test:** {scan.created_at.strftime('%d/%m/%Y') if scan and scan.created_at else datetime.now().strftime('%d/%m/%Y')}
- **Type de test:** {scan.scan_type if scan else 'blackbox'}

### Résumé des résultats

| Métrique | Valeur |
|----------|--------|
| Vulnérabilités critiques | {critical} |
| Vulnérabilités élevées | {high} |
| Vulnérabilités moyennes | {medium} |
| Vulnérabilités basses | {low} |
| Exploits réussis | {successful_exploits} |

---

## 2. Méthodologie

### Pipeline en 7 phases

| Phase | Description | Outils |
|-------|-------------|--------|
| 1. Reconnaissance | Découverte réseau passive | Nmap, Responder, netexec |
| 2. Énumération | Collecte objets AD | Kerbrute, ldap3, PowerView, SharpHound |
| 3. Analyse données | Stockage et traitement | Neo4j, PostgreSQL |
| 4. Détection vulnérabilités | Identification automatique | DetectionEngine (12 checks) |
| 5. Exploitation | Exécution attaques | Impacket, GodPotato, mitm6 |
| 6. Analyse IA | Analyse intelligente | Ollama + LangChain |
| 7. Rapport | Génération rapport | Jinja2, WeasyPrint |

---

## 3. Périmètre et Cibles

| Type | Adresse IP | Rôle |
|------|------------|------|
| DC | 192.168.142.128 | Contrôleur de domaine |
| Cible | 192.168.142.134 | Station de travail |
| Attacker | 192.168.142.131 | Machine de test |

---

## 4. Findings Techniques

"""
            
            # Add findings by severity
            severity_order = ["critical", "high", "medium", "low"]
            
            for severity in severity_order:
                severity_findings = [f for f in findings if f.severity == severity]
                
                if severity_findings:
                    md_content += f"### {severity.upper()}\n\n"
                    
                    for i, finding in enumerate(severity_findings, 1):
                        md_content += f"""
#### {i}. {finding.title}

**Description:** {finding.description or 'N/A'}

**Impact:** {finding.impact or 'N/A'}

**Cible:** {finding.affected_target or 'N/A'}

**Remédiation:** {finding.remediation or 'N/A'}

---
"""
            
            # Add evidence section
            md_content += """
## 5. Preuves d'Exploitation

"""
            
            for exploit in exploits:
                if exploit.get("success"):
                    md_content += f"""
### {exploit.get('attack', 'Attack')}

**Cible:** {exploit.get('target', 'N/A')}

**Outil:** {exploit.get('tool', 'N/A')}

**Résultat:**
```
{exploit.get('evidence', 'Exécution réussie')}
```

**Impact:** {exploit.get('impact', 'N/A')}

---
"""
            
            # Add AI analysis section
            if ai_analysis and ai_analysis.get("recommendations"):
                md_content += """
## 6. Analyse par Intelligence Artificielle

### Recommandations IA

"""
                for rec in ai_analysis.get("recommendations", [])[:5]:
                    md_content += f"""
- **{rec.get('title', 'N/A')}**: {rec.get('description', '')}
"""
            
            # Add remediation section
            md_content += """
## 7. Plan de Remédiation

### Priorités immédiates (0-7 jours)

| Vulnérabilité | Action | Complexité |
|---------------|--------|------------|
| Kerberoasting | Configurer msDS-SupportedEncryptionTypes | Moyenne |
| AS-REP Roasting | Activer Kerberos pre-auth | Faible |
| Passwords in description | Supprimer mots de passe des descriptions | Faible |
| SMB Signing | Activer SMB signing | Moyenne |
| Unconstrained Delegation | Désactiver si non nécessaire | Moyenne |

### Actions court terme (7-30 jours)

1. **Implémenter LCS (Least Privilege)**
2. **Sécuriser AD CS**
3. **Déployer monitoring**

### Actions long terme (30-90 jours)

1. **Modernisation authentification** (FIDO2/WebAuthn)
2. **Segmentation réseau**
3. **Formation sensibilisation**

---

*Rapport généré par PentestAI-AD*
"""
            
            # Write report
            output_file = self.output_dir / f"pentest_report_{scan_id}.md"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(md_content)
            
            print(f"[+] Report generated: {output_file}")
            
            return {
                "path": str(output_file),
                "format": "markdown",
                "sections": ["Résumé exécutif", "Méthodologie", "Périmètre", "Findings", "Preuves", "Analyse IA", "Remédiation"],
                "scan_id": str(scan_id)
            }
            
        finally:
            db.close()