"""
AI Engine - LangChain Integration for AD Pentest Analysis
"""
import asyncio
from typing import List, Dict, Any, Optional
from uuid import UUID

from langchain.llms import Ollama
from langchain.chains import ConversationalRetrievalChain, LLMChain
from langchain.prompts import PromptTemplate
from langchain.schema import HumanMessage, SystemMessage
from langchain.memory import ConversationBufferMemory
from langchain.tools import Tool

from app.config import settings
from app.database import SessionLocal, get_neo4j
from app.models.finding import Finding
from app.models.scan import Scan


class AIEngine:
    """AI-powered analysis engine using LangChain and Ollama"""
    
    def __init__(self):
        # Initialize Ollama LLM
        self.llm = Ollama(
            base_url=settings.OLLAMA_BASE_URL,
            model=settings.OLLAMA_MODEL,
            temperature=0.7
        )
        
        # Define custom prompts
        self.system_prompt = self._get_system_prompt()
        self.analysis_prompt = self._get_analysis_prompt()
        
        # Initialize tools
        self.tools = self._initialize_tools()
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for the AI assistant"""
        return """You are an expert cybersecurity analyst specializing in Active Directory security assessments.
        
You have deep knowledge of:
- Active Directory attack techniques (Kerberoasting, AS-REP Roasting, ACL attacks, delegation attacks)
- AD CS vulnerabilities and exploitation
- BloodHound attack path analysis
- Privilege escalation in Windows environments
- Remediation strategies for AD security issues

You help analyze pentest findings, explain attack paths, and provide actionable remediation advice.
Always provide accurate, security-focused recommendations based on the findings provided.

When analyzing, consider:
1. The severity and exploitability of each finding
2. The context of the AD environment
3. Potential attack chains and privilege escalation paths
4. Practical remediation steps that balance security and usability"""
    
    def _get_analysis_prompt(self) -> PromptTemplate:
        """Get prompt template for finding analysis"""
        return PromptTemplate(
            template="""Analyze the following security finding from an Active Directory pentest:

Finding: {title}
Severity: {severity}
Category: {category}
Description: {description}
Affected Target: {target}
Evidence: {evidence}

Provide:
1. A detailed explanation of the vulnerability
2. How an attacker could exploit this
3. Potential impact if exploited
4. Prioritized remediation steps
5. Related attack techniques that could be chained

Focus on actionable, practical advice.""",
            input_variables=["title", "severity", "category", "description", "target", "evidence"]
        )
    
    def _initialize_tools(self) -> List[Tool]:
        """Initialize LangChain tools"""
        return [
            Tool(
                name="analyze_finding",
                func=self._analyze_finding_sync,
                description="Analyze a security finding and provide detailed explanation and remediation"
            ),
            Tool(
                name="find_attack_paths",
                func=self._find_attack_paths_sync,
                description="Find attack paths from a source to target in the AD environment"
            ),
            Tool(
                name="explain_concept",
                func=self._explain_concept_sync,
                description="Explain a cybersecurity concept or attack technique"
            ),
            Tool(
                name="prioritize_findings",
                func=self._prioritize_findings_sync,
                description="Prioritize security findings based on risk and business impact"
            )
        ]
    
    async def chat(
        self,
        message: str,
        scan_id: Optional[UUID] = None,
        history: List[Dict[str, str]] = None
    ) -> str:
        """Process chat message and return AI response"""
        
        # Build context from scan data if provided
        context = ""
        if scan_id:
            context = await self._build_scan_context(scan_id)
        
        # Build full prompt with context
        full_prompt = f"{self.system_prompt}\n\nContext:\n{context}\n\nUser Question: {message}"
        
        # Get response from LLM
        response = await self._get_llm_response(full_prompt, history)
        
        return response
    
    async def _build_scan_context(self, scan_id: UUID) -> str:
        """Build context from scan data"""
        db = SessionLocal()
        
        try:
            # Get scan info
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return ""
            
            # Get findings
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            
            # Build context string
            context = f"""
Scan: {scan.name}
Target Domain: {scan.target_domain}
Status: {scan.status}

Findings Summary:
- Critical: {sum(1 for f in findings if f.severity == 'critical')}
- High: {sum(1 for f in findings if f.severity == 'high')}
- Medium: {sum(1 for f in findings if f.severity == 'medium')}
- Low: {sum(1 for f in findings if f.severity == 'low')}

Top Findings:
"""
            for f in findings[:10]:  # Top 10 findings
                context += f"- [{f.severity.upper()}] {f.title}: {f.description[:100]}...\n"
            
            return context
            
        finally:
            db.close()
    
    async def _get_llm_response(self, prompt: str, history: List[Dict] = None) -> str:
        """Get response from LLM"""
        loop = asyncio.get_event_loop()
        
        def _call_llm():
            messages = [SystemMessage(content=self.system_prompt)]
            
            # Add history
            if history:
                for msg in history[-5:]:  # Last 5 messages
                    if msg["role"] == "user":
                        messages.append(HumanMessage(content=msg["content"]))
                    else:
                        messages.append(SystemMessage(content=msg["content"]))
            
            # Add current message
            messages.append(HumanMessage(content=prompt))
            
            return self.llm.invoke(messages)
        
        return await loop.run_in_executor(None, _call_llm)
    
    async def analyze_finding(self, finding_id: UUID) -> str:
        """Analyze a specific finding"""
        db = SessionLocal()
        
        try:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                return "Finding not found"
            
            # Build prompt
            prompt = self.analysis_prompt.format(
                title=finding.title,
                severity=finding.severity,
                category=finding.category,
                description=finding.description or "",
                target=finding.affected_target or "Unknown",
                evidence=str(finding.evidence)
            )
            
            # Get response
            response = await self._get_llm_response(prompt)
            
            return response
            
        finally:
            db.close()
    
    async def find_attack_paths(
        self,
        scan_id: UUID,
        source: str = None,
        target: str = None
    ) -> List[Dict[str, Any]]:
        """Find attack paths in AD environment"""
        neo4j = get_neo4j()
        
        if source and target:
            query = """
            MATCH path = (start:ADObject {scan_id: $scan_id, name: $source})
                -[*1..5]->
                (end:ADObject {scan_id: $scan_id, name: $target})
            RETURN path, length(path) as path_length
            ORDER BY path_length
            LIMIT 10
            """
            params = {"scan_id": str(scan_id), "source": source, "target": target}
        else:
            # Find critical paths
            query = """
            MATCH path = (start:ADObject {scan_id: $scan_id})
                -[*1..5]->
                (end:ADObject {scan_id: $scan_id})
            WHERE start.high_value = true OR end.sensitive = true
            RETURN path, length(path) as path_length
            ORDER BY path_length
            LIMIT 20
            """
            params = {"scan_id": str(scan_id)}
        
        paths = []
        with neo4j.session() as session:
            result = session.run(query, **params)
            
            for record in result:
                path = record["path"]
                nodes = [dict(n) for n in path.nodes]
                rels = [r.type for r in path.relationships]
                
                paths.append({
                    "nodes": nodes,
                    "relationships": rels,
                    "length": record["path_length"]
                })
        
        return paths
    
    async def prioritize_findings(self, scan_id: UUID) -> List[Dict[str, Any]]:
        """Prioritize findings based on risk score"""
        db = SessionLocal()
        
        try:
            findings = db.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.status != "false_positive"
            ).all()
            
            # Sort by risk score
            prioritized = []
            for f in findings:
                score = self._calculate_priority_score(f)
                prioritized.append({
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "risk_score": f.risk_score,
                    "priority_score": score,
                    "recommendation": self._get_priority_recommendation(score)
                })
            
            # Sort by priority score
            prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
            
            return prioritized
            
        finally:
            db.close()
    
    def _calculate_priority_score(self, finding: Finding) -> int:
        """Calculate priority score for a finding"""
        severity_weights = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10
        }
        
        base = severity_weights.get(finding.severity, 0)
        
        # Adjust for exploitability
        if finding.evidence and finding.evidence.get("exploitable"):
            base += 20
        
        # Adjust for network exposure
        if finding.evidence and finding.evidence.get("exposed"):
            base += 10
        
        return min(base, 150)
    
    def _get_priority_recommendation(self, score: int) -> str:
        """Get recommendation based on priority score"""
        if score >= 100:
            return "Immediate action required - critical vulnerability"
        elif score >= 75:
            return "High priority - address within 1 week"
        elif score >= 50:
            return "Medium priority - address within 1 month"
        elif score >= 25:
            return "Low priority - address during regular maintenance"
        else:
            return "Informational - review during next assessment"
    
    # Synchronous versions for Tool usage
    def _analyze_finding_sync(self, finding_data: str) -> str:
        """Synchronous analyze finding"""
        # This would be called by LangChain tools
        return "Analysis not implemented in sync mode"
    
    def _find_attack_paths_sync(self, params: str) -> str:
        """Synchronous find attack paths"""
        return "Attack path analysis not implemented in sync mode"
    
    def _explain_concept_sync(self, concept: str) -> str:
        """Synchronous explain concept"""
        return "Concept explanation not implemented in sync mode"
    
    def _prioritize_findings_sync(self, scan_id: str) -> str:
        """Synchronous prioritize findings"""
        return "Prioritization not implemented in sync mode"