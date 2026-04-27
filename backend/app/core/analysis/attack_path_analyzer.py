"""
Attack Path Analysis Module
Analyzes AD graph to find privilege escalation paths
"""
import asyncio
from typing import Dict, Any, List, Optional
from uuid import UUID
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_neo4j
from app.models import AttackPath


class AttackPathAnalyzer:
    """
    Attack Path Analysis Engine
    
    Analyzes AD relationships to find:
    - Shortest paths to Domain Admin
    - Critical attack paths
    - Privilege escalation chains
    - Dependencies and chokepoints
    """
    
    def __init__(self, scan_id: UUID):
        self.scan_id = scan_id
        self.db = SessionLocal()
        self.neo4j = get_neo4j()
    
    async def analyze_paths(self) -> List[Dict[str, Any]]:
        """
        Analyze all attack paths
        
        Returns:
            List of attack paths with details
        """
        print("[*] Analyzing attack paths...")
        
        paths = []
        
        # Find paths to Domain Admin
        da_paths = await self._find_paths_to_domain_admin()
        paths.extend(da_paths)
        
        # Find paths to Enterprise Admin
        ea_paths = await self._find_paths_to_enterprise_admin()
        paths.extend(ea_paths)
        
        # Find critical paths (shortest)
        critical_paths = await self._find_critical_paths()
        paths.extend(critical_paths)
        
        # Find delegation-based paths
        delegation_paths = await self._find_delegation_paths()
        paths.extend(delegation_paths)
        
        # Store paths in database
        await self._store_paths(paths)
        
        print(f"[+] Found {len(paths)} attack paths")
        
        self.db.close()
        return paths
    
    async def _find_paths_to_domain_admin(self) -> List[Dict[str, Any]]:
        """Find paths to Domain Admin group"""
        paths = []
        
        query = """
        MATCH path = (u:User)-[:memberOf*1..3]->(g:Group {name: 'Domain Admins'})
        WHERE u.scanId = $scan_id
        RETURN path, length(path) as hops
        ORDER BY hops
        LIMIT 10
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, scan_id=str(self.scan_id))
            
            for record in result:
                path = record.get("path")
                hops = record.get("hops")
                
                nodes = []
                for node in path.nodes:
                    nodes.append({
                        "name": node.get("samAccountName", node.get("name", "Unknown")),
                        "type": list(node.labels)[0] if node.labels else "Unknown",
                        "properties": dict(node)
                    })
                
                paths.append({
                    "name": f"Path to Domain Admin ({hops} hops)",
                    "description": f"User can become Domain Admin through {hops} group memberships",
                    "source_object": nodes[0].get("name") if nodes else "Unknown",
                    "target_object": "Domain Admins",
                    "path_type": "privilege_escalation",
                    "nodes": nodes,
                    "complexity": "low" if hops <= 2 else "medium",
                    "impact_score": 10,
                    "final_score": 10 - hops
                })
        
        return paths
    
    async def _find_paths_to_enterprise_admin(self) -> List[Dict[str, Any]]:
        """Find paths to Enterprise Admin group"""
        paths = []
        
        query = """
        MATCH path = (u:User)-[:memberOf*1..4]->(g:Group)
        WHERE g.name IN ['Enterprise Admins', 'Schema Admins'] AND u.scanId = $scan_id
        RETURN path, length(path) as hops
        ORDER BY hops
        LIMIT 5
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, scan_id=str(self.scan_id))
            
            for record in result:
                path = record.get("path")
                hops = record.get("hops")
                
                nodes = []
                for node in path.nodes:
                    nodes.append({
                        "name": node.get("samAccountName", node.get("name", "Unknown")),
                        "type": list(node.labels)[0] if node.labels else "Unknown",
                        "properties": dict(node)
                    })
                
                paths.append({
                    "name": f"Path to Enterprise/Schema Admin ({hops} hops)",
                    "description": f"User can become Enterprise/Schema Admin through {hops} group memberships",
                    "source_object": nodes[0].get("name") if nodes else "Unknown",
                    "target_object": "Enterprise/Schema Admins",
                    "path_type": "privilege_escalation",
                    "nodes": nodes,
                    "complexity": "medium",
                    "impact_score": 10,
                    "final_score": 10 - hops
                })
        
        return paths
    
    async def _find_critical_paths(self) -> List[Dict[str, Any]]:
        """Find critical/shorthand attack paths"""
        paths = []
        
        # Find users who are members of privileged groups
        query = """
        MATCH (u:User)-[:memberOf]->(g:Group)
        WHERE g.isPrivileged = true AND u.scanId = $scan_id
        RETURN u.samAccountName as user, collect(g.name) as groups
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, scan_id=str(self.scan_id))
            
            for record in result:
                user = record.get("user")
                groups = record.get("groups", [])
                
                if user and groups:
                    paths.append({
                        "name": f"Direct privileged access: {user}",
                        "description": f"User has direct membership in: {', '.join(groups)}",
                        "source_object": user,
                        "target_object": ", ".join(groups),
                        "path_type": "direct_access",
                        "nodes": [{"name": user, "type": "User"}, {"name": groups[0], "type": "Group"}],
                        "complexity": "low",
                        "impact_score": 10,
                        "final_score": 10
                    })
        
        return paths
    
    async def _find_delegation_paths(self) -> List[Dict[str, Any]]:
        """Find delegation-based attack paths"""
        paths = []
        
        # Unconstrained delegation
        query_unconstrained = """
        MATCH (u:User)-[:hasSession]->(c:Computer)
        WHERE c.trustedForDelegation = true AND u.scanId = $scan_id
        RETURN u.samAccountName as user, c.samAccountName as computer
        """
        
        with self.neo4j.session() as session:
            result = session.run(query_unconstrained, scan_id=str(self.scan_id))
            
            for record in result:
                user = record.get("user")
                computer = record.get("computer")
                
                if user and computer:
                    paths.append({
                        "name": f"Unconstrained Delegation: {computer}",
                        "description": f"User {user} has sessions on {computer} which has unconstrained delegation. TGT can be captured.",
                        "source_object": user,
                        "target_object": computer,
                        "path_type": "delegation",
                        "nodes": [
                            {"name": user, "type": "User"},
                            {"name": computer, "type": "Computer", "delegation": "unconstrained"}
                        ],
                        "complexity": "medium",
                        "impact_score": 9,
                        "final_score": 8
                    })
        
        # RBCD paths
        query_rbcd = """
        MATCH (attacker:Computer)<-[:CanPSRemote]-(u:User)
        WHERE attacker.delegationType = 'rbcd' AND u.scanId = $scan_id
        RETURN u.samAccountName as user, attacker.samAccountName as computer
        """
        
        with self.neo4j.session() as session:
            result = session.run(query_rbcd, scan_id=str(self.scan_id))
            
            for record in result:
                user = record.get("user")
                computer = record.get("computer")
                
                if user and computer:
                    paths.append({
                        "name": f"RBCD Attack: {computer}",
                        "description": f"User {user} can abuse RBCD on {computer} to execute code as any user.",
                        "source_object": user,
                        "target_object": computer,
                        "path_type": "delegation",
                        "nodes": [
                            {"name": user, "type": "User"},
                            {"name": computer, "type": "Computer", "delegation": "rbcd"}
                        ],
                        "complexity": "medium",
                        "impact_score": 8,
                        "final_score": 7
                    })
        
        return paths
    
    async def _store_paths(self, paths: List[Dict[str, Any]]):
        """Store attack paths in database"""
        
        for path_data in paths:
            path = AttackPath(
                scan_id=self.scan_id,
                name=path_data["name"],
                description=path_data.get("description"),
                source_object=path_data["source_object"],
                target_object=path_data["target_object"],
                path_type=path_data["path_type"],
                nodes=path_data.get("nodes", []),
                edges=path_data.get("edges", []),
                complexity=path_data.get("complexity", "medium"),
                impact_score=path_data.get("impact_score", 5),
                final_score=path_data.get("final_score", 5)
            )
            self.db.add(path)
        
        self.db.commit()
        print(f"[+] Stored {len(paths)} attack paths in database")
    
    async def get_shortest_path(self, source: str, target: str) -> Optional[Dict[str, Any]]:
        """Get shortest path between two objects"""
        
        query = """
        MATCH path = shortestPath((source {samAccountName: $source})-[*..10]->(target {name: $target}))
        RETURN path, length(path) as hops
        """
        
        with self.neo4j.session() as session:
            result = session.run(query, source=source, target=target)
            
            record = result.single()
            if record:
                path = record.get("path")
                hops = record.get("hops")
                
                nodes = []
                for node in path.nodes:
                    nodes.append({
                        "name": node.get("samAccountName", node.get("name")),
                        "type": list(node.labels)[0] if node.labels else "Unknown"
                    })
                
                return {
                    "source": source,
                    "target": target,
                    "hops": hops,
                    "nodes": nodes
                }
        
        return None


# Quick test function
async def test_attack_paths():
    """Test attack path analysis"""
    from uuid import uuid4
    
    scan_id = uuid4()
    analyzer = AttackPathAnalyzer(scan_id)
    
    paths = await analyzer.analyze_paths()
    
    print("\n" + "="*50)
    print("ATTACK PATH ANALYSIS RESULTS")
    print("="*50)
    
    for path in paths:
        print(f"\n[{path['path_type']}] {path['name']}")
        print(f"  Source: {path['source_object']} -> Target: {path['target_object']}")
        print(f"  Complexity: {path['complexity']}, Score: {path['final_score']}")
    
    return paths


if __name__ == "__main__":
    asyncio.run(test_attack_paths())