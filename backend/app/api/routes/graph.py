"""
Graph Database Routes (Neo4j)
"""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_neo4j, get_db
from app.models.user import User
from app.schemas.graph import (
    NodeResponse, EdgeResponse, GraphResponse,
    AttackPathResponse
)
from app.api.routes.auth import get_current_user

router = APIRouter()


@router.get("/nodes", response_model=List[NodeResponse])
async def get_nodes(
    scan_id: UUID,
    node_type: Optional[str] = None,
    limit: int = 1000,
    current_user: User = Depends(get_current_user)
):
    """Get AD objects as nodes"""
    driver = get_neo4j()
    
    query = """
    MATCH (n:ADObject {scan_id: $scan_id})
    """
    if node_type:
        query += f"WHERE n.type = '{node_type}' "
    query += "RETURN n LIMIT $limit"
    
    with driver.session() as session:
        result = session.run(query, scan_id=str(scan_id), limit=limit)
        nodes = [record["n"] for record in result]
    
    return [
        NodeResponse(
            id=node.get("id"),
            type=node.get("type"),
            name=node.get("name"),
            properties=node
        )
        for node in nodes
    ]


@router.get("/edges", response_model=List[EdgeResponse])
async def get_edges(
    scan_id: UUID,
    relationship_type: Optional[str] = None,
    limit: int = 2000,
    current_user: User = Depends(get_current_user)
):
    """Get relationships between AD objects"""
    driver = get_neo4j()
    
    query = """
    MATCH (a:ADObject {scan_id: $scan_id})-[r]->(b:ADObject {scan_id: $scan_id})
    """
    if relationship_type:
        query += f"WHERE type(r) = '{relationship_type}' "
    query += "RETURN a, r, b LIMIT $limit"
    
    with driver.session() as session:
        result = session.run(query, scan_id=str(scan_id), limit=limit)
        edges = []
        for record in result:
            edges.append(EdgeResponse(
                source=record["a"].get("id"),
                target=record["b"].get("id"),
                type=record["r"].type,
                properties=dict(record["r"])
            ))
    
    return edges


@router.get("/graph", response_model=GraphResponse)
async def get_graph(
    scan_id: UUID,
    node_type: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get complete graph for visualization"""
    nodes = await get_nodes(scan_id, node_type, 1000, current_user)
    edges = await get_edges(scan_id, None, 2000, current_user)
    
    return GraphResponse(nodes=nodes, edges=edges)


@router.get("/attack-paths", response_model=List[AttackPathResponse])
async def get_attack_paths(
    scan_id: UUID,
    source_node: Optional[str] = None,
    target_node: Optional[str] = None,
    max_length: int = 5,
    current_user: User = Depends(get_current_user)
):
    """Find attack paths in AD"""
    driver = get_neo4j()
    
    if source_node and target_node:
        # Find specific path
        query = """
        MATCH path = (start:ADObject {scan_id: $scan_id, id: $source_node})
            -[*1..{max_length}]->
            (end:ADObject {scan_id: $scan_id, id: $target_node})
        RETURN path, length(path) as path_length
        ORDER BY path_length
        LIMIT 10
        """
        params = {
            "scan_id": str(scan_id),
            "source_node": source_node,
            "target_node": target_node,
            "max_length": max_length
        }
    else:
        # Find all critical paths (from high privilege to sensitive targets)
        query = """
        MATCH path = (start:ADObject {scan_id: $scan_id})
            -[*1..{max_length}]->
            (end:ADObject {scan_id: $scan_id})
        WHERE start.high_value = true OR end.sensitive = true
        RETURN path, length(path) as path_length
        ORDER BY path_length
        LIMIT 20
        """
        params = {
            "scan_id": str(scan_id),
            "max_length": max_length
        }
    
    with driver.session() as session:
        result = session.run(query, **params)
        paths = []
        for record in result:
            path = record["path"]
            nodes = [dict(node) for node in path.nodes]
            relationships = [rel.type for rel in path.relationships]
            
            paths.append(AttackPathResponse(
                nodes=nodes,
                relationships=relationships,
                length=record["path_length"]
            ))
    
    return paths


@router.get("/domain-info")
async def get_domain_info(
    scan_id: UUID,
    current_user: User = Depends(get_current_user)
):
    """Get domain information"""
    driver = get_neo4j()
    
    query = """
    MATCH (d:Domain {scan_id: $scan_id})
    RETURN d
    LIMIT 1
    """
    
    with driver.session() as session:
        result = session.run(query, scan_id=str(scan_id))
        record = result.single()
        
        if not record:
            raise HTTPException(status_code=404, detail="Domain not found")
        
        return dict(record["d"])