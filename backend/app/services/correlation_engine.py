import json
import networkx as nx
from typing import Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from app.db.models import (
    Email, ReceivedHop, EmailUrl, EmailAttachment, Case, Campaign,
    GraphEntity, GraphRelationship, Indicator
)


def build_and_sync_email_graph(db: Session, email_id: int) -> Dict[str, Any]:
    """
    Builds and syncs graph nodes and edges for a specific email and updates
    the graph entity repository in the database.
    """
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        return {"nodes": [], "edges": []}

    nodes_to_add = []
    edges_to_add = []

    # 1. Email Node
    email_key = f"email:{email.id}"
    nodes_to_add.append({
        "id": email_key,
        "type": "Email",
        "label": f"Email #{email.id}: {email.raw_subject or 'No Subject'}"[:40],
        "risk": email.total_risk_score,
        "classification": email.risk_classification
    })

    # 2. Sender Node
    if email.raw_from:
        sender_key = f"sender:{email.raw_from.strip()}"
        nodes_to_add.append({
            "id": sender_key,
            "type": "Sender",
            "label": email.raw_from[:40]
        })
        edges_to_add.append({
            "source": email_key,
            "target": sender_key,
            "relationship": "SENT_FROM"
        })

    # 3. Domain Node
    if email.sender_domain:
        domain_key = f"domain:{email.sender_domain}"
        nodes_to_add.append({
            "id": domain_key,
            "type": "Domain",
            "label": email.sender_domain
        })
        if email.raw_from:
            edges_to_add.append({
                "source": f"sender:{email.raw_from.strip()}",
                "target": domain_key,
                "relationship": "BELONGS_TO_DOMAIN"
            })

    # 4. Earliest Public IP and Hop IPs
    hops = db.query(ReceivedHop).filter(ReceivedHop.email_id == email.id).all()
    for hop in hops:
        if hop.extracted_ip:
            ip_key = f"ip:{hop.extracted_ip}"
            nodes_to_add.append({
                "id": ip_key,
                "type": "IP",
                "label": f"{hop.extracted_ip} ({hop.ip_classification})",
                "is_public": hop.ip_classification == "Public",
                "geo": hop.geo_country or "Unknown"
            })
            edges_to_add.append({
                "source": email_key,
                "target": ip_key,
                "relationship": "DELIVERED_THROUGH",
                "hop_order": hop.hop_order
            })

    # 5. URLs
    urls = db.query(EmailUrl).filter(EmailUrl.email_id == email.id).all()
    for u in urls:
        url_key = f"url:{u.raw_url[:60]}"
        nodes_to_add.append({
            "id": url_key,
            "type": "URL",
            "label": u.raw_url[:40],
            "risk": u.risk_score
        })
        edges_to_add.append({
            "source": email_key,
            "target": url_key,
            "relationship": "LINKS_TO"
        })

    # 6. Attachment Hashes
    attachments = db.query(EmailAttachment).filter(EmailAttachment.email_id == email.id).all()
    for att in attachments:
        hash_key = f"hash:{att.sha256_hash[:16]}"
        nodes_to_add.append({
            "id": hash_key,
            "type": "AttachmentHash",
            "label": f"{att.filename} ({att.sha256_hash[:8]}...)",
            "risk": att.risk_score
        })
        edges_to_add.append({
            "source": email_key,
            "target": hash_key,
            "relationship": "CONTAINS_ATTACHMENT"
        })

    # 7. Case Node (if assigned)
    if email.case_id:
        case_key = f"case:{email.case_id}"
        nodes_to_add.append({
            "id": case_key,
            "type": "Case",
            "label": f"Case #{email.case_id}"
        })
        edges_to_add.append({
            "source": email_key,
            "target": case_key,
            "relationship": "LINKED_TO_CASE"
        })

    # Deduplicate and save to database
    for node in nodes_to_add:
        existing = db.query(GraphEntity).filter(GraphEntity.entity_key == node["id"]).first()
        if not existing:
            ge = GraphEntity(
                entity_type=node["type"],
                entity_key=node["id"],
                label=node["label"],
                properties_json=json.dumps(node)
            )
            db.add(ge)

    for edge in edges_to_add:
        existing_rel = db.query(GraphRelationship).filter(
            GraphRelationship.source_entity_key == edge["source"],
            GraphRelationship.target_entity_key == edge["target"],
            GraphRelationship.relationship_type == edge["relationship"]
        ).first()
        if not existing_rel:
            gr = GraphRelationship(
                source_entity_key=edge["source"],
                target_entity_key=edge["target"],
                relationship_type=edge["relationship"],
                weight=1.0,
                properties_json=json.dumps(edge)
            )
            db.add(gr)

    db.commit()

    return {"nodes": nodes_to_add, "edges": edges_to_add}


def get_full_correlation_graph(db: Session) -> Dict[str, Any]:
    """
    Constructs a NetworkX graph of all entities and relationships across all emails,
    computing connected components (campaign clusters) and centrality metrics.
    """
    entities = db.query(GraphEntity).all()
    relationships = db.query(GraphRelationship).all()

    G = nx.Graph()

    nodes_list = []
    for ent in entities:
        props = json.loads(ent.properties_json or "{}")
        G.add_node(ent.entity_key, type=ent.entity_type, label=ent.label)
        nodes_list.append({
            "id": ent.entity_key,
            "type": ent.entity_type,
            "label": ent.label,
            "properties": props
        })

    edges_list = []
    for rel in relationships:
        props = json.loads(rel.properties_json or "{}")
        G.add_edge(rel.source_entity_key, rel.target_entity_key, relationship=rel.relationship_type)
        edges_list.append({
            "id": f"{rel.source_entity_key}->{rel.target_entity_key}",
            "source": rel.source_entity_key,
            "target": rel.target_entity_key,
            "relationship": rel.relationship_type,
            "weight": rel.weight
        })

    # Graph metrics
    clusters = []
    if len(G.nodes) > 0:
        connected = list(nx.connected_components(G))
        for idx, comp in enumerate(connected, start=1):
            if len(comp) > 1:
                subgraph = G.subgraph(comp)
                clusters.append({
                    "cluster_id": f"CAMPAIGN-CLUSTER-{idx:02d}",
                    "node_count": len(comp),
                    "nodes": list(comp),
                    "density": round(nx.density(subgraph), 3)
                })

        degree_centrality = nx.degree_centrality(G)
        for node in nodes_list:
            node["centrality"] = round(degree_centrality.get(node["id"], 0.0), 3)

    return {
        "nodes": nodes_list,
        "edges": edges_list,
        "total_nodes": len(nodes_list),
        "total_edges": len(edges_list),
        "campaign_clusters": clusters,
        "disclaimer": "Graph relationships indicate observed infrastructure links and shared IoCs. They do not constitute legal proof of common operator ownership."
    }
