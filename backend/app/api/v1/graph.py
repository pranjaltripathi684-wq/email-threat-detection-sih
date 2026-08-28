from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.services.correlation_engine import get_full_correlation_graph

router = APIRouter(prefix="/graph", tags=["Correlation Graph"])


@router.get("/correlation")
def get_graph_data(db: Session = Depends(get_db)):
    """
    Returns full network graph (nodes, edges, connected campaign clusters, and centrality metrics)
    for interactive visual rendering in Cytoscape.js or Canvas.
    """
    return get_full_correlation_graph(db)
