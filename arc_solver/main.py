"""
FastAPI application and routers for ARC Solver API.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from loguru import logger

from .config import load_config
from .models import (
    ARCTask, ARCGrid, ARCPair, Workspace, WorkspaceStatus,
    CandidateSolution, SolveResponse, APIResponse
)
from .services.orchestrator import get_orchestrator

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class CreateWorkspaceRequest(BaseModel):
    task: ARCTask
    strategy: Optional[str] = None

class SolveRequest(BaseModel):
    task_id: str
    train_pairs: List[Dict[str, Any]]
    test_inputs: List[List[List[int]]]
    strategy: Optional[str] = None

class QuickSolveRequest(BaseModel):
    """Simplified request format."""
    train: List[Dict[str, List[List[int]]]]  # [{"input": [[...]], "output": [[...]]}]
    test: List[List[List[int]]]              # [[[...]]]
    task_id: Optional[str] = "anonymous"

# ============================================================================
# APP FACTORY
# ============================================================================

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    cfg = load_config()
    
    app = FastAPI(
        title="ARC Solver Unified",
        description="ARC-AGI solver using multi-provider LLMs, MCTS, and critic meta-reasoning",
        version="1.0.0",
    )
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(workspace_router, prefix="/api/v1/workspaces", tags=["workspaces"])
    app.include_router(solve_router, prefix="/api/v1/solve", tags=["solve"])
    app.include_router(health_router, tags=["health"])
    
    return app

# ============================================================================
# ROUTERS
# ============================================================================

from fastapi import APIRouter

# Health Router
health_router = APIRouter()

@health_router.get("/healthz")
async def health_check():
    return {"status": "ok", "version": "1.0.0"}

@health_router.get("/readyz")
async def ready_check():
    cfg = load_config()
    providers = [p for p, c in cfg.providers.items() if c.enabled and c.api_key]
    return {
        "status": "ready" if providers else "degraded",
        "providers_available": providers
    }

# Workspace Router
workspace_router = APIRouter()

@workspace_router.post("/", response_model=Workspace)
async def create_workspace(request: CreateWorkspaceRequest):
    """Create a new solving workspace."""
    orchestrator = get_orchestrator()
    ws = orchestrator.create_workspace(request.task, request.strategy)
    return ws

@workspace_router.get("/{workspace_id}", response_model=Workspace)
async def get_workspace(workspace_id: str):
    """Get workspace status and details."""
    orchestrator = get_orchestrator()
    ws = orchestrator.get_workspace(workspace_id)
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws

@workspace_router.post("/{workspace_id}/solve", response_model=Workspace)
async def solve_workspace(workspace_id: str):
    """Start solving the task in the workspace."""
    orchestrator = get_orchestrator()
    ws = orchestrator.get_workspace(workspace_id)
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    try:
        result = await orchestrator.solve(workspace_id)
        return result
    except Exception as e:
        logger.error(f"Solve failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@workspace_router.get("/{workspace_id}/cot")
async def get_cot_log(workspace_id: str):
    """Get the chain-of-thought log for a workspace."""
    orchestrator = get_orchestrator()
    cot = orchestrator.get_cot_log(workspace_id)
    if not cot:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return cot.to_dict()

# Solve Router (convenience endpoints)
solve_router = APIRouter()

@solve_router.post("/", response_model=SolveResponse)
async def solve_task(request: SolveRequest):
    """Solve a task directly (creates workspace and solves)."""
    # Convert to ARCTask
    train_pairs = []
    for pair in request.train_pairs:
        inp = ARCGrid.from_list(pair["input"])
        out = ARCGrid.from_list(pair["output"])
        train_pairs.append(ARCPair(input=inp, output=out))
    
    test_inputs = [ARCGrid.from_list(t) for t in request.test_inputs]
    
    task = ARCTask(
        task_id=request.task_id,
        train_pairs=train_pairs,
        test_inputs=test_inputs
    )
    
    orchestrator = get_orchestrator()
    ws = orchestrator.create_workspace(task, request.strategy)
    
    try:
        ws = await orchestrator.solve(ws.workspace_id)
        cot = orchestrator.get_cot_log(ws.workspace_id)
        
        return SolveResponse(
            workspace_id=ws.workspace_id,
            task_id=task.task_id,
            solved=ws.is_solved,
            predictions=ws.predictions,
            prediction_confidences=ws.prediction_confidences,
            confidence=cot.best_score if cot else 0.0,
            metrics=ws.metrics,
            best_candidate_ids=ws.best_candidate_ids
        )
    except Exception as e:
        logger.error(f"Solve failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@solve_router.post("/quick", response_model=SolveResponse)
async def quick_solve(request: QuickSolveRequest):
    """Quick solve with simplified input format."""
    train_pairs = []
    for pair in request.train:
        inp = ARCGrid.from_list(pair["input"])
        out = ARCGrid.from_list(pair["output"])
        train_pairs.append(ARCPair(input=inp, output=out))
    
    test_inputs = [ARCGrid.from_list(t) for t in request.test]
    
    task = ARCTask(
        task_id=request.task_id or "anonymous",
        train_pairs=train_pairs,
        test_inputs=test_inputs
    )
    
    orchestrator = get_orchestrator()
    ws = orchestrator.create_workspace(task)
    
    try:
        ws = await orchestrator.solve(ws.workspace_id)
        cot = orchestrator.get_cot_log(ws.workspace_id)
        
        return SolveResponse(
            workspace_id=ws.workspace_id,
            task_id=task.task_id,
            solved=ws.is_solved,
            predictions=ws.predictions,
            prediction_confidences=ws.prediction_confidences,
            confidence=cot.best_score if cot else 0.0,
            metrics=ws.metrics,
            best_candidate_ids=ws.best_candidate_ids
        )
    except Exception as e:
        logger.error(f"Solve failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# MAIN APP
# ============================================================================

app = create_app()

if __name__ == "__main__":
    import uvicorn
    cfg = load_config()
    uvicorn.run(
        "arc_solver.main:app",
        host=cfg.app.host,
        port=cfg.app.port,
        reload=cfg.app.debug
    )
