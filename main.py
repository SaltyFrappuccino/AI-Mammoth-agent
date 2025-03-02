from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import random
from aggregator import Aggregator
from semantic_db import SemanticDB
from config import embeddings

app = FastAPI()

class AnalysisRequest(BaseModel):
    requirements: str
    code: str
    test_cases: str
    documentation: str = ""
    semantic_db: Dict 

class AnalysisResponse(BaseModel):
    final_report: str
    bugs_count: int
    bugs_explanations: str

def perform_analysis(requirements: str, code: str, test_cases: str, documentation: str, semantic_db: Dict) -> tuple:
    documents = semantic_db.get("documents", [])
    semantic_db_instance = SemanticDB(embeddings=embeddings, documents=documents)
    
    aggregator = Aggregator(semantic_db=semantic_db_instance)
    
    final_report, bug_estimation = aggregator.aggregate(
        requirements_text=requirements,
        code_text=code,
        test_cases_text=test_cases,
        documentation_text=documentation
    )
    return final_report, bug_estimation

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    try:
        final_report, bug_estimation = perform_analysis(
            requirements=request.requirements,
            code=request.code,
            test_cases=request.test_cases,
            documentation=request.documentation,
            semantic_db=request.semantic_db
        )
        return {
            "final_report": final_report, 
            "bugs_count": bug_estimation["bug_count"],
            "bugs_explanations": bug_estimation["explanations"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при выполнении анализа: {str(e)}")
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
    