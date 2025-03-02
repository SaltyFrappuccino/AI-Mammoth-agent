# agents/semantic_agent.py
class SemanticAgent:
    def __init__(self, semantic_db):
        self.semantic_db = semantic_db

    def query_service(self, service_name: str) -> str:
        description = self.semantic_db.query(service_name)
        return f"{service_name}: {description}"
