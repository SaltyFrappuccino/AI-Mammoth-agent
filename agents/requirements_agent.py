# agents/requirements_agent.py
from agents.base_agent import BaseAgent

class RequirementsAgent(BaseAgent):
    def __init__(self, semantic_db=None):
        system_prompt = (
            "Ты профессиональный аналитик требований. Проанализируй предоставленный текст задачи и выдели ключевые требования. "
            "Используй дополнительную информацию из базы знаний для уточнения требований."
        )
        super().__init__("RequirementsAgent", system_prompt)
        self.semantic_db = semantic_db

    def call(self, input_text: str) -> str:
        if self.semantic_db:
            relevant_info = self.semantic_db.search(input_text, k=3)
            input_text += "\n\nДополнительная информация из базы знаний:\n" + "\n".join(relevant_info)
        return super().call(input_text)