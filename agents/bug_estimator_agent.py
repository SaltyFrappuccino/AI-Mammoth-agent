# agents/bug_estimator_agent.py
from agents.base_agent import BaseAgent
from langchain_core.messages import HumanMessage, SystemMessage
from config import llm

class BugEstimatorAgent(BaseAgent):
    def __init__(self):
        system_prompt = (
            "Ты эксперт по оценке качества кода. Проанализируй требования и код, "
            "предскажи количество потенциальных багов (несоответствий требованиям). "
            "Для каждого потенциального бага опиши его суть, причину возникновения и рекомендации по исправлению. "
            "Структурируй ответ следующим образом:\n"
            "Количество багов: [число от 0 до 10]\n\n"
            "Объяснения:\n"
            "1. [Описание первого бага, его причины и рекомендации]\n"
            "2. [Описание второго бага, его причины и рекомендации]\n"
            "И так далее для каждого потенциального бага."
        )
        super().__init__("BugEstimatorAgent", system_prompt)
        
    def estimate_bugs(self, requirements: str, code_analysis: str) -> dict:
        analysis_text = (
            "Требования:\n" + requirements + "\n\n" +
            "Анализ кода:\n" + code_analysis + "\n\n" +
            "Предскажи количество багов и опиши каждый из них согласно указанному формату:"
        )
        
        messages = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=analysis_text)
        ]
        
        response = llm.invoke(messages)
        response_content = response.content.strip()
        
        # Разбор ответа
        try:
            lines = response_content.split('\n')
            count_line = next((line for line in lines if line.startswith('Количество багов:')), '')
            bug_count = int(count_line.split(':')[1].strip()) if count_line else 0
            
            # Извлечение объяснений
            explanations_start = response_content.find('Объяснения:')
            explanations = response_content[explanations_start:] if explanations_start != -1 else ""
            
            return {
                "bug_count": bug_count,
                "explanations": explanations
            }
        except:
            return {
                "bug_count": 0,
                "explanations": "Не удалось определить баги"
            }

bug_estimator_schema = {
    "name": "estimate_potential_bugs",
    "description": "Оценка количества потенциальных багов на основе анализа требований и кода",
    "parameters": {
        "type": "object",
        "properties": {
            "requirements": {"type": "string", "description": "Текст требований"},
            "code_analysis": {"type": "string", "description": "Анализ кода"}
        },
        "required": ["requirements", "code_analysis"]
    },
    "return_parameters": {
        "type": "object",
        "properties": {
            "bug_count": {"type": "integer", "description": "Предполагаемое количество багов"},
            "explanations": {"type": "string", "description": "Объяснения для каждого потенциального бага"}
        },
        "required": ["bug_count", "explanations"]
    }
}