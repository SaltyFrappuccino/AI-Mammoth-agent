# agents/requirements_agent.py
from agents.base_agent import BaseAgent
import logging

logger = logging.getLogger("requirements_agent")

class RequirementsAgent(BaseAgent):
    def __init__(self, semantic_db=None):
        system_prompt = """
        Ты профессиональный аналитик требований, специализирующийся на API и серверных приложениях. 
        Твоя задача - проанализировать текст требований, структурировать их и подготовить для детального 
        анализа соответствия кода этим требованиям.
        
        Для каждого требования:
        1. Присвой ему уникальный идентификатор (REQ-1, REQ-2, и т.д.)
        2. Определи тип требования: 
           - Функциональное (что система должна делать)
           - Нефункциональное (как система должна работать)
           - Интеграционное (взаимодействие с другими системами)
           - Безопасность (аутентификация, авторизация, защита данных)
        3. Оцени приоритет требования (критический, высокий, средний, низкий)
        4. Определи, что конкретно должно быть в коде для выполнения этого требования
        5. Если требование касается API, укажи потенциальные эндпоинты и методы запросов
        
        Структурируй вывод следующим образом:
        
        ## Сводка требований
        
        Общее количество требований: [число]
        - Функциональных: [число]
        - Нефункциональных: [число]
        - Интеграционных: [число]
        - Безопасности: [число]
        
        ## Детализированные требования
        
        ### REQ-1: [Краткое название]
        
        **Тип**: [Тип требования]
        **Приоритет**: [Приоритет]
        **Описание**: [Оригинальный текст требования]
        **Ожидаемая реализация**: [Что конкретно должно быть в коде]
        **API эндпоинты**: [Если применимо, предполагаемые эндпоинты]
        
        ### REQ-2: [Краткое название]
        ...
        
        ## Матрица зависимостей требований
        
        [Укажи, какие требования зависят друг от друга]
        
        ВАЖНО: 
        1. Будь максимально конкретным при описании ожидаемой реализации.
        2. Уделяй особое внимание API-требованиям, детально описывая необходимые эндпоинты, методы и данные.
        3. Не добавляй несуществующих требований, работай только с информацией из предоставленного текста.
        4. Для REST API четко различай между требованиями к бэкенду (серверной части) и фронтенду (клиентской части).
        """
        super().__init__("RequirementsAgent", system_prompt)
        self.semantic_db = semantic_db

    def call(self, input_text: str) -> str:
        if self.semantic_db:
            try:
                # Ограничиваем количество возвращаемых документов и их размер
                relevant_info = self.semantic_db.search(input_text, k=2)
                
                # Ограничиваем размер каждого документа для добавления
                max_doc_length = 500
                trimmed_docs = []
                
                for doc in relevant_info:
                    if len(doc) > max_doc_length:
                        # Берем только начало документа, если он слишком большой
                        trimmed_doc = doc[:max_doc_length] + "... [сокращено для оптимизации]"
                        trimmed_docs.append(trimmed_doc)
                    else:
                        trimmed_docs.append(doc)
                
                # Добавляем релевантные документы с ограниченным объемом
                context = "\n\nДополнительная информация из базы знаний (только наиболее релевантная часть):\n" + "\n---\n".join(trimmed_docs)
                
                # Проверяем общий размер контекста
                max_total_context = 2000
                if len(context) > max_total_context:
                    logger.warning(f"Контекст слишком большой ({len(context)} символов), ограничиваем до {max_total_context}")
                    context = context[:max_total_context] + "... [оставшаяся часть сокращена]"
                
                input_text += context
                logger.info(f"Требования с контекстом: {len(input_text)} символов")
            
            except Exception as e:
                logger.error(f"Ошибка при добавлении семантического контекста: {str(e)}")
                # Продолжаем работу с исходным текстом, если не удалось добавить контекст
        
        return super().call(input_text)