from langchain_chroma import Chroma
from langchain_gigachat.embeddings.gigachat import GigaChatEmbeddings
from chromadb.config import Settings

class SemanticDB:
    def __init__(self, embeddings, documents=None):
        self.db = Chroma(
            embedding_function=embeddings,
            client_settings=Settings(anonymized_telemetry=False))
        if documents:
            self.add_documents(documents)
    
    def add_documents(self, documents):
        self.db.add_texts(documents)
    
    def search(self, query: str, k: int = 3) -> list:
        docs = self.db.similarity_search(query, k=k)
        return [doc.page_content for doc in docs]