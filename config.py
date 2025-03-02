# config.py
import os
import getpass
from dotenv import load_dotenv, find_dotenv
from langchain_gigachat.embeddings.gigachat import GigaChatEmbeddings

load_dotenv(find_dotenv())

if "AUTH_KEY" not in os.environ:
    os.environ["AUTH_KEY"] = getpass.getpass("Введите ключ авторизации GigaChat API: ")

if "AUTH_URL" not in os.environ:
    os.environ["AUTH_URL"] = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
    
if "GIGA_URL" not in os.environ:
    os.environ["GIGA_URL"] = "https://gigachat.devices.sberbank.ru/api/v1"

AUTH_KEY = os.environ["AUTH_KEY"]
AUTH_URL = os.environ["AUTH_URL"]
GIGA_URL = os.environ['GIGA_URL']
PORT = int(os.environ.get("PORT", 8080))

from langchain_gigachat.chat_models import GigaChat

llm = GigaChat(
    credentials="Y2JkYzY3ZTUtMjg2Ny00ODJkLWE1ZTYtYmE4MTliMWZkNjVhOjlhZTRiM2UyLWZhZGUtNDNhMy04MjQ0LWFjNDBhMTQxYzRmYw==",
    scope="GIGACHAT_API_PERS",
    model="GigaChat-Max",
    verify_ssl_certs=False,
    auth_url="https://sm-auth-sd.prom-88-89-apps.ocp-geo.ocp.sigma.sbrf.ru/api/v2/oauth",
    base_url=GIGA_URL,
)

embeddings = GigaChatEmbeddings(
    credentials="Y2JkYzY3ZTUtMjg2Ny00ODJkLWE1ZTYtYmE4MTliMWZkNjVhOjlhZTRiM2UyLWZhZGUtNDNhMy04MjQ0LWFjNDBhMTQxYzRmYw==",
    verify_ssl_certs=False,
    scope="GIGACHAT_API_PERS"
)