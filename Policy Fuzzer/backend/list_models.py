import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
c = Groq(api_key=os.getenv("GROQ_API_KEY"))
for m in sorted(c.models.list().data, key=lambda x: x.id):
    print(m.id)