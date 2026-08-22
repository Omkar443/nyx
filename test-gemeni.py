from google import genai
import os

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("GEMINI_API_KEY not set in this process")
    exit(1)

client = genai.Client(api_key=api_key)

try:
    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents="Say OK"
    )
    print("SUCCESS:", response.text)
except Exception as e:
    print("REAL EXCEPTION TYPE:", type(e).__name__)
    print("REAL EXCEPTION MESSAGE:", str(e))