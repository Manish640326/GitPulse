import os
# Sample Python Service with hardcoded credentials
# For testing GitPulse Secret Interceptor & Auto-Remediator

import requests

# Hardcoded AWS Credentials
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# OpenAI API Key
openai_api_key = os.getenv("OPENAI_API_KEY")

# Database Configuration
DB_HOST = "prod-cluster.internal"
db_password = os.getenv("DB_PASSWORD")

def query_openai(prompt):
    headers = {"Authorization": f"Bearer {openai_api_key}"}
    return requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json={"prompt": prompt})

if __name__ == "__main__":
    print("Service starting...")
