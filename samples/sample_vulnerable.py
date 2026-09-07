# Sample Python Service with hardcoded credentials
# For testing GitPulse Secret Interceptor & Auto-Remediator

import requests

# Hardcoded AWS Credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# OpenAI API Key
openai_api_key = "sk-proj-abc1234567890def1234567890ghi1234567890"

# Database Configuration
DB_HOST = "prod-cluster.internal"
db_password = "d41d8cd98f00b204e9800998ecf8427e"

def query_openai(prompt):
    headers = {"Authorization": f"Bearer {openai_api_key}"}
    return requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json={"prompt": prompt})

if __name__ == "__main__":
    print("Service starting...")
