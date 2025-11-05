import os
import json
import time
import logging
from dotenv import load_dotenv
from huggingface_hub import InferenceClient
from requests.exceptions import RequestException

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


class HuggingFaceClient:
    """High-level Hugging Face API client using InferenceClient."""

    def __init__(self, api_key=None, model="openai/gpt-oss-120b", provider="groq"):
        self.api_key = api_key or os.getenv("HF_TOKEN")
        if not self.api_key:
            raise ValueError("Hugging Face API key is required. Set HF_TOKEN environment variable.")
        
        self.model = model
        self.provider = provider
        self.client = InferenceClient(provider=provider, api_key=self.api_key)

    def generate(self, prompt, system_prompt=None, retries=3, temperature=0.7, max_tokens=2000):
        """Generate text completion with retry and structured output."""

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        for attempt in range(retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens
                )

                text = response.choices[0].message.content.strip()
                json_data = self._extract_json(text)

                return {
                    "success": True,
                    "text": text,
                    "json": json_data
                }

            except RequestException as e:
                logger.warning(f"Request attempt {attempt + 1}/{retries} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(5)
                else:
                    logger.error("Max retries reached. Generation failed.")
                    return {"success": False, "error": str(e)}
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                return {"success": False, "error": str(e)}

    def _extract_json(self, text):
        """Extract and parse JSON from text if present."""
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start != -1 and end > start:
                return json.loads(text[start:end])
        except json.JSONDecodeError:
            logger.debug("No valid JSON found in model output.")
        return None


if __name__ == "__main__":
    # Example usage
    client = HuggingFaceClient()
    result = client.generate("List 3 benefits of using containerization in DevOps.")
    print(result["text"])
