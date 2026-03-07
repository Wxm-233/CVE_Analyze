# llm_safe.py
import os
import json
from openai import OpenAI  # 按你环境使用的 SDK 调整
from typing import Optional

SYSTEM_MESSAGE = """
You are a professional Linux developer and Linux analyzer.
Respond with strict JSON as requested in the prompt. No extra commentary.
"""

class LLMQuery:
    def __init__(self, api_key_env="OPENAI_API_KEY", base_url=None):
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise EnvironmentError(f"Please set environment variable {api_key_env} with your API key.")
        # 通过环境变量 OPENAI_BASE_URL 提供内部 base_url
        base_url = base_url or os.environ.get("OPENAI_BASE_URL", None)
        # 初始化客户端
        if base_url:
            self.client = OpenAI(api_key=api_key, base_url=base_url)
        else:
            self.client = OpenAI(api_key=api_key)
        self.max_tokens = 4096

    def analyze_by_LLM(self, content: str, prompt_prefix: str = "", max_allowed_tokens_for_content: int = 3000) -> Optional[dict]:
        """
        发送分析请求，期望 LLM 返回 JSON。会尝试 parse JSON 并返回 dict。
        对 content 做简单截断（以字符数为近似）。
        """
        # 截断 content（简单策略：字符截断）
        if len(content) > max_allowed_tokens_for_content:
            content = content[:max_allowed_tokens_for_content] + "\n\n/* TRUNCATED FOR TOKEN LIMIT */\n"
        user_message = prompt_prefix + "\n\n" + content
        try:
            resp = self.client.chat.completions.create(
                model="DeepSeek-V3.2-Instruct",
                messages=[
                    {"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=1024,
                temperature=0.0
            )
            text = resp.choices[0].message.content.strip()
            # 尝试把 text 当成 JSON parse
            try:
                parsed = json.loads(text)
                return parsed
            except json.JSONDecodeError:
                # 如果不是严格 JSON，可尝试从中抽出 {...}
                import re
                m = re.search(r'(\{.*\})', text, flags=re.DOTALL)
                if m:
                    try:
                        return json.loads(m.group(1))
                    except:
                        return {"error": "invalid_json", "raw": text}
                return {"error": "not_json", "raw": text}
        except Exception as e:
            return {"error": "exception", "message": str(e)}