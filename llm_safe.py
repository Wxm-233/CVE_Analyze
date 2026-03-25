# llm_safe.py
import os
import json
import ast
from openai import OpenAI  # 按你环境使用的 SDK 调整
from typing import Optional

SYSTEM_MESSAGE = """
You are a professional Linux developer and Linux analyzer.
Respond strictly as requested in the prompt. No extra commentary.
"""

class LLMQuery:
    def __init__(self, api_key_env="OPENAI_API_KEY", base_url="https://chatbox.isrc.ac.cn/api/"):
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise EnvironmentError(f"Please set environment variable {api_key_env} with your API key.")
        # 初始化客户端
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.max_tokens = 65536

    def analyze_by_LLM(self, content: str, prompt_prefix: str = "", max_allowed_tokens_for_content: int = 12000) -> str:
        """
        发送分析请求，期望 LLM 返回 JSON。会尝试 parse JSON 并返回 dict。
        对 content 做简单截断（以字符数为近似）。
        """
        # 截断 content（简单策略：字符截断）
        # if len(content) > max_allowed_tokens_for_content:
        #     content = content[:max_allowed_tokens_for_content] + "\n\n/* TRUNCATED FOR TOKEN LIMIT */\n"
        user_message = prompt_prefix + "\n\n" + content
        try:
            resp = self.client.chat.completions.create(
                model="DeepSeek-V3.2-Instruct",
                messages=[
                    {"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=self.max_tokens,
                temperature=0.7,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            return ""

    def initial_analysis(self, title_body: str) -> Optional[dict]:
        """
        第一个LLM调用：分析邮件标题和正文，判断是否有效（可能为跨域BUG），提取调用栈，提取引入版本。
        返回JSON: {"is_valid": bool, "call_stacks": [[str]], "introduced_version": str}
        """
        prompt = """
            Analyze the following email title and body from a Linux CVE announcement.
            Determine if this email contains call stacks that indicate a cross-scope bug (e.g., a race condition between two paths).
            We say valid for softer standard: if you can find any call stack, even if it's not certain, say it's valid.
            If there are call stacks, extract them as separate arrays of function names.
            Extract the version where the bug was introduced, typically in format like "Issue introduced in X.Y".

            Return only JSON in this format:
            {
                "is_valid": true/false,
                "call_stacks": [["func1", "func2", ...], ["func3", "func4", ...]],
                "introduced_version": "X.Y..."
            }
            Be aware only responde with '{' started and '}' ended.
            If no call stacks or version found, use empty arrays or empty string.
            """
        return self.analyze_by_LLM(title_body, prompt_prefix=prompt)

    def cross_scope_judgment(self, func_defs: str, mail_content: str) -> str:
        """
        第二个LLM调用：给出函数定义，判断是否涉及cross-scope。
        标准：产生错误的调用路径里，有一个内核资源在某子模块的函数里被写，而在另一个不同的子模块的函数里被读。由于该内核资源的值错误，导致出错。
        如果找不到，则不必追求是内核资源的值导致错误的发生；
        如果还找不到，则内核资源不必限制为全局变量。
        回答yes/no only.
        """
        prompt = f"""
            Given the following function definitions from the Linux kernel source, which are extracted from a CVE announcement email:

            {func_defs}

            And the following email content:

            {mail_content}

            Does this involve a cross-scope error according to these criteria:
            - In the error-causing call path, a kernel resource is written in a function of one module and read in a function of a different module, causing the error due to incorrect value.
            - If not found, do not require the kernel resource value to cause the error.
            - If still not found, kernel resource not limited to global variables.

            Return only JSON in this format:
            {{
                "is_cross_scope": true/false,
                "conflicting_resources": ["resource1", "resource2", ...]
            }}
            Be aware only respond with '{{' started and '}}' ended.
            If no conflicting resources found, use empty array.
            """
        result = self.analyze_by_LLM('', prompt_prefix=prompt)
        return result