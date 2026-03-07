from openai import OpenAI

# PROMPT = """
# Below is the description of a specific Linux source code commit related to a CVE bug. Based on the description, please judge whether this patch is architecture-related (e.g., x86, Arm and RISC-V), and also related to an issue induced by another different architecture (i.e., at first a patch is proposed to fix a non-architecture-specific or architecture-specific bug, but induces a bug in another architecture, so developers proposed this patch to fix it). To automate this process using python scripts, you should only first return “True” or “False” based on whether this patch is to fix cross-architecture issues and then your detailed reason in Chinese.
# Attention: Your reply show be inherently consistent. i.e., you cannot first reply "True" and then say that this patch is really to fix cross-architecture issues.

# Content:

# """

PROMPT = """
Below is the description of a Linux CVE bug. Please extract the call trace stack of this bug according to the description, and only return your answer in JSON format. If you cannot deduce the offset of functions, then just return the function name without offset. You are forbidden to output any irrelevant content to the JSON.
For example:
Desciprtion:
This issue can be reproduced in the following scenario:
After unloading the SELinux policy module via 'semodule -d', if an IMA
measurement is triggered before ima_lsm_rules is updated,
in ima_match_rules(), the first call to ima_filter_rule_match() returns
-ESTALE. This causes the code to enter the 'if (rc == -ESTALE &&
!rule_reinitialized)' block, perform ima_lsm_copy_rule() and retry. In
ima_lsm_copy_rule(), since the SELinux module has been removed, the rule
becomes NULL, and the second call to ima_filter_rule_match() returns
-ENOENT. This bypasses the 'if (!rc)' check and results in a false match.

Call trace:
selinux_audit_rule_match+0x310/0x3b8
security_audit_rule_match+0x60/0xa0

Fix this by changing 'if (!rc)' to 'if (rc <= 0)' to ensure that error
codes like -ENOENT do not bypass the check and accidentally result in a
successful match.

Your output:
{"call_stack" : ["selinux_audit_rule_match+0x310/0x3b8","security_audit_rule_match+0x60/0xa0"],"related_functions": ["selinux_audit_rule_match", "security_audit_rule_match"]}
"""

SYSTEM_MESSAGE = """
You are a professional Linux developer and Linux analyzer.
Respond with strict JSON as requested in the prompt. No extra commentary.
"""

class LLMQuery():
    def __init__(self):
        self.api_key = "sk-8ba479918da8429c9f961780cc22c223"
        self.client = OpenAI(api_key=self.api_key,
                             base_url="https://chatbox.isrc.ac.cn/api/")
        self.max_tokens = 4096

    def analyze_by_LLM(self, content):
        try:
            response = self.client.chat.completions.create(
                model="DeepSeek-V3.2-Instruct",
                messages=[
                    {"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": PROMPT + content},
                ],
                max_tokens=self.max_tokens,
                temperature=0.7,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"错误: {e}"