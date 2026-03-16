# pipeline.py
import os
from cve_cross_scopes import get_linux_cve_details
from source_manager import ensure_kernel_checkout, run_ctags
from extractor import find_function_definition
from llm_safe import LLMQuery

def build_prompt(description: str, func_defs: list):
    # 拼 prompt 的简单策略：把 description 放前面，再拼函数定义（每个函数保持文件头注释）
    pieces = []
    pieces.append(
        '''
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
        '''
    )
    pieces.append("Description:\n" + description + "\n")
    pieces.append("Call the following functions may be related, their definitions are shown below:\n")
    for d in func_defs:
        if d:
            pieces.append(d + "\n/* ----- next function ----- */\n")
    # 截断防护在 llm 内部完成
    return "\n".join(pieces)

def main():
    # 示例：处理单个 CVE（可改成循环处理 CVEs 列表）
    cve_id = "CVE-2026-23228"  # 从 cve.py 获得 CVE 列表并调用本流程
    details = get_linux_cve_details(cve_id)
    desc = details.get("description","")
    funcs = details.get("related_functions", [])[:10]  # 限制函数数，避免 prompt 过大

    # 尝试获得源码
    version = details.get("linux_version")
    src_path = None
    if version:
        src_path = ensure_kernel_checkout(version)
    if not src_path:
        src_path = os.environ.get("LOCAL_LINUX_SRC", "~/linux618")

    # 为每个函数提取定义
    func_defs = []
    for f in funcs:
        d = find_function_definition(f, src_path)
        if not d:
            d = f"/* could not find definition for {f} */"
        func_defs.append(d)

    prompt = build_prompt(desc, func_defs)

    llm = LLMQuery()
    # 原来期待 LLM 输出 {"call_stack": [...], "related_functions": [...]}
    response = llm.analyze_by_LLM(prompt_prefix="", content=prompt)
    print("LLM response:", response)

if __name__ == "__main__":
    main()