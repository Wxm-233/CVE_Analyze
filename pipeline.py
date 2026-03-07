# pipeline.py
import os
from cve_cross_scopes import get_linux_cve_details
from source_manager import ensure_kernel_checkout, run_ctags
from extractor import find_function_definition
from llm_safe import LLMQuery

def build_prompt(description: str, func_defs: list):
    # 拼 prompt 的简单策略：把 description 放前面，再拼函数定义（每个函数保持文件头注释）
    pieces = []
    pieces.append("Description:\n" + description + "\n")
    pieces.append("Call the following functions may be related, their definitions are shown below:\n")
    for d in func_defs:
        if d:
            pieces.append(d + "\n/* ----- next function ----- */\n")
    # 截断防护在 llm 内部完成
    return "\n".join(pieces)

def main():
    # 示例：处理单个 CVE（生产中可改成循环处理 CVEs 列表）
    cve_id = "CVE-2024-XXXX"  # 你会从 cve.py 获得 CVE 列表并调用本流程
    details = get_linux_cve_details(cve_id)
    desc = details.get("description","")
    funcs = details.get("related_functions", [])[:10]  # 限制函数数，避免 prompt 过大

    # 尝试获得源码
    version = details.get("linux_version")
    src_path = None
    if version:
        src_path = ensure_kernel_checkout(version)
    if not src_path:
        src_path = os.environ.get("LOCAL_LINUX_SRC", "/path/to/local/linux")  # 用户需提供

    # 为每个函数提取定义
    func_defs = []
    for f in funcs:
        d = find_function_definition(f, src_path)
        if not d:
            d = f"/* could not find definition for {f} */"
        func_defs.append(d)

    prompt = build_prompt(desc, func_defs)

    llm = LLMQuery()
    # 你原来期待 LLM 输出 {"call_stack": [...], "related_functions": [...]}
    response = llm.analyze_by_LLM(prompt_prefix="", content=prompt)
    print("LLM response:", response)

if __name__ == "__main__":
    main()