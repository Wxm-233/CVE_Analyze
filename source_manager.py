# source_manager.py
import os
import subprocess
from pathlib import Path
from typing import Optional

KERNEL_MIRROR = os.environ.get("KERNEL_MIRROR", "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git")

def ensure_kernel_checkout(version: str, outdir: str = "linux_src") -> Optional[str]:
    """
    尝试获取指定版本的 Linux 源码，使用主要版本共享基础仓库，小版本使用 worktree。
    返回源码路径(路径字符串)或者 None(失败)。
    """
    p = Path(outdir)
    p.mkdir(parents=True, exist_ok=True)
    dest = p / f"linux-{version}"
    if dest.exists():
        return str(dest)
    
    major = version.split('.')[0]
    base_dest = p / f"linux-{major}"
    
    if not base_dest.exists():
        try:
            # Clone base repo for major version with shallow depth first
            cmd = ["git", "clone", "--depth", "1", KERNEL_MIRROR, str(base_dest)]
            subprocess.check_call(cmd)
            # Fetch all tags and unshallow to get full history
            subprocess.check_call(["git", "-C", str(base_dest), "fetch", "--tags", "--unshallow"])
        except subprocess.CalledProcessError:
            return None
    
    try:
        # Create worktree for specific version
        rel_path = f"../linux-{version}"
        subprocess.check_call(["git", "-C", str(base_dest), "worktree", "add", rel_path, f"v{version}"])
        return str(dest)
    except subprocess.CalledProcessError:
        return None

def run_ctags(src_path: str, tags_file: str = "tags"):
    """在 src_path 下运行 ctags(需要系统安装 exuberant-ctags 或 universal-ctags)"""
    try:
        subprocess.check_call(["ctags", "-R", "--languages=C", "--fields=+n", "--extras=+q", "-f", tags_file], cwd=src_path)
        return True
    except Exception as e:
        print("ctags 运行失败：", e)
        return False