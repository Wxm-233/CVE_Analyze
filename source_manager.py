# source_manager.py
import os
import subprocess
from pathlib import Path
from typing import Optional

KERNEL_MIRROR = os.environ.get("KERNEL_MIRROR", "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git")

def ensure_kernel_checkout(version: str, outdir: str = "linux_src") -> Optional[str]:
    """
    尝试获取指定版本的 Linux 源码(浅克隆特定 tag/branch)。
    返回源码路径(路径字符串)或者 None(失败)。
    """
    p = Path(outdir)
    p.mkdir(parents=True, exist_ok=True)
    dest = p / f"linux-{version}"
    if dest.exists():
        return str(dest)
    try:
        # 注意：网络需要能访问 git.kernel.org；失败时用户可手动准备源码
        cmd = ["git", "clone", "--depth", "1", "--branch", f"v{version}", KERNEL_MIRROR, str(dest)]
        subprocess.check_call(cmd)
        return str(dest)
    except subprocess.CalledProcessError:
        # fallback: try to clone generic repo and checkout tag (slower)
        try:
            tmpdest = p / "linux-latest"
            if not tmpdest.exists():
                subprocess.check_call(["git", "clone", "--depth", "1", KERNEL_MIRROR, str(tmpdest)])
            # try checkout
            subprocess.check_call(["git", "-C", str(tmpdest), "fetch", "--tags"])
            subprocess.check_call(["git", "-C", str(tmpdest), "checkout", f"v{version}"])
            alt = p / f"linux-{version}"
            subprocess.check_call(["mv", str(tmpdest), str(alt)])
            return str(alt)
        except Exception:
            return None

def run_ctags(src_path: str, tags_file: str = "tags"):
    """在 src_path 下运行 ctags(需要系统安装 exuberant-ctags 或 universal-ctags)"""
    try:
        subprocess.check_call(["ctags", "-R", "--languages=C", "--fields=+n", "--extras=+q", "-f", tags_file], cwd=src_path)
        return True
    except Exception as e:
        print("ctags 运行失败：", e)
        return False