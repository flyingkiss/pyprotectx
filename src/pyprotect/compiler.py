from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional


def compile_file(py_path: Path, module_name: str) -> Optional[Path]:
    from Cython.Build import cythonize
    from setuptools import Distribution, Extension

    import os

    save_cwd = os.getcwd()
    try:
        os.chdir(str(py_path.parent))
        extra_link_args = []
        if sys.platform == "darwin":
            extra_link_args = ["-undefined", "dynamic_lookup"]
        ext = Extension(module_name, [py_path.name], extra_link_args=extra_link_args)
        exts = cythonize(
            [ext],
            compiler_directives={
                "language_level": "3",
                "boundscheck": False,
                "annotation_typing": False,
            },
            force=True,
            quiet=True,
        )
        dist = Distribution({"ext_modules": exts})
        cmd = dist.get_command_obj("build_ext")
        cmd.inplace = True
        cmd.ensure_finalized()
        cmd.run()

        stem = py_path.stem
        for f in py_path.parent.iterdir():
            if f.suffix in (".so", ".pyd") and f.stem.startswith(stem):
                return f
        return None
    except BaseException as e:
        print(f"  Cython compile failed for {py_path.name}: {e}", file=sys.stderr)
        return None
    finally:
        os.chdir(save_cwd)


def compile_batch(
    py_files: list[Path], project_root: Path, nthreads: int = 0
) -> tuple[list[Path], list[Path]]:
    from Cython.Build import cythonize
    from setuptools import Distribution, Extension

    if not py_files:
        return [], []

    all_exts = []
    for py_path in py_files:
        rel = py_path.relative_to(project_root)
        module = str(rel).replace("/", ".").replace("\\", ".").replace(".py", "")
        all_exts.append(Extension(module, [str(py_path)]))

    import os

    nthreads = nthreads or min(os.cpu_count() or 4, 8)
    save_cwd = os.getcwd()

    try:
        os.chdir(str(project_root))
        result_exts = cythonize(
            all_exts,
            compiler_directives={
                "language_level": "3",
                "boundscheck": False,
                "annotation_typing": False,
            },
            nthreads=nthreads,
            force=True,
            quiet=True,
        )
        dist = Distribution({"ext_modules": result_exts})
        cmd = dist.get_command_obj("build_ext")
        cmd.inplace = True
        cmd.ensure_finalized()
        cmd.run()
    except Exception as e:
        print(f"  Batch compile error ({type(e).__name__}): {e}", file=sys.stderr)
        print("  Falling back to per-file compilation...", file=sys.stderr)
        os.chdir(save_cwd)
        return _compile_individual(py_files, project_root)
    finally:
        os.chdir(save_cwd)

    compiled = []
    failed = []
    for py_path in py_files:
        stem = py_path.stem
        if any(
            f.suffix in (".so", ".pyd") and f.stem.startswith(stem)
            for f in py_path.parent.iterdir()
        ):
            compiled.append(py_path)
        else:
            rel = py_path.relative_to(project_root)
            print(f"  No .so generated: {rel}", file=sys.stderr)
            failed.append(py_path)

    return compiled, failed


def _compile_individual(py_files: list[Path], project_root: Path) -> tuple[list[Path], list[Path]]:
    compiled = []
    failed = []
    for py_path in py_files:
        rel = py_path.relative_to(project_root)
        module = str(rel).replace("/", ".").replace("\\", ".").replace(".py", "")
        so_path = compile_file(py_path, module_name=module)
        if so_path is not None:
            compiled.append(py_path)
        else:
            failed.append(py_path)
    return compiled, failed
