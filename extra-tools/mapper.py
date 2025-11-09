import os
import re
import sys
import json
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(r'c:\path\to\dart_project_root')
OUTPUT_DOT = 'dart_call_map.dot'
RENDER_PNG = True

IGNORE_DIRS = {'.git', '.dart_tool', 'build', '.idea', '.vscode'}
IMPORT_RE = re.compile(r'(?:^|\s)(import|export)\s+["\']([^"\']+)["\']', re.MULTILINE)
PART_RE = re.compile(r'(?:^|\s)part\s+["\']([^"\']+)["\']', re.MULTILINE)
MAIN_FN_RE = re.compile(r'\b(?:Future<\s*void\s*>\s*)?void\s+main\s*\(')

def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ""

def find_pubspec_name(root: Path) -> str | None:
    cur = root
    if cur.is_file():
        cur = cur.parent
    while True:
        pub = cur / 'pubspec.yaml'
        if pub.exists():
            for line in pub.read_text(encoding='utf-8', errors='ignore').splitlines():
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                if s.startswith('name:'):
                    return s.split(':', 1)[1].strip().strip('"\'')
                if re.match(r'^[a-zA-Z_]\w*\s*:', s) and not s.startswith('name:'):
                    break
            return None
        if cur.parent == cur:
            break
        cur = cur.parent
    return None

def collect_dart_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            if fn.endswith('.dart'):
                p = Path(dirpath) / fn
                rel = p.relative_to(root)
                files[rel.as_posix()] = p
    return files

def resolve_import(spec: str, src_file: Path, root: Path, files_index: dict[str, Path], pkg_name: str | None) -> str | None:
    if spec.startswith('dart:'):
        return None
    if spec.startswith('/'):
        tgt = (root / spec.lstrip('/')).resolve()
        try:
            rel = tgt.relative_to(root).as_posix()
        except ValueError:
            return None
        return rel if rel in files_index else None
    if spec.startswith('package:'):
        try:
            pkg_spec = spec[len('package:'):]
            pkg, pth = pkg_spec.split('/', 1)
        except ValueError:
            return None
        if pkg_name and pkg == pkg_name:
            lib_root = root if root.name == 'lib' else (root / 'lib')
            tgt = (lib_root / pth).resolve()
            try:
                rel = tgt.relative_to(root).as_posix()
            except ValueError:
                return None
            return rel if rel in files_index else None
        return None
    tgt = (src_file.parent / spec).resolve()
    try:
        rel = tgt.relative_to(root).as_posix()
    except ValueError:
        return None
    return rel if rel in files_index else None

def parse_deps(file_rel: str, files_index: dict[str, Path], root: Path, pkg_name: str | None) -> set[str]:
    p = files_index[file_rel]
    content = read_text(p)
    deps: set[str] = set()
    for _, spec in IMPORT_RE.findall(content):
        r = resolve_import(spec, p, root, files_index, pkg_name)
        if r:
            deps.add(r)
    for spec in PART_RE.findall(content):
        r = resolve_import(spec, p, root, files_index, pkg_name)
        if r:
            deps.add(r)
    return deps

def pick_main(root: Path, files_index: dict[str, Path], explicit: Path | None) -> str:
    if explicit:
        if not explicit.exists():
            sys.exit(f'--main not found: {explicit}')
        return explicit.relative_to(root).as_posix()
    candidates = [k for k in files_index.keys() if k.endswith('main.dart')]
    with_main = [k for k in candidates if MAIN_FN_RE.search(read_text(files_index[k]))]
    if with_main:
        for pref in ('bin/main.dart', 'lib/main.dart'):
            if pref in with_main:
                return pref
        return with_main[0]
    if candidates:
        return candidates[0]
    sys.exit('No main.dart found under the provided root.')

def build_graph(root: Path, main_rel: str, files_index: dict[str, Path], pkg_name: str | None) -> tuple[dict[str, set[str]], set[str]]:
    graph: dict[str, set[str]] = {}
    for rel in files_index.keys():
        graph[rel] = parse_deps(rel, files_index, root, pkg_name)
    reachable: set[str] = set()
    stack = [main_rel]
    while stack:
        cur = stack.pop()
        if cur in reachable:
            continue
        reachable.add(cur)
        stack.extend([d for d in graph.get(cur, []) if d in files_index and d not in reachable])
    return graph, reachable

def write_dot(out_path: Path, root: Path, main_rel: str, graph: dict[str, set[str]], files_index: dict[str, Path], reachable: set[str]) -> None:
    all_nodes = set(files_index.keys())
    unreachable = sorted(all_nodes - reachable)
    reachable_nodes = sorted(reachable)

    lines: list[str] = []
    lines.append('// Dart file dependency map generated by mapper.py (dark mode)')
    lines.append(f'// root: {root}')
    lines.append(f'// main: {main_rel}')
    lines.append('digraph DartDeps {')
    lines.append('  graph [bgcolor="#1e1e1e", fontcolor="#e0e0e0"];')
    lines.append('  rankdir=LR;')
    lines.append('  node [shape=box, fontname="Arial", style="filled,rounded", fillcolor="#2d2d2d", color="#444444", fontcolor="#e0e0e0"];')
    lines.append('  edge [color="#777777"];')

    lines.append('  subgraph cluster_reachable {')
    lines.append('    label="Reachable from main.dart"; color="#2f5f2f"; fontcolor="#a6e3a1"; style="rounded";')
    for n in reachable_nodes:
        if n == main_rel:
            lines.append(f'    "{n}" [fillcolor="#335533", color="#4caf50", penwidth=2];')
        else:
            lines.append(f'    "{n}";')
    for src in reachable_nodes:
        for dst in sorted(graph.get(src, [])):
            if dst in reachable:
                lines.append(f'    "{src}" -> "{dst}" [color="#4caf50"];')
    lines.append('  }')

    if unreachable:
        lines.append('  subgraph cluster_unreachable {')
        lines.append('    label="Uncalled / Unreachable"; color="#5f2f2f"; fontcolor="#f28b82"; style="rounded";')
        for n in unreachable:
            lines.append(f'    "{n}" [fillcolor="#3a2222", fontcolor="#ff9595", color="#ff5555"];')
        lines.append('  }')

    lines.append('}')
    out_path.write_text('\n'.join(lines), encoding='utf-8')

def try_render_png(dot_file: Path, png_file: Path) -> bool:
    dot_exe = shutil.which('dot')
    if not dot_exe:
        print("Graphviz 'dot' not found. Install from https://graphviz.org/download/ to render PNG.")
        return False
    try:
        subprocess.run([dot_exe, '-Tpng', str(dot_file), '-o', str(png_file)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    root = (Path(__file__).parent.parent / 'lib').resolve()
    if not root.exists():
        sys.exit(f'Root directory not found: {root}')
    files_index = collect_dart_files(root)
    if not files_index:
        sys.exit('No .dart files found under the provided root.')
    main_rel = pick_main(root, files_index, None)
    pkg_name = find_pubspec_name(root)
    graph, reachable = build_graph(root, main_rel, files_index, pkg_name)
    out_path = Path(os.getcwd()) / OUTPUT_DOT
    write_dot(out_path, root, main_rel, graph, files_index, reachable)
    if RENDER_PNG:
        png_path = out_path.with_suffix('.png')
        if try_render_png(out_path, png_path):
            print(f'Wrote: {out_path} and {png_path}')
            return
    print(f'Wrote: {out_path}')

if __name__ == '__main__':
    main()
