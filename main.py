#!/usr/bin/env python3
# main.py
import argparse
import json
import re
from pathlib import Path

import requests
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)


def banner():
    print(
        Fore.CYAN
        + Style.BRIGHT
        + r"""
  ░██████   ░██                   ░██░██     ░██            ░██                   ░██ 
 ░██   ░██  ░██                      ░██     ░██            ░██                   ░██ 
░██         ░████████   ░██████   ░██░██     ░██ ░██    ░██ ░██ ░██    ░██  ░████████ 
 ░████████  ░██    ░██       ░██  ░██░██████████ ░██    ░██ ░██ ░██    ░██ ░██    ░██ 
        ░██ ░██    ░██  ░███████  ░██░██     ░██ ░██    ░██ ░██ ░██    ░██ ░██    ░██ 
 ░██   ░██  ░██    ░██ ░██   ░██  ░██░██     ░██ ░██   ░███ ░██ ░██   ░███ ░██   ░███ 
  ░██████   ░██    ░██  ░█████░██ ░██░██     ░██  ░█████░██ ░██  ░█████░██  ░█████░██ 
                                                                                      
"""
        + Fore.MAGENTA
        + Style.BRIGHT
        + "             🏴‍☠️ Shai-Hulud Checker by m10sec@proton.me 🏴‍☠️\n"
        + Style.RESET_ALL
    )


def load_json(path_or_url):
    """Carga JSON desde archivo local o URL"""
    try:
        if str(path_or_url).startswith("http"):
            r = requests.get(path_or_url, timeout=15)
            r.raise_for_status()
            return r.json()
        return json.loads(Path(path_or_url).read_text(encoding="utf-8"))
    except Exception:
        return None


def parse_yarn_lock(path):
    data = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return data
    for m in re.finditer(
        r'^(?P<name>[\w@/\-+.]+)@.+\n(?:[^\n]*\n)*?  version "(?P<ver>[\d\w\-.+~]+)"',
        text,
        re.M,
    ):
        data[m.group("name")] = m.group("ver")
    return data


# ------------------ Paquetes afectados ------------------
try:
    AFFECTED = json.loads(Path("affected_packages.json").read_text(encoding="utf-8"))
    AFFECTED = {k: set(v) for k, v in AFFECTED.items()}
except Exception:
    AFFECTED = {}
print("[debug] paquetes cargados:", list(AFFECTED.keys())[:5])
AFFECTED_PREFIXES = [
    "@art-ws/",
    "@crowdstrike/",
    "@ctrl/",
    "@nativescript-community/",
    "@operato/",
    "@things-factory/",
]

SUSPICIOUS_SCRIPTS = {"postinstall", "prepare", "preinstall"}

# ------------------ Escaneo de JS ------------------
JS_IMPORT_RE = re.compile(
    r"""(?m)
    (?:require\(\s*['"](?P<req>[^'"]+)['"]\s*\)
    |import\s+(?:[\w\{\}\*\s,]+from\s+)?['"](?P<imp>[^'"]+)['"]
    )""",
    re.X,
)

JS_SUSPICIOUS_PATTERNS = {
    "eval": re.compile(r"\beval\s*\(", re.I),
    "new Function": re.compile(r"new\s+Function\s*\(", re.I),
    "child_process": re.compile(
        r"\b(child_process|require\(['\"]child_process['\"]\))", re.I
    ),
    "exec": re.compile(r"\b(exec|execSync|spawnSync|spawn)\s*\(", re.I),
    "download_exec": re.compile(r"(curl|wget|bash\s+-c|sh\s+-c|powershell\s+-c)", re.I),
    "fetch_http": re.compile(r"\bfetch\(\s*['\"]https?://", re.I),
    "xhr": re.compile(r"XMLHttpRequest\s*\(", re.I),
    "atob": re.compile(r"\batob\s*\(", re.I),
    "base64_buf": re.compile(r"Buffer\.from\([^,]+,\s*['\"]base64['\"]\)", re.I),
    "eval_unescape": re.compile(r"eval\(\s*unescape\(", re.I),
}


def scan_js_files(root_path, findings, max_files=None):
    js_files = list(Path(root_path).rglob("*.js"))
    for js_file in tqdm(js_files, desc="Escaneando .js", unit="file"):
        try:
            text = js_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel = str(js_file.relative_to(root_path))

        # imports/requires
        for m in JS_IMPORT_RE.finditer(text):
            pkg = m.group("req") or m.group("imp")
            if not pkg:
                continue
            pkg_name = pkg.split("/")[0]
            if pkg.startswith("@"):
                parts = pkg.split("/")
                if len(parts) >= 2:
                    pkg_name = f"{parts[0]}/{parts[1]}"

            if pkg_name in AFFECTED:
                findings.append(
                    {
                        "type": "js_import",
                        "package_import": pkg,
                        "package_name": pkg_name,
                        "file": rel,
                        "reason": "import/require encontrado en JS",
                    }
                )
            else:
                for p in AFFECTED_PREFIXES:
                    if pkg_name.startswith(p):
                        findings.append(
                            {
                                "type": "js_import_prefix",
                                "package_import": pkg,
                                "package_name": pkg_name,
                                "file": rel,
                                "reason": f"import coincide con prefijo '{p}'",
                            }
                        )
                        break

        # patrones sospechosos
        for name, cre in JS_SUSPICIOUS_PATTERNS.items():
            for sm in cre.finditer(text):
                snippet = text[sm.start() : sm.end() + 80].splitlines()[0]
                findings.append(
                    {
                        "type": "js_suspicious_code",
                        "pattern": name,
                        "file": rel,
                        "match_snippet": snippet.strip()[:300],
                        "reason": f"patrón sospechoso '{name}' encontrado",
                    }
                )

        if max_files and len(findings) >= max_files:
            break


# ------------------ Lockfile (v6 y v7+) ------------------
def check_lockfile(lock_json, findings, source_label):
    if not lock_json:
        return

    # npm v6 o menor -> "dependencies"
    deps = lock_json.get("dependencies") or {}
    for name, meta in deps.items():
        if isinstance(meta, dict):
            ver = meta.get("version")
            if ver:
                check_package_version(name, ver, findings, source=source_label)

    # npm v7+ -> "packages"
    pkgs = lock_json.get("packages") or {}
    for name, meta in pkgs.items():
        if not isinstance(meta, dict):
            continue
        ver = meta.get("version")
        if not ver:
            continue

        # normalizar nombre
        norm_name = name
        if norm_name.startswith("node_modules/"):
            norm_name = norm_name[len("node_modules/") :]
        if norm_name and norm_name != "":
            check_package_version(norm_name, ver, findings, source=source_label)


def check_package_version(name, ver, findings, source):
    if name in AFFECTED and ver in AFFECTED[name]:
        findings.append(
            {
                "type": "affected_version",
                "package": name,
                "version": ver,
                "source": source,
                "reason": "match exact affected package/version list",
            }
        )
    else:
        for p in AFFECTED_PREFIXES:
            if name.startswith(p):
                findings.append(
                    {
                        "type": "maybe_affected_prefix",
                        "package": name,
                        "version": ver,
                        "source": source,
                        "reason": f"package matches affected prefix '{p}'",
                    }
                )
                break


# ------------------ Node modules ------------------
def scan_node_modules(root, findings):
    nm = Path(root) / "node_modules"
    if not nm.exists():
        return
    pkg_files = list(nm.rglob("package.json"))
    for pkg_dir in tqdm(pkg_files, desc="Escaneando node_modules", unit="pkg"):
        try:
            pkg = json.loads(pkg_dir.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = pkg.get("name")
        ver = pkg.get("version")
        relpath = str(pkg_dir.relative_to(root))
        if name and ver:
            check_package_version(name, ver, findings, source=f"node_modules:{relpath}")
        scripts = pkg.get("scripts", {})
        for s in SUSPICIOUS_SCRIPTS:
            if s in scripts:
                findings.append(
                    {
                        "type": "suspicious_script",
                        "package": name,
                        "version": ver,
                        "script": s,
                        "script_contents": scripts.get(s),
                        "source": f"node_modules:{relpath}",
                    }
                )
# completo
def scan_project(path, verbose=False):
    root = Path(path).resolve()
    findings = []

    # package.json
    pjson = load_json(root / "package.json")
    if pjson:
        for area in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            deps = pjson.get(area, {}) or {}
            for name, ver_spec in deps.items():
                findings.append(
                    {
                        "type": "declared_dep",
                        "package": name,
                        "version_spec": ver_spec,
                        "source": f"package.json:{area}",
                    }
                )

    # package-lock.json
    lock = load_json(root / "package-lock.json")
    if lock:
        check_lockfile(lock, findings, "package-lock.json")

    # yarn.lock
    ylock = root / "yarn.lock"
    if ylock.exists():
        parsed = parse_yarn_lock(ylock)
        for name, ver in parsed.items():
            check_package_version(name, ver, findings, "yarn.lock")

    # node_modules
    scan_node_modules(root, findings)

    # js files
    scan_js_files(root, findings)

    # npm-shrinkwrap.json
    shrink = load_json(root / "npm-shrinkwrap.json")
    if shrink:
        check_lockfile(shrink, findings, "npm-shrinkwrap.json")

    # deduplicar
    uniq, seen = [], set()
    for f in findings:
        key = (
            f.get("type"),
            f.get("package"),
            f.get("version") or f.get("version_spec"),
            f.get("source"),
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    return uniq


# main
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Scan for indicators related to Shai-Hulud npm supply-chain incident"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Proyecto local o URL a package.json / package-lock.json remoto",
    )
    parser.add_argument(
        "--output", "-o", help="guardar informe JSON", default="shai_hulud_report.json"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    findings = []

    # remoto (arreglado, ya diferencia los js de los json y las carpetas)
    if args.path.startswith("http"):
        data = load_json(args.path)
        if data:
            check_lockfile(data, findings, args.path)
    else:
        p = Path(args.path)
        if p.is_file() and p.suffix == ".json":
            # package.json / package-lock.json suelto
            data = load_json(p)
            if data:
                check_lockfile(data, findings, str(p))
        else:
            # 👉 Si es carpeta, escanea el proyecto entero
            findings = scan_project(args.path, verbose=args.verbose)

    # clasificar
    infected = [f for f in findings if f["type"] == "affected_version"]
    suspicious = [f for f in findings if f["type"] != "affected_version"]

    # resumen
    print("=" * 60)
    if infected:
        print(f"{Fore.RED}[!] ☠️ INFECTADO: {len(infected)} paquetes comprometidos")
        for f in infected:
            print(f"    - {f['package']}@{f['version']} ({f['source']})")
    elif suspicious:
        print(f"{Fore.YELLOW}[~] {len(suspicious)} indicadores sospechosos, sin infección confirmada")
    else:
        print(f"{Fore.GREEN}[+] Limpio: no se encontraron hallazgos")

    if args.verbose:
        for f in findings:
            print(json.dumps(f, ensure_ascii=False, indent=2))

    try:
        Path(args.output).write_text(
            json.dumps({"path": args.path, "findings": findings}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[i] Informe guardado en {args.output}")
    except Exception as e:
        print("[X] No se pudo guardar informe:", e)


if __name__ == "__main__":
    main()