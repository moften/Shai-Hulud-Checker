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
        + "             🏴‍☠️ Shai-Hulud Enhanced Checker by m10sec@proton.me 🏴‍☠️\n"
        + Style.RESET_ALL
    )


# Rutas comunes donde buscar archivos de configuración
COMMON_PATHS = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "composer.json",
    "composer.lock",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
]

# Indicadores de compromiso específicos de Shai-Hulud
IOC_FILES = [
    "setup_bun.js",
    "bun_environment.js",
    "discussion.yaml",
    ".github/workflows/discussion.yaml",
    ".github/workflows/discussion.yml",
]

# Patrones de runners de GitHub sospechosos
SUSPICIOUS_RUNNER_PATTERN = re.compile(r"SHA1HULUD", re.I)

# Dominios/IPs sospechosos (añade los que conozcas del incidente)
SUSPICIOUS_DOMAINS = [
    # Añade aquí dominios conocidos del incidente
    "pastebin.com/raw",
    "paste.ee/r",
]


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


# paquetes afectados
try:
    AFFECTED = json.loads(Path("affected_packages.json").read_text(encoding="utf-8"))
    AFFECTED = {k: set(v) for k, v in AFFECTED.items()}
except Exception:
    AFFECTED = {}

AFFECTED_PREFIXES = [
    "@art-ws/",
    "@crowdstrike/",
    "@ctrl/",
    "@nativescript-community/",
    "@operato/",
    "@things-factory/",
]

SUSPICIOUS_SCRIPTS = {"postinstall", "prepare", "preinstall"}

# JS
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
    "rm_rf": re.compile(r"(rm\s+-rf|rmdir\s+/s|Remove-Item.*-Recurse)", re.I),
}


def scan_ioc_files(root_path, findings):
    """Busca archivos indicadores de compromiso específicos"""
    root = Path(root_path)
    
    print(f"{Fore.YELLOW}[*] Buscando indicadores de compromiso específicos...")
    
    for ioc_file in IOC_FILES:
        file_path = root / ioc_file
        if file_path.exists():
            findings.append({
                "type": "IOC_FILE_FOUND",
                "severity": "CRITICAL",
                "file": str(file_path.relative_to(root)),
                "reason": f"Archivo IOC '{ioc_file}' detectado - indicador de compromiso Shai-Hulud"
            })
            print(f"{Fore.RED}[!] ☠️ IOC CRÍTICO: {ioc_file} encontrado!")
    
    # Buscar archivos adicionales con patrones sospechosos
    for pattern in ["**/setup_bun*.js", "**/bun_*.js", "**/*discussion*.yaml", "**/*discussion*.yml"]:
        for found_file in root.rglob(pattern):
            rel_path = str(found_file.relative_to(root))
            if rel_path not in [f["file"] for f in findings if f["type"] == "IOC_FILE_FOUND"]:
                findings.append({
                    "type": "IOC_FILE_PATTERN",
                    "severity": "HIGH",
                    "file": rel_path,
                    "reason": f"Archivo coincide con patrón IOC: {pattern}"
                })


def scan_github_workflows(root_path, findings):
    """Escanea workflows de GitHub Actions por runners sospechosos"""
    workflows_dir = Path(root_path) / ".github" / "workflows"
    
    if not workflows_dir.exists():
        return
    
    print(f"{Fore.YELLOW}[*] Escaneando GitHub Actions workflows...")
    
    for workflow_file in workflows_dir.rglob("*.y*ml"):
        try:
            content = workflow_file.read_text(encoding="utf-8", errors="ignore")
            
            # Buscar runner SHA1HULUD
            if SUSPICIOUS_RUNNER_PATTERN.search(content):
                findings.append({
                    "type": "SUSPICIOUS_GITHUB_RUNNER",
                    "severity": "CRITICAL",
                    "file": str(workflow_file.relative_to(root_path)),
                    "reason": "Runner 'SHA1HULUD' detectado en workflow - indicador de compromiso confirmado"
                })
                print(f"{Fore.RED}[!] ☠️ RUNNER MALICIOSO: SHA1HULUD en {workflow_file.name}")
            
            # Buscar dominios sospechosos en workflows
            for domain in SUSPICIOUS_DOMAINS:
                if domain in content:
                    findings.append({
                        "type": "SUSPICIOUS_DOMAIN_IN_WORKFLOW",
                        "severity": "HIGH",
                        "file": str(workflow_file.relative_to(root_path)),
                        "domain": domain,
                        "reason": f"Dominio sospechoso '{domain}' encontrado en workflow"
                    })
                    
        except Exception as e:
            print(f"{Fore.YELLOW}[~] Error leyendo {workflow_file}: {e}")


def scan_for_suspicious_deletions(root_path, findings):
    """Busca scripts que contengan operaciones de borrado de directorios"""
    root = Path(root_path)
    
    print(f"{Fore.YELLOW}[*] Buscando scripts con operaciones de borrado sospechosas...")
    
    script_patterns = ["*.sh", "*.bash", "*.js", "*.ps1", "*.bat"]
    
    for pattern in script_patterns:
        for script_file in root.rglob(pattern):
            try:
                content = script_file.read_text(encoding="utf-8", errors="ignore")
                
                if JS_SUSPICIOUS_PATTERNS["rm_rf"].search(content):
                    # Buscar si está borrando directorios del usuario
                    user_dir_patterns = [r"\$HOME", r"~\/", r"%USERPROFILE%", r"os\.homedir\(\)"]
                    for user_pattern in user_dir_patterns:
                        if re.search(user_pattern, content, re.I):
                            findings.append({
                                "type": "SUSPICIOUS_DELETION",
                                "severity": "HIGH",
                                "file": str(script_file.relative_to(root)),
                                "reason": "Script contiene operaciones de borrado de directorios del usuario"
                            })
                            break
                            
            except Exception:
                continue


def discover_common_paths(root_path):
    """Descubre todas las rutas comunes de archivos de configuración"""
    root = Path(root_path)
    discovered = {}
    
    print(f"{Fore.YELLOW}[*] Descubriendo archivos de configuración...")
    
    for common_path in COMMON_PATHS:
        file_path = root / common_path
        if file_path.exists():
            discovered[common_path] = file_path
            print(f"{Fore.GREEN}[+] Encontrado: {common_path}")
    
    # Buscar recursivamente archivos package.json en subdirectorios
    for pkg_json in root.rglob("package.json"):
        if "node_modules" not in str(pkg_json):
            rel_path = str(pkg_json.relative_to(root))
            if rel_path not in discovered:
                discovered[rel_path] = pkg_json
                print(f"{Fore.GREEN}[+] Encontrado: {rel_path}")
    
    return discovered


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
                findings.append({
                    "type": "js_import",
                    "package_import": pkg,
                    "package_name": pkg_name,
                    "file": rel,
                    "reason": "import/require encontrado en JS",
                })
            else:
                for p in AFFECTED_PREFIXES:
                    if pkg_name.startswith(p):
                        findings.append({
                            "type": "js_import_prefix",
                            "package_import": pkg,
                            "package_name": pkg_name,
                            "file": rel,
                            "reason": f"import coincide con prefijo '{p}'",
                        })
                        break

        # patrones sospechosos
        for name, cre in JS_SUSPICIOUS_PATTERNS.items():
            for sm in cre.finditer(text):
                snippet = text[sm.start() : sm.end() + 80].splitlines()[0]
                findings.append({
                    "type": "js_suspicious_code",
                    "pattern": name,
                    "file": rel,
                    "match_snippet": snippet.strip()[:300],
                    "reason": f"patrón sospechoso '{name}' encontrado",
                })
        
        # Buscar dominios sospechosos en código JS
        for domain in SUSPICIOUS_DOMAINS:
            if domain in text:
                findings.append({
                    "type": "SUSPICIOUS_DOMAIN_IN_CODE",
                    "severity": "HIGH",
                    "file": rel,
                    "domain": domain,
                    "reason": f"Dominio sospechoso '{domain}' encontrado en código"
                })

        if max_files and len(findings) >= max_files:
            break


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

    # npm v7+ -> "packages" como dict
    pkgs = lock_json.get("packages")
    if isinstance(pkgs, dict):
        for name, meta in pkgs.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if not ver:
                continue

            norm_name = name
            if norm_name.startswith("node_modules/"):
                norm_name = norm_name[len("node_modules/") :]
            if norm_name and norm_name != "":
                check_package_version(norm_name, ver, findings, source=source_label)

    # Composer -> "packages" como lista
    elif isinstance(pkgs, list):
        for meta in pkgs:
            if not isinstance(meta, dict):
                continue
            name = meta.get("name")
            ver = meta.get("version")
            if name and ver:
                check_package_version(name, ver, findings, source=source_label)


def check_package_version(name, ver, findings, source):
    if name in AFFECTED and ver in AFFECTED[name]:
        findings.append({
            "type": "affected_version",
            "severity": "CRITICAL",
            "package": name,
            "version": ver,
            "source": source,
            "reason": "match exact affected package/version list",
        })
    else:
        for p in AFFECTED_PREFIXES:
            if name.startswith(p):
                findings.append({
                    "type": "maybe_affected_prefix",
                    "severity": "MEDIUM",
                    "package": name,
                    "version": ver,
                    "source": source,
                    "reason": f"package matches affected prefix '{p}'",
                })
                break


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
                findings.append({
                    "type": "suspicious_script",
                    "severity": "MEDIUM",
                    "package": name,
                    "version": ver,
                    "script": s,
                    "script_contents": scripts.get(s),
                    "source": f"node_modules:{relpath}",
                })


def scan_project(path, verbose=False):
    root = Path(path).resolve()
    findings = []

    # Descubrir rutas comunes primero
    discovered_files = discover_common_paths(root)
    
    # Escanear IOCs específicos de Shai-Hulud
    scan_ioc_files(root, findings)
    
    # Escanear GitHub workflows
    scan_github_workflows(root, findings)
    
    # Buscar scripts con borrado sospechoso
    scan_for_suspicious_deletions(root, findings)

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
                findings.append({
                    "type": "declared_dep",
                    "package": name,
                    "version_spec": ver_spec,
                    "source": f"package.json:{area}",
                })

    # Procesar todos los archivos descubiertos
    for path_name, file_path in discovered_files.items():
        if path_name.endswith(".json"):
            lock = load_json(file_path)
            if lock:
                check_lockfile(lock, findings, path_name)
        elif "yarn.lock" in path_name:
            parsed = parse_yarn_lock(file_path)
            for name, ver in parsed.items():
                check_package_version(name, ver, findings, path_name)

    # node_modules
    scan_node_modules(root, findings)

    # js files
    scan_js_files(root, findings)

    # deduplicar
    uniq, seen = [], set()
    for f in findings:
        key = (
            f.get("type"),
            f.get("package"),
            f.get("version") or f.get("version_spec"),
            f.get("source"),
            f.get("file"),
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    return uniq


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

    # remoto
    if args.path.startswith("http"):
        data = load_json(args.path)
        if data:
            check_lockfile(data, findings, args.path)
    else:
        p = Path(args.path)
        if p.is_file() and p.suffix == ".json":
            data = load_json(p)
            if data:
                check_lockfile(data, findings, str(p))
        else:
            findings = scan_project(args.path, verbose=args.verbose)

    # clasificar por severidad
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]
    others = [f for f in findings if "severity" not in f]

    # resumen
    print("\n" + "=" * 70)
    print(f"{Fore.CYAN}{Style.BRIGHT}RESUMEN DEL ESCANEO{Style.RESET_ALL}")
    print("=" * 70)
    
    if critical:
        print(f"\n{Fore.RED}{Style.BRIGHT}[!] ☠️  CRÍTICO: {len(critical)} indicadores de compromiso confirmados{Style.RESET_ALL}")
        for f in critical:
            print(f"{Fore.RED}    ━ {f.get('reason', 'N/A')}")
            if 'package' in f:
                print(f"      Paquete: {f['package']}@{f.get('version', 'N/A')}")
            if 'file' in f:
                print(f"      Archivo: {f['file']}")
    
    if high:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[!] ⚠️  ALTO: {len(high)} hallazgos sospechosos{Style.RESET_ALL}")
        for f in high[:5]:  # Mostrar solo los primeros 5
            print(f"{Fore.YELLOW}    ━ {f.get('reason', 'N/A')}")
    
    if medium:
        print(f"\n{Fore.YELLOW}[~] MEDIO: {len(medium)} hallazgos que requieren revisión{Style.RESET_ALL}")
    
    if not critical and not high and not medium and not others:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] ✓ Limpio: no se encontraron indicadores de compromiso{Style.RESET_ALL}")
    
    print("\n" + "=" * 70)

    if args.verbose:
        print(f"\n{Fore.CYAN}DETALLES COMPLETOS:{Style.RESET_ALL}\n")
        for f in findings:
            print(json.dumps(f, ensure_ascii=False, indent=2))

    try:
        report = {
            "scan_date": str(Path(args.output).stat().st_mtime) if Path(args.output).exists() else "N/A",
            "path": args.path,
            "summary": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "total": len(findings)
            },
            "findings": findings
        }
        
        Path(args.output).write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\n{Fore.GREEN}[i] Informe guardado en {args.output}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[X] No se pudo guardar informe: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()