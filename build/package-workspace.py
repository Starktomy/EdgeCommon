#!/usr/bin/env python3
"""Build matched community archives from sibling source checkouts, without install."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile


MODULES = {"node": "EdgeNode", "api": "EdgeAPI", "admin": "EdgeAdmin"}
SOURCE_ROOTS = {"cmd", "internal", "pkg", "web", "build", "doc", "docs", "libs", "licenses"}
RUNTIME_ROOTS = {"dist", "logs", "data", "node_modules", "coverage"}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}


def command(args, cwd=None, env=None, capture=False):
    if not capture:
        print("+ " + " ".join(str(arg) for arg in args), flush=True)
    return subprocess.run(args, cwd=cwd, env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_source(path):
    if path.is_absolute() or ".." in path.parts:
        return False
    if any(part.startswith(".") or part == "__pycache__" for part in path.parts):
        return False
    if path.parts[0] in RUNTIME_ROOTS:
        return False
    if path.parts[:2] == ("web", "tmp"):
        return False
    if path.parts[0] == "build" and len(path.parts) > 1 and path.parts[1] in {
            "bin", "deploy", "installers", "logs", "data", "caches"}:
        return False
    if path.name.startswith(".env") or path.suffix.lower() in SECRET_SUFFIXES:
        return False
    if path.suffix.lower() in {".zip", ".log"} or path.name.endswith(".tar.gz"):
        return False
    if "configs" in path.parts and path.suffix.lower() in {".yaml", ".yml", ".json"}:
        if not (path.name.endswith(".template.yaml") or path.name.endswith(".template.json")):
            return False
    return (path.parts[0] in SOURCE_ROOTS or path.suffix == ".go" or
            path.name in {"go.mod", "go.sum"} or path.name.startswith(("LICENSE", "NOTICE")))


def source_snapshot(source, destination):
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=source)
    tree = hashlib.sha256()
    count = 0
    for name in sorted(set(paths.split(b"\0"))):
        if not name:
            continue
        relative = PurePosixPath(os.fsdecode(name))
        if not safe_source(relative):
            continue
        original = source / relative
        if not original.exists() and not original.is_symlink():
            continue  # A deletion in this working tree is part of its snapshot.
        info = original.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"source snapshot rejects links or special files: {source.name}/{relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        mode = 0o755 if info.st_mode & 0o111 else 0o644
        target.chmod(mode)
        tree.update(name + b"\0" + str(mode).encode("ascii") + b"\0" + bytes.fromhex(digest(target)))
        count += 1
    if not (destination / "go.mod").is_file():
        raise ValueError(f"missing Go module in snapshot: {source}")
    return {
        "commit": command(["git", "rev-parse", "HEAD"], cwd=source, capture=True).strip(),
        "dirty": bool(command(["git", "status", "--porcelain", "--untracked-files=normal"],
                              cwd=source, capture=True)),
        "snapshotSHA256": tree.hexdigest(),
        "snapshotFiles": count,
        "goModSHA256": digest(destination / "go.mod"),
        "goSumSHA256": digest(destination / "go.sum"),
    }


def component_constant(module, name):
    match = re.search(r'^\s*' + re.escape(name) + r'\s*=\s*"([0-9]+(?:\.[0-9]+)+)"',
                      (module / "internal/const/const.go").read_text(), re.MULTILINE)
    if not match:
        raise ValueError(f"cannot read {module.name} {name}")
    return match.group(1)


def version(module):
    return component_constant(module, "Version")


def copy_file(source, destination):
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"required regular asset missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def copy_tree(source, destination):
    if not source.is_dir():
        raise ValueError(f"required assets missing: {source}")
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part.startswith(".") or part == "tmp" for part in relative.parts):
            continue
        if "_plus." in path.name or "-plus." in path.name or "@plus." in path.name:
            continue
        if path.is_symlink():
            raise ValueError(f"asset symlink is not supported: {path}")
        if path.is_file():
            copy_file(path, destination / relative)


def layout(root):
    root.mkdir(parents=True, exist_ok=True)
    for name in ("bin", "configs", "logs", "data"):
        path = root / name
        path.mkdir(exist_ok=True)
        path.chmod(0o755 if name == "bin" else 0o700)


def templates(module, root):
    files = sorted((module / "build/configs").glob("*.template.yaml"))
    files += sorted((module / "build/configs").glob("*.template.json"))
    if not files:
        raise ValueError(f"configuration templates missing: {module.name}")
    for path in files:
        copy_file(path, root / "configs" / path.name)


def deterministic_zip(root, output, epoch):
    # ZIP timestamps have a two-second resolution and start in 1980.
    stamp = time.gmtime(max(315532800, epoch))[:6]
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in [root] + sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"archive rejects symlinks: {path}")
            is_dir = path.is_dir()
            name = path.relative_to(root.parent).as_posix() + ("/" if is_dir else "")
            info = zipfile.ZipInfo(name, stamp)
            info.create_system = 3
            mode = (stat.S_IFDIR | (0o700 if path.stat().st_mode & 0o077 == 0 else 0o755)) if is_dir else (
                stat.S_IFREG | (0o755 if path.stat().st_mode & 0o111 else 0o644))
            info.external_attr = mode << 16
            if is_dir:
                info.external_attr |= 0x10
            info.compress_type = zipfile.ZIP_DEFLATED
            if is_dir:
                archive.writestr(info, b"")
            else:
                with path.open("rb") as stream, archive.open(info, "w") as target:
                    shutil.copyfileobj(stream, target)


def inspect_archive(path, required):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip():
            raise ValueError(f"archive CRC failed: {path.name}")
        entries = {entry.filename: entry for entry in archive.infolist()}
        if len(entries) != len(archive.infolist()):
            raise ValueError(f"archive has duplicate paths: {path.name}")
        for name, executable in required.items():
            if name not in entries:
                raise ValueError(f"archive is incomplete: {path.name}: {name}")
            if executable and not entries[name].external_attr >> 16 & 0o111:
                raise ValueError(f"archive executable has lost its mode: {name}")
        for name in entries:
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe archive path: {name}")
            if "configs" in relative.parts and name.endswith((".yaml", ".json")) and not (
                    name.endswith(".template.yaml") or name.endswith(".template.json")):
                raise ValueError(f"live configuration leaked into archive: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True, help="new output directory; never overwritten")
    parser.add_argument("--component", choices=["all", *MODULES], default="all")
    parser.add_argument("--arch", choices=["amd64", "arm64"], default="amd64")
    parser.add_argument("--node-arches", default="amd64,arm64", help="comma-separated deployment targets")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--check", action="store_true", help="validate inputs and print build plan without compiling")
    args = parser.parse_args()
    node_arches = sorted(set(args.node_arches.split(",")))
    if not node_arches or not set(node_arches) <= {"amd64", "arm64"} or args.jobs < 1:
        raise ValueError("node arches must contain amd64 and/or arm64; jobs must be positive")
    requested = set(MODULES) if args.component == "all" else {args.component}
    if "admin" in requested:
        requested |= {"api", "node"}
    if "api" in requested:
        requested.add("node")
    if args.component == "node":
        node_arches = [args.arch]
    elif args.arch not in node_arches:
        raise ValueError("deployment node arches must include the archive's target architecture")
    names = ["EdgeCommon"] + [MODULES[name] for name in ("node", "api", "admin") if name in requested]
    workspace, output = args.workspace.resolve(), args.output.absolute()
    if output.exists():
        raise ValueError("output already exists; choose a new directory")
    if any(output.is_relative_to(workspace / name) for name in names):
        raise ValueError("put release artifacts outside the module source checkouts")
    go = shutil.which("go")
    if not go:
        raise ValueError("Go 1.27.4 must be available in PATH")
    env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly", GOEXPERIMENT="")
    if command([go, "env", "GOVERSION"], env=env, capture=True).strip() != "go1.27.4":
        raise ValueError("select Go 1.27.4 in PATH")
    host = command([go, "env", "GOHOSTOS", "GOHOSTARCH"], env=env, capture=True).split()
    if host[0] != "linux" or host[1] not in {"amd64", "arm64"}:
        raise ValueError("this release packager supports Linux AMD64/ARM64 build hosts")
    compilers = {}
    for arch in node_arches:
        compiler = "gcc" if arch == host[1] else {"amd64": "x86_64-linux-gnu-gcc", "arm64": "aarch64-linux-gnu-gcc"}[arch]
        path = shutil.which(compiler)
        if not path:
            raise ValueError(f"CGO compiler required for Node {arch}: {compiler}")
        compilers[arch] = {"path": path, "version": command([path, "--version"], capture=True).splitlines()[0]}
    for name in names:
        if not (workspace / name / "go.mod").is_file():
            raise ValueError(f"matching sibling source checkout required: {name}")
    plan = {"go": "go1.27.4", "os": "linux", "arch": args.arch, "edition": "community",
            "components": sorted(requested), "nodeArchitectures": node_arches, "compilers": compilers}
    if args.check:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".edge-package-", dir=output.parent) as temporary:
        temporary = Path(temporary)
        source, stage, artifacts = temporary / "sources", temporary / "stage", temporary / "artifacts"
        source.mkdir()
        artifacts.mkdir()
        sources = {name: source_snapshot(workspace / name, source / name) for name in names}
        if "api" in requested and component_constant(source / "EdgeAPI", "NodeVersion") != version(source / "EdgeNode"):
            raise ValueError("API NodeVersion does not match the bundled Node source version")
        if "admin" in requested and component_constant(source / "EdgeAdmin", "APINodeVersion") != version(source / "EdgeAPI"):
            raise ValueError("Admin APINodeVersion does not match the bundled API source version")
        for name in names:
            command([go, "mod", "verify"], cwd=source / name, env=env)
        gowebp = Path(command([go, "list", "-m", "-f", "{{.Dir}}", "github.com/iwind/gowebp"],
                             cwd=source / "EdgeNode", env=env, capture=True).strip())
        # Default to committed source time, not wall-clock time. Set this to the
        # release's agreed timestamp when coordinating otherwise different refs.
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", max(int(command(
            ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=workspace / name, capture=True).strip()) for name in names)))
        if epoch < 0 or epoch > 4354819198:
            raise ValueError("SOURCE_DATE_EPOCH is outside ZIP's supported range")
        env["SOURCE_DATE_EPOCH"] = str(epoch)
        results = []

        def build(module, target, package, arch, cgo=False):
            target.parent.mkdir(parents=True, exist_ok=True)
            build_env = dict(env, GOOS="linux", GOARCH=arch, CGO_ENABLED="1" if cgo else "0",
                             GOAMD64="v1", GOARM64="v8.0")
            if cgo:
                build_env.update(CC=compilers[arch]["path"], CGO_CFLAGS="-O2 -g", CGO_LDFLAGS="")
            command([go, "build", "-p", str(args.jobs), "-trimpath", "-buildvcs=false", "-tags=community",
                     "-ldflags=-s -w -buildid=", "-o", str(target), package], cwd=source / module, env=build_env)
            with target.open("rb") as binary:
                header = binary.read(20)
            if header[:5] != b"\x7fELF\x02" or int.from_bytes(header[18:20], "little") != {"amd64": 62, "arm64": 183}[arch]:
                raise ValueError(f"incorrect executable architecture: {target}")
            target.chmod(0o755)

        def record(component, archive, arch):
            item = {"component": component, "version": version(source / MODULES[component]),
                    "os": "linux", "arch": arch, "filename": archive.name,
                    "sha256": digest(archive), "size": archive.stat().st_size}
            results.append(item)
            return item

        nodes = {}
        node_version = version(source / "EdgeNode")
        for arch in node_arches:
            node_root = stage / ("node-" + arch) / "edge-node"
            layout(node_root)
            build("EdgeNode", node_root / "bin/edge-node", "./cmd/edge-node", arch, cgo=True)
            templates(source / "EdgeNode", node_root)
            copy_tree(source / "EdgeNode/build/pages", node_root / "pages")
            copy_tree(source / "EdgeNode/build/www", node_root / "www")
            copy_file(source / "EdgeNode/build/configs/README.md", node_root / "configs/README.md")
            copy_file(source / "EdgeNode/internal/waf/injectionutils/libinjection/COPYING", node_root / "doc/licenses/libinjection.txt")
            copy_file(gowebp / "LICENSE", node_root / "doc/licenses/gowebp.txt")
            copy_file(gowebp / "internal/libwebp-1.3.2/COPYING", node_root / "doc/licenses/libwebp.txt")
            copy_file(gowebp / "internal/libwebp-1.3.2/PATENTS", node_root / "doc/licenses/libwebp-PATENTS.txt")
            archive = artifacts / f"edge-node-linux-{arch}-v{node_version}.zip"
            deterministic_zip(node_root, archive, epoch)
            inspect_archive(archive, {"edge-node/bin/edge-node": True,
                                     "edge-node/configs/api_node.template.yaml": False, "edge-node/www/index.html": False})
            nodes[arch] = archive
            record("node", archive, arch)

        api_root = stage / "api" / "edge-api"
        if "api" in requested:
            layout(api_root)
            build("EdgeAPI", api_root / "bin/edge-api", "./cmd/edge-api", args.arch)
            templates(source / "EdgeAPI", api_root)
            (api_root / "deploy").mkdir()
            (api_root / "installers").mkdir()
            for arch, archive in nodes.items():
                copy_file(archive, api_root / "deploy" / archive.name)
                build("EdgeAPI", api_root / "installers" / f"edge-installer-helper-linux-{arch}", "./cmd/installer-helper", arch)
            for path in sorted((source / "EdgeAPI/docs").glob("*.md")):
                copy_file(path, api_root / "docs" / path.name)
            api_version = version(source / "EdgeAPI")
            api_archive = artifacts / f"edge-api-linux-{args.arch}-v{api_version}.zip"
            deterministic_zip(api_root, api_archive, epoch)
            required = {"edge-api/bin/edge-api": True, "edge-api/configs/db.template.yaml": False}
            for arch, node in nodes.items():
                required[f"edge-api/deploy/{node.name}"] = False
                required[f"edge-api/installers/edge-installer-helper-linux-{arch}"] = True
            inspect_archive(api_archive, required)
            record("api", api_archive, args.arch)

        if "admin" in requested:
            admin_root = stage / "admin" / "edge-admin"
            layout(admin_root)
            build("EdgeAdmin", admin_root / "bin/edge-admin", "./cmd/edge-admin", args.arch)
            # Generate into the temporary snapshot, with a native binary; do not
            # modify checked-out frontend assets or try to execute cross binaries.
            generator_env = dict(env, CGO_ENABLED="0", GOOS=host[0], GOARCH=host[1], GithubDIR=str(source))
            generated = source / "EdgeAdmin/web/public/js/components.src.js"
            generated.unlink(missing_ok=True)
            command([go, "run", "-p", str(args.jobs), "-trimpath", "-buildvcs=false", "-tags=community",
                     "./cmd/edge-admin", "generate"], cwd=source / "EdgeAdmin", env=generator_env)
            if "window.WAF_RULE_CHECKPOINTS" not in generated.read_text():
                raise ValueError("administrator component generation failed")
            copy_tree(source / "EdgeAdmin/web", admin_root / "web")
            copy_file(generated, admin_root / "web/public/js/components.js")
            copy_file(source / "EdgeAdmin/web/public/js/utils.js", admin_root / "web/public/js/utils.min.js")
            templates(source / "EdgeAdmin", admin_root)
            shutil.copytree(api_root, admin_root / "edge-api")
            for name in ("admin-security.md", "signed-upgrades.md"):
                copy_file(source / "EdgeAdmin/doc" / name, admin_root / "doc" / name)
            admin_version = version(source / "EdgeAdmin")
            admin_archive = artifacts / f"edge-admin-linux-{args.arch}-v{admin_version}.zip"
            deterministic_zip(admin_root, admin_archive, epoch)
            required = {"edge-admin/bin/edge-admin": True, "edge-admin/edge-api/bin/edge-api": True,
                        "edge-admin/configs/upgrade-trust.template.json": False,
                        "edge-admin/web/public/js/security.js": False, "edge-admin/web/public/js/components.js": False}
            for arch, node in nodes.items():
                required[f"edge-admin/edge-api/deploy/{node.name}"] = False
                required[f"edge-admin/edge-api/installers/edge-installer-helper-linux-{arch}"] = True
            inspect_archive(admin_archive, required)
            record("admin", admin_archive, args.arch)
            signer = artifacts / f"edge-sign-release-linux-{args.arch}"
            build("EdgeAdmin", signer, "./cmd/edge-sign-release", args.arch)
            results.append({"component": "release-tool", "filename": signer.name,
                            "sha256": digest(signer), "size": signer.stat().st_size})

        inventory = {"schema": 1, "build": dict(plan, sourceDateEpoch=epoch),
                     "sources": sources, "signed": False,
                     "signing": "Sign final administrator ZIP using edge-sign-release on the offline signing host. This inventory is not an upgrade signature."}
        inventory["build"]["componentVersions"] = {name: version(source / MODULES[name]) for name in requested}
        inventory["bundledNodeArchives"] = []
        if args.component != "all":
            keep = {args.component, "release-tool"}
            if args.component in {"admin", "api"}:
                prefix = "edge-admin/edge-api" if args.component == "admin" else "edge-api"
                inventory["bundledNodeArchives"] = [dict(item, path=f"{prefix}/deploy/{item['filename']}")
                                                     for item in results if item["component"] == "node"]
            for item in results:
                if item["component"] not in keep:
                    (artifacts / item["filename"]).unlink()
            results = [item for item in results if item["component"] in keep]
        inventory["artifacts"] = results
        (artifacts / f"build-manifest-linux-{args.arch}.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
        (artifacts / f"SHA256SUMS-linux-{args.arch}").write_text("".join(
            f"{digest(path)}  {path.name}\n" for path in sorted(artifacts.iterdir()) if path.is_file()))
        # Publish the complete artifact directory atomically after all checks.
        if output.exists():
            raise ValueError("output appeared during the build; refusing to replace it")
        artifacts.rename(output)
        print(f"Artifacts verified and written to {output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"package-workspace: {error}", file=sys.stderr)
        sys.exit(1)
