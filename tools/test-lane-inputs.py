#!/usr/bin/env python3
"""Check lane dependency assembly and default bake inputs without booting a VM."""
import argparse
import contextlib
import hashlib
import json
import io
import os
import runpy
import socket
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
assemble = ROOT / "tools/assemble-guest-deps.py"
bootstrap = runpy.run_path(str(ROOT / "tools/bootstrap-kcov-env.py"))
baker = runpy.run_path(str(ROOT / "bundle/baker/bake_nfs_protocol_image.py"))

with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    deps, proxy, output = (work / name for name in ("deps.tar.gz", "proxy", "lane.tar.gz"))
    proxy.write_bytes(b"\x7fELFtest")
    with tarfile.open(deps, "w:gz") as archive:
        for name in ("./usr/sbin/ganesha.nfsd", "usr/sbin/rpc.nfsd"):
            member = tarfile.TarInfo(name)
            member.size, member.mode = 4, 0o755
            archive.addfile(member, io.BytesIO(b"test"))
        link = tarfile.TarInfo("./usr/lib/libtest.so")
        link.type, link.linkname = tarfile.SYMTYPE, "libtest.so.1"
        archive.addfile(link)

    # Incomplete deps must be rejected before bootstrap starts.
    with contextlib.redirect_stderr(io.StringIO()) as errors:
        try:
            bootstrap["check_lane_deps"](argparse.ArgumentParser(), deps)
        except SystemExit as error:
            assert error.code == 2 and "usr/sbin/nfs-proxy" in errors.getvalue()
        else:
            raise AssertionError("incomplete lane deps accepted")

    command = [sys.executable, str(assemble), "--ganesha-deps", str(deps),
               "--proxy", str(proxy), "--out", str(output)]
    subprocess.run(command, check=True, capture_output=True)
    bootstrap["check_lane_deps"](argparse.ArgumentParser(), output)
    with tarfile.open(output) as archive:
        assert archive.extractfile("./usr/sbin/nfs-proxy").read() == proxy.read_bytes()
        assert archive.getmember("./usr/sbin/nfs-proxy").mode == 0o755
        assert archive.extractfile("usr/sbin/rpc.nfsd").read() == b"test"
        assert archive.getmember("./usr/lib/libtest.so").issym()
        assert archive.getmember("./usr/lib/libtest.so").linkname == "libtest.so.1"
    before = output.read_bytes()
    retry = subprocess.run(command, capture_output=True)
    assert retry.returncode == 2 and b"already exists" in retry.stderr
    assert output.read_bytes() == before

    # Parsing must find all three moved lane files without explicit overrides.
    for version in ("3", "4.0", "4.1", "4.2"):
        args = baker["parse_args"]([
            "--base-image", str(proxy), "--kernel", str(proxy), "--ssh-key", str(proxy),
            "--deps-tar", str(output), "--output", str(work / "image.qcow2"),
            "--version", version])
        assert args.version == version
        assert args.lane_script == ROOT / "bundle/lane/lane.sh"
        assert args.boot_fixture == ROOT / "bundle/lane/boot-fixture.sh"
        assert args.service == ROOT / "bundle/lane/fixture.service"

    manager = work / "manager.cfg"
    live = work / "manager-live.cfg"
    manager.write_text(json.dumps({"type": "qemu", "workdir": str(work / "workdir"),
                                   "enable_syscalls": [
                                       "openat$nfs", "syz_open_nfs_lane_profile",
                                       "syz_socket_connect_nfs",
                                       "syz_socket_connect_nfs_pair$client0_knfsd",
                                       "syz_socket_connect_nfs_pair$client0_ganesha",
                                       "syz_send_nfs_fuzz$retry",
                                       "sendmsg$inet_nfs_fuzz_retry_tcp",
                                       "recvfrom$inet_nfs_fuzz_tcp", "close"],
                                   "vm": {"cmdline": "nfs.localio_enabled=N"}}))
    subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                    str(manager), str(live), "--version", "3", "--image", str(proxy)],
                   check=True,
                   capture_output=True)
    prepared = json.loads(live.read_text())
    lane_bytes = (ROOT / "bundle/lane/lane.sh").read_bytes()
    lane_text = lane_bytes.decode()
    assert 'test -s "$status_lane_root/server/lifecycle.pid"' in lane_text
    assert ('pid_in_named_netns "$status_lifecycle_pid" '
            '"$status_server_ns"') in lane_text
    assert "lifecycle admin process identity mismatch" in lane_text
    assert 'pid_owns_unix_socket "$status_lifecycle_pid"' in lane_text
    assert "lifecycle admin does not own its socket" in lane_text
    assert 'server/lifecycle.starttime' in lane_text
    # The broker owns bounded nfsdcld control; status accepts only the exact
    # daemon it last validated, idle, unstopped and holding the CLD pipe.
    assert '--cld-daemon "$cld_daemon"' in lane_text
    assert '--cld-state "$lane_root/server/cld.state"' in lane_text
    assert 'cld_daemon_valid "$status_lane_root/server/cld.state"' in lane_text
    assert "nfsdcld is not the broker-validated idle daemon" in lane_text
    cld_start = lane_text.index("cld_daemon_valid()\n{")
    cld_end = lane_text.index("\n}\n", cld_start) + 3
    cld_function = lane_text[cld_start:cld_end]
    for required in ("state=", "pid_in_named_netns", "ns/mnt", "$22",
                     "nfsdcld ", "rpc_pipefs/nfsd/cld", '"$cld_pipe"',
                     "pgrep -x nfsdcld", 'test "$cld_count" -eq 1',
                     "R|S|D"):
        assert required in cld_function, required

    # Exercise the exact shell ownership helper when the environment permits
    # AF_UNIX binds. A stale pathname and a socket owned by another live PID
    # must not satisfy the expected broker PID.
    function_start = lane_text.index("pid_owns_unix_socket()\n{")
    function_end = lane_text.index("\n}\n", function_start) + 3
    owner_function = lane_text[function_start:function_end]

    def owns_socket(pid, path):
        script = owner_function + '\npid_owns_unix_socket "$1" "$2"\n'
        return subprocess.run(
            ["sh", "-c", script, "socket-owner-test", str(pid), str(path)],
            capture_output=True).returncode == 0

    owned_path = work / "owned.sock"
    owned = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        owned.bind(str(owned_path))
    except PermissionError:
        owned.close()
    else:
        owned.listen(1)
        assert owns_socket(os.getpid(), owned_path)

        stale_path = work / "stale.sock"
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        stale.bind(str(stale_path))
        stale.close()
        assert not owns_socket(os.getpid(), stale_path)

        foreign_path = work / "foreign.sock"
        holder = subprocess.Popen(
            [sys.executable, "-u", "-c",
             "import socket,sys,time; "
             "s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); "
             "s.bind(sys.argv[1]); s.listen(1); print('ready'); time.sleep(30)",
             str(foreign_path)], stdout=subprocess.PIPE, text=True)
        try:
            assert holder.stdout.readline().strip() == "ready"
            assert not owns_socket(os.getpid(), foreign_path)
            assert owns_socket(holder.pid, foreign_path)
        finally:
            holder.terminate()
            holder.wait(timeout=5)
            owned.close()

    lane_sha = hashlib.sha256(lane_bytes).hexdigest()
    assert (Path(prepared["workdir_template"]) / "lane.sh").read_bytes() == lane_bytes
    assert "path={{TEMPLATE}}" in prepared["vm"]["qemu_args"]
    assert "-snapshot" in prepared["vm"]["qemu_args"].split()
    assert "koov.nfs_version=3" in prepared["vm"]["cmdline"]
    assert "koov.lane_sha256=" + lane_sha in prepared["vm"]["cmdline"]
    assert prepared["image"] == str(proxy.resolve())
    assert prepared["workdir"] == str(work / "workdir")
    assert prepared["enable_syscalls"] == [
        "openat$nfs",
        "syz_open_nfs_lane_profile$client0_knfsd_v3",
        "syz_open_nfs_lane_profile$client1_knfsd_v3",
        "syz_socket_connect_nfs",
        "syz_socket_connect_nfs_pair$client0_knfsd",
        "syz_send_nfs_fuzz$retry",
        "sendmsg$inet_nfs_fuzz_retry_tcp",
        "recvfrom$inet_nfs_fuzz_tcp",
        "close",
    ]

    ganesha = work / "manager-ganesha.cfg"
    subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                    str(manager), str(ganesha), "--profile", "ganesha-v41",
                    "--image", str(proxy)], check=True, capture_output=True)
    ganesha_prepared = json.loads(ganesha.read_text())
    assert "koov.nfs_version=4.1" in ganesha_prepared["vm"]["cmdline"]
    assert ganesha_prepared["enable_syscalls"][1:3] == [
        "syz_open_nfs_lane_profile$client0_ganesha_v41",
        "syz_open_nfs_lane_profile$client1_ganesha_v41",
    ]
    assert all(not any(call == prefix or call.startswith(prefix + "$")
                       for prefix in (
                           "syz_socket_connect_nfs", "syz_socket_connect_nfs_pair",
                           "syz_send_nfs_fuzz", "sendmsg$inet_nfs_fuzz",
                           "recvfrom$inet_nfs_fuzz"))
               for call in ganesha_prepared["enable_syscalls"])

    # Proxy target mode: rule sets and sessions ride the lane share, one
    # journal port per lane points at that lane's host sink.
    target_inputs = work / "target-inputs"
    target_inputs.mkdir()
    for lane in range(4):
        (target_inputs / ("lane%d.nfsprul1" % lane)).write_bytes(b"NFSPRUL1 lane %d" % lane)
        (target_inputs / ("lane%d.session" % lane)).write_text("ps-%d\n" % lane)
    target = work / "manager-target.cfg"
    subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                    str(manager), str(target), "--version", "4.1", "--image", str(proxy),
                    "--nfs-target", str(target_inputs),
                    "--journal-socket-dir", str(work / "sinks"), "--qemu-version", "9.2"],
                   check=True, capture_output=True)
    target_prepared = json.loads(target.read_text())
    target_template = Path(target_prepared["workdir_template"])
    assert target_template != Path(prepared["workdir_template"])
    assert (target_template / "lane.sh").read_bytes() == lane_bytes
    for lane in range(4):
        assert (target_template / "target" / ("lane%d.nfsprul1" % lane)).read_bytes() == \
            b"NFSPRUL1 lane %d" % lane
        assert ("chardev=nfspj%d,name=nfsp-journal-%d" % (lane, lane)) in \
            target_prepared["vm"]["qemu_args"]
        assert ("path=%s,reconnect-ms=1000" % (work / "sinks" / ("lane%d.sock" % lane)).resolve()) \
            in target_prepared["vm"]["qemu_args"]
    assert "koov.nfs_target=1" in target_prepared["vm"]["cmdline"].split()
    # Older QEMU only knows reconnect=SECONDS; the version is read from the
    # configured binary unless given.
    fake_qemu = work / "qemu-6.2"
    fake_qemu.write_text("#!/bin/sh\necho 'QEMU emulator version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6)'\n")
    fake_qemu.chmod(0o755)
    old_manager = work / "manager-old-qemu.cfg"
    old_config = json.loads(manager.read_text())
    old_config["vm"]["qemu"] = str(fake_qemu)
    old_manager.write_text(json.dumps(old_config))
    for extra in ([], ["--qemu-version", "6.2"]):
        old_target = work / ("manager-target-old%d.cfg" % len(extra))
        subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                        str(old_manager if not extra else manager), str(old_target),
                        "--version", "4.1", "--image", str(proxy),
                        "--nfs-target", str(target_inputs),
                        "--journal-socket-dir", str(work / "sinks")] + extra,
                       check=True, capture_output=True)
        old_args = json.loads(old_target.read_text())["vm"]["qemu_args"]
        assert "reconnect=1 " in old_args and "reconnect-ms" not in old_args, old_args
    old_config["vm"]["qemu"] = str(work / "no-such-qemu")
    old_manager.write_text(json.dumps(old_config))
    unknown = subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                              str(old_manager), str(work / "unknown.cfg"), "--version", "4.1",
                              "--image", str(proxy), "--nfs-target", str(target_inputs),
                              "--journal-socket-dir", str(work / "sinks")],
                             capture_output=True, text=True)
    assert unknown.returncode != 0 and "pass --qemu-version" in unknown.stderr, unknown.stderr
    assert "koov.lane_sha256=" + lane_sha in target_prepared["vm"]["cmdline"]
    for bad_args, needle in (
            (["--nfs-target", str(target_inputs)], "--journal-socket-dir"),
            (["--journal-socket-dir", str(work)], "--nfs-target"),
            (["--nfs-target", str(work), "--journal-socket-dir", str(work)], "missing target input"),
            (["--qemu-version", "9.2"], "--qemu-version needs --nfs-target"),
            (["--nfs-target", str(target_inputs), "--journal-socket-dir", str(work),
              "--qemu-version", "nine"], "--qemu-version must look like")):
        refused = subprocess.run(
            [sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
             str(manager), str(work / "refused.cfg"), "--version", "4.1",
             "--image", str(proxy)] + bad_args, capture_output=True, text=True)
        assert refused.returncode != 0 and needle in refused.stderr, refused.stderr
    multi = work / "manager-multi.cfg"
    multi.write_text(json.dumps({**json.loads(manager.read_text()),
                                 "vm": {"cmdline": "nfs.localio_enabled=N", "count": 2}}))
    refused = subprocess.run(
        [sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
         str(multi), str(work / "refused.cfg"), "--version", "4.1", "--image", str(proxy),
         "--nfs-target", str(target_inputs), "--journal-socket-dir", str(work / "sinks")],
        capture_output=True, text=True)
    assert refused.returncode != 0 and "vm.count 1" in refused.stderr, refused.stderr

    broad = work / "manager-broad.cfg"
    broad_state = work / "persistent-broad-state"
    subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                    str(manager), str(broad), "--broad-knfsd", "--image", str(proxy),
                    "--state-dir", str(broad_state)],
                   check=True, capture_output=True)
    broad_prepared = json.loads(broad.read_text())
    assert broad_prepared["workdir"] == str(broad_state.resolve() / "workdir")
    assert Path(broad_prepared["workdir_template"]).parent == broad_state.resolve()
    assert "koov.nfs_fixture=broad-knfsd" in broad_prepared["vm"]["cmdline"]
    assert "koov.nfs_version=" not in broad_prepared["vm"]["cmdline"]
    assert "koov.lane_sha256=" + lane_sha in broad_prepared["vm"]["cmdline"]
    assert "-snapshot" in broad_prepared["vm"]["qemu_args"].split()
    broad_calls = [call for call in broad_prepared["enable_syscalls"]
                   if call.startswith("syz_open_nfs_lane_profile")]
    assert len(broad_calls) == 8
    assert all("ganesha" not in call for call in broad_calls)
    assert broad_calls == [
        "syz_open_nfs_lane_profile$client%d_knfsd_%s" % (client, version)
        for version in ("v3", "v40", "v41", "v42") for client in (0, 1)
    ]
    assert "syz_socket_connect_nfs" in broad_prepared["enable_syscalls"]
    assert not any(call.startswith("syz_socket_connect_nfs_pair$") and
                   call.endswith("_ganesha")
                   for call in broad_prepared["enable_syscalls"])

# --skip-build must fail before deleting an incomplete existing checkout.
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    for tree in ("linux", "syzkaller"):
        checkout = work / tree
        checkout.mkdir()
        marker = checkout / "keep"
        marker.write_text("existing data")
        args = argparse.Namespace(target=work, kernel_ref=bootstrap["KERNEL_TAG"],
                                  variants=["kasan"], skip_build=True)
        stage = bootstrap["stage_kernel"] if tree == "linux" else bootstrap["stage_syzkaller"]
        try:
            stage(args, {}, True)
        except RuntimeError as error:
            assert "--skip-build" in str(error)
        else:
            raise AssertionError(f"{tree}: incomplete checkout was accepted")
        assert marker.read_text() == "existing data"

# --skip-build reuses a build only when its recorded series is the checked-in one.
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    bundle = work / "bundle"
    # run_path returns a copy; the functions read their own module globals.
    module = bootstrap["series_fingerprint"].__globals__
    real_bundle = module["BUNDLE"]
    module["BUNDLE"] = bundle
    try:
        def git(tree, *command):
            return subprocess.run(["git", "-C", str(tree), *command], check=True,
                                  capture_output=True, text=True).stdout.strip()

        def make_tree(tree, sentinel, text):
            sentinel = tree / sentinel
            sentinel.parent.mkdir(parents=True)
            git(work, "init", "-q", str(tree))
            for key, value in (("user.email", "t@localhost"), ("user.name", "t")):
                git(tree, "config", key, value)
            (tree / "base").write_text("base")
            git(tree, "add", "base")
            git(tree, "commit", "-qm", "base")
            base = git(tree, "rev-parse", "HEAD")
            sentinel.write_text(text)
            git(tree, "add", ".")
            git(tree, "commit", "-qm", "series")
            return base

        target = work / "env"
        linux, syz = target / "linux", target / "syzkaller"
        kernel_base = make_tree(linux, "include/linux/sunrpc/fuzz.h",
                                "sunrpc_fuzz_svc_remote_grant")
        syz_base = make_tree(syz, "sys/linux/socket_inet_nfs.txt", "syz_send_nfs_fuzz")
        for kind in ("kernel", "syzkaller"):
            (bundle / kind).mkdir(parents=True)
            (bundle / kind / "0001-a.patch").write_text(kind + " v1")
        images = target / "images" / "kasan"
        images.mkdir(parents=True)
        for name in ("bzImage", ".config"):
            (images / name).write_text(name)
        for relative in ("bin/syz-manager", "bin/linux_amd64/syz-executor",
                         "bin/linux_amd64/syz-execprog", "bin/syz-db"):
            (syz / relative).parent.mkdir(parents=True, exist_ok=True)
            (syz / relative).write_text("binary")
        args = argparse.Namespace(target=target, kernel_ref=bootstrap["KERNEL_TAG"],
                                  variants=["kasan"], skip_build=True)
        stages = (("kernel", bootstrap["stage_kernel"], images / "build.json", kernel_base),
                  ("syzkaller", bootstrap["stage_syzkaller"], syz / "bin/build.json",
                   syz_base))

        def refused(stage, needle):
            try:
                stage(args, {}, True)
            except RuntimeError as error:
                assert "--skip-build" in str(error) and needle in str(error), error
            else:
                raise AssertionError("stale build reused")

        # An env from before series tracking carries no record: never reuse it.
        for kind, stage, record_path, base in stages:
            refused(stage, "no build record")

        # A record from the current series is reused, and the manifest reports it.
        for kind, stage, record_path, base in stages:
            tree = linux if kind == "kernel" else syz
            record = bootstrap["build_record"](kind, tree, base)
            assert record["commits"] == 1
            record_path.write_text(json.dumps(record))
            manifest = {}
            stage(args, manifest, True)
            assert manifest[kind]["series_sha256"] == record["series_sha256"]
            assert manifest[kind]["head"] == record["head"]
            assert manifest[kind]["commits"] == 1

        # Changing one patch of the series makes the old build stale.
        for kind, stage, record_path, base in stages:
            (bundle / kind / "0001-a.patch").write_text(kind + " v2")
            refused(stage, "series changed")
    finally:
        module["BUNDLE"] = real_bundle

manifest = json.loads((ROOT / "bundle/corpus/nfs-normal/manifest.json").read_text())
assert manifest["schema"] == 3
assert manifest["purpose"] == "mutation_seed"
assert Path(ROOT / manifest["required_syzkaller_patch"]).is_file()
assert Path(ROOT / manifest["required_syzkaller_validator_patch"]).is_file()
syzkaller_patches = sorted((ROOT / "bundle/patches/syzkaller").glob("*.patch"))
assert len(syzkaller_patches) == 38
assert syzkaller_patches[-1].name.startswith("0040-")
programs = {entry["path"]: entry for entry in manifest["programs"]}
assert len(programs) == len(manifest["programs"]) == 12
for entry in manifest["programs"]:
    source = ROOT / "bundle/corpus/nfs-normal" / entry["path"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["sha256"]
    assert sum(bool(line.strip()) for line in source.read_text().splitlines()) == entry["calls"]
    assert entry["native_profile"] in manifest["profiles"]
    assert entry["backend"] == manifest["profiles"][entry["native_profile"]]["backend"]
    assert entry["native_version"] == manifest["profiles"][entry["native_profile"]]["native_version"]
    if entry["path"] != "nfs3-create-retry-tcp.prog":
        assert "syz_open_nfs_lane_profile$" in source.read_text()

listed = []
for name, profile in manifest["profiles"].items():
    for path in profile["programs"]:
        assert path in programs
        assert programs[path]["native_profile"] == name
        listed.append(path)
assert sorted(listed) == sorted(programs)
broad_profiles = manifest["fixtures"]["broad-knfsd"]["profiles"]
assert broad_profiles == ["knfsd-v3", "knfsd-v40", "knfsd-v41", "knfsd-v42"]
assert manifest["fixtures"]["broad-knfsd"]["automatic_promotion"] is False
assert "ganesha-v41" not in broad_profiles
lane_source = (ROOT / "bundle/lane/lane.sh").read_text()
assert "for trace_group in nfsd lockd sunrpc rpcgss" in lane_source
assert "events/sunrpc/svc_xprt_accept/enable" in lane_source
assert "buffer_size_kb" in lane_source
# NFS tracing is opt-in: off unless boot-fixture maps koov.nfs_trace=1.
assert "nfs_trace=${NFS_TRACE:-0}" in lane_source
assert 'if [ "$nfs_trace" = 1 ]; then' in lane_source
assert lane_source.index('if [ "$nfs_trace" = 1 ]; then') < lane_source.index(
    "for trace_group in nfsd lockd sunrpc rpcgss")
assert '"nfs_trace":%s' in lane_source
boot_source = (ROOT / "bundle/lane/boot-fixture.sh").read_text()
# nlm-knfsd is the NFSv3 single fixture with kernel lockd locking: it is
# selected by name, records its own mode and refuses other versions and a
# missing Ganesha side before touching the host.
assert "broad-knfsd|nlm-knfsd)" in boot_source
assert "NFS_FIXTURE=$fixture_mode" in boot_source
assert 'printf \'%s\\n\' "$fixture_label" > "$root/fixture.mode"' in lane_source
assert "nlm_prepare_host" in lane_source
assert lane_source.index('printf \'%s\\n\' "$fixture_label" > "$root/fixture.mode"') < \
    lane_source.index("        nlm_prepare_host\n")
assert "mount_lock=nolock" in lane_source and "$mount_lock,sec=sys" in lane_source
assert 'nlm_start_client_daemons "$setup_lane_id" 0 "$setup_client0_ns"' in lane_source
assert 'nlm_probe_mount "$setup_lane_root/client1/knfsd"' in lane_source
assert '"nlm_port":%s' in lane_source
for nlm_env, nlm_message in (
        ({"NFS_FIXTURE": "nlm-knfsd", "NFS_VERSION": "4.1"},
         "nlm-knfsd is an NFSv3 fixture"),
        ({"NFS_FIXTURE": "nlm-knfsd", "SERVER_IMPL": "knfsd"},
         "nlm-knfsd requires SERVER_IMPL=both"),
        ({"NFS_FIXTURE": "other"}, "single, broad-knfsd or nlm-knfsd")):
    nlm_result = subprocess.run(
        ["sh", str(ROOT / "bundle/lane/lane.sh"), "status",
         "/tmp/frozen-phase9.nlminputs"],
        env={**os.environ, **nlm_env}, capture_output=True, text=True)
    assert nlm_result.returncode == 2, nlm_result
    assert nlm_message in nlm_result.stderr, nlm_result.stderr
assert "koov.nfs_trace=*) trace=${arg#koov.nfs_trace=} ;;" in boot_source
assert "trace=0\n" in boot_source
# Proxy target mode is opt-in: koov.nfs_target=1 maps the share's target/
# files to NFS_PROXY_TARGET_DIR, which swaps the legacy arm socket for the
# rule set, journal port and executor activation endpoint.
assert "koov.nfs_target=*) target=${arg#koov.nfs_target=} ;;" in boot_source
assert "target=0\n" in boot_source
assert "NFS_PROXY_TARGET_DIR=/run/frozen-phase9/target" in boot_source
assert boot_source.index("NFS_PROXY_TARGET_DIR=/run/frozen-phase9/target") < \
    boot_source.index('umount "$source_dir"\nactual_sha')
assert "proxy_target_dir=${NFS_PROXY_TARGET_DIR:-}" in lane_source
assert "export proxy_target_dir" in lane_source
assert '--activation "$executor_root/proc-$lane/activation/activation.sock"' in lane_source
assert '--journal "/dev/virtio-ports/nfsp-journal-$lane"' in lane_source
assert '"$executor_root/proc-$setup_lane_id/activation/rule_set_id"' in lane_source
# The server namespace replaces /run, so the proxy reads its inputs from the
# lane root, and every Proxy start gets a fresh session in the host series.
assert 'cp "$setup_rules" "$setup_lane_root/server/target/rules.nfsprul1"' in lane_source
assert lane_source.index('cp "$setup_rules" "$setup_lane_root/server/target/rules.nfsprul1"') < \
    lane_source.index('mount --bind "$lane_root/server/state/run" /run')
assert '--target "$lane_root/server/target/rules.nfsprul1"' in lane_source
assert '$(cat /proc/sys/kernel/random/uuid)' in lane_source
assert '--session-id "$proxy_session"' in lane_source
assert '$proxy_target_dir/lane$lane' not in lane_source
assert 'printf \'%s\\n\' "$proxy_target_dir" > "$root/fixture.target"' in lane_source
assert 'proxy_target_dir=$(cat "$root/fixture.target")' in lane_source
assert manifest["fixtures"]["broad-knfsd"]["mixed_profile_runtime"] == "allowed"
assert manifest["fixtures"]["broad-knfsd"]["promotion_policy"] == {
    "nfs_root_required": True,
    "single_profile_required": True,
    "matching_single_fixture_replay_required": True,
}

builder = runpy.run_path(str(ROOT / "tools/build-normal-corpus.py"))
selected, description = builder["select_programs"](
    argparse.ArgumentParser(), manifest, programs, None, "broad-knfsd")
assert len(selected) == 11
assert description["profiles"] == broad_profiles
assert "basic-v41-ganesha-tcp.prog" not in selected

auditor = runpy.run_path(str(ROOT / "tools/audit-normal-corpus.py"))
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    renamed_db = work / "corpus.db.preserved-copy"
    renamed_db.write_bytes((0xBADDB).to_bytes(4, "little") + b"preserved")
    assert auditor["is_corpus_db"](renamed_db)
    single = work / "single.prog"
    single.write_text(
        "r0 = syz_open_nfs_lane_profile$client0_knfsd_v41(0x2, 0x0)\n"
        "r1 = openat$nfs(r0, 0x0, 0x0, 0x0)\n")
    assert not auditor["is_corpus_db"](single)
    digest = hashlib.sha256(single.read_bytes()).hexdigest()
    result = auditor["inspect"](
        single, broad_profiles, "knfsd-v41", {digest: True})
    assert result["runtime_admissible"] and result["promotion_ready"]

    mixed = work / "mixed.prog"
    mixed.write_text(
        "r0 = syz_open_nfs_lane_profile$client0_knfsd_v40(0x1, 0x0)\n"
        "r1 = syz_open_nfs_lane_profile$client1_knfsd_v42(0x3, 0x1)\n")
    result = auditor["inspect"](mixed, broad_profiles, None, {})
    assert result["runtime_admissible"] and result["mixed_profiles"]
    result = auditor["inspect"](mixed, ["knfsd-v42"], "knfsd-v42", {})
    assert not result["promotion_ready"] and "mixed_profiles" in result["reasons"]

    no_root = work / "no-root.prog"
    no_root.write_text("r0 = openat(0xffffffffffffff9c, 0x0, 0x0, 0x0)\n")
    result = auditor["inspect"](no_root, broad_profiles, None, {})
    assert not result["runtime_admissible"] and result["reasons"] == ["no_nfs_root"]

    ganesha_seed = ROOT / "bundle/corpus/nfs-normal/basic-v41-ganesha-tcp.prog"
    result = auditor["inspect"](ganesha_seed, broad_profiles, None, {})
    assert not result["runtime_admissible"]
    assert result["disallowed_profiles"] == ["ganesha-v41"]

    raw_ganesha = work / "raw-ganesha.prog"
    raw_ganesha.write_text(
        "r0 = syz_socket_connect_nfs_pair$client0_ganesha(0x0, 0x1)\n")
    result = auditor["inspect"](raw_ganesha, broad_profiles, None, {})
    assert not result["runtime_admissible"]
    assert "disallowed_raw_backend" in result["reasons"]

    raw_knfsd = work / "raw-knfsd.prog"
    raw_knfsd.write_text("r0 = syz_socket_connect_nfs$client0(0x0)\n")
    assert auditor["inspect"](
        raw_knfsd, ["knfsd-v3"], None, {})["runtime_admissible"]
    result = auditor["inspect"](raw_knfsd, ["knfsd-v42"], None, {})
    assert not result["runtime_admissible"]
    assert "raw_root_not_allowed" in result["reasons"]

    report_results = [
        auditor["inspect"](single, broad_profiles, None, {}),
        auditor["inspect"](mixed, broad_profiles, None, {}),
        auditor["inspect"](no_root, broad_profiles, None, {}),
    ]
    assert sum(bool(item["profiles"]) and item["raw_roots"] == 0
               for item in report_results) == 2

print("PASS: lane deps, fixture modes, and profile-aware mutation corpus")
