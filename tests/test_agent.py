"""Tests for agent/humlab_agents.py. Run: python3 -m unittest discover -s tests"""

import argparse
import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))
import humlab_agents as ha  # noqa: E402

DIRECTORY_LABEL = "com.docker.compose.project.working_dir"


class ReadUserFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def test_reads_a_regular_file(self):
        Path(self.path("a")).write_text("hello")
        self.assertEqual(ha.read_user_file(self.path("a")), "hello")

    def test_caps_the_read(self):
        Path(self.path("a")).write_text("x" * 5000)
        self.assertEqual(len(ha.read_user_file(self.path("a"), limit=100)), 100)

    def test_refuses_a_symlink_to_dev_zero(self):
        os.symlink("/dev/zero", self.path("env"))
        with self.assertRaises(OSError):
            ha.read_user_file(self.path("env"))

    def test_refuses_a_symlink_to_a_regular_file(self):
        Path(self.path("a")).write_text("x")
        os.symlink(self.path("a"), self.path("b"))
        with self.assertRaises(OSError):
            ha.read_user_file(self.path("b"))

    def test_refuses_a_fifo_without_blocking(self):
        os.mkfifo(self.path("fifo"))
        with self.assertRaises(OSError):
            ha.read_user_file(self.path("fifo"))

    def test_compose_project_name_survives_a_hostile_env_file(self):
        Path(self.path("compose.yaml")).write_text("name: shop\n")
        os.symlink("/dev/zero", self.path(".env"))
        self.assertIn("shop", ha.declared_project_names(self.dir.name))

    def test_compose_project_name_survives_a_fifo_env_file(self):
        os.mkfifo(self.path(".env"))
        ha.declared_project_names(self.dir.name)

    def test_unit_with_hostile_dropins_is_still_parsed(self):
        unit = self.path("web.container")
        Path(unit).write_text("[Container]\nEnvironmentFile=/srv/web/.env\n")
        os.mkdir(unit + ".d")
        os.mkfifo(os.path.join(unit + ".d", "10-fifo.conf"))
        os.symlink("/dev/zero", os.path.join(unit + ".d", "20-zero.conf"))
        with mock.patch.object(ha.pwd, "getpwnam", return_value=SimpleNamespace(pw_dir="/srv/web", pw_uid=1000)):
            self.assertEqual(ha.host_paths(unit, "web"), ["/srv/web/.env"])


class Registry(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        for attr, name in (("REGISTRY", "services.conf"), ("IGNORED", "ignored.conf")):
            patcher = mock.patch.object(ha, attr, Path(self.dir.name, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def container(self, name, labels):
        return {"id": "a" * 64, "name": name, "image": "img", "image_id": "i", "labels": labels}

    def discover(self, containers):
        listed = {("podman", ha.pwd.getpwuid(os.getuid()).pw_name): containers}
        with mock.patch.object(ha, "running_containers", return_value=listed), \
                mock.patch.object(ha, "quadlet_users", return_value=[]), \
                mock.patch.object(ha, "find_compose_dirs", return_value=[]), \
                mock.patch.dict(os.environ, {"SERVICE_DISCOVERY": "auto"}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return ha.cmd_services(argparse.Namespace(auto=True))

    def test_label_with_newline_cannot_add_a_section(self):
        evil = self.container("evil", {"com.docker.compose.project": "x]\n[visp", DIRECTORY_LABEL: self.dir.name})
        self.assertEqual(self.discover([evil]), 0)
        names = [s.name for s in ha.load_registry()]
        self.assertNotIn("visp", names)
        self.assertNotIn("x]\n[visp", names)
        # The file must still load as a whole.
        import configparser
        configparser.ConfigParser(interpolation=None).read(ha.REGISTRY)

    def test_working_dir_with_newline_is_ignored(self):
        evil = self.container("evil", {"com.docker.compose.project": "ok", DIRECTORY_LABEL: "/srv/a\n[visp]"})
        self.assertEqual(self.discover([evil]), 0)
        self.assertNotIn("visp", [s.name for s in ha.load_registry()])

    def test_save_registry_drops_invalid_names(self):
        good = ha.Service("good", "container", "podman", "root", "", container="c")
        bad = ha.Service("a]\n[b", "container", "podman", "root", "", container="c")
        evil_value = ha.Service("fine", "compose", "podman", "root", "/srv/x\n[b]")
        with contextlib.redirect_stderr(io.StringIO()):
            ha.save_registry([good, bad, evil_value])
        self.assertEqual([s.name for s in ha.load_registry()], ["good"])

    def test_load_registry_skips_invalid_section_names(self):
        ha.REGISTRY.write_text("[Bad Name]\ndeployment = compose\n[good]\ndeployment = compose\n")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual([s.name for s in ha.load_registry()], ["good"])

    def test_clean_name_always_satisfies_name_re(self):
        for raw in ("x]\n[visp", "_x", "...", "", "ÅÄÖ", "A B", "web_1"):
            self.assertRegex(ha.clean_name(raw, "fallback"), ha.NAME_RE)
        self.assertRegex(ha.clean_name("", "_bad"), ha.NAME_RE)


class Inventory(unittest.TestCase):
    def test_rows_carry_the_owners_uid(self):
        # Vector accepts a registered container's lines only from this uid.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        me = ha.pwd.getpwuid(os.getuid())
        svc = ha.Service("web", "compose", "podman", me.pw_name, "/srv/web")
        svc.containers = [{"id": "1" * 64, "name": "web-1", "image": "nginx", "labels": {}}]
        inventory = Path(tmp.name, "inventory.csv")
        with mock.patch.object(ha, "INVENTORY", inventory), \
                mock.patch.object(ha, "load_registry", return_value=[svc]), \
                mock.patch.object(ha, "attach_containers"), \
                contextlib.redirect_stderr(io.StringIO()):
            ha.cmd_inventory(argparse.Namespace(no_reload=True))
        self.assertEqual(inventory.read_text().splitlines(),
                         ["container_id,container_name,service,image,owner_uid",
                          f"{'1' * 64},web-1,web,nginx,{me.pw_uid}"])


class RunAs(unittest.TestCase):
    def test_service_user_commands_get_no_terminal_and_a_new_session(self):
        with mock.patch.object(ha.subprocess, "run") as run:
            ha.run_as("root", ["true"])
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["stdin"], ha.subprocess.DEVNULL)
        self.assertTrue(kwargs["start_new_session"])


class ScanImage(unittest.TestCase):
    def fake_user(self, name):
        return SimpleNamespace(pw_name=name, pw_uid=4242, pw_gid=4242)

    def run_scan(self, rootless):
        seen = {}
        chowns = []
        svc = ha.Service("web", "compose" if not rootless else "quadlet", "podman" if rootless else "docker",
                         "web" if rootless else "root", "/srv/web")
        container = {"image": "img:1", "image_id": "sha", "name": "c", "labels": {}}

        def fake_run_as(owner, argv, env=None, **kwargs):
            if "save" in argv:
                archive = argv[argv.index("-o") + 1]
                Path(archive).write_bytes(b"tar")
                seen["tmp_mode"] = stat.S_IMODE(os.stat(os.path.dirname(archive)).st_mode)
                seen["tmp"] = os.path.dirname(archive)
                return SimpleNamespace(stdout="")
            seen["syft_env"] = env
            return SimpleNamespace(stdout='{"components": []}')

        def fake_chown(path, uid, gid, **kwargs):
            chowns.append((path, kwargs.get("follow_symlinks", True)))

        with mock.patch.object(ha.pwd, "getpwnam", side_effect=self.fake_user), \
                mock.patch.object(ha.os, "chown", side_effect=fake_chown), \
                mock.patch.object(ha, "run_as", side_effect=fake_run_as):
            ha.scan_image(svc, container)
        return seen, chowns

    def test_root_saved_archive_is_chowned_without_following_symlinks(self):
        seen, chowns = self.run_scan(rootless=False)
        archive = [c for c in chowns if c[0].endswith("image.tar")]
        self.assertEqual(len(archive), 1)
        self.assertIs(archive[0][1], False)
        # The scanner owns nothing it could plant a symlink in next to the archive.
        self.assertEqual([c[0] for c in chowns if not c[0].endswith("image.tar")],
                         [os.path.join(seen["tmp"], "work")])
        self.assertEqual(seen["tmp_mode"], 0o711)
        self.assertEqual(seen["syft_env"]["TMPDIR"], os.path.join(seen["tmp"], "work"))

    def test_rootless_scan_uses_the_owners_directory(self):
        seen, chowns = self.run_scan(rootless=True)
        self.assertEqual(len(chowns), 1)
        self.assertEqual(chowns[0][0], seen["tmp"])


if __name__ == "__main__":
    unittest.main()
