#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Bind a transferred amd64 image to this run's complete multiarch build."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest


def digest(stream):
    value = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        value.update(chunk)
    return "sha256:" + value.hexdigest()


def file_digest(path):
    with Path(path).open("rb") as stream:
        return digest(stream)


class Archive:
    def __init__(self, path):
        self.tar = tarfile.open(path, "r:*")
        self.members = {}
        for entry in self.tar:
            if entry.name in self.members:
                raise ValueError("duplicate image archive member")
            if entry.isfile():
                self.members[entry.name] = entry

    def close(self):
        self.tar.close()

    def read(self, name):
        # Read named regular members only; never extract paths or links.
        with self.tar.extractfile(self.members[name]) as stream:
            return stream.read()

    def blob(self, descriptor):
        value = descriptor["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("unsupported OCI digest")
        raw = self.read("blobs/sha256/" + value[7:])
        if len(raw) != descriptor["size"] or digest(io.BytesIO(raw)) != value:
            raise ValueError("OCI metadata digest/size mismatch")
        return json.loads(raw)

    def verify_layer(self, descriptor):
        value = descriptor["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("unsupported layer digest")
        member = self.members["blobs/sha256/" + value[7:]]
        with self.tar.extractfile(member) as stream:
            if member.size != descriptor["size"] or digest(stream) != value:
                raise ValueError("OCI layer bytes do not match their descriptor")


def config_identity(config, sha, component, edition, platform):
    labels = config.get("config", {}).get("Labels", {})
    if (config.get("os"), config.get("architecture")) != tuple(platform.split("/")):
        raise ValueError("image platform differs from its declared platform")
    expected = {"org.opencontainers.image.revision": sha, "org.probectl.component": component, "org.probectl.edition": edition}
    if any(labels.get(key) != value for key, value in expected.items()):
        raise ValueError("image source/component/edition identity differs")


def docker_identity(path, sha, component, edition):
    archive = Archive(path)
    try:
        manifests = json.loads(archive.read("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("transfer must contain exactly one single-platform image")
        manifest = manifests[0]
        tag = f"probectl/{component}:ci"
        tags = manifest.get("RepoTags", [])
        if not tags or any(value not in {tag, "docker.io/" + tag} for value in tags):
            raise ValueError("unexpected transferred image tags")
        raw = archive.read(manifest["Config"])
        config = json.loads(raw)
        config_identity(config, sha, component, edition, "linux/amd64")
        layers = manifest["Layers"]
        if len(layers) != len(config["rootfs"]["diff_ids"]):
            raise ValueError("image layer list is incomplete")
        if any(layer not in archive.members or not archive.members[layer].size for layer in layers):
            raise ValueError("image layer bytes are missing")
        return {"image_id": digest(io.BytesIO(raw)), "tag": tag, "tar_sha256": file_digest(path)}
    finally:
        archive.close()


def produce(oci, docker, sha, component, edition, run_id, attempt):
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[a-z0-9-]+", component) or edition not in {"core", "ee"}:
        raise ValueError("invalid image build identity")
    archive = Archive(oci)
    try:
        if json.loads(archive.read("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("unsupported OCI layout")
        index = json.loads(archive.read("index.json"))
        platforms = {}
        attestations = []

        def visit(descriptor):
            value = archive.blob(descriptor)
            if "manifests" in value:
                for child in value["manifests"]:
                    visit(child)
                return
            if descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                attestations.append({"descriptor": descriptor, "manifest": value, "contents": [archive.blob(layer) for layer in value["layers"]]})
                return
            config = archive.blob(value["config"])
            platform = config["os"] + "/" + config["architecture"]
            if platform not in {"linux/amd64", "linux/arm64"} or platform in platforms:
                raise ValueError("unexpected or repeated multiarch platform")
            config_identity(config, sha, component, edition, platform)
            if len(value["layers"]) != len(config["rootfs"]["diff_ids"]):
                raise ValueError("OCI layer list is incomplete")
            for layer in value["layers"]:
                archive.verify_layer(layer)
            declared = descriptor.get("platform", {})
            if declared.get("os") != config["os"] or declared.get("architecture") != config["architecture"]:
                raise ValueError("OCI descriptor/config platform mismatch")
            platforms[platform] = {"descriptor": descriptor, "manifest": value, "config": config}

        for descriptor in index["manifests"]:
            visit(descriptor)
        if set(platforms) != {"linux/amd64", "linux/arm64"}:
            raise ValueError("complete amd64 and arm64 build is required")
        transferred = docker_identity(docker, sha, component, edition)
        if transferred["image_id"] != platforms["linux/amd64"]["manifest"]["config"]["digest"]:
            raise ValueError("transfer is not the exact multiarch amd64 image")
        return {"schema_version": 1, "sha": sha, "component": component, "edition": edition, "run_id": run_id, "producer_attempt": attempt, "docker": transferred, "oci": {"tar_sha256": file_digest(oci), "index": index, "platforms": platforms, "attestations": attestations}}
    finally:
        archive.close()


def validate_transfer(proof, docker, sha, component, edition, run_id, attempt):
    expected = {"schema_version": 1, "sha": sha, "component": component, "edition": edition, "run_id": run_id}
    if any(proof.get(key) != value for key, value in expected.items()) or not 1 <= proof.get("producer_attempt", 0) <= attempt:
        raise ValueError("image receipt belongs to a different source/run/component/edition")
    actual = docker_identity(docker, sha, component, edition)
    if actual != proof["docker"] or actual["image_id"] != proof["oci"]["platforms"]["linux/amd64"]["manifest"]["config"]["digest"]:
        raise ValueError("transferred image differs from the sealed build receipt")
    if set(proof["oci"]["platforms"]) != {"linux/amd64", "linux/arm64"}:
        raise ValueError("multiarch receipt is incomplete")
    return actual


class ImageTests(unittest.TestCase):
    def fixture(self, root, arches=("amd64", "arm64"), revision="a" * 40):
        blobs = {}

        def blob(value):
            raw = json.dumps(value, sort_keys=True).encode()
            hashed = digest(io.BytesIO(raw))
            blobs["blobs/sha256/" + hashed[7:]] = raw
            return {"digest": hashed, "size": len(raw)}

        manifests = []
        for arch in arches:
            config = {"os": "linux", "architecture": arch, "rootfs": {"diff_ids": ["sha256:" + "c" * 64]}, "config": {"Labels": {"org.opencontainers.image.revision": revision, "org.probectl.component": "probectl-control", "org.probectl.edition": "core"}}}
            descriptor = blob(config)
            layer = blob({"fixture_layer": arch})
            manifest = blob({"schemaVersion": 2, "config": descriptor, "layers": [layer]})
            manifest["platform"] = {"os": "linux", "architecture": arch}
            manifests.append(manifest)
            if arch == "amd64":
                docker = {"manifest.json": json.dumps([{"Config": "config.json", "RepoTags": ["probectl/probectl-control:ci"], "Layers": ["layer.tar"]}]).encode(), "config.json": blobs["blobs/sha256/" + descriptor["digest"][7:]], "layer.tar": b"fixture layer"}

        def write(path, files):
            with tarfile.open(path, "w") as archive:
                for name, raw in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))

        oci_path, docker_path = Path(root)/"oci.tar", Path(root)/"image.tar"
        write(oci_path, dict(blobs, **{"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": json.dumps({"manifests": manifests}).encode()}))
        write(docker_path, docker)
        return oci_path, docker_path

    def test_exact_transfer_keeps_both_platforms_and_original_run_identity(self):
        with tempfile.TemporaryDirectory() as root:
            oci, docker = self.fixture(root)
            proof = produce(oci, docker, "a" * 40, "probectl-control", "core", 123, 1)
            self.assertEqual(set(proof["oci"]["platforms"]), {"linux/amd64", "linux/arm64"})
            self.assertEqual(validate_transfer(proof, docker, "a" * 40, "probectl-control", "core", 123, 2), proof["docker"])
            for sha, component, edition, run in [("b" * 40, "probectl-control", "core", 123), ("a" * 40, "probectl-agent", "core", 123), ("a" * 40, "probectl-control", "ee", 123), ("a" * 40, "probectl-control", "core", 124)]:
                with self.assertRaises(ValueError):
                    validate_transfer(proof, docker, sha, component, edition, run, 1)
            with docker.open("ab") as stream:
                stream.write(b"replaced bytes")
            with self.assertRaises(ValueError):
                validate_transfer(proof, docker, "a" * 40, "probectl-control", "core", 123, 1)

    def test_docker_transfer_never_substitutes_for_missing_arm64_or_source(self):
        with tempfile.TemporaryDirectory() as root:
            oci, docker = self.fixture(root, arches=("amd64",))
            with self.assertRaisesRegex(ValueError, "complete amd64 and arm64"):
                produce(oci, docker, "a" * 40, "probectl-control", "core", 123, 1)
            oci, docker = self.fixture(root, revision="b" * 40)
            with self.assertRaisesRegex(ValueError, "source/component/edition"):
                produce(oci, docker, "a" * 40, "probectl-control", "core", 123, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=["produce", "load"])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--oci", type=Path)
    parser.add_argument("--docker", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--component")
    parser.add_argument("--edition", default="core", choices=["core", "ee"])
    parser.add_argument("--tag")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.selftest:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ImageTests))
        return 0 if result.wasSuccessful() else 1
    sha, run_id, attempt = os.environ["GITHUB_SHA"], int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    if args.mode == "produce":
        proof = produce(args.oci, args.docker, sha, args.component, args.edition, run_id, attempt)
    elif args.mode == "load":
        proof = json.loads(args.receipt.read_text())
        image = validate_transfer(proof, args.docker, sha, args.component, args.edition, run_id, attempt)
        if not re.fullmatch(r"probectl/[a-z0-9-]+:(scan|e2e)", args.tag or ""):
            raise ValueError("unsupported consumer tag")
        subprocess.run(["docker", "load", "--input", str(args.docker)], check=True)
        actual = json.loads(subprocess.check_output(["docker", "image", "inspect", image["image_id"]], text=True))[0]
        if actual["Id"] != image["image_id"] or (actual["Os"], actual["Architecture"]) != ("linux", "amd64"):
            raise ValueError("loaded image identity/platform differs")
        subprocess.run(["docker", "tag", image["image_id"], args.tag], check=True)
        proof = {"sha": sha, "run_id": run_id, "consumer_attempt": attempt, "producer_attempt": proof["producer_attempt"], "image_id": image["image_id"], "tar_sha256": image["tar_sha256"], "tag": args.tag, "loaded": True}
    else:
        parser.error("select produce or load")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({"mode": args.mode, "sha": sha, "component": args.component, "receipt": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
