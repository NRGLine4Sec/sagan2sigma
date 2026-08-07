"""Tests for the emitted Vector pipeline, base and GeoIP-enabled."""

from __future__ import annotations

from pathlib import Path

import yaml

from sagan2sigma.emit.vector import build_config, write_pipeline


class TestBaseConfig:
    def test_chains_transforms_in_order(self) -> None:
        config = yaml.safe_load(build_config("1.0"))
        assert config["transforms"]["sagan_parse_ip"]["inputs"] == ["appliances"]
        assert config["transforms"]["sagan_username"]["inputs"] == ["sagan_parse_ip"]
        assert config["sinks"]["rsigma"]["inputs"] == ["sagan_username"]

    def test_no_geoip_without_country_rules(self) -> None:
        config = yaml.safe_load(build_config("1.0"))
        assert "enrichment_tables" not in config
        assert "sagan_geoip" not in config["transforms"]


class TestGeoipConfig:
    def test_declares_a_provider_agnostic_mmdb_table(self) -> None:
        config = yaml.safe_load(build_config("1.0", geoip=True))
        table = config["enrichment_tables"]["sagan_geoip"]
        # The mmdb type returns the raw record, so any provider's MMDB works;
        # the geoip type would hard-code the MaxMind schema.
        assert table["type"] == "mmdb"
        assert table["path"].endswith(".mmdb")

    def test_geoip_transform_sits_after_ip_parsing(self) -> None:
        config = yaml.safe_load(build_config("1.0", geoip=True))
        transforms = config["transforms"]
        assert transforms["sagan_geoip"]["inputs"] == ["sagan_parse_ip"]
        assert transforms["sagan_username"]["inputs"] == ["sagan_geoip"]
        assert config["sinks"]["rsigma"]["inputs"] == ["sagan_username"]

    def test_valid_yaml_either_way(self) -> None:
        assert yaml.safe_load(build_config("1.0")) is not None
        assert yaml.safe_load(build_config("1.0", geoip=True)) is not None


class TestWritePipeline:
    def test_writes_base_transforms(self, tmp_path: Path) -> None:
        written = write_pipeline(tmp_path, "1.0")
        names = {p.name for p in written}
        assert "vector.yaml" in names
        assert "sagan-parse-ip.vrl" in names
        assert "sagan-geoip.vrl" not in names

    def test_geoip_ships_the_transform(self, tmp_path: Path) -> None:
        written = write_pipeline(tmp_path, "1.0", geoip=True)
        assert (tmp_path / "transforms" / "sagan-geoip.vrl").read_text()
        assert (tmp_path / "transforms" / "sagan-geoip.vrl") in written
        assert "enrichment_tables" in (tmp_path / "vector.yaml").read_text()
