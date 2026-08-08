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


class TestIntelConfig:
    def test_denylist_and_zeek_declare_their_own_mmdb_tables(self) -> None:
        config = yaml.safe_load(build_config("1.0", denylist=True, zeek=True))
        tables = config["enrichment_tables"]
        assert tables["sagan_denylist"]["type"] == "mmdb"
        assert tables["sagan_zeek_intel"]["type"] == "mmdb"
        transforms = config["transforms"]
        assert "sagan_denylist" in transforms
        assert "sagan_zeek_intel" in transforms

    def test_only_requested_tables_appear(self) -> None:
        config = yaml.safe_load(build_config("1.0", denylist=True))
        assert "sagan_denylist" in config["enrichment_tables"]
        assert "sagan_zeek_intel" not in config["enrichment_tables"]

    def test_all_optionals_together_chain_and_validate(self) -> None:
        config = yaml.safe_load(
            build_config("1.0", geoip=True, denylist=True, zeek=True, time=True)
        )
        # Every optional transform is present and the sink still ends the chain.
        for name in ("sagan_geoip", "sagan_denylist", "sagan_zeek_intel", "sagan_time"):
            assert name in config["transforms"]
        assert config["sinks"]["rsigma"]["inputs"] == ["sagan_username"]
        assert set(config["enrichment_tables"]) == {
            "sagan_geoip",
            "sagan_denylist",
            "sagan_zeek_intel",
        }


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
