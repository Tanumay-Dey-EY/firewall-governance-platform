# benchmark_loader.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Callable, Any, List, Optional
# A control is evaluated by a rule function: rule(ctx) -> dict
RuleFn = Callable[[Dict[str, Any]], Dict[str, Any]]
@dataclass
class ControlDef:
   control_id: str
   category: str
   name: str
   weight: int
   level: str  # L1/L2 etc (optional)
   rule_key: str  # maps to a rule function
@dataclass
class BenchmarkPack:
   pack_id: str
   pack_name: str
   pack_version: str
   family: str  # "7.0.x" / "7.4.x"
   selection: str  # "auto" / "manual"
   controls: List[ControlDef]
   rules: Dict[str, RuleFn]
def _import_pack(module_path: str) -> BenchmarkPack:
   mod = __import__(module_path, fromlist=["PACK"])
   return getattr(mod, "PACK")
def list_supported_packs() -> Dict[str, str]:
   # key -> import path
   return {
       "7.0.x|v1.2.0": "benchmark_packs.cis_fgt_7_0_v1_2",
       "7.0.x|v1.3.0": "benchmark_packs.cis_fgt_7_0_v1_3",
       "7.0.x|v1.4.0": "benchmark_packs.cis_fgt_7_0_v1_4",
       "7.4.x|v1.0.0": "benchmark_packs.cis_fgt_7_4_v1_0_0",
       "7.4.x|v1.0.1": "benchmark_packs.cis_fgt_7_4_v1_0_1",
   }
def detect_branch(version: str) -> str:
   import re
   m = re.match(r"^\s*(\d+)\.(\d+)\.", str(version).strip())
   if not m:
       return "unknown"
   major = int(m.group(1))
   minor = int(m.group(2))
   return f"{major}.{minor}"
def auto_select_pack(fw_version: str) -> tuple[str, str]:
   """
   Returns (family, version)
   """
   branch = detect_branch(fw_version)
   if branch == "7.0":
       return ("7.0.x", "v1.4.0")
   if branch == "7.4":
       return ("7.4.x", "v1.0.1")
   # fallback
   return ("7.0.x", "v1.4.0")
def load_pack(
   fw_version: str,
   benchmark_family: str = "Auto (from firmware)",
   benchmark_version: str = "Auto",
) -> BenchmarkPack:
   mapping = list_supported_packs()
   if benchmark_family.startswith("Auto"):
       fam, ver = auto_select_pack(fw_version)
       key = f"{fam}|{ver}"
       pack = _import_pack(mapping[key])
       pack.selection = "auto"
       return pack
   # UI values: "FortiOS 7.0.x" / "FortiOS 7.4.x"
   fam = "7.0.x" if "7.0" in benchmark_family else "7.4.x"
   ver = benchmark_version if benchmark_version and benchmark_version != "Auto" else ("v1.4.0" if fam == "7.0.x" else "v1.0.1")
   key = f"{fam}|{ver.replace(' (Archive)','')}".strip()
   if key not in mapping:
       # fallback to auto if unsupported
       fam2, ver2 = auto_select_pack(fw_version)
       pack = _import_pack(mapping[f"{fam2}|{ver2}"])
       pack.selection = "auto"
       return pack
   pack = _import_pack(mapping[key])
   pack.selection = "manual"
   return pack