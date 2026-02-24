import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple
# -------------------------
# Parsing Helpers
# -------------------------
def extract_block(section_header: str, text: str) -> str:
   m = re.search(rf"(?ms)^{re.escape(section_header)}\s*(.*?)^end\s*$", text)
   return m.group(0) if m else ""
def parse_kv_block(block: str) -> Dict[str, str]:
   d = {}
   for line in block.splitlines():
       line = line.strip()
       if line.startswith("set "):
           parts = line.split(None, 2)
           if len(parts) == 3:
               d[parts[1]] = parts[2].strip()
   return d
def parse_config_edit_block(section_header: str, text: str) -> Dict[str, Dict[str, str]]:
   """
   Parse:
   config X
     edit "name" / edit 1
       set k v
     next
   end
   """
   block = extract_block(section_header, text)
   if not block:
       return {}
   items: Dict[str, Dict[str, str]] = {}
   cur_key = None
   cur: Dict[str, str] = {}
   for raw in block.splitlines():
       line = raw.strip()
       if line.startswith("edit "):
           if cur_key is not None:
               items[cur_key] = cur
           cur_key = line[5:].strip().strip('"')
           cur = {}
       elif line.startswith("set ") and cur_key is not None:
           parts = line.split(None, 2)
           if len(parts) == 3:
               cur[parts[1]] = parts[2].strip()
       elif line == "next":
           if cur_key is not None:
               items[cur_key] = cur
               cur_key = None
               cur = {}
       elif line == "end":
           break
   if cur_key is not None:
       items[cur_key] = cur
   return items
def norm_list_val(v) -> List[str]:
   if not v:
       return []
   tokens = re.findall(r'"([^"]+)"|(\S+)', str(v))
   return [a if a else b for a, b in tokens]
def is_all(vals: List[str]) -> bool:
   return any(x.lower() == "all" for x in (vals or []))
def has_utm(p: Dict[str, str]) -> bool:
   keys = [
       "av-profile", "ips-sensor", "webfilter-profile",
       "application-list", "ssl-ssh-profile", "profile-protocol-options"
   ]
   return any(k in p and p.get(k) not in (None, "", "0", "\"\"") for k in keys)
# -------------------------
# Firmware Extraction (MATCHES YOUR HEADER)
# -------------------------
def extract_firmware_info(text: str) -> Tuple[str, str, str]:
   """
   Returns (platform, version, build) from FortiGate config export headers.
   Your header example:
     #config-version=FGVMGC-7.00-FW-build2829-000000:...
     #version=700
     #build=2829
     #platform=FORTIGATE-VM64-GCP
   """
   # Platform
   platform = "Unknown"
   m = re.search(r'(?mi)^#platform=(.+)$', text)
   if m:
       platform = m.group(1).strip()
   else:
       # fallback inference
       if re.search(r"FORTIGATE-VM|FGVM", text, re.IGNORECASE):
           platform = "FORTIGATE-VM"
   # Build
   build = "Unknown"
   m = re.search(r'(?mi)^#build=(\d+)\s*$', text)
   if m:
       build = m.group(1)
   else:
       m = re.search(r'(?i)build0*(\d+)', text)
       if m:
           build = m.group(1)
   # Version
   version = "Unknown"
   # 1) From config-version: FGVMGC-7.00-FW-build2829
   m = re.search(r'(?mi)^#config-version=.*?-(\d+\.\d+)-FW-build', text)
   if m:
       raw = m.group(1)  # e.g. 7.00
       major, minor2 = raw.split(".")
       minor = str(int(minor2))  # "00" -> "0"
       version = f"{major}.{minor}.0"
       return platform, version, build
   # 2) From #version=700 => 7.0.0
   m = re.search(r'(?mi)^#version=(\d+)\s*$', text)
   if m:
       v = m.group(1).strip()
       if len(v) == 3:
           version = f"{v[0]}.{v[1]}.{v[2]}"  # 700 -> 7.0.0
       elif len(v) == 4:
           version = f"{v[0]}.{v[1]}.{v[2:]}"  # 7021 -> 7.0.21
       else:
           version = v
       return platform, version, build
   # 3) Generic fallback: vX.Y.Z buildNNNN
   m = re.search(r'\bv(\d+\.\d+\.\d+)\b.*?\bbuild\s*0*(\d+)\b', text, re.IGNORECASE)
   if m:
       return platform, m.group(1), m.group(2)
   return platform, version, build
# -------------------------
# Lifecycle Assessment (OFFLINE / POLICY-BASED)
# -------------------------
def derive_lifecycle_assessment(platform: str, version: str, build: str) -> Dict[str, Any]:
   """
   Lightweight lifecycle posture (offline rules).
   Replace later with live Fortinet lifecycle + PSIRT lookups if allowed.
   """
   platform_status = "Supported" if ("VM" in platform.upper() or "FORTIGATE-VM" in platform.upper()) else "Review"
   firmware_status = "Review"
   recommendation = "Review firmware lifecycle against Fortinet lifecycle policy and plan upgrades accordingly."
   exposure = "Unknown"
   m = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)\s*$", version)
   if m:
       major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
       branch = f"{major}.{minor}"
       if branch == "7.0":
           firmware_status = "EOL / Unsupported"
           exposure = "High (no ongoing security patching on this branch)"
           recommendation = "Upgrade to a supported branch (7.4.x stable or 7.6.x LTS) after validation in test environment."
       elif branch in ("7.2", "7.4", "7.6"):
           firmware_status = "Supported (subject to vendor lifecycle)"
           exposure = "Normal (ensure running latest patch for branch)"
           recommendation = f"Remain on branch {branch} and keep current with latest patch releases; monitor PSIRT advisories."
       else:
           firmware_status = "Review"
           exposure = "Unknown"
           recommendation = "Validate this branch support status and move to a supported LTS/stable branch."
   return {
       "platform": platform,
       "platform_status": platform_status,
       "firmware_version": version,
       "firmware_build": build,
       "firmware_status": firmware_status,
       "security_exposure": exposure,
       "recommendation": recommendation,
   }
# -------------------------
# Policy Analytics
# -------------------------
def permissive_score(p: Dict[str, str]) -> Tuple[int, str, str]:
   src = norm_list_val(p.get("srcaddr"))
   dst = norm_list_val(p.get("dstaddr"))
   svc = norm_list_val(p.get("service"))
   action = (p.get("action", "").strip('"').lower())
   logtraffic = (p.get("logtraffic", "").strip('"').lower())
   score = 0
   reasons = []
   if action == "accept":
       if is_all(src) and is_all(dst) and (is_all(svc) or any(x.upper() == "ALL" for x in svc)):
           score += 10; reasons.append("ANY-ANY-ANY ACCEPT")
       elif is_all(src) and is_all(dst):
           score += 7; reasons.append("ANY-ANY ACCEPT")
       elif is_all(dst) and (is_all(svc) or any(x.upper() == "ALL" for x in svc)):
           score += 7; reasons.append("ANY-DST + ANY-SVC")
       elif is_all(src) and (is_all(svc) or any(x.upper() == "ALL" for x in svc)):
           score += 7; reasons.append("ANY-SRC + ANY-SVC")
   if logtraffic in ("disable", "none", ""):
       score += 2; reasons.append("Logging not enabled")
   if not has_utm(p):
       score += 2; reasons.append("No UTM profiles detected")
   if score >= 10: sev = "CRITICAL"
   elif score >= 8: sev = "HIGH"
   elif score >= 5: sev = "MEDIUM"
   else: sev = "LOW"
   return score, sev, ", ".join(reasons)
def policy_signature(p: Dict[str, str]) -> Tuple:
   return (
       tuple(sorted(norm_list_val(p.get("srcintf")))),
       tuple(sorted(norm_list_val(p.get("dstintf")))),
       tuple(sorted(norm_list_val(p.get("srcaddr")))),
       tuple(sorted(norm_list_val(p.get("dstaddr")))),
       tuple(sorted(norm_list_val(p.get("service")))),
       p.get("schedule", ""),
       p.get("action", ""),
       p.get("status", "enable"),
   )
def covers(prev: Dict[str, str], curr: Dict[str, str]) -> bool:
   # Conservative: only 'all' covers anything; otherwise exact match.
   def covers_list(prev_list, curr_list):
       sp = set([x.lower() for x in prev_list])
       sc = set([x.lower() for x in curr_list])
       if "all" in sp:
           return True
       return sp == sc
   return (
       covers_list(norm_list_val(prev.get("srcaddr")), norm_list_val(curr.get("srcaddr"))) and
       covers_list(norm_list_val(prev.get("dstaddr")), norm_list_val(curr.get("dstaddr"))) and
       covers_list(norm_list_val(prev.get("service")), norm_list_val(curr.get("service"))) and
       prev.get("action", "").lower() == curr.get("action", "").lower()
   )
# -------------------------
# Result Object
# -------------------------
@dataclass
class AnalysisResult:
   meta: Dict[str, Any]
   cis: List[Dict[str, Any]]
   policies_raw: List[Dict[str, Any]]
   permissive: List[Dict[str, Any]]
   duplicates: List[Dict[str, Any]]
   shadowed: List[Dict[str, Any]]
   redundant: List[Dict[str, Any]]
   segmentation: List[Dict[str, Any]]
   sec_profile_coverage: Dict[str, Any]
   lifecycle_assessment: Dict[str, Any]
# -------------------------
# Main Analysis
# -------------------------
def analyze_config(text: str) -> AnalysisResult:
   sys_global = parse_kv_block(extract_block("config system global", text))
   pwd_policy = parse_kv_block(extract_block("config system password-policy", text))
   interfaces = parse_config_edit_block("config system interface", text)
   snmp_users = parse_config_edit_block("config system snmp user", text)
   ntp = parse_kv_block(extract_block("config system ntp", text))
   syslog = parse_kv_block(extract_block("config log syslogd setting", text))
   faz = parse_kv_block(extract_block("config log fortianalyzer setting", text))
   central_mgmt = parse_kv_block(extract_block("config system central-management", text))
   policies = parse_config_edit_block("config firewall policy", text)
   hostname = sys_global.get("hostname", "").strip('"').strip() or "Unknown"
   platform, fw_ver, fw_build = extract_firmware_info(text)
   # CIS subset controls (extend as needed)
   cis: List[Dict[str, Any]] = []
   def add(cid, cat, name, status, observed, expected, weight, remediation):
       cis.append({
           "control_id": cid, "category": cat, "control_name": name, "status": status,
           "observed": observed, "expected": expected, "weight": weight, "remediation": remediation
       })
   add("CIS-1.1", "System Hardening", "Hostname configured",
       "PASS" if hostname != "Unknown" else "FAIL", hostname, "Non-empty", 6, "")
   add("CIS-1.2", "System Hardening", "Pre-login banner enabled",
       "PASS" if sys_global.get("pre-login-banner") == "enable" else "FAIL",
       sys_global.get("pre-login-banner",""), "enable", 6,
       "config system global\n set pre-login-banner enable\nend")
   add("CIS-1.3", "System Hardening", "CLI audit logging enabled",
       "PASS" if sys_global.get("cli-audit-log") == "enable" else "FAIL",
       sys_global.get("cli-audit-log",""), "enable", 7,
       "config system global\n set cli-audit-log enable\nend")
   add("CIS-2.1", "Password & Auth", "Password policy enabled",
       "PASS" if pwd_policy.get("status") == "enable" else "FAIL",
       pwd_policy.get("status",""), "enable", 9,
       "config system password-policy\n set status enable\nend")
   min_len = int(re.sub(r"\D","", pwd_policy.get("minimum-length","0")) or 0)
   add("CIS-2.2", "Password & Auth", "Minimum password length >= 14",
       "PASS" if min_len >= 14 else "FAIL", str(min_len), ">= 14", 10,
       "config system password-policy\n set minimum-length 14\nend")
   trust_allow = interfaces.get("port3", {}).get("allowaccess", "")
   add("CIS-3.1", "Network", "No HTTPS/SSH management on TRUST interface",
       "FAIL" if ("https" in trust_allow or "ssh" in trust_allow) else "PASS",
       f"port3 allowaccess: {trust_allow}", "No https/ssh on TRUST", 8,
       "config system interface\n edit port3\n  set allowaccess ping snmp\n next\nend")
   add("CIS-4.1", "Logging & Time", "NTP configured",
       "PASS" if ntp else "UNKNOWN", "present" if ntp else "not found", "Configured NTP servers", 6,
       "config system ntp\n set status enable\nend")
   add("CIS-4.2", "Logging & Time", "Syslog configured",
       "PASS" if syslog.get("status") == "enable" else ("UNKNOWN" if not syslog else "FAIL"),
       syslog.get("status", "not found"), "enable", 7,
       "config log syslogd setting\n set status enable\n set server <IP>\nend")
   add("CIS-4.3", "Logging & Time", "FortiAnalyzer logging enabled",
       "PASS" if faz.get("status") == "enable" else ("UNKNOWN" if not faz else "FAIL"),
       faz.get("status", "not found"), "enable", 7,
       "config log fortianalyzer setting\n set status enable\n set server <IP>\nend")
   snmp_ok = False
   snmp_obs = ""
   for u, ud in snmp_users.items():
       snmp_obs = f"{u}: {ud.get('security-level','')} {ud.get('auth-proto','')} {ud.get('priv-proto','')}"
       if ud.get("security-level") == "auth-priv" and ud.get("auth-proto") == "sha512" and ud.get("priv-proto") == "aes256":
           snmp_ok = True
           break
   add("CIS-5.1", "Monitoring", "SNMP uses v3 auth-priv with strong crypto",
       "PASS" if snmp_ok else ("UNKNOWN" if not snmp_users else "FAIL"),
       snmp_obs if snmp_users else "not configured", "auth-priv + sha512 + aes256", 5,
       "config system snmp user\n edit <user>\n  set security-level auth-priv\n  set auth-proto sha512\n  set priv-proto aes256\n next\nend")
   add("CIS-6.1", "Governance", "Central management configured (FortiManager)",
       "PASS" if central_mgmt.get("type") == "fortimanager" else ("UNKNOWN" if not central_mgmt else "FAIL"),
       f"type={central_mgmt.get('type','')}, fmg={central_mgmt.get('fmg','')}", "fortimanager + fmg IP", 5,
       "config system central-management\n set type fortimanager\n set fmg <IP>\nend")
   # Policies raw
   ordered_ids = sorted([int(k) for k in policies.keys() if str(k).isdigit()])
   policies_raw: List[Dict[str, Any]] = []
   for pid in ordered_ids:
       p = policies[str(pid)]
       policies_raw.append({
           "policy_id": pid,
           "name": p.get("name",""),
           "status": p.get("status","enable"),
           "srcintf": " ".join(norm_list_val(p.get("srcintf"))),
           "dstintf": " ".join(norm_list_val(p.get("dstintf"))),
           "srcaddr": " ".join(norm_list_val(p.get("srcaddr"))),
           "dstaddr": " ".join(norm_list_val(p.get("dstaddr"))),
           "service": " ".join(norm_list_val(p.get("service"))),
           "action": p.get("action",""),
           "schedule": p.get("schedule",""),
           "logtraffic": p.get("logtraffic",""),
           "utm_detected": "YES" if has_utm(p) else "NO",
       })
   # Permissive rules
   permissive: List[Dict[str, Any]] = []
   for pid in ordered_ids:
       p = policies[str(pid)]
       score, sev, reasons = permissive_score(p)
       if score >= 5:
           permissive.append({
               "policy_id": pid, "name": p.get("name",""),
               "srcintf": " ".join(norm_list_val(p.get("srcintf"))),
               "dstintf": " ".join(norm_list_val(p.get("dstintf"))),
               "srcaddr": " ".join(norm_list_val(p.get("srcaddr"))),
               "dstaddr": " ".join(norm_list_val(p.get("dstaddr"))),
               "service": " ".join(norm_list_val(p.get("service"))),
               "action": p.get("action",""),
               "logtraffic": p.get("logtraffic",""),
               "utm_detected": "YES" if has_utm(p) else "NO",
               "risk_score": score, "severity": sev, "reasons": reasons
           })
   permissive.sort(key=lambda x: (-x["risk_score"], x["policy_id"]))
   # Duplicates
   sig_map = defaultdict(list)
   for pid in ordered_ids:
       sig_map[policy_signature(policies[str(pid)])].append(pid)
   duplicates: List[Dict[str, Any]] = []
   for sig, ids in sig_map.items():
       if len(ids) > 1:
           base = ids[0]
           for other in ids[1:]:
               duplicates.append({"policy_id": other, "duplicate_of": base, "criteria": "Exact signature match"})
   duplicates.sort(key=lambda x: x["policy_id"])
   # Shadowed / redundant (conservative)
   shadowed: List[Dict[str, Any]] = []
   redundant: List[Dict[str, Any]] = []
   for idx, pid in enumerate(ordered_ids):
       curr = policies[str(pid)]
       for prev_id in ordered_ids[:idx]:
           prev = policies[str(prev_id)]
           if covers(prev, curr):
               shadowed.append({"policy_id": pid, "shadowed_by": prev_id, "reason": "Superset/equal match above (conservative)"})
               break
   for idx, pid in enumerate(ordered_ids):
       curr = policies[str(pid)]
       if curr.get("action","").lower() != "accept":
           continue
       for prev_id in ordered_ids[:idx]:
           prev = policies[str(prev_id)]
           if prev.get("action","").lower() != "accept":
               continue
           if covers(prev, curr):
               redundant.append({"policy_id": pid, "covered_by": prev_id, "reason": "Covered by broader/equal allow (conservative)"})
               break
   # Segmentation matrix
   matrix = defaultdict(int)
   for pid in ordered_ids:
       p = policies[str(pid)]
       if p.get("action","").lower() != "accept":
           continue
       for s in norm_list_val(p.get("srcintf")):
           for d in norm_list_val(p.get("dstintf")):
               matrix[(s, d)] += 1
   segmentation: List[Dict[str, Any]] = []
   for (s, d), count in sorted(matrix.items(), key=lambda x: (-x[1], x[0][0], x[0][1])):
       indicator = "Review"
       if s == d:
           indicator = "Hairpin / Same-Zone"
       if "untrust" in d.lower():
           indicator = "Internet-Bound Traffic"
       if "trust" in s.lower() and "trust" in d.lower():
           indicator = "Internal East-West Exposure"
       segmentation.append({"srcintf": s, "dstintf": d, "policy_count": count, "indicator": indicator})
   # UTM coverage on internet-bound
   internet_policies = 0
   utm_attached = 0
   for pid in ordered_ids:
       p = policies[str(pid)]
       dstintf = norm_list_val(p.get("dstintf"))
       if any("untrust" in x.lower() for x in dstintf):
           internet_policies += 1
           if has_utm(p):
               utm_attached += 1
   coverage_pct = (utm_attached / internet_policies * 100.0) if internet_policies else 0.0
   lifecycle_assessment = derive_lifecycle_assessment(platform, fw_ver, fw_build)
   meta = {
       "hostname": hostname,
       "platform": platform,
       "firmware_version": fw_ver,
       "firmware_build": fw_build,
   }
   return AnalysisResult(
       meta=meta,
       cis=cis,
       policies_raw=policies_raw,
       permissive=permissive,
       duplicates=duplicates,
       shadowed=shadowed,
       redundant=redundant,
       segmentation=segmentation,
       sec_profile_coverage={
           "total_policies": len(ordered_ids),
           "internet_bound_policies": internet_policies,
           "internet_with_utm": utm_attached,
           "utm_coverage_pct": round(coverage_pct, 2),
       },
       lifecycle_assessment=lifecycle_assessment
   )