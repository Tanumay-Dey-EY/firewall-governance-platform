# benchmark_packs/cis_fgt_7_0_v1_4.py
from __future__ import annotations
from typing import Dict, Any
from benchmark_loader import BenchmarkPack, ControlDef, RuleFn
# -------- Rule implementations (reused across packs) --------
def rule_hostname_configured(ctx: Dict[str, Any]) -> Dict[str, Any]:
   hostname = ctx["meta"].get("hostname", "Unknown")
   ok = hostname != "Unknown" and str(hostname).strip() != ""
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": hostname,
       "expected": "Non-empty hostname",
       "remediation": "",
       "why_failed": "" if ok else "Hostname is missing/empty in system global."
   }
def rule_prelogin_banner(ctx: Dict[str, Any]) -> Dict[str, Any]:
   v = ctx["sys_global"].get("pre-login-banner", "")
   ok = v == "enable"
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": v or "not set",
       "expected": "enable",
       "remediation": "config system global\n set pre-login-banner enable\nend",
       "why_failed": "" if ok else "Pre-login banner not enabled."
   }
def rule_cli_audit(ctx: Dict[str, Any]) -> Dict[str, Any]:
   v = ctx["sys_global"].get("cli-audit-log", "")
   ok = v == "enable"
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": v or "not set",
       "expected": "enable",
       "remediation": "config system global\n set cli-audit-log enable\nend",
       "why_failed": "" if ok else "CLI audit logging not enabled."
   }
def rule_password_policy_status(ctx: Dict[str, Any]) -> Dict[str, Any]:
   v = ctx["pwd_policy"].get("status", "")
   ok = v == "enable"
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": v or "not set",
       "expected": "enable",
       "remediation": "config system password-policy\n set status enable\nend",
       "why_failed": "" if ok else "Password policy not enabled."
   }
def rule_password_minlen_14(ctx: Dict[str, Any]) -> Dict[str, Any]:
   import re
   raw = ctx["pwd_policy"].get("minimum-length", "0")
   min_len = int(re.sub(r"\D","", raw) or 0)
   ok = min_len >= 14
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": str(min_len),
       "expected": ">= 14",
       "remediation": "config system password-policy\n set minimum-length 14\nend",
       "why_failed": "" if ok else f"Minimum length is {min_len}, expected >=14."
   }
def rule_ntp_configured(ctx: Dict[str, Any]) -> Dict[str, Any]:
   ntp = ctx["ntp"]
   ok = bool(ntp)
   return {
       "status": "PASS" if ok else "UNKNOWN",
       "observed": "present" if ok else "not found",
       "expected": "Configured NTP servers",
       "remediation": "config system ntp\n set status enable\nend",
       "why_failed": "" if ok else "NTP block not found in config export."
   }
def rule_syslog_enabled(ctx: Dict[str, Any]) -> Dict[str, Any]:
   syslog = ctx["syslog"]
   if not syslog:
       return {
           "status": "UNKNOWN",
           "observed": "not found",
           "expected": "enable",
           "remediation": "config log syslogd setting\n set status enable\n set server <IP>\nend",
           "why_failed": "Syslog configuration block not found."
       }
   v = syslog.get("status","")
   ok = v == "enable"
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": v or "not set",
       "expected": "enable",
       "remediation": "config log syslogd setting\n set status enable\n set server <IP>\nend",
       "why_failed": "" if ok else "Syslog status not enabled."
   }
def rule_faz_enabled(ctx: Dict[str, Any]) -> Dict[str, Any]:
   faz = ctx["faz"]
   if not faz:
       return {
           "status": "UNKNOWN",
           "observed": "not found",
           "expected": "enable",
           "remediation": "config log fortianalyzer setting\n set status enable\n set server <IP>\nend",
           "why_failed": "FortiAnalyzer logging block not found."
       }
   v = faz.get("status","")
   ok = v == "enable"
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": v or "not set",
       "expected": "enable",
       "remediation": "config log fortianalyzer setting\n set status enable\n set server <IP>\nend",
       "why_failed": "" if ok else "FortiAnalyzer logging not enabled."
   }
def rule_snmp_strong(ctx: Dict[str, Any]) -> Dict[str, Any]:
   snmp_users = ctx["snmp_users"]
   if not snmp_users:
       return {
           "status": "UNKNOWN",
           "observed": "not configured",
           "expected": "auth-priv + sha512 + aes256",
           "remediation": "config system snmp user\n edit <user>\n  set security-level auth-priv\n  set auth-proto sha512\n  set priv-proto aes256\n next\nend",
           "why_failed": "SNMP users not present in config."
       }
   ok = False
   obs = ""
   for u, ud in snmp_users.items():
       obs = f"{u}: {ud.get('security-level','')} {ud.get('auth-proto','')} {ud.get('priv-proto','')}"
       if ud.get("security-level") == "auth-priv" and ud.get("auth-proto") == "sha512" and ud.get("priv-proto") == "aes256":
           ok = True
           break
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": obs,
       "expected": "auth-priv + sha512 + aes256",
       "remediation": "config system snmp user\n edit <user>\n  set security-level auth-priv\n  set auth-proto sha512\n  set priv-proto aes256\n next\nend",
       "why_failed": "" if ok else "No SNMPv3 user found with auth-priv + sha512 + aes256."
   }
def rule_fmg_configured(ctx: Dict[str, Any]) -> Dict[str, Any]:
   cm = ctx["central_mgmt"]
   if not cm:
       return {
           "status": "UNKNOWN",
           "observed": "not found",
           "expected": "fortimanager + fmg IP",
           "remediation": "config system central-management\n set type fortimanager\n set fmg <IP>\nend",
           "why_failed": "Central management block not present."
       }
   ok = cm.get("type") == "fortimanager"
   obs = f"type={cm.get('type','')}, fmg={cm.get('fmg','')}"
   return {
       "status": "PASS" if ok else "FAIL",
       "observed": obs,
       "expected": "fortimanager + fmg IP",
       "remediation": "config system central-management\n set type fortimanager\n set fmg <IP>\nend",
       "why_failed": "" if ok else "Central management type is not fortimanager."
   }
# Rules mapping
RULES: Dict[str, RuleFn] = {
   "hostname_configured": rule_hostname_configured,
   "prelogin_banner": rule_prelogin_banner,
   "cli_audit": rule_cli_audit,
   "password_policy_status": rule_password_policy_status,
   "password_minlen_14": rule_password_minlen_14,
   "ntp_configured": rule_ntp_configured,
   "syslog_enabled": rule_syslog_enabled,
   "faz_enabled": rule_faz_enabled,
   "snmp_strong": rule_snmp_strong,
   "fmg_configured": rule_fmg_configured,
}
CONTROLS = [
   ControlDef("CIS-1.1", "System Hardening", "Hostname configured", 6, "L1", "hostname_configured"),
   ControlDef("CIS-1.2", "System Hardening", "Pre-login banner enabled", 6, "L1", "prelogin_banner"),
   ControlDef("CIS-1.3", "System Hardening", "CLI audit logging enabled", 7, "L1", "cli_audit"),
   ControlDef("CIS-2.1", "Password & Auth", "Password policy enabled", 9, "L1", "password_policy_status"),
   ControlDef("CIS-2.2", "Password & Auth", "Minimum password length >= 14", 10, "L1", "password_minlen_14"),
   ControlDef("CIS-4.1", "Logging & Time", "NTP configured", 6, "L1", "ntp_configured"),
   ControlDef("CIS-4.2", "Logging & Time", "Syslog configured", 7, "L1", "syslog_enabled"),
   ControlDef("CIS-4.3", "Logging & Time", "FortiAnalyzer logging enabled", 7, "L1", "faz_enabled"),
   ControlDef("CIS-5.1", "Monitoring", "SNMP uses v3 auth-priv with strong crypto", 5, "L2", "snmp_strong"),
   ControlDef("CIS-6.1", "Governance", "Central management configured (FortiManager)", 5, "L1", "fmg_configured"),
]
PACK = BenchmarkPack(
   pack_id="cis_fgt_7_4_v1_0_0",
   pack_name="CIS FortiGate 7.0.x Benchmark",
   pack_version="v1.0.0",
   family="7.4.x",
   selection="manual",  # overwritten by loader
   controls=CONTROLS,
   rules=RULES
)