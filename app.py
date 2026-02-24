# =========================
# app.py (FULL UPDATED)
# Adds: Redaction toggle + password gate + demo-safe UI rendering
# =========================
import re
import streamlit as st
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from datetime import datetime
from analyzer import analyze_config
from report_generator import build_excel_report
# ---------------------------
# Password Gate (Streamlit Cloud Secrets)
# Add in Streamlit Cloud > Settings > Secrets:
# APP_PASSWORD="YourStrongPassword123"
# ---------------------------
if "authed" not in st.session_state:
   st.session_state.authed = False
if not st.session_state.authed:
   st.title("Firewall Governance")
   st.caption("Access restricted for internal demo.")
   pwd = st.text_input("Enter access password", type="password")
   if st.button("Access"):
       if pwd == st.secrets.get("APP_PASSWORD", ""):
           st.session_state.authed = True
           st.rerun()
       else:
           st.error("Invalid password")
   st.stop()
# ---------------------------
# Page config
# ---------------------------
st.set_page_config(
   page_title="Firewall Governance MVP",
   layout="wide",
   initial_sidebar_state="expanded",
)
# ---------------------------
# Commercial SaaS CSS
# ---------------------------
st.markdown("""
<style>
.stApp { background: #0b1220; }
.block-container { padding-top: 1.0rem; padding-bottom: 2.0rem; max-width: 1350px; }
section[data-testid="stSidebar"]{
 background: #0f172a;
 border-right: 1px solid rgba(255,255,255,.06);
}
.navbar {
 background: linear-gradient(90deg, #0f172a, #111827);
 border: 1px solid rgba(255,255,255,.08);
 border-radius: 16px;
 padding: 16px 18px;
 box-shadow: 0 18px 38px rgba(0,0,0,.35);
}
.nav-title { color: #e5e7eb; font-size: 18px; font-weight: 900; letter-spacing: .2px; }
.nav-sub { color: rgba(229,231,235,.7); font-size: 12px; margin-top: 4px; }
.surface {
 background: #111827;
 border: 1px solid rgba(255,255,255,.08);
 border-radius: 16px;
 padding: 16px 16px;
 box-shadow: 0 18px 34px rgba(0,0,0,.28);
}
.kpi {
 background: #0f172a;
 border: 1px solid rgba(255,255,255,.08);
 border-radius: 16px;
 padding: 14px 14px;
 box-shadow: 0 14px 26px rgba(0,0,0,.25);
}
.kpi-title { font-size: 12px; color: rgba(229,231,235,.75); margin-bottom: 6px; }
.kpi-value { font-size: 22px; font-weight: 900; color: #e5e7eb; line-height: 1.1; }
.kpi-sub   { font-size: 12px; color: rgba(229,231,235,.65); margin-top: 6px; }
.h { font-size: 15px; font-weight: 900; color:#e5e7eb; margin: 0 0 6px; }
.p { font-size: 12px; color: rgba(229,231,235,.65); margin: 0 0 10px; }
.banner {
 border-radius: 16px;
 padding: 14px 16px;
 border: 1px solid rgba(255,255,255,.10);
 background: linear-gradient(90deg, rgba(239,68,68,.18), rgba(17,24,39,0));
}
.banner-title { color:#fecaca; font-size: 13px; font-weight: 900; letter-spacing:.3px; }
.banner-text { color: rgba(229,231,235,.85); font-size: 12px; margin-top: 6px; }
.banner-sub { color: rgba(229,231,235,.60); font-size: 12px; margin-top: 4px; }
.pill { display:inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 800; }
.pill-green { background: rgba(34,197,94,.16); color:#86efac; border: 1px solid rgba(34,197,94,.35); }
.pill-amber { background: rgba(245,158,11,.16); color:#fcd34d; border: 1px solid rgba(245,158,11,.35); }
.pill-red   { background: rgba(239,68,68,.16); color:#fecaca; border: 1px solid rgba(239,68,68,.35); }
.pill-slate { background: rgba(148,163,184,.12); color:#e5e7eb; border: 1px solid rgba(148,163,184,.25); }
[data-testid="stDataFrame"]{
 background: #111827;
 border: 1px solid rgba(255,255,255,.08);
 border-radius: 16px;
 overflow: hidden;
}
.stTabs [data-baseweb="tab"] { font-weight: 800; }
</style>
""", unsafe_allow_html=True)
# ---------------------------
# Redaction utilities
# ---------------------------
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
def mask_ip(ip: str) -> str:
   parts = ip.split(".")
   if len(parts) == 4:
       return f"{parts[0]}.XX.XX.X"
   return "X.X.X.X"
def redact_text(text: str) -> str:
   """
   Redacts common sensitive patterns in FortiGate configs for demo safety.
   - IPv4 addresses
   - serial numbers in header
   - hostname
   - SNMP community
   - passwords / secrets / tokens / keys (best-effort)
   """
   t = text
   # Serial
   t = re.sub(r"(?mi)^(#serialno=)(.+)$", r"\1FG**************", t)
   # Hostname in headers or config system global
   t = re.sub(r'(?mi)^(set\s+hostname\s+).+$', r'\1"FW-DEMO-01"', t)
   # SNMP community / passwords (best-effort: mask values after set)
   sensitive_keys = [
       "password", "passwd", "secret", "token", "private-key", "psksecret",
       "community", "key", "apikey", "auth-pwd", "priv-pwd"
   ]
   for k in sensitive_keys:
       t = re.sub(rf'(?mi)^(set\s+{re.escape(k)}\s+).+$', r'\1"***REDACTED***"', t)
   # IPs
   t = _IP_RE.sub(lambda m: mask_ip(m.group(0)), t)
   return t
def redact_value(val):
   if val is None:
       return val
   s = str(val)
   # mask any IPs in values
   s = _IP_RE.sub(lambda m: mask_ip(m.group(0)), s)
   # mask long ids/serial-like tokens
   s = re.sub(r"\bFG[A-Z0-9]{6,}\b", "FG************", s)
   return s
def redact_df(df: pd.DataFrame) -> pd.DataFrame:
   if df is None or df.empty:
       return df
   out = df.copy()
   for c in out.columns:
       out[c] = out[c].apply(redact_value)
   return out
def redact_lifecycle_dict(d: dict) -> dict:
   if not d:
       return d
   out = {}
   for k, v in d.items():
       out[k] = redact_value(v) if isinstance(v, (str, int, float)) else v
   return out
# ---------------------------
# Navbar
# ---------------------------
st.markdown("""
<div class="navbar">
<div class="nav-title">Firewall Governance</div>
<div class="nav-sub">CIS • Hygiene • Segmentation • Lifecycle risk • Evidence export</div>
</div>
""", unsafe_allow_html=True)
# ---------------------------
# Sidebar
# ---------------------------
with st.sidebar:
   st.markdown("### Upload")
   uploaded = st.file_uploader("FortiGate config (.txt/.conf/.cfg)", type=["txt", "conf", "cfg"])
   st.markdown("---")
   st.markdown("### Demo Safety")
   redact = st.toggle("Redact sensitive data (recommended)", value=True)
   st.caption("Masks IPs, serials, hostnames, and secrets in UI/export.")
   st.markdown("---")
   st.markdown("### Run context")
   st.write(f"Time: `{datetime.now().strftime('%Y-%m-%d %H:%M')}`")
if not uploaded:
   st.info("Upload a config file to begin.")
   st.stop()
raw_text = uploaded.read().decode("utf-8", errors="ignore")
# Analyze on original text (to keep detection accurate)
with st.spinner("Analyzing configuration..."):
   result = analyze_config(raw_text)
# If redaction enabled, create redacted copies for display/export
display_meta = dict(result.meta)
display_life = dict(result.lifecycle_assessment or {})
display_cis = pd.DataFrame(result.cis)
display_perm = pd.DataFrame(result.permissive)
display_dup = pd.DataFrame(result.duplicates)
display_shd = pd.DataFrame(result.shadowed)
display_red = pd.DataFrame(result.redundant)
display_seg = pd.DataFrame(result.segmentation)
display_cov = dict(result.sec_profile_coverage)
if redact:
   # meta
   for k in list(display_meta.keys()):
       display_meta[k] = redact_value(display_meta[k])
   # lifecycle
   display_life = redact_lifecycle_dict(display_life)
   # dataframes
   display_cis = redact_df(display_cis)
   display_perm = redact_df(display_perm)
   display_dup = redact_df(display_dup)
   display_shd = redact_df(display_shd)
   display_red = redact_df(display_red)
   display_seg = redact_df(display_seg)
# ---------------------------
# Metrics
# ---------------------------
hostname = display_meta.get("hostname", "Unknown")
platform = display_meta.get("platform", "Unknown")
fw_ver = display_meta.get("firmware_version", "Unknown")
fw_build = display_meta.get("firmware_build", "Unknown")
fw_status = str(display_life.get("firmware_status", "Review"))
pass_count = int((pd.DataFrame(result.cis)["status"] == "PASS").sum()) if result.cis else 0
fail_count = int((pd.DataFrame(result.cis)["status"] == "FAIL").sum()) if result.cis else 0
unk_count  = int((pd.DataFrame(result.cis)["status"] == "UNKNOWN").sum()) if result.cis else 0
total_count = len(result.cis) if result.cis else 0
compliance_pct = round((pass_count / total_count) * 100, 2) if total_count else 0.0
utm_pct = result.sec_profile_coverage.get("utm_coverage_pct", 0)
perm_cnt = len(result.permissive)
dup_cnt  = len(result.duplicates)
shd_cnt  = len(result.shadowed)
red_cnt  = len(result.redundant)
is_eol = fw_status.startswith("EOL")
banner_level = "CRITICAL" if is_eol else ("ELEVATED" if fail_count > 0 or perm_cnt > 0 else "NORMAL")
# ---------------------------
# Top row: Context + Risk
# ---------------------------
c1, c2 = st.columns([1.6, 1.1])
with c1:
   st.markdown("<div class='surface'>", unsafe_allow_html=True)
   st.markdown("<div class='h'>Asset Context</div>", unsafe_allow_html=True)
   st.markdown("<div class='p'>Device identification and detected runtime metadata</div>", unsafe_allow_html=True)
   st.write(f"**Hostname:** `{hostname}`")
   st.write(f"**Platform:** `{platform}`")
   st.write(f"**Firmware:** `{fw_ver} (build {fw_build})`")
   st.markdown("</div>", unsafe_allow_html=True)
with c2:
   if banner_level == "CRITICAL":
       pill = "<span class='pill pill-red'>CRITICAL</span>"
   elif banner_level == "ELEVATED":
       pill = "<span class='pill pill-amber'>ELEVATED</span>"
   else:
       pill = "<span class='pill pill-green'>NORMAL</span>"
   exposure = display_life.get("security_exposure", "—")
   st.markdown("<div class='surface'>", unsafe_allow_html=True)
   st.markdown("<div class='h'>Risk Posture</div>", unsafe_allow_html=True)
   st.markdown("<div class='p'>Executive summary of current exposure</div>", unsafe_allow_html=True)
   st.markdown(
       f"<div class='banner'>"
       f"<div class='banner-title'>{pill}  Lifecycle / Configuration Risk</div>"
       f"<div class='banner-text'>Firmware status: <b>{fw_status}</b></div>"
       f"<div class='banner-sub'>Exposure: {exposure}</div>"
       f"</div>",
       unsafe_allow_html=True
   )
   st.caption("Lifecycle assessment applies to vendor support status of detected FortiOS branch (not an individual firewall rule).")
   st.markdown("</div>", unsafe_allow_html=True)
st.markdown("")
# ---------------------------
# KPI row
# ---------------------------
k1, k2, k3, k4, k5, k6 = st.columns(6)
def kpi(col, title, value, sub=""):
   col.markdown(
       f"""
<div class="kpi">
<div class="kpi-title">{title}</div>
<div class="kpi-value">{value}</div>
<div class="kpi-sub">{sub}</div>
</div>
       """,
       unsafe_allow_html=True
   )
kpi(k1, "CIS Compliance", f"{compliance_pct}%", f"PASS {pass_count} / {total_count}")
kpi(k2, "CIS FAIL", f"{fail_count}", "Controls needing remediation")
kpi(k3, "Permissive Rules", f"{perm_cnt}", "MEDIUM+ risk rules")
kpi(k4, "Shadowed", f"{shd_cnt}", "Conservative detection")
kpi(k5, "Redundant", f"{red_cnt}", "Conservative detection")
kpi(k6, "UTM Coverage", f"{utm_pct}%", "Internet-bound policies")
st.markdown("")
# ---------------------------
# Charts
# ---------------------------
def donut_chart(pass_n, fail_n, unk_n):
   fig, ax = plt.subplots(figsize=(3.2, 3.2))
   ax.pie(
       [pass_n, fail_n, unk_n],
       labels=["PASS", "FAIL", "UNKNOWN"],
       autopct=lambda p: f"{p:.0f}%" if p > 0 else "",
       startangle=90
   )
   centre_circle = plt.Circle((0, 0), 0.70, fc="#111827")
   fig.gca().add_artist(centre_circle)
   ax.set_title("CIS Status Mix", fontsize=12, fontweight="bold", color="#e5e7eb")
   fig.patch.set_facecolor("#111827")
   ax.set_facecolor("#111827")
   return fig
def bar_chart(labels, values, title):
   fig, ax = plt.subplots(figsize=(4.2, 3.2))
   ax.bar(labels, values)
   ax.set_title(title, fontsize=12, fontweight="bold", color="#e5e7eb")
   fig.patch.set_facecolor("#111827")
   ax.set_facecolor("#111827")
   ax.tick_params(colors="#cbd5e1")
   for spine in ax.spines.values():
       spine.set_color("#334155")
   return fig
ch1, ch2, ch3 = st.columns([1.0, 1.2, 1.2])
with ch1:
   st.markdown("<div class='surface'><div class='h'>Compliance Overview</div><div class='p'>PASS/FAIL/UNKNOWN distribution</div>", unsafe_allow_html=True)
   st.pyplot(donut_chart(pass_count, fail_count, unk_count), clear_figure=True)
   st.markdown("</div>", unsafe_allow_html=True)
with ch2:
   st.markdown("<div class='surface'><div class='h'>Rule Hygiene</div><div class='p'>Top indicators for policy cleanup</div>", unsafe_allow_html=True)
   st.pyplot(bar_chart(["Permissive", "Shadowed", "Redundant", "Duplicates"], [perm_cnt, shd_cnt, red_cnt, dup_cnt], "Rule Hygiene Counts"), clear_figure=True)
   st.markdown("</div>", unsafe_allow_html=True)
with ch3:
   internet_total = result.sec_profile_coverage.get("internet_bound_policies", 0)
   internet_utm = result.sec_profile_coverage.get("internet_with_utm", 0)
   st.markdown("<div class='surface'><div class='h'>Security Controls</div><div class='p'>UTM on internet-bound rules</div>", unsafe_allow_html=True)
   st.pyplot(bar_chart(["Internet total", "Internet w/ UTM"], [internet_total, internet_utm], "Internet Control Coverage"), clear_figure=True)
   st.markdown("</div>", unsafe_allow_html=True)
st.markdown("")
# ---------------------------
# Tabs
# ---------------------------
tab_dash, tab_cis, tab_fail, tab_hyg, tab_seg, tab_life, tab_export = st.tabs([
   "Executive",
   "CIS Scorecard",
   "Failures & Why",
   "Policy Hygiene",
   "Segmentation",
   "Lifecycle",
   "Export"
])
with tab_dash:
   st.markdown("<div class='surface'><div class='h'>Executive Summary</div><div class='p'>Decision-ready highlights</div>", unsafe_allow_html=True)
   bullets = []
   if is_eol:
       bullets.append("🔴 Firmware branch detected as **EOL/Unsupported** (upgrade recommended).")
   if fail_count:
       bullets.append(f"🟠 **{fail_count}** CIS controls failing in evaluated subset.")
   if perm_cnt:
       bullets.append(f"🟠 **{perm_cnt}** permissive rules flagged (MEDIUM+).")
   if utm_pct == 0 and result.sec_profile_coverage.get("internet_bound_policies", 0) > 0:
       bullets.append("🟠 Internet-bound policies show **0% UTM coverage** in this subset (verify profiles).")
   if not bullets:
       bullets.append("🟢 No critical findings detected in the evaluated subset.")
   st.markdown("\n".join([f"- {b}" for b in bullets]))
   st.markdown("</div>", unsafe_allow_html=True)
with tab_cis:
   st.markdown("<div class='surface'><div class='h'>CIS Scorecard</div><div class='p'>Subset of verifiable controls from configuration export</div>", unsafe_allow_html=True)
   st.dataframe(display_cis, use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_fail:
   st.markdown("<div class='surface'><div class='h'>Failures & Why</div><div class='p'>Observed vs Expected + remediation CLI</div>", unsafe_allow_html=True)
   fail_df = pd.DataFrame(result.cis)
   fail_df = fail_df[fail_df["status"] == "FAIL"] if not fail_df.empty else fail_df
   fail_df_disp = redact_df(fail_df) if redact else fail_df
   if fail_df_disp.empty:
       st.success("No FAIL controls in the evaluated CIS subset.")
   else:
       show_cols = ["control_id", "category", "control_name", "observed", "expected", "remediation"]
       st.dataframe(fail_df_disp[show_cols], use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_hyg:
   st.markdown("<div class='surface'><div class='h'>Policy Hygiene</div><div class='p'>Permissive, duplicate, shadowed and redundant rule checks</div>", unsafe_allow_html=True)
   st.markdown("#### Permissive Rules (MEDIUM+)")
   st.dataframe(display_perm, use_container_width=True, hide_index=True)
   c1, c2 = st.columns(2)
   with c1:
       st.markdown("#### Duplicate Rules")
       st.dataframe(display_dup, use_container_width=True, hide_index=True)
   with c2:
       st.markdown("#### Shadowed Rules")
       st.dataframe(display_shd, use_container_width=True, hide_index=True)
   st.markdown("#### Redundant Rules")
   st.dataframe(display_red, use_container_width=True, hide_index=True)
   st.caption("Shadowed/Redundant are conservative. For precision, resolve address/service objects & groups.")
   st.markdown("</div>", unsafe_allow_html=True)
with tab_seg:
   st.markdown("<div class='surface'><div class='h'>Segmentation</div><div class='p'>Interface-to-interface allow matrix and governance indicators</div>", unsafe_allow_html=True)
   st.dataframe(display_seg, use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_life:
   st.markdown("<div class='surface'><div class='h'>Lifecycle Details</div><div class='p'>Applies to firmware branch support status</div>", unsafe_allow_html=True)
   life_df = pd.DataFrame([
       ["Applies to", "Firmware branch lifecycle (FortiOS support status)"],
       ["Detected platform", display_life.get("platform", platform)],
       ["Platform status", display_life.get("platform_status", "Review")],
       ["Detected firmware", f"{display_life.get('firmware_version', fw_ver)} (build {display_life.get('firmware_build', fw_build)})"],
       ["Firmware status", display_life.get("firmware_status", "Review")],
       ["Security exposure (why)", display_life.get("security_exposure", "Unknown")],
       ["Recommended action", display_life.get("recommendation", "")]
   ], columns=["Field", "Value"])
   st.dataframe(life_df, use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_export:
   st.markdown("<div class='surface'><div class='h'>Export</div><div class='p'>Download the evidence workbook</div>", unsafe_allow_html=True)
   # For demo safety, export redacted workbook by generating on redacted text
   if redact:
       safe_text = redact_text(raw_text)
       safe_result = analyze_config(safe_text)
       excel_bytes = build_excel_report(safe_result)
       st.caption("Export is redacted for demo safety.")
   else:
       excel_bytes = build_excel_report(result)
   st.download_button(
       "Download Excel Report",
       data=excel_bytes,
       file_name=f"Firewall_Governance_{hostname}.xlsx",
       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
   )
   st.markdown("</div>", unsafe_allow_html=True)