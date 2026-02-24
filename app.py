import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from analyzer import analyze_config
from report_generator import build_excel_report
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
/* Dark SaaS canvas */
.stApp { background: #0b1220; }
/* constrain width a bit for premium feel */
.block-container { padding-top: 1.0rem; padding-bottom: 2.0rem; max-width: 1350px; }
/* Sidebar as dark panel */
section[data-testid="stSidebar"]{
 background: #0f172a;
 border-right: 1px solid rgba(255,255,255,.06);
}
/* Top nav */
.navbar {
 background: linear-gradient(90deg, #0f172a, #111827);
 border: 1px solid rgba(255,255,255,.08);
 border-radius: 16px;
 padding: 16px 18px;
 box-shadow: 0 18px 38px rgba(0,0,0,.35);
}
.nav-title { color: #e5e7eb; font-size: 18px; font-weight: 900; letter-spacing: .2px; }
.nav-sub { color: rgba(229,231,235,.7); font-size: 12px; margin-top: 4px; }
.nav-tags { margin-top: 10px; display:flex; gap:8px; flex-wrap:wrap; }
.tag {
 display:inline-block; padding: 4px 10px; border-radius: 999px;
 font-size: 12px; font-weight: 700;
 border: 1px solid rgba(255,255,255,.10);
 background: rgba(255,255,255,.04);
 color: rgba(229,231,235,.9);
}
/* Surface cards */
.surface {
 background: #111827;
 border: 1px solid rgba(255,255,255,.08);
 border-radius: 16px;
 padding: 16px 16px;
 box-shadow: 0 18px 34px rgba(0,0,0,.28);
}
/* KPI */
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
/* headings */
.h { font-size: 15px; font-weight: 900; color:#e5e7eb; margin: 0 0 6px; }
.p { font-size: 12px; color: rgba(229,231,235,.65); margin: 0 0 10px; }
/* Risk banner */
.banner {
 border-radius: 16px;
 padding: 14px 16px;
 border: 1px solid rgba(255,255,255,.10);
 background: linear-gradient(90deg, rgba(239,68,68,.18), rgba(17,24,39,0));
}
.banner-title { color:#fecaca; font-size: 13px; font-weight: 900; letter-spacing:.3px; }
.banner-text { color: rgba(229,231,235,.85); font-size: 12px; margin-top: 6px; }
.banner-sub { color: rgba(229,231,235,.60); font-size: 12px; margin-top: 4px; }
/* Pills */
.pill { display:inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 800; }
.pill-green { background: rgba(34,197,94,.16); color:#86efac; border: 1px solid rgba(34,197,94,.35); }
.pill-amber { background: rgba(245,158,11,.16); color:#fcd34d; border: 1px solid rgba(245,158,11,.35); }
.pill-red   { background: rgba(239,68,68,.16); color:#fecaca; border: 1px solid rgba(239,68,68,.35); }
.pill-slate { background: rgba(148,163,184,.12); color:#e5e7eb; border: 1px solid rgba(148,163,184,.25); }
/* Dataframes in dark surface */
[data-testid="stDataFrame"]{
 background: #111827;
 border: 1px solid rgba(255,255,255,.08);
 border-radius: 16px;
 overflow: hidden;
}
/* Tabs spacing */
.stTabs [data-baseweb="tab"] { font-weight: 800; }
</style>
""", unsafe_allow_html=True)
# ---------------------------
# Navbar
# ---------------------------
st.markdown("""
<div class="navbar">
<div class="nav-title">Firewall Governance</div>
<div class="nav-sub">CIS alignment • Policy hygiene • Segmentation • Lifecycle risk • Evidence export</div>
</div>
""", unsafe_allow_html=True)
# ---------------------------
# Sidebar
# ---------------------------
with st.sidebar:
   st.markdown("### Upload")
   uploaded = st.file_uploader("FortiGate config (.txt/.conf/.cfg)", type=["txt", "conf", "cfg"])
   st.markdown("---")
   st.markdown("### Run context")
   st.write(f"Time: `{datetime.now().strftime('%Y-%m-%d %H:%M')}`")
   st.caption("Tip: Use FortiGate *backup config* to include header + build info.")
if not uploaded:
   st.info("Upload a config file to begin.")
   st.stop()
raw_text = uploaded.read().decode("utf-8", errors="ignore")
with st.spinner("Analyzing configuration..."):
   result = analyze_config(raw_text)
# ---------------------------
# Compute metrics
# ---------------------------
hostname = result.meta.get("hostname", "Unknown")
platform = result.meta.get("platform", "Unknown")
fw_ver = result.meta.get("firmware_version", "Unknown")
fw_build = result.meta.get("firmware_build", "Unknown")
life = result.lifecycle_assessment or {}
fw_status = str(life.get("firmware_status", "Review"))
cis_df = pd.DataFrame(result.cis)
pass_count = int((cis_df["status"] == "PASS").sum()) if not cis_df.empty else 0
fail_count = int((cis_df["status"] == "FAIL").sum()) if not cis_df.empty else 0
unk_count  = int((cis_df["status"] == "UNKNOWN").sum()) if not cis_df.empty else 0
total_count = int(len(cis_df))
compliance_pct = round((pass_count / total_count) * 100, 2) if total_count else 0.0
utm_pct = result.sec_profile_coverage.get("utm_coverage_pct", 0)
perm_cnt = len(result.permissive)
dup_cnt  = len(result.duplicates)
shd_cnt  = len(result.shadowed)
red_cnt  = len(result.redundant)
# risk level heuristic for banner
is_eol = fw_status.startswith("EOL")
banner_level = "CRITICAL" if is_eol else ("ELEVATED" if fail_count > 0 or perm_cnt > 0 else "NORMAL")
# ---------------------------
# Top row: Context + Risk Banner
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
   # badge
   if banner_level == "CRITICAL":
       pill = "<span class='pill pill-red'>CRITICAL</span>"
   elif banner_level == "ELEVATED":
       pill = "<span class='pill pill-amber'>ELEVATED</span>"
   else:
       pill = "<span class='pill pill-green'>NORMAL</span>"
   exposure = life.get("security_exposure", "—")
   rec = life.get("recommendation", "—")
   st.markdown("<div class='surface'>", unsafe_allow_html=True)
   st.markdown("<div class='h'>Risk Posture</div>", unsafe_allow_html=True)
   st.markdown("<div class='p'>Executive summary of current exposure</div>", unsafe_allow_html=True)
   st.markdown(f"<div class='banner'><div class='banner-title'>{pill}  Lifecycle / Configuration Risk</div>"
               f"<div class='banner-text'>Firmware status: <b>{fw_status}</b></div>"
               f"<div class='banner-sub'>Exposure: {exposure}</div></div>", unsafe_allow_html=True)
   st.caption("This lifecycle assessment applies to vendor support status of the detected FortiOS branch (not an individual firewall rule).")
   st.markdown("</div>", unsafe_allow_html=True)
st.markdown("")
# ---------------------------
# KPIs
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
# Charts row (premium feel)
# ---------------------------
ch1, ch2, ch3 = st.columns([1.0, 1.2, 1.2])
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
   ax.tick_params(axis='x', rotation=0)
   fig.patch.set_facecolor("#111827")
   ax.set_facecolor("#111827")
   ax.tick_params(colors="#cbd5e1")
   for spine in ax.spines.values():
       spine.set_color("#334155")
   ax.yaxis.label.set_color("#cbd5e1")
   ax.xaxis.label.set_color("#cbd5e1")
   return fig
with ch1:
   st.markdown("<div class='surface'><div class='h'>Compliance Overview</div><div class='p'>PASS/FAIL/UNKNOWN distribution</div>", unsafe_allow_html=True)
   st.pyplot(donut_chart(pass_count, fail_count, unk_count), clear_figure=True)
   st.markdown("</div>", unsafe_allow_html=True)
with ch2:
   st.markdown("<div class='surface'><div class='h'>Rule Hygiene</div><div class='p'>Top indicators for policy cleanup</div>", unsafe_allow_html=True)
   st.pyplot(bar_chart(["Permissive", "Shadowed", "Redundant", "Duplicates"], [perm_cnt, shd_cnt, red_cnt, dup_cnt], "Rule Hygiene Counts"), clear_figure=True)
   st.markdown("</div>", unsafe_allow_html=True)
with ch3:
   # UTM / Internet overview
   internet_total = result.sec_profile_coverage.get("internet_bound_policies", 0)
   internet_utm = result.sec_profile_coverage.get("internet_with_utm", 0)
   st.markdown("<div class='surface'><div class='h'>Security Controls</div><div class='p'>UTM attachment on internet-bound rules</div>", unsafe_allow_html=True)
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
   st.markdown("\n\n".join([f"- {b}" for b in bullets]))
   st.markdown("</div>", unsafe_allow_html=True)
with tab_cis:
   st.markdown("<div class='surface'><div class='h'>CIS Scorecard</div><div class='p'>Subset of verifiable controls from configuration export</div>", unsafe_allow_html=True)
   st.dataframe(cis_df, use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_fail:
   st.markdown("<div class='surface'><div class='h'>Failures & Why</div><div class='p'>Observed vs Expected + remediation CLI</div>", unsafe_allow_html=True)
   fail_df = cis_df[cis_df["status"] == "FAIL"].copy()
   if fail_df.empty:
       st.success("No FAIL controls in the evaluated CIS subset.")
   else:
       show_cols = ["control_id", "category", "control_name", "observed", "expected", "remediation"]
       st.dataframe(fail_df[show_cols], use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_hyg:
   st.markdown("<div class='surface'><div class='h'>Policy Hygiene</div><div class='p'>Permissive, duplicate, shadowed and redundant rule checks</div>", unsafe_allow_html=True)
   st.markdown("#### Permissive Rules (MEDIUM+)")
   st.dataframe(pd.DataFrame(result.permissive), use_container_width=True, hide_index=True)
   c1, c2 = st.columns(2)
   with c1:
       st.markdown("#### Duplicate Rules")
       st.dataframe(pd.DataFrame(result.duplicates), use_container_width=True, hide_index=True)
   with c2:
       st.markdown("#### Shadowed Rules")
       st.dataframe(pd.DataFrame(result.shadowed), use_container_width=True, hide_index=True)
   st.markdown("#### Redundant Rules")
   st.dataframe(pd.DataFrame(result.redundant), use_container_width=True, hide_index=True)
   st.caption("Shadowed/Redundant are conservative. For precision, resolve address/service objects & groups.")
   st.markdown("</div>", unsafe_allow_html=True)
with tab_seg:
   st.markdown("<div class='surface'><div class='h'>Segmentation</div><div class='p'>Interface-to-interface allow matrix and governance indicators</div>", unsafe_allow_html=True)
   st.dataframe(pd.DataFrame(result.segmentation), use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_life:
   st.markdown("<div class='surface'><div class='h'>Lifecycle Details</div><div class='p'>Applies to firmware branch support status</div>", unsafe_allow_html=True)
   life_df = pd.DataFrame([
       ["Applies to", "Firmware branch lifecycle (FortiOS support status)"],
       ["Detected platform", life.get("platform", platform)],
       ["Platform status", life.get("platform_status", "Review")],
       ["Detected firmware", f"{life.get('firmware_version', fw_ver)} (build {life.get('firmware_build', fw_build)})"],
       ["Firmware status", life.get("firmware_status", "Review")],
       ["Security exposure (why)", life.get("security_exposure", "Unknown")],
       ["Recommended action", life.get("recommendation", "")]
   ], columns=["Field", "Value"])
   st.dataframe(life_df, use_container_width=True, hide_index=True)
   st.markdown("</div>", unsafe_allow_html=True)
with tab_export:
   st.markdown("<div class='surface'><div class='h'>Export</div><div class='p'>Download the evidence workbook</div>", unsafe_allow_html=True)
   excel_bytes = build_excel_report(result)
   st.download_button(
       "Download Excel Report",
       data=excel_bytes,
       file_name=f"Firewall_Governance_{hostname}.xlsx",
       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
   )
   st.markdown("</div>", unsafe_allow_html=True)