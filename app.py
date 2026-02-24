import streamlit as st
import pandas as pd
from analyzer import analyze_config
from report_generator import build_excel_report
# -----------------------------------
# Page Config
# -----------------------------------
st.set_page_config(
   page_title="Firewall Governance",
   page_icon="🛡️",
   layout="wide",
   initial_sidebar_state="expanded",
)
# -----------------------------------
# Premium SaaS Dark UI (CSS)
# -----------------------------------
st.markdown(
   """
<style>
:root{
 --bg0:#070b14;
 --bg1:#0b1220;
 --panel:rgba(255,255,255,0.06);
 --panel2:rgba(255,255,255,0.08);
 --border:rgba(148,163,184,0.22);
 --text:#e5e7eb;
 --muted:rgba(229,231,235,0.70);
 --muted2:rgba(229,231,235,0.55);
 --good:#22c55e;
 --warn:#f59e0b;
 --bad:#ef4444;
 --info:#38bdf8;
 --shadow:0 14px 30px rgba(0,0,0,0.35);
 --shadow2:0 10px 24px rgba(0,0,0,0.20);
}
/* App background */
html, body, [data-testid="stAppViewContainer"]{
 background:
   radial-gradient(1200px 600px at 18% 0%, rgba(56,189,248,0.13), transparent 55%),
   radial-gradient(900px 500px at 88% 10%, rgba(34,197,94,0.11), transparent 55%),
   linear-gradient(180deg, var(--bg1) 0%, var(--bg0) 100%);
 color:var(--text);
}
.block-container{ padding-top:1.0rem; padding-bottom:2.2rem; }
/* Sidebar */
section[data-testid="stSidebar"]{
 background: linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
 border-right:1px solid var(--border);
}
section[data-testid="stSidebar"] *{ color:var(--text); }
/* Hide Streamlit header */
header{ visibility:hidden; height:0px; }
/* Hero */
.hero{
 background: linear-gradient(135deg, rgba(56,189,248,0.20), rgba(34,197,94,0.12));
 border:1px solid var(--border);
 border-radius:18px;
 padding:18px 18px;
 box-shadow:var(--shadow);
}
.heroTitle{ font-size:20px; font-weight:900; letter-spacing:.2px; margin:0; }
.heroSub{ margin-top:6px; font-size:12.5px; color:var(--muted); }
.heroRow{ margin-top:10px; display:flex; gap:10px; flex-wrap:wrap; }
.pill{
 display:inline-flex; align-items:center; gap:8px;
 padding:6px 10px;
 border-radius:999px;
 background: rgba(255,255,255,0.06);
 border:1px solid var(--border);
 font-size:12px;
 white-space:nowrap;
}
.dot{ width:8px; height:8px; border-radius:99px; background:var(--info); }
.good .dot{ background:var(--good); }
.warn .dot{ background:var(--warn); }
.bad  .dot{ background:var(--bad); }
/* Surfaces */
.surface{
 background: var(--panel);
 border:1px solid var(--border);
 border-radius:16px;
 padding:14px 16px;
 box-shadow:0 1px 0 rgba(255,255,255,0.02);
 backdrop-filter: blur(10px);
}
.surfaceTitle{ font-weight:900; font-size:14px; margin-bottom:6px; }
.surfaceSub{ color:var(--muted); font-size:12px; }
/* FULL-WIDTH wrap pill for asset labels (fix cropping) */
.asset-pill{
 display:block;          /* full width */
 width:100%;
 padding:8px 12px;
 border-radius:12px;
 background: rgba(34,197,94,0.16);
 border:1px solid rgba(34,197,94,0.22);
 color: var(--good);
 font-weight:800;
 font-size:14px;
 white-space:normal;
 word-break:break-word;
 line-height:1.25;
}
/* KPI */
.kpi{
 background: var(--panel2);
 border:1px solid var(--border);
 border-radius:16px;
 padding:14px;
 box-shadow:var(--shadow2);
 min-height:88px;
}
.kpiLabel{ font-size:12px; color:var(--muted); margin-bottom:8px; font-weight:700; }
.kpiValue{ font-size:22px; font-weight:950; line-height:1.1; }
.kpiSub{ margin-top:6px; font-size:12px; color:var(--muted2); }
.kgood{ color:var(--good); }
.kwarn{ color:var(--warn); }
.kbad { color:var(--bad); }
.hr{ height:1px; background:rgba(148,163,184,0.18); margin:16px 0; border-radius:10px; }
/* Tabs */
.stTabs [data-baseweb="tab-list"]{ gap:8px; }
.stTabs [data-baseweb="tab"]{
 background: rgba(255,255,255,0.05);
 border:1px solid rgba(148,163,184,0.20);
 border-radius:999px;
 padding:8px 14px;
}
.stTabs [aria-selected="true"]{
 background: rgba(56,189,248,0.15);
 border:1px solid rgba(56,189,248,0.35);
}
/* Tables */
[data-testid="stDataFrame"]{
 border:1px solid var(--border);
 border-radius:14px;
 overflow:hidden;
 box-shadow:0 10px 24px rgba(0,0,0,0.10);
}
/* Buttons */
.stDownloadButton button, .stButton button{
 border-radius:12px !important;
 border:1px solid rgba(148,163,184,0.26) !important;
 background: rgba(255,255,255,0.06) !important;
}
.stDownloadButton button:hover, .stButton button:hover{
 border:1px solid rgba(56,189,248,0.38) !important;
 background: rgba(56,189,248,0.10) !important;
}
/* File uploader */
[data-testid="stFileUploaderDropzone"]{
 border:1px dashed rgba(148,163,184,0.35) !important;
 border-radius:16px !important;
 background: rgba(255,255,255,0.04) !important;
}
</style>
""",
   unsafe_allow_html=True,
)
def render_kpi(col, label, value, sub="", tone=""):
   tone_cls = {"good":"kgood","warn":"kwarn","bad":"kbad"}.get(tone,"")
   col.markdown(
       f"""
<div class="kpi">
<div class="kpiLabel">{label}</div>
<div class="kpiValue {tone_cls}">{value}</div>
<div class="kpiSub">{sub}</div>
</div>
       """,
       unsafe_allow_html=True,
   )
# -----------------------------------
# Sidebar: Upload + Benchmark Pack
# -----------------------------------
with st.sidebar:
   st.markdown("### Upload")
   uploaded = st.file_uploader("FortiGate config (.txt/.conf/.cfg)", type=["txt","conf","cfg"])
   st.markdown("---")
   st.markdown("### CIS Benchmark Pack")
   st.caption("Choose the CIS pack you want to claim in the report (subset controls in MVP).")
   pack = st.selectbox(
       "Benchmark family",
       ["Auto (from firmware)", "FortiOS 7.0.x", "FortiOS 7.4.x"],
       index=0
   )
   pack_ver = "Auto"
   if pack == "FortiOS 7.0.x":
       pack_ver = st.selectbox("Version", ["v1.4.0", "v1.3.0", "v1.2.0 (Archive)"], index=0)
   elif pack == "FortiOS 7.4.x":
       pack_ver = st.selectbox("Version", ["v1.0.1", "v1.0.0"], index=0)
   st.markdown("---")
   st.markdown("### Output")
   st.caption("After analysis, download the executive Excel report from the Export tab.")
if not uploaded:
   st.markdown(
       """
<div class="hero">
<div class="heroTitle">Firewall Governance</div>
<div class="heroSub">CIS • Hygiene • Segmentation • Lifecycle risk • Evidence export</div>
<div class="heroRow">
<span class="pill good"><span class="dot"></span>Policy Assurance</span>
<span class="pill"><span class="dot"></span>Config-driven checks</span>
<span class="pill warn"><span class="dot"></span>Offline-friendly</span>
</div>
</div>
       """,
       unsafe_allow_html=True,
   )
   st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
   st.info("Upload a FortiGate configuration from the left sidebar to begin.")
   st.stop()
# -----------------------------------
# Header
# -----------------------------------
st.markdown(
   """
<div class="hero">
<div class="heroTitle">Firewall Governance</div>
<div class="heroSub">Commercial SaaS-style governance dashboard for CIS benchmarking, hygiene, segmentation, and lifecycle risk.</div>
<div class="heroRow">
<span class="pill good"><span class="dot"></span>Executive-ready</span>
<span class="pill"><span class="dot"></span>Evidence export</span>
<span class="pill warn"><span class="dot"></span>MVP subset controls</span>
</div>
</div>
""",
   unsafe_allow_html=True,
)
st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
# -----------------------------------
# Analyze
# -----------------------------------
raw_text = uploaded.read().decode("utf-8", errors="ignore")
with st.spinner("Analyzing configuration…"):
   result = analyze_config(
       raw_text,
       benchmark_family=pack,
       benchmark_version=pack_ver
   )
meta = result.meta or {}
hostname = meta.get("hostname", "Unknown")
platform = meta.get("platform", "Unknown")
fw_ver = meta.get("firmware_version", "Unknown")
fw_build = meta.get("firmware_build", "Unknown")
life = result.lifecycle_assessment or {}
bench = getattr(result, "benchmark_meta", {}) or {}
scores = getattr(result, "scores", {}) or {}
cis_df = pd.DataFrame(result.cis or [])
if cis_df.empty:
   cis_df = pd.DataFrame(columns=["control_id","category","control_name","status","observed","expected","weight","remediation"])
# KPI computation
status_upper = cis_df["status"].astype(str).str.upper()
pass_count = int((status_upper == "PASS").sum())
fail_count = int((status_upper == "FAIL").sum())
unk_count  = int((~status_upper.isin(["PASS","FAIL"])).sum())
total_count = int(len(cis_df))
compliance_pct = float(scores.get("compliance_score", 0.0))
maturity_pct   = scores.get("maturity_score", None)
utm_pct = (result.sec_profile_coverage or {}).get("utm_coverage_pct", 0)
perm_cnt = len(result.permissive or [])
dup_cnt  = len(result.duplicates or [])
shd_cnt  = len(result.shadowed or [])
red_cnt  = len(result.redundant or [])
# -----------------------------------
# Context cards
# -----------------------------------
left, right = st.columns([2.3, 1.1], gap="large")
with left:
   st.markdown(
       """
<div class="surface">
<div class="surfaceTitle">Asset Context</div>
<div class="surfaceSub">Device identification and detected runtime metadata</div>
</div>
       """,
       unsafe_allow_html=True,
   )
   st.markdown("")
   c1, c2, c3 = st.columns([1.1, 1.2, 1.4], gap="large")
   with c1:
       st.markdown("**Hostname**")
       st.markdown(f"<div class='asset-pill'>{hostname}</div>", unsafe_allow_html=True)
   with c2:
       st.markdown("**Platform**")
       st.markdown(f"<div class='asset-pill'>{platform}</div>", unsafe_allow_html=True)
   with c3:
       fw_label = f"{fw_ver} (build {fw_build})" if fw_build not in [None,"","Unknown"] else fw_ver
       st.markdown("**Firmware**")
       st.markdown(f"<div class='asset-pill'>{fw_label}</div>", unsafe_allow_html=True)
with right:
   fw_status = (life.get("firmware_status","Review") or "Review")
   plat_status = (life.get("platform_status","Review") or "Review")
   def pill(label, value):
       v = str(value).upper()
       cls = "warn"
       if "EOL" in v or "UNSUPPORTED" in v:
           cls = "bad"
       elif "SUPPORTED" in v or "OK" in v:
           cls = "good"
       return f"<span class='pill {cls}'><span class='dot'></span>{label}: {value}</span>"
   bench_line = f"{bench.get('pack_name','Auto')} {bench.get('pack_version','')}".strip()
   st.markdown(
       f"""
<div class="surface">
<div class="surfaceTitle">Risk Posture</div>
<div class="surfaceSub">Lifecycle + benchmark context</div>
<div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
           {pill("Platform", plat_status)}
           {pill("Firmware", fw_status)}
<span class="pill"><span class="dot"></span>Benchmark: {bench_line}</span>
</div>
<div style="margin-top:10px; color:var(--muted); font-size:12px;">
           {life.get("security_exposure","")}
</div>
</div>
       """,
       unsafe_allow_html=True,
   )
st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
# -----------------------------------
# KPI Row
# -----------------------------------
k1, k2, k3, k4, k5, k6 = st.columns(6, gap="large")
render_kpi(k1, "CIS Compliance", f"{compliance_pct:.2f}%", f"PASS {pass_count} / {total_count}",
          tone="good" if compliance_pct >= 80 else "warn")
render_kpi(k2, "CIS FAIL", f"{fail_count}", "Controls needing remediation", tone="bad" if fail_count else "good")
render_kpi(k3, "Permissive Rules", f"{perm_cnt}", "MEDIUM+ risk rules", tone="warn" if perm_cnt else "good")
render_kpi(k4, "Duplicates", f"{dup_cnt}", "Exact matches", tone="warn" if dup_cnt else "good")
render_kpi(k5, "Shadowed", f"{shd_cnt}", "Conservative detection", tone="warn" if shd_cnt else "good")
render_kpi(k6, "UTM Coverage", f"{utm_pct}%", "Internet-bound policies", tone="good" if utm_pct >= 80 else "warn")
if maturity_pct is not None:
   st.markdown("")
   m1, m2, m3, m4 = st.columns(4, gap="large")
   render_kpi(m1, "Maturity Score", f"{float(maturity_pct):.2f}%", "Weight-adjusted", tone="good" if maturity_pct >= 80 else "warn")
   render_kpi(m2, "CIS UNKNOWN", f"{unk_count}", "Not verifiable / missing", tone="warn" if unk_count else "good")
   render_kpi(m3, "Redundant", f"{red_cnt}", "Candidates to remove", tone="warn" if red_cnt else "good")
   render_kpi(m4, "Benchmark Pack", bench_line, "Included in report", tone="good")
st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
# -----------------------------------
# Tabs
# -----------------------------------
tab_exec, tab_cis, tab_fail, tab_hyg, tab_seg, tab_life, tab_export = st.tabs(
   ["Executive", "CIS Scorecard", "Failures & Why", "Policy Hygiene", "Segmentation", "Lifecycle", "Export"]
)
with tab_exec:
   st.markdown("### Executive Snapshot")
   st.caption("High-level view for leadership review (controls, drivers, recommended actions).")
   drivers = []
   if fail_count: drivers.append(f"• **{fail_count} CIS controls failed** — see Failures & Why tab for remediation.")
   if unk_count: drivers.append(f"• **{unk_count} controls unknown** — not verifiable from config or missing check logic.")
   if perm_cnt: drivers.append(f"• **{perm_cnt} permissive rules** — increases attack surface.")
   if fw_status.upper().startswith("EOL") or "UNSUPPORTED" in fw_status.upper():
       drivers.append("• **Firmware branch is EOL/Unsupported** — upgrade planning required.")
   if not drivers:
       drivers.append("• No critical drivers detected in evaluated subset.")
   st.markdown("\n".join(drivers))
   st.markdown("### Control Overview")
   view_cols = ["control_id","category","control_name","status"]
   st.dataframe(cis_df[view_cols], use_container_width=True, hide_index=True)
with tab_cis:
   st.markdown("### CIS Scorecard")
   st.caption("Subset of verifiable controls from configuration export.")
   st.dataframe(cis_df, use_container_width=True, hide_index=True)
with tab_fail:
   st.markdown("### Failures & Why")
   st.caption("Observed vs Expected + remediation CLI.")
   fail_df = cis_df[status_upper == "FAIL"].copy()
   if fail_df.empty:
       st.success("No FAIL controls in the evaluated CIS subset.")
   else:
       show_cols = ["control_id","category","control_name","observed","expected","remediation"]
       st.dataframe(fail_df[show_cols], use_container_width=True, hide_index=True)
with tab_hyg:
   st.markdown("### Policy Hygiene")
   st.markdown("#### Permissive Rules (MEDIUM+)")
   st.dataframe(pd.DataFrame(result.permissive or []), use_container_width=True, hide_index=True)
   c1, c2 = st.columns(2, gap="large")
   with c1:
       st.markdown("#### Duplicate Rules")
       st.dataframe(pd.DataFrame(result.duplicates or []), use_container_width=True, hide_index=True)
   with c2:
       st.markdown("#### Shadowed Rules")
       st.dataframe(pd.DataFrame(result.shadowed or []), use_container_width=True, hide_index=True)
   st.markdown("#### Redundant Rules")
   st.dataframe(pd.DataFrame(result.redundant or []), use_container_width=True, hide_index=True)
   st.caption("Note: Shadowed/Redundant is conservative for MVP (ALL/exact). For precision, expand object groups.")
with tab_seg:
   st.markdown("### Segmentation")
   st.caption("Interface-to-interface allow matrix and indicators.")
   st.dataframe(pd.DataFrame(result.segmentation or []), use_container_width=True, hide_index=True)
   st.markdown("#### Security Profile Coverage")
   st.json(result.sec_profile_coverage or {})
with tab_life:
   st.markdown("### Lifecycle Risk")
   st.caption("Offline lifecycle posture. Replace with vendor lifecycle + PSIRT feeds when permitted.")
   st.json(result.lifecycle_assessment or {})
   st.markdown("#### Recommendation")
   st.write((result.lifecycle_assessment or {}).get("recommendation", ""))
with tab_export:
   st.markdown("### Export")
   st.caption("Download the Excel workbook with dashboard + evidence-ready tables.")
   excel_bytes = build_excel_report(result)
   safe_name = "".join([c if c.isalnum() or c in ("-","_") else "_" for c in hostname]) or "Firewall"
   st.download_button(
       "Download Excel Report",
       data=excel_bytes,
       file_name=f"Firewall_Governance_{safe_name}.xlsx",
       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
       use_container_width=True
   )
