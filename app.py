# app.py
# Firewall Governance MVP — Premium SaaS-style Streamlit UI
# - Fixes cropped Hostname/Platform/Firmware badges
# - Adds “CIS Version Applied” banner (if analyzer provides benchmark_meta/scores)
# - Executive KPIs + Pass/Fail/Why + Tabs + Export
# - Dark premium theme + glass surfaces + clean tables
import streamlit as st
import pandas as pd
from analyzer import analyze_config
from report_generator import build_excel_report

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(
   page_title="Firewall Governance",
   page_icon="🛡️",
   layout="wide",
   initial_sidebar_state="expanded",
)

# -----------------------------
# Premium CSS (dark SaaS)
# -----------------------------
st.markdown(
   """
<style>
/* ---------- Global ---------- */
:root{
 --bg0: #0b1220;
 --bg1: #0e172a;
 --card: rgba(255,255,255,0.06);
 --card2: rgba(255,255,255,0.08);
 --border: rgba(148,163,184,0.20);
 --text: #e5e7eb;
 --muted: rgba(229,231,235,0.70);
 --muted2: rgba(229,231,235,0.55);
 --good: #22c55e;
 --warn: #f59e0b;
 --bad:  #ef4444;
 --info: #38bdf8;
 --pill: rgba(34,197,94,0.18);
 --pillBorder: rgba(34,197,94,0.25);
 --shadow: 0 8px 24px rgba(0,0,0,0.35);
}
html, body, [data-testid="stAppViewContainer"]{
 background: radial-gradient(1200px 600px at 20% 0%, rgba(56,189,248,0.12), transparent 55%),
             radial-gradient(900px 500px at 90% 10%, rgba(34,197,94,0.10), transparent 55%),
             linear-gradient(180deg, var(--bg1) 0%, var(--bg0) 100%);
 color: var(--text);
}
.block-container{ padding-top: 1.0rem; padding-bottom: 2.0rem; }
/* Remove extra padding in sidebar */
section[data-testid="stSidebar"]{
 background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));
 border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] * { color: var(--text); }
/* ---------- Top Header ---------- */
.hero{
 background: linear-gradient(135deg, rgba(56,189,248,0.18), rgba(34,197,94,0.12));
 border: 1px solid var(--border);
 border-radius: 18px;
 padding: 18px 18px;
 box-shadow: var(--shadow);
}
.heroTitle{
 font-size: 20px;
 font-weight: 800;
 letter-spacing: 0.2px;
 margin: 0;
}
.heroSub{
 margin-top: 6px;
 font-size: 12.5px;
 color: var(--muted);
}
.heroPills{
 margin-top: 10px;
 display:flex;
 gap:10px;
 flex-wrap:wrap;
}
/* ---------- Pills / Badges ---------- */
.pill{
 display:inline-flex;
 align-items:center;
 gap:8px;
 padding: 6px 10px;
 border-radius: 999px;
 background: rgba(255,255,255,0.06);
 border: 1px solid var(--border);
 color: var(--text);
 font-size: 12px;
 white-space: nowrap;
}
.pillDot{ width:8px; height:8px; border-radius:99px; background: var(--info); opacity: 0.95; }
.pillGood .pillDot{ background: var(--good); }
.pillWarn .pillDot{ background: var(--warn); }
.pillBad  .pillDot{ background: var(--bad);  }
/* Asset pill (fix cropping) */
.asset-pill{
 display: inline-flex;
 align-items: center;
 padding: 6px 12px;
 border-radius: 10px;
 background: var(--pill);
 border: 1px solid var(--pillBorder);
 color: var(--good);
 font-weight: 700;
 font-size: 14px;
 max-width: 100%;
 white-space: normal;      /* allow wrap */
 word-break: break-word;   /* break long strings */
 line-height: 1.25;
}
/* ---------- Surfaces / Cards ---------- */
.surface{
 background: var(--card);
 border: 1px solid var(--border);
 border-radius: 16px;
 padding: 14px 16px;
 box-shadow: 0 1px 0 rgba(255,255,255,0.02);
 backdrop-filter: blur(10px);
}
.surfaceTitle{
 font-weight: 800;
 font-size: 14px;
 margin-bottom: 6px;
}
.surfaceSub{
 color: var(--muted);
 font-size: 12px;
}
/* KPI cards */
.kpi{
 background: var(--card2);
 border: 1px solid var(--border);
 border-radius: 16px;
 padding: 14px 14px;
 box-shadow: 0 10px 24px rgba(0,0,0,0.18);
 min-height: 86px;
}
.kpiLabel{
 font-size: 12px;
 color: var(--muted);
 margin-bottom: 8px;
 font-weight: 600;
}
.kpiValue{
 font-size: 22px;
 font-weight: 900;
 line-height: 1.1;
}
.kpiSub{
 margin-top: 6px;
 font-size: 12px;
 color: var(--muted2);
}
.kpiGood{ color: var(--good); }
.kpiWarn{ color: var(--warn); }
.kpiBad{  color: var(--bad);  }
/* Divider */
.hr{
 height:1px;
 background: rgba(148,163,184,0.18);
 margin: 16px 0;
 border-radius: 10px;
}
/* Tabs styling */
.stTabs [data-baseweb="tab-list"]{
 gap: 8px;
}
.stTabs [data-baseweb="tab"]{
 background: rgba(255,255,255,0.05);
 border: 1px solid rgba(148,163,184,0.20);
 border-radius: 999px;
 padding: 8px 14px;
}
.stTabs [aria-selected="true"]{
 background: rgba(56,189,248,0.15);
 border: 1px solid rgba(56,189,248,0.35);
}
/* Tables */
[data-testid="stDataFrame"]{
 border: 1px solid var(--border);
 border-radius: 14px;
 overflow: hidden;
 box-shadow: 0 10px 24px rgba(0,0,0,0.10);
}
[data-testid="stTable"]{
 border: 1px solid var(--border);
 border-radius: 14px;
 overflow:hidden;
}
/* Buttons */
.stDownloadButton button, .stButton button{
 border-radius: 12px !important;
 border: 1px solid rgba(148,163,184,0.26) !important;
 background: rgba(255,255,255,0.06) !important;
}
.stDownloadButton button:hover, .stButton button:hover{
 border: 1px solid rgba(56,189,248,0.38) !important;
 background: rgba(56,189,248,0.10) !important;
}
/* File uploader */
[data-testid="stFileUploaderDropzone"]{
 border: 1px dashed rgba(148,163,184,0.35) !important;
 border-radius: 16px !important;
 background: rgba(255,255,255,0.04) !important;
}
/* Remove Streamlit default header space */
header { visibility: hidden; height: 0px; }
</style>
""",
   unsafe_allow_html=True,
)

# -----------------------------
# Helpers
# -----------------------------
def safe_get(obj, attr, default=None):
   return getattr(obj, attr, default) if obj is not None else default

def render_kpi(col, label, value, sub="", tone=""):
   tone_class = {"good": "kpiGood", "warn": "kpiWarn", "bad": "kpiBad"}.get(tone, "")
   col.markdown(
       f"""
<div class="kpi">
<div class="kpiLabel">{label}</div>
<div class="kpiValue {tone_class}">{value}</div>
<div class="kpiSub">{sub}</div>
</div>
       """,
       unsafe_allow_html=True,
   )

def status_tone(status: str) -> str:
   s = (status or "").upper()
   if s == "PASS":
       return "good"
   if s == "FAIL":
       return "bad"
   return "warn"

# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:
   st.markdown("### Upload Config")
   uploaded = st.file_uploader("FortiGate config (.txt/.conf/.cfg)", type=["txt", "conf", "cfg"])
   st.markdown("---")
   st.markdown("### Options")
   show_all_rows = st.toggle("Show all rows in tables", value=False)
   compact_tables = st.toggle("Compact tables", value=True)
   st.markdown("---")
   st.caption("Tip: Keep secrets out of configs before uploading.")

# -----------------------------
# Header
# -----------------------------
st.markdown(
   """
<div class="hero">
<div class="heroTitle">Firewall Governance</div>
<div class="heroSub">CIS • Hygiene • Segmentation • Lifecycle risk • Evidence export</div>
<div class="heroPills">
<span class="pill pillGood"><span class="pillDot"></span>Policy Assurance</span>
<span class="pill"><span class="pillDot"></span>Config-driven checks</span>
<span class="pill pillWarn"><span class="pillDot"></span>Offline-friendly</span>
</div>
</div>
""",
   unsafe_allow_html=True,
)
st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
if not uploaded:
   st.info("Upload a FortiGate configuration from the left sidebar to begin.")
   st.stop()
# -----------------------------
# Run Analysis
# -----------------------------
raw_text = uploaded.read().decode("utf-8", errors="ignore")
with st.spinner("Analyzing configuration…"):
   result = analyze_config(raw_text)
meta = safe_get(result, "meta", {}) or {}
hostname = meta.get("hostname", "Unknown")
platform = meta.get("platform", "Unknown")
fw_ver = meta.get("firmware_version", "Unknown")
fw_build = meta.get("firmware_build", "Unknown")
life = safe_get(result, "lifecycle_assessment", {}) or {}
bench = safe_get(result, "benchmark_meta", {}) or {}
scores = safe_get(result, "scores", {}) or {}
cis_rows = safe_get(result, "cis", []) or []
cis_df = pd.DataFrame(cis_rows) if cis_rows else pd.DataFrame(columns=["control_id", "category", "control_name", "status"])
# Normalize for older outputs (some versions use controlId/control_name etc.)
for col in ["control_id", "category", "control_name", "status"]:
   if col not in cis_df.columns:
       cis_df[col] = ""
# Pass/Fail/Unknown counts
pass_count = int((cis_df["status"].astype(str).str.upper() == "PASS").sum()) if not cis_df.empty else 0
fail_count = int((cis_df["status"].astype(str).str.upper() == "FAIL").sum()) if not cis_df.empty else 0
unk_count = int((~cis_df["status"].astype(str).str.upper().isin(["PASS", "FAIL"])).sum()) if not cis_df.empty else 0
total_count = int(len(cis_df)) if not cis_df.empty else 0
compliance_pct = scores.get("compliance_score")
if compliance_pct is None:
   compliance_pct = round((pass_count / total_count) * 100, 2) if total_count else 0.0
maturity_pct = scores.get("maturity_score", None)
perm_cnt = len(safe_get(result, "permissive", []) or [])
dup_cnt = len(safe_get(result, "duplicates", []) or [])
shd_cnt = len(safe_get(result, "shadowed", []) or [])
red_cnt = len(safe_get(result, "redundant", []) or [])
sec_cov = safe_get(result, "sec_profile_coverage", {}) or {}
utm_pct = sec_cov.get("utm_coverage_pct", 0)
# -----------------------------
# Top Summary: Asset + Lifecycle + Benchmark
# -----------------------------
left, right = st.columns([2.2, 1.2], gap="large")
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
   c1, c2, c3 = st.columns([1.0, 1.0, 1.0], gap="large")
   with c1:
       st.markdown("**Hostname**")
       st.markdown(f"<span class='asset-pill' title='{hostname}'>{hostname}</span>", unsafe_allow_html=True)
   with c2:
       st.markdown("**Platform**")
       st.markdown(f"<span class='asset-pill' title='{platform}'>{platform}</span>", unsafe_allow_html=True)
   with c3:
       fw_label = f"{fw_ver} (build {fw_build})" if fw_build not in [None, "", "Unknown"] else f"{fw_ver}"
       st.markdown("**Firmware**")
       st.markdown(f"<span class='asset-pill' title='{fw_label}'>{fw_label}</span>", unsafe_allow_html=True)
with right:
   # Lifecycle tone
   fw_status = (life.get("firmware_status") or "Review").upper()
   plat_status = (life.get("platform_status") or "Review").upper()
   def pill_for_status(label, status):
       s = (status or "").upper()
       if "EOL" in s or "UNSUPPORTED" in s:
           cls = "pillBad"
       elif "SUPPORTED" in s or "OK" in s:
           cls = "pillGood"
       else:
           cls = "pillWarn"
       return f"<span class='pill {cls}'><span class='pillDot'></span>{label}: {status}</span>"
   # Benchmark details (if available)
   pack_name = bench.get("pack_name", "CIS-aligned checks")
   pack_ver = bench.get("pack_version", "")
   sel = bench.get("selection", "auto")
   bench_line = f"{pack_name} {pack_ver}".strip()
   st.markdown(
       f"""
<div class="surface">
<div class="surfaceTitle">Risk Posture</div>
<div class="surfaceSub">Lifecycle + benchmark context</div>
<div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
           {pill_for_status("Platform", plat_status.title())}
           {pill_for_status("Firmware", fw_status.title())}
<span class="pill"><span class="pillDot"></span>Benchmark: {bench_line}</span>
<span class="pill"><span class="pillDot"></span>Selection: {sel}</span>
</div>
<div style="margin-top:10px; color: var(--muted); font-size:12px;">
           {life.get("security_exposure","")}
</div>
</div>
       """,
       unsafe_allow_html=True,
   )
# -----------------------------
# KPI Row
# -----------------------------
st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
k1, k2, k3, k4, k5, k6 = st.columns(6, gap="large")
render_kpi(k1, "CIS Compliance", f"{compliance_pct:.2f}%", f"PASS {pass_count} / {total_count}", tone="good" if compliance_pct >= 80 else "warn")
render_kpi(k2, "CIS FAIL", f"{fail_count}", "Controls needing remediation", tone="bad" if fail_count else "good")
render_kpi(k3, "Permissive Rules", f"{perm_cnt}", "MEDIUM+ risk rules", tone="warn" if perm_cnt else "good")
render_kpi(k4, "Duplicates", f"{dup_cnt}", "Exact matches", tone="warn" if dup_cnt else "good")
render_kpi(k5, "Shadowed", f"{shd_cnt}", "Conservative detection", tone="warn" if shd_cnt else "good")
render_kpi(k6, "UTM Coverage", f"{utm_pct}%", "Internet-bound policies", tone="good" if utm_pct >= 80 else "warn")
# Optional maturity KPI row
if maturity_pct is not None:
   st.markdown("")
   m1, m2, m3, m4 = st.columns(4, gap="large")
   render_kpi(m1, "Maturity Score", f"{float(maturity_pct):.2f}%", "Weight × maturity adjusted", tone="good" if maturity_pct >= 80 else "warn")
   render_kpi(m2, "CIS UNKNOWN", f"{unk_count}", "Not verifiable / not implemented", tone="warn" if unk_count else "good")
   render_kpi(m3, "Redundant", f"{red_cnt}", "Candidates to remove", tone="warn" if red_cnt else "good")
   render_kpi(m4, "Total Controls", f"{total_count}", "Evaluated benchmark subset", tone="good" if total_count else "warn")
st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
# -----------------------------
# Tabs
# -----------------------------
tab_exec, tab_cis, tab_fail, tab_hyg, tab_seg, tab_life, tab_export = st.tabs(
   ["Executive", "CIS Scorecard", "Failures & Why", "Policy Hygiene", "Segmentation", "Lifecycle", "Export"]
)
# Executive
with tab_exec:
   st.markdown("### Executive Snapshot")
   st.caption("High-level view for leadership review (controls, key drivers, and recommended next actions).")
   # Light summary cards
   s1, s2 = st.columns([1.4, 1.0], gap="large")
   with s1:
       st.markdown(
           """
<div class="surface">
<div class="surfaceTitle">Key Findings</div>
<div class="surfaceSub">Most material items detected from configuration</div>
</div>
           """,
           unsafe_allow_html=True,
       )
       drivers = []
       if fail_count:
           drivers.append(f"• **{fail_count} CIS controls failed** — remediation actions available in the Failures tab.")
       if unk_count:
           drivers.append(f"• **{unk_count} controls unknown** — not verifiable from config or missing check logic.")
       if perm_cnt:
           drivers.append(f"• **{perm_cnt} permissive rule(s)** — may increase attack surface.")
       if shd_cnt:
           drivers.append(f"• **{shd_cnt} shadowed rule(s)** — potential rule cleanup opportunity.")
       if dup_cnt:
           drivers.append(f"• **{dup_cnt} duplicate rule(s)** — consolidate to reduce policy sprawl.")
       if "EOL" in fw_status or "UNSUPPORTED" in fw_status:
           drivers.append("• **Firmware lifecycle risk** — upgrade planning required to remain supported.")
       if not drivers:
           drivers.append("• No critical drivers detected in the evaluated subset.")
       st.markdown("\n".join(drivers))
   with s2:
       st.markdown(
           """
<div class="surface">
<div class="surfaceTitle">Recommended Actions</div>
<div class="surfaceSub">Next steps aligned to governance + assurance</div>
</div>
           """,
           unsafe_allow_html=True,
       )
       actions = [
           "1) Remediate failed CIS controls (prioritize authentication & logging).",
           "2) Validate permissive rules against business justification; tighten where possible.",
           "3) Review shadowed/duplicate rules and consolidate with change management.",
           "4) Capture evidence (screenshots/exports) per control for audit readiness.",
       ]
       if "EOL" in fw_status or "UNSUPPORTED" in fw_status:
           actions.append("5) Plan firmware uplift to supported branch; assess PSIRT exposure.")
       st.markdown("\n".join(actions))
   st.markdown("### Control Overview")
   if cis_df.empty:
       st.info("No CIS controls available from analyzer output.")
   else:
       view_cols = [c for c in ["control_id", "category", "control_name", "status"] if c in cis_df.columns]
       df_view = cis_df[view_cols].copy()
       st.dataframe(df_view, use_container_width=True, hide_index=True)
# CIS Scorecard
with tab_cis:
   st.markdown("### CIS Scorecard")
   st.caption("CIS-aligned controls evaluated from the configuration dump. (Subset-based unless benchmark packs are enabled.)")
   if cis_df.empty:
       st.info("No CIS controls available.")
   else:
       st.dataframe(cis_df, use_container_width=True, hide_index=True)
# Failures
with tab_fail:
   st.markdown("### Failures & Why")
   st.caption("Observed vs expected gaps and suggested CLI remediation.")
   if cis_df.empty:
       st.info("No CIS controls available.")
   else:
       upper = cis_df["status"].astype(str).str.upper()
       fail_df = cis_df[upper == "FAIL"].copy()
       if fail_df.empty:
           st.success("No FAIL controls in the evaluated CIS subset.")
       else:
           cols_preferred = ["control_id", "category", "control_name", "observed", "expected", "why_failed", "remediation"]
           cols = [c for c in cols_preferred if c in fail_df.columns]
           st.dataframe(fail_df[cols], use_container_width=True, hide_index=True)
       with st.expander("How to interpret FAIL results"):
           st.write("**Why failed** indicates the observed configuration does not meet the expected requirement.")
           st.write("Use **Remediation** as a starting point and validate via change control prior to production changes.")
# Hygiene
with tab_hyg:
   st.markdown("### Policy Hygiene")
   st.caption("Rule hygiene signals: permissive, duplicates, shadowed, redundant (heuristic-based for MVP).")
   permissive = pd.DataFrame(safe_get(result, "permissive", []) or [])
   duplicates = pd.DataFrame(safe_get(result, "duplicates", []) or [])
   shadowed = pd.DataFrame(safe_get(result, "shadowed", []) or [])
   redundant = pd.DataFrame(safe_get(result, "redundant", []) or [])
   st.markdown("#### Permissive Rules (MEDIUM+)")
   st.dataframe(permissive, use_container_width=True, hide_index=True)
   c1, c2 = st.columns(2, gap="large")
   with c1:
       st.markdown("#### Duplicate Rules")
       st.dataframe(duplicates, use_container_width=True, hide_index=True)
   with c2:
       st.markdown("#### Shadowed Rules")
       st.dataframe(shadowed, use_container_width=True, hide_index=True)
   st.markdown("#### Redundant Rules")
   st.dataframe(redundant, use_container_width=True, hide_index=True)
   st.caption("Note: Shadowed/Redundant detection is conservative for MVP. For precision, resolve address/service groups and object expansion.")
# Segmentation
with tab_seg:
   st.markdown("### Segmentation")
   st.caption("Interface-to-interface allow matrix and governance indicators.")
   seg = pd.DataFrame(safe_get(result, "segmentation", []) or [])
   st.dataframe(seg, use_container_width=True, hide_index=True)
   st.markdown("#### Security Profile Coverage")
   st.json(sec_cov)
# Lifecycle
with tab_life:
   st.markdown("### Lifecycle Risk")
   st.caption("Offline lifecycle posture. Replace with live Fortinet lifecycle + PSIRT feeds when permitted.")
   st.json(life)
   rec = (life.get("recommendation") or "").strip()
   if rec:
       st.markdown("#### Recommendation")
       st.write(rec)
# Export
with tab_export:
   st.markdown("### Export Evidence Workbook")
   st.caption("Download an Excel workbook with dashboard + evidence-ready tables.")
   try:
       excel_bytes = build_excel_report(result)
       filename_safe = "".join([c if c.isalnum() or c in ("-", "_") else "_" for c in hostname]) or "Firewall"
       st.download_button(
           "Download Excel Report",
           data=excel_bytes,
           file_name=f"Firewall_Governance_{filename_safe}.xlsx",
           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
           use_container_width=True,
       )
   except Exception as e:
       st.error("Excel export failed. Check report_generator.py / analyzer output structure.")
       st.code(str(e))
# Table height preferences (optional)
if compact_tables:
   st.markdown(
       """
<style>
       div[data-testid="stDataFrame"] div[role="grid"] { min-height: 280px; }
</style>
       """,
       unsafe_allow_html=True,
   )
# Optional: expand table row display
if show_all_rows:
   st.caption("Showing all rows may reduce performance on large configs.")
   st.session_state["show_all_rows"] = True
