"""QuantumGuard dashboard (Streamlit).

Every number on this dashboard comes from running the real pipeline against a
repository path. Synthetic data appears only when the user explicitly builds
the demo repository, and it is labelled as such.

Run:  streamlit run app.py
"""
from __future__ import annotations

import copy
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from quantumguard import __version__
from quantumguard.config import QGError, load_json
from quantumguard.demo_builder import build_demo_repo
from quantumguard.git_history import GitError, git_toplevel, run_git
from quantumguard.pipeline import run_audit
from quantumguard.policy_engine import format_markdown, load_ci_policy, run_ci_gate
from quantumguard.report_generator import to_csv, to_json, to_markdown
from quantumguard.risk_engine import apply_scores, load_policy

st.set_page_config(page_title="QuantumGuard", layout="wide", initial_sidebar_state="expanded")

SEV_COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6", "info": "#64748b"}
DECISION_COLORS = {"block": "#ef4444", "warn": "#eab308", "pass": "#22c55e"}
PAGES = ["Overview", "Repository scan", "Historical audit", "PQC validation",
         "Risk prioritization", "CI/CD gate", "Reports"]

st.markdown("""
<style>
  .block-container {padding-top: 1.6rem; max-width: 1400px;}
  .qg-brand {font-size: 1.35rem; font-weight: 700; letter-spacing: .02em; color: #e2e8f0;}
  .qg-sub {font-size: .78rem; color: #94a3b8; margin-top: -4px;}
  .qg-card {background: #131c31; border: 1px solid #1f2a44; border-radius: 10px; padding: 14px 16px;}
  .qg-card .lbl {font-size: .72rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .06em;}
  .qg-card .val {font-size: 1.7rem; font-weight: 700; color: #f1f5f9; line-height: 1.2;}
  .qg-badge {display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: .72rem;
             font-weight: 700; color: #0b1220; text-transform: uppercase; letter-spacing: .04em;}
  .qg-banner {background: #3b2f0a; border: 1px solid #a16207; color: #fde68a; border-radius: 8px;
              padding: 8px 14px; font-size: .85rem; margin-bottom: 10px;}
  .qg-muted {color: #94a3b8; font-size: .85rem;}
  .qg-mono {font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .82rem; color: #cbd5e1;}
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers

def badge(text: str, color: str) -> str:
    return f'<span class="qg-badge" style="background:{color}">{text}</span>'


def card(col, label, value, color=None):
    style = f' style="color:{color}"' if color else ""
    col.markdown(f'<div class="qg-card"><div class="lbl">{label}</div><div class="val"{style}>{value}</div></div>',
                 unsafe_allow_html=True)


def state():
    ss = st.session_state
    ss.setdefault("audit", None)
    ss.setdefault("scored", None)
    ss.setdefault("risk_overrides", {})
    ss.setdefault("demo_path", None)
    ss.setdefault("repo_path", "")
    ss.setdefault("ci_result", None)
    return ss


def is_demo(ss) -> bool:
    return bool(ss.demo_path and ss.audit and ss.audit.repo == str(Path(ss.demo_path).resolve()))


def demo_banner(ss):
    if is_demo(ss):
        st.markdown('<div class="qg-banner"><b>DEMO MODE</b> - results come from running QuantumGuard on a '
                    'generated repository of SYNTHETIC code with a controlled Git history.</div>',
                    unsafe_allow_html=True)


def do_audit(ss, path, ref, max_commits, include_history):
    with st.spinner("Scanning current code, walking Git history, validating PQC evidence..."):
        try:
            audit = run_audit(path, ref=ref or "HEAD", max_commits=int(max_commits),
                              include_history=include_history, risk_overrides=ss.risk_overrides or None)
        except QGError as exc:
            st.sidebar.error(str(exc))
            return
    ss.audit, ss.scored, ss.ci_result = audit, audit.items, None
    ss.repo_path = audit.repo


def rescore(ss):
    policy = load_policy(overrides=ss.risk_overrides or None)
    ss.scored = apply_scores(copy.deepcopy(ss.audit.items), policy, ss.audit.repo_declared)


def items_df(items) -> pd.DataFrame:
    rows = []
    for i in items:
        rows.append({"Score": i["score"], "Severity": i["severity"], "Type": "PQC" if i["kind"] == "pqc" else "Crypto",
                     "Finding": i["title"], "Algorithm": i["algorithm"],
                     "Status": i.get("status_label", i.get("status")),
                     "Location": f"{i.get('file')}:{i.get('line')}", "id": i["id"]})
    return pd.DataFrame(rows)


def empty_state():
    st.markdown("### No audit loaded yet")
    st.markdown(
        "Enter a local repository path in the sidebar and press **Run audit**, or open **Demo mode** in the "
        "sidebar to build a clearly labelled synthetic repository and audit it.")
    st.markdown('<p class="qg-muted">QuantumGuard only reads files and runs read-only git commands. '
                'Nothing is uploaded.</p>', unsafe_allow_html=True)


def interval_rows(items, head_ts):
    rows = []
    for i in items:
        if i["kind"] != "crypto":
            continue
        start = None
        for e in i.get("events", []):
            if e["type"] in ("introduced", "reintroduced", "present_at_window_start"):
                start = e["timestamp"]
            elif e["type"] == "removed" and start is not None:
                rows.append((i, start, e["timestamp"], "Removed"))
                start = None
        if start is not None:
            rows.append((i, start, max(head_ts, start + 86400), "Present at audited commit"))
    out = []
    for i, s, e, label in rows:
        out.append({"Finding": f"{i['file']} | {i['rule_id']}", "Start": datetime.fromtimestamp(s, timezone.utc),
                    "End": datetime.fromtimestamp(e, timezone.utc), "State": label,
                    "Status": i["status_label"], "Severity": i["severity"]})
    return pd.DataFrame(out)


# ------------------------------------------------------------------ sidebar

ss = state()
with st.sidebar:
    st.markdown('<div class="qg-brand">QuantumGuard</div>'
                f'<div class="qg-sub">PQC risk auditor, validator and CI guard - v{__version__}</div>',
                unsafe_allow_html=True)
    st.write("")
    page = st.radio("Navigate", PAGES, label_visibility="collapsed")
    st.divider()
    st.markdown("**Target repository**")
    path = st.text_input("Local path", value=ss.repo_path, placeholder="/path/to/git/repository")
    ref = st.text_input("Ref to audit history", value="HEAD")
    max_commits = st.number_input("Max commits", min_value=10, max_value=20000, value=1000, step=100)
    include_history = st.checkbox("Include Git history", value=True)
    if st.button("Run audit", type="primary", width="stretch"):
        do_audit(ss, path, ref, max_commits, include_history)
    with st.expander("Demo mode (synthetic data)"):
        st.caption("Builds a repository of SYNTHETIC code with fixed-date commits, then audits it with the "
                   "same pipeline used for real repositories.")
        if st.button("Build and audit demo repository", width="stretch"):
            target = Path(tempfile.gettempdir()) / "quantumguard-demo-repo"
            try:
                info = build_demo_repo(target, force=True)
            except QGError as exc:
                st.error(str(exc))
            else:
                ss.demo_path = info["path"]
                do_audit(ss, info["path"], "HEAD", 1000, True)
    if ss.audit:
        st.caption(f"Loaded: {ss.audit.repo}")


audit = ss.audit
items = ss.scored or []

# ------------------------------------------------------------------ pages

if page == "Overview":
    st.title("Overview")
    demo_banner(ss)
    if not audit:
        empty_state()
        st.stop()
    counts = audit.counts()
    sev = {s: 0 for s in SEV_COLORS}
    for i in items:
        sev[i["severity"]] += 1
    c = st.columns(6)
    card(c[0], "Findings", len(items))
    card(c[1], "Critical", sev["critical"], SEV_COLORS["critical"])
    card(c[2], "High", sev["high"], SEV_COLORS["high"])
    card(c[3], "Historical only", counts["historical_only"])
    card(c[4], "Reintroduced", counts["reintroduced"])
    card(c[5], "PQC needing review", counts["pqc_outdated"] + counts["pqc_manual"])
    st.write("")
    left, right = st.columns([1, 1])
    with left:
        df = pd.DataFrame({"Severity": list(sev), "Count": list(sev.values())})
        fig = px.bar(df, x="Severity", y="Count", color="Severity", color_discrete_map=SEV_COLORS,
                     title="Findings by severity")
        fig.update_layout(showlegend=False, height=320, margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")
    with right:
        status_counts = pd.Series([i.get("status_label", i["status"]) for i in items]).value_counts()
        fig = px.bar(status_counts.sort_values(), orientation="h", title="Findings by status")
        fig.update_layout(showlegend=False, height=320, margin=dict(t=50, b=10), xaxis_title="Count", yaxis_title="")
        fig.update_traces(marker_color="#38bdf8")
        st.plotly_chart(fig, width="stretch")
    st.subheader("Top prioritised risks")
    top = items_df(items[:5])
    st.dataframe(top.drop(columns=["id"]), hide_index=True,
                 column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100,
                                                                         format="%.1f")})
    st.caption(audit.policy.get("disclaimer", ""))
    h = audit.history
    meta = [f"Files scanned: {audit.scan_stats.files_scanned}",
            f"Commits audited: {h.commits_scanned if h else 0}",
            f"Manifests read: {len(audit.pqc.manifests)}", f"Generated: {audit.generated_at}"]
    st.markdown(f'<p class="qg-muted">{" | ".join(meta)}</p>', unsafe_allow_html=True)
    if audit.history_error:
        st.info(audit.history_error)
    for w in audit.warnings:
        st.warning(w)

elif page == "Repository scan":
    st.title("Repository scan - current code")
    demo_banner(ss)
    if not audit:
        empty_state()
        st.stop()
    findings = audit.current_findings
    st.markdown(f"**{len(findings)}** current finding(s) in **{audit.scan_stats.files_scanned}** files. "
                f"Skipped: {dict(audit.scan_stats.skipped) or 'none'}.")
    if not findings:
        st.success("No configured quantum-vulnerable patterns found in the current working tree.")
    else:
        df = pd.DataFrame([{"Rule": f.rule_id, "Title": f.title, "Algorithm": f.algorithm,
                            "Operation": f.operation, "Context": f.context, "File": f.file, "Line": f.line,
                            "Code": f.snippet} for f in findings])
        c1, c2 = st.columns(2)
        ctx = c1.multiselect("Context", sorted(df["Context"].unique()), default=sorted(df["Context"].unique()))
        alg = c2.multiselect("Algorithm", sorted(df["Algorithm"].unique()), default=sorted(df["Algorithm"].unique()))
        st.dataframe(df[df["Context"].isin(ctx) & df["Algorithm"].isin(alg)], hide_index=True)
    st.caption("Comments, Python docstrings, test paths and 'quantumguard: ignore' markers are handled by the "
               "shared detection engine; test-path findings are kept but marked 'test'.")

elif page == "Historical audit":
    st.title("Historical audit - Git timeline")
    demo_banner(ss)
    if not audit:
        empty_state()
        st.stop()
    h = audit.history
    if not h:
        st.info(audit.history_error or "No history available.")
        st.stop()
    crypto = [i for i in items if i["kind"] == "crypto" and i.get("events")]
    c = st.columns(4)
    card(c[0], "Commits audited", h.commits_scanned)
    card(c[1], "Patterns seen in history", len(crypto))
    card(c[2], "Historical only", sum(1 for i in crypto if i["status"] == "historical_only"))
    card(c[3], "Reintroduced", sum(1 for i in crypto if i.get("reintroduced")))
    st.write("")
    df = interval_rows(crypto, h.head_timestamp)
    if not df.empty:
        fig = px.timeline(df, x_start="Start", x_end="End", y="Finding", color="State",
                          color_discrete_map={"Removed": "#64748b", "Present at audited commit": "#f97316"},
                          hover_data=["Status", "Severity"], title="Exposure windows (from commit dates)")
        fig.update_yaxes(autorange="reversed", title="")
        fig.update_layout(height=120 + 40 * df["Finding"].nunique(), margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")
    st.caption("Exposure windows show when vulnerable code existed in history. They indicate potential "
               "exposure only and do not show that any data was captured or decrypted.")
    st.subheader("Events")
    events = []
    for i in crypto:
        for e in i["events"]:
            events.append({"Date": e["date"], "Event": e["type"], "Commit": e["short"], "Subject": e["subject"],
                           "File": i["file"], "Rule": i["rule_id"], "Current status": i["status_label"]})
    ev = pd.DataFrame(events).sort_values("Date") if events else pd.DataFrame()
    if not ev.empty:
        kinds = st.pills("Event types", sorted(ev["Event"].unique()), selection_mode="multi",
                         default=sorted(ev["Event"].unique()))
        st.dataframe(ev[ev["Event"].isin(kinds or [])], hide_index=True)
    hist_only = [i for i in crypto if i["status"] == "historical_only"]
    st.subheader(f"Historical-only findings ({len(hist_only)})")
    for i in hist_only:
        with st.expander(f"{i['file']} - {i['title']} - exposure {i['exposure_days']:g} days"):
            st.markdown(f'<div class="qg-mono">{i["snippet"]}</div>', unsafe_allow_html=True)
            st.markdown(f"First seen **{i['first_seen']['short']}** ({i['first_seen']['date']}), removed "
                        f"**{i['removed_in'][-1]['short']}** ({i['removed_in'][-1]['date']}).")
            st.markdown(f"**Recommended action:** {i['recommendation']}")
    with st.expander(f"Commit list ({len(h.commits)})"):
        st.dataframe(pd.DataFrame(h.commits).drop(columns=["commit", "timestamp"]), hide_index=True)
    for w in h.warnings:
        st.warning(w)

elif page == "PQC validation":
    st.title("PQC validation - draft versus final standard")
    demo_banner(ss)
    rules = load_json("pqc_library_rules.json")
    cols = st.columns(2)
    for col, (sid, s) in zip(cols, rules["standards"].items()):
        col.markdown(f'<div class="qg-card"><div class="lbl">{sid} - {s["algorithm"]}</div>'
                     f'<div style="font-weight:600">{s["title"]}</div>'
                     f'<div class="qg-muted">Published {s["published"]} - <a href="{s["url"]}">{s["url"]}</a></div>'
                     f'</div>', unsafe_allow_html=True)
    st.write("")
    if not audit:
        empty_state()
        st.stop()
    pqc_items = [i for i in items if i["kind"] == "pqc"]
    if not pqc_items:
        st.success("No PQC dependencies or API identifiers were found.")
    status_color = {"potentially_outdated_draft": "#f97316", "needs_manual_verification": "#eab308",
                    "standard_aligned": "#22c55e"}
    for i in pqc_items:
        with st.container(border=True):
            st.markdown(f"{badge(i['status_label'], status_color.get(i['status'], '#64748b'))} "
                        f"{badge('confidence: ' + i['confidence'], '#94a3b8')} "
                        f"{badge('SYNTHETIC', '#a855f7') if i.get('synthetic') else ''}"
                        f"&nbsp; **{i['title']}** - {i['standard']}", unsafe_allow_html=True)
            c1, c2 = st.columns([1, 1])
            c1.markdown(f"**Declared version:** `{i['declared_version']}`  \n"
                        f"**Manifest:** `{i['manifest'] or 'none'}`  \n**Priority:** {i['score']:g} ({i['severity']})")
            locs = i.get("code_locations", [])
            c2.markdown("**Code locations:**  \n" + ("  \n".join(f"`{l['file']}:{l['line']}`" for l in locs[:5])
                                                    or "none"))
            st.markdown("**Evidence**")
            for e in i["evidence"]:
                if e:
                    st.markdown(f"- {e}")
            if i.get("sources"):
                st.markdown("**Sources:** " + " | ".join(f"[{s['title']}]({s['url']})" for s in i["sources"]))
            st.markdown(f"**Recommended action:** {i['recommendation']}")
    deps = audit.pqc.dependencies
    with st.expander(f"All parsed dependencies ({len(deps)}) from {len(audit.pqc.manifests)} manifest(s)"):
        if deps:
            st.dataframe(pd.DataFrame([d.to_dict() for d in deps]), hide_index=True)
    st.caption("A 'Kyber' name alone is never treated as outdated: without verifiable version evidence the "
               "result is 'Needs manual verification'.")

elif page == "Risk prioritization":
    st.title("Risk prioritization")
    demo_banner(ss)
    if not audit:
        empty_state()
        st.stop()
    st.caption(audit.policy.get("disclaimer", ""))
    with st.expander("Adjust scoring factors (no code changes needed)"):
        base = load_policy()
        ov = copy.deepcopy(ss.risk_overrides)
        st.markdown("**Data sensitivity by path prefix** - one `prefix=high|medium|low` per line. "
                    "These are treated as user-supplied facts.")
        current_map = ov.get("data_sensitivity", {}).get("paths", {})
        text = st.text_area("Sensitivity map", "\n".join(f"{k}={v}" for k, v in current_map.items()),
                            placeholder="payments/=high\nreports/=low")
        c1, c2, c3 = st.columns(3)
        op_pts = {k: c1.slider(f"Operation: {k}", 0, 30, int(base["operation_points"][k]))
                  for k in base["operation_points"]}
        alg_pts = {k: c2.slider(f"Algorithm risk: {k}", 0, 40, int(base["algorithm_risk_points"][k]))
                   for k in base["algorithm_risk_points"]}
        pres = {k: c3.slider(f"Presence: {k}", 0, 30, int(base["presence_points"][k]))
                for k in base["presence_points"]}
        assume = st.selectbox("Assumed sensitivity when unknown", ["medium", "low", "high", "(do not assume)"])
        if st.button("Apply and re-score", type="primary"):
            paths = {}
            for line in text.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    if v.strip().lower() in ("high", "medium", "low") and k.strip():
                        paths[k.strip()] = v.strip().lower()
            ss.risk_overrides = {"operation_points": op_pts, "algorithm_risk_points": alg_pts,
                                 "presence_points": pres,
                                 "data_sensitivity": {"paths": paths,
                                                      "unknown_assumption": None if assume.startswith("(") else assume}}
            rescore(ss)
            st.rerun()
        if ss.risk_overrides:
            st.download_button("Download overrides as JSON", json.dumps(ss.risk_overrides, indent=2),
                               "risk_overrides.json", "application/json")
    items = ss.scored
    df = items_df(items)
    c1, c2, c3 = st.columns(3)
    sev_f = c1.multiselect("Severity", list(SEV_COLORS), default=[s for s in SEV_COLORS if s in set(df["Severity"])])
    type_f = c2.multiselect("Type", ["Crypto", "PQC"], default=["Crypto", "PQC"])
    status_f = c3.multiselect("Status", sorted(df["Status"].unique()), default=sorted(df["Status"].unique()))
    view = df[df["Severity"].isin(sev_f) & df["Type"].isin(type_f) & df["Status"].isin(status_f)]
    event = st.dataframe(view.drop(columns=["id"]), hide_index=True, on_select="rerun", selection_mode="single-row",
                         column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0,
                                                                                 max_value=100, format="%.1f")})
    rows = event.selection.rows if event and event.selection else []
    selected_id = view.iloc[rows[0]]["id"] if rows else (view.iloc[0]["id"] if len(view) else None)
    if selected_id:
        item = next(i for i in items if i["id"] == selected_id)
        st.subheader(item["title"])
        st.markdown(f"{badge(item['severity'], SEV_COLORS[item['severity']])} &nbsp; **Score {item['score']:g}/100** "
                    f"- {item['severity_reason']}  \n`{item.get('file')}:{item.get('line')}` - "
                    f"{item.get('status_label', item['status'])}", unsafe_allow_html=True)
        fdf = pd.DataFrame(item["factors"])
        basis_colors = {"fact": "#38bdf8", "user_supplied": "#22c55e", "repo_declared": "#a3e635",
                        "assumption": "#eab308", "unknown": "#64748b"}
        fig = go.Figure()
        fig.add_bar(y=fdf["factor"], x=fdf["max_points"], orientation="h", marker_color="#1f2a44",
                    name="Max", hoverinfo="skip")
        fig.add_bar(y=fdf["factor"], x=fdf["points"], orientation="h", name="Points",
                    marker_color=[basis_colors[b] for b in fdf["basis"]], text=fdf["basis"], textposition="inside")
        fig.update_layout(barmode="overlay", height=60 + 42 * len(fdf), showlegend=False,
                          margin=dict(t=10, b=10), xaxis_title="Points (bar colour = basis)")
        st.plotly_chart(fig, width="stretch")
        st.dataframe(fdf.rename(columns={"factor": "Factor", "points": "Points", "max_points": "Max",
                                         "basis": "Basis", "reason": "Why"}), hide_index=True)
        if item.get("assumptions"):
            st.warning("Assumptions used: " + ", ".join(item["assumptions"]) + ". Supply real values above.")
        if item.get("unknowns"):
            st.info("Unknown inputs (scored 0): " + ", ".join(item["unknowns"]))
        st.markdown(f"**Recommended action:** {item['recommendation']}")

elif page == "CI/CD gate":
    st.title("CI/CD gate")
    demo_banner(ss)
    st.markdown(
        "The gate scans only the lines a change **adds**, with the same rules as the scanner. "
        "**Block** fails the check (exit code 1); **warn** reports without failing; pre-existing code is "
        "never blocked. A pattern that was removed earlier and comes back is blocked as a reintroduction.")
    policy = load_ci_policy()
    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("**Policy** (`config/ci_policy.json`, editable for this session)")
        policy_text = st.text_area("Policy JSON", json.dumps(policy, indent=2), height=360,
                                   label_visibility="collapsed")
    with c2:
        repo = ss.repo_path or ""
        branches = []
        if repo:
            try:
                out = run_git(git_toplevel(repo), ["for-each-ref", "--format=%(refname:short)", "refs/heads"])
                branches = out.decode().split()
            except GitError:
                branches = []
        st.markdown(f"**Repository:** `{repo or 'run an audit first'}`")
        base = st.selectbox("Base", branches, index=branches.index("main") if "main" in branches else 0) \
            if branches else st.text_input("Base ref", "main")
        heads = [b for b in branches if b != base]
        head = st.selectbox("Head (proposed change)", heads) if heads else st.text_input("Head ref", "HEAD")
        st.markdown('<p class="qg-muted">Local equivalent: <span class="qg-mono">python -m quantumguard ci '
                    '--repo PATH --base BASE --head HEAD</span></p>', unsafe_allow_html=True)
        if st.button("Run CI gate", type="primary", disabled=not repo):
            try:
                overrides = json.loads(policy_text)
                with st.spinner("Diffing, scanning added lines, checking history for reintroductions..."):
                    ss.ci_result = run_ci_gate(repo, base, head, policy_overrides=overrides)
            except json.JSONDecodeError as exc:
                st.error(f"Policy JSON is invalid: {exc}")
            except QGError as exc:
                st.error(str(exc))
    res = ss.ci_result
    if res:
        color = {"BLOCKED": "#ef4444", "PASSED WITH WARNINGS": "#eab308", "PASSED": "#22c55e"}[res.outcome]
        st.markdown(f"### {badge(res.outcome, color)} &nbsp; exit code {res.exit_code}", unsafe_allow_html=True)
        st.caption(f"{res.base} -> {res.head} (merge-base {res.merge_base[:8]}), mode '{res.mode}', "
                   f"{len(res.changed_files)} changed file(s)")
        for d in res.decisions:
            with st.container(border=True):
                st.markdown(f"{badge(d.decision, DECISION_COLORS[d.decision])} &nbsp; **{d.title}** "
                            f"`{d.file}:{d.line}` - {d.rule_id}", unsafe_allow_html=True)
                if d.snippet:
                    st.code(d.snippet, language=None)
                for r in d.reasons:
                    st.markdown(f"- {r}")
                st.markdown(f"**Fix:** {d.recommendation}")
        if not res.decisions:
            st.success("No quantum-vulnerable cryptography added by this change.")
        with st.expander("GitHub job summary preview"):
            st.markdown(format_markdown(res))
        for w in res.warnings:
            st.caption(w)

elif page == "Reports":
    st.title("Reports")
    demo_banner(ss)
    if not audit:
        empty_state()
        st.stop()
    report = audit.to_dict()
    report["findings"] = items
    if ss.risk_overrides:
        report["risk_overrides_applied"] = ss.risk_overrides
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    c1, c2, c3 = st.columns(3)
    c1.download_button("Download JSON", to_json(report), f"quantumguard-{stamp}.json", "application/json",
                       width="stretch", type="primary")
    c2.download_button("Download CSV", to_csv(items), f"quantumguard-{stamp}.csv", "text/csv", width="stretch")
    c3.download_button("Download Markdown", to_markdown(report), f"quantumguard-{stamp}.md", "text/markdown",
                       width="stretch")
    st.markdown("The JSON report contains every finding with evidence, Git events, score factors (with basis), "
                "recommendations, the risk policy used, and scan metadata.")
    st.dataframe(items_df(items).drop(columns=["id"]), hide_index=True)
