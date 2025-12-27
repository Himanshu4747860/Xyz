# webscan/runner.py
import os
from webscan.scoring import compute_scores, category_of
from webscan.report import generate_pdf
from webscan.utils import extract_domain

def scan_single(url: str, config: dict):
    domain = extract_domain(url)

    checks = []      # list of CheckResult objects
    artifacts = {}   # dict of collected artifacts

    parameter_risks = {c.name: c.status for c in checks}
    summary = compute_scores(parameter_risks)
    category_risks = summary.get("category_risks", {})

    return domain, checks, artifacts, summary, category_risks

def collect_parameters(domain):
    # Replace these stubs with your real checks; return normalized risks in [0,1]
    params = {}
    # Examples
    params["ssl_expired"] = 1.0 if False else 0.0
    params["ssl_expiry_days"] = 0.8  # sample normalized
    params["missing_csp_header"] = 1.0 if True else 0.0
    params["dkim_absent"] = 0.0
    params["hidden_spam_links"] = 0.0
    params["response_time_high"] = 0.6
    return params

def top_risks(parameters):
    # Sort by risk × weight importance for readability
    from weight_mapping import WEIGHT_MAP
    ranked = sorted(parameters.items(), key=lambda kv: kv[1]*WEIGHT_MAP.get(kv[0],0.2), reverse=True)
    return [name for name, _ in ranked[:5]]

def run_for_domain(domain, out_dir, db_conn=None):
    os.makedirs(out_dir, exist_ok=True)
    parameters = collect_parameters(domain)
    summary = compute_scores(parameters)
    summary["param_to_cat_map"] = {p: category_of(p) for p in parameters}
    pdf_path = os.path.join(out_dir, f"{domain.replace(':','_')}.pdf")
    generate_pdf(pdf_path, domain, summary, top_risks(parameters), parameters, summary["category_risks"])
    return summary, pdf_path
