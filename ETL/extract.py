from pathlib import Path
import pandas as pd


def extract_data():

    # -------------------------------
    # Project Root
    # -------------------------------

    BASE_DIR = Path(__file__).resolve().parent.parent

    DATASET_DIR = BASE_DIR / "Dataset"

    print("\n===================================")
    print("        EXTRACT PHASE")
    print("===================================\n")

    # -------------------------------
    # Read CSV Files
    # -------------------------------

    otx = pd.read_csv(DATASET_DIR / "1_otx_threat_intel.csv")

    cve = pd.read_csv(DATASET_DIR / "2_cve_vulnerabilities.csv")

    domains = pd.read_csv(DATASET_DIR / "3_malicious_domains.csv")

    ips = pd.read_csv(DATASET_DIR / "4_malicious_ips.csv")

    print("✅ OTX Loaded :", otx.shape)
    print("✅ CVE Loaded :", cve.shape)
    print("✅ Domains Loaded :", domains.shape)
    print("✅ IPs Loaded :", ips.shape)

    return {

        "otx": otx,

        "cve": cve,

        "domains": domains,

        "ips": ips

    }