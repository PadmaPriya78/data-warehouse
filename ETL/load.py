import pandas as pd
from sqlalchemy import text


def load_date_dimension(dim_date, engine):

    print("Loading Dim_Date...")

    # Clear old data
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM dim_date"))
        conn.execute(text("ALTER TABLE dim_date AUTO_INCREMENT = 1"))

    # Insert new data
    dim_date.to_sql(
        "dim_date",
        con=engine,
        if_exists="append",
        index=False
    )

    print("✅ Dim_Date Loaded Successfully!")


def load_fact_table(cve, engine):

    print("Loading Fact Table...")

    # Read Dimension Tables
    vendor = pd.read_sql("SELECT * FROM dim_vendor", engine)
    product = pd.read_sql("SELECT * FROM dim_product", engine)
    cwe = pd.read_sql("SELECT * FROM dim_cwe", engine)
    source = pd.read_sql("SELECT * FROM dim_source", engine)
    date_dim = pd.read_sql("SELECT * FROM dim_date", engine)

    fact = cve.copy()

    # Vendor Lookup
    fact = fact.merge(
        vendor,
        left_on="vendorProject",
        right_on="Vendor_Name",
        how="left"
    )

    # Product Lookup
    fact = fact.merge(
        product,
        left_on="product",
        right_on="Product_Name",
        how="left"
    )

    # CWE Lookup
    fact = fact.merge(
        cwe,
        left_on="cwes",
        right_on="CWE_Code",
        how="left"
    )

    # Source Lookup
    fact["Source_Name"] = "CISA"

    fact = fact.merge(
        source,
        on="Source_Name",
        how="left"
    )

    # Date Lookup
    date_dim["Full_Date"] = pd.to_datetime(date_dim["Full_Date"])
    fact["dateAdded"] = pd.to_datetime(fact["dateAdded"])

    fact = fact.merge(
        date_dim,
        left_on="dateAdded",
        right_on="Full_Date",
        how="left"
    )

    # No direct mapping available
    fact["Threat_ID"] = None

    final = pd.DataFrame()

    final["CVE_ID"] = fact["cveID"]
    final["Date_ID"] = fact["Date_ID"]
    final["Vendor_ID"] = fact["Vendor_ID"]
    final["Product_ID"] = fact["Product_ID"]
    final["CWE_ID"] = fact["CWE_ID"]
    final["Source_ID"] = fact["Source_ID"]
    final["Threat_ID"] = fact["Threat_ID"]
    final["Known_Ransomware"] = fact["knownRansomwareCampaignUse"]

    final["CVSS_Score"] = None
    final["Severity"] = None

    # Clear old fact table
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM fact_vulnerability"))
        conn.execute(text("ALTER TABLE fact_vulnerability AUTO_INCREMENT = 1"))

    final.to_sql(
        "fact_vulnerability",
        con=engine,
        if_exists="append",
        index=False
    )

    print("✅ Fact Table Loaded Successfully!")