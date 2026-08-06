import pandas as pd


def transform_data(data):

    print("\n===================================")
    print("       TRANSFORM PHASE")
    print("===================================\n")

    # ==============================
    # Get DataFrames
    # ==============================

    otx = data["otx"]
    cve = data["cve"]
    domains = data["domains"]
    ips = data["ips"]

    # ==============================
    # Dim Vendor
    # ==============================

    dim_vendor = (
        cve[['vendorProject']]
        .dropna()
        .drop_duplicates()
        .rename(columns={
            "vendorProject": "Vendor_Name"
        })
    )

    # ==============================
    # Dim Product
    # ==============================

    dim_product = (
        cve[['product']]
        .dropna()
        .drop_duplicates()
        .rename(columns={
            "product": "Product_Name"
        })
    )

    # ==============================
    # Dim CWE
    # ==============================

    dim_cwe = (
        cve[['cwes']]
        .dropna()
        .drop_duplicates()
        .rename(columns={
            "cwes": "CWE_Code"
        })
    )

    # ==============================
    # Dim Source
    # ==============================

    dim_source = pd.DataFrame({

        "Source_Name": [

            "AlienVault OTX",
            "CISA",
            "NVD"

        ]

    })

    # ==============================
    # Dim Date
    # ==============================

    dim_date = (
        cve[['dateAdded']]
        .dropna()
        .drop_duplicates()
        .copy()
    )

    dim_date["dateAdded"] = pd.to_datetime(dim_date["dateAdded"])

    dim_date["Day_Number"] = dim_date["dateAdded"].dt.day
    dim_date["Month_Number"] = dim_date["dateAdded"].dt.month
    dim_date["Month_Name"] = dim_date["dateAdded"].dt.month_name()
    dim_date["Quarter_Number"] = dim_date["dateAdded"].dt.quarter
    dim_date["Year_Number"] = dim_date["dateAdded"].dt.year

    dim_date.rename(
        columns={
            "dateAdded": "Full_Date"
        },
        inplace=True
    )

    # ==============================
    # Dim Threat
    # ==============================

    dim_threat = (
        otx[[
            "Title",
            "Malware_Families",
            "Attack_IDs",
            "Tags"
        ]]
        .copy()
    )

    dim_threat.columns = [

        "Threat_Name",
        "Malware_Family",
        "Attack_ID",
        "Tags"

    ]

    dim_threat.fillna("Unknown", inplace=True)

    dim_threat.drop_duplicates(inplace=True)

    # ==============================
    # Fact Data
    # ==============================

    fact = cve.copy()

    print("✅ Vendor Records :", len(dim_vendor))
    print("✅ Product Records:", len(dim_product))
    print("✅ CWE Records    :", len(dim_cwe))
    print("✅ Source Records :", len(dim_source))
    print("✅ Date Records   :", len(dim_date))
    print("✅ Threat Records :", len(dim_threat))
    print("✅ Fact Records   :", len(fact))

    return {

        "vendor": dim_vendor,

        "product": dim_product,

        "cwe": dim_cwe,

        "source": dim_source,

        "date": dim_date,

        "threat": dim_threat,

        "fact": fact,

        "domains": domains,

        "ips": ips

    }