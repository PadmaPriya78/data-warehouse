from extract import extract_data
from transform import transform_data
from load import load_date_dimension, load_fact_table
from sqlalchemy import create_engine


def main():

    print("==========================================")
    print(" CYBER THREAT DATA WAREHOUSE ETL PROJECT ")
    print("==========================================")

    data = extract_data()

    transformed = transform_data(data)

    engine = create_engine(
        "mysql+pymysql://root:7777@localhost/CyberThreatDW"
    )

    print("✅ Connected to MySQL")

    # Load Date Dimension first
    load_date_dimension(
        transformed["date"],
        engine
    )

    # Load Fact Table
    load_fact_table(
        transformed["fact"],
        engine
    )

    print("\n==========================================")
    print(" ETL COMPLETED SUCCESSFULLY ")
    print("==========================================")


if __name__ == "__main__":
    main()