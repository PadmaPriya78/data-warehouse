CREATE DATABASE CyberThreatDW;
USE CyberThreatDW;
SHOW DATABASES;
USE CyberThreatDW;

CREATE TABLE Dim_Date (
    Date_ID INT AUTO_INCREMENT PRIMARY KEY,
    Full_Date DATE NOT NULL,
    Day_Number INT,
    Month_Number INT,
    Month_Name VARCHAR(20),
    Quarter_Number INT,
    Year_Number INT
);
SHOW TABLES;
CREATE TABLE Dim_Vendor (
    Vendor_ID INT AUTO_INCREMENT PRIMARY KEY,
    Vendor_Name VARCHAR(255) NOT NULL
);
CREATE TABLE Dim_Product (
    Product_ID INT AUTO_INCREMENT PRIMARY KEY,
    Product_Name VARCHAR(255) NOT NULL
);
CREATE TABLE Dim_CWE (
    CWE_ID INT AUTO_INCREMENT PRIMARY KEY,
    CWE_Code VARCHAR(50) NOT NULL
);
CREATE TABLE Dim_Source (
    Source_ID INT AUTO_INCREMENT PRIMARY KEY,
    Source_Name VARCHAR(100) NOT NULL
);
CREATE TABLE Dim_Threat (
    Threat_ID INT AUTO_INCREMENT PRIMARY KEY,
    Threat_Name VARCHAR(255),
    Malware_Family VARCHAR(255),
    Attack_ID VARCHAR(100),
    Tags TEXT
);
CREATE TABLE Fact_Vulnerability (
    Fact_ID INT AUTO_INCREMENT PRIMARY KEY,
    CVE_ID VARCHAR(50) NOT NULL,
    Date_ID INT,
    Vendor_ID INT,
    Product_ID INT,
    CWE_ID INT,
    Source_ID INT,
    Threat_ID INT,
    Known_Ransomware VARCHAR(20),

    FOREIGN KEY (Date_ID) REFERENCES Dim_Date(Date_ID),
    FOREIGN KEY (Vendor_ID) REFERENCES Dim_Vendor(Vendor_ID),
    FOREIGN KEY (Product_ID) REFERENCES Dim_Product(Product_ID),
    FOREIGN KEY (CWE_ID) REFERENCES Dim_CWE(CWE_ID),
    FOREIGN KEY (Source_ID) REFERENCES Dim_Source(Source_ID),
    FOREIGN KEY (Threat_ID) REFERENCES Dim_Threat(Threat_ID)
);
SHOW TABLES;
DESCRIBE fact_vulnerability;

SELECT * FROM Dim_Vendor;
SELECT * FROM Dim_Product;
SELECT * FROM Dim_CWE;
SELECT * FROM Dim_Source;
DROP TABLE Dim_Threat;
CREATE TABLE Dim_Threat (
    Threat_ID INT AUTO_INCREMENT PRIMARY KEY,
    Threat_Name TEXT,
    Malware_Family TEXT,
    Attack_ID TEXT,
    Tags TEXT
);
DROP TABLE fact_vulnerability;
DROP TABLE dim_threat;
CREATE TABLE dim_threat (
    Threat_ID INT AUTO_INCREMENT PRIMARY KEY,
    Threat_Name TEXT,
    Malware_Family TEXT,
    Attack_ID TEXT,
    Tags TEXT
);

ALTER TABLE dim_vendor ADD UNIQUE (Vendor_Name);
ALTER TABLE dim_product ADD UNIQUE (Product_Name);
ALTER TABLE dim_cwe ADD UNIQUE (CWE_Code);
ALTER TABLE dim_source ADD UNIQUE (Source_Name);

ALTER TABLE dim_threat
MODIFY Threat_Name TEXT,
MODIFY Malware_Family TEXT,
MODIFY Attack_ID TEXT,
MODIFY Tags TEXT;

SELECT Vendor_Name, COUNT(*) AS Total
FROM dim_vendor
GROUP BY Vendor_Name
HAVING COUNT(*) > 1;
DELETE FROM dim_vendor;
ALTER TABLE dim_vendor AUTO_INCREMENT = 1;

SET SQL_SAFE_UPDATES = 0;
DELETE FROM dim_vendor;
ALTER TABLE dim_vendor AUTO_INCREMENT = 1;
ALTER TABLE dim_vendor
ADD CONSTRAINT uq_vendor UNIQUE (Vendor_Name);


SET SQL_SAFE_UPDATES = 0;
DELETE FROM dim_product;
ALTER TABLE dim_product AUTO_INCREMENT = 1;
ALTER TABLE dim_product
ADD CONSTRAINT uq_product UNIQUE (Product_Name);

SET SQL_SAFE_UPDATES = 0;
DELETE FROM dim_cwe;
ALTER TABLE dim_cwe AUTO_INCREMENT = 1;
ALTER TABLE dim_cwe
ADD CONSTRAINT uq_cwe UNIQUE (CWE_Code);

SET SQL_SAFE_UPDATES = 0;
DELETE FROM dim_source;
ALTER TABLE dim_source AUTO_INCREMENT = 1;
ALTER TABLE dim_source
ADD CONSTRAINT uq_source UNIQUE (Source_Name);

DESCRIBE fact_vulnerability;
SHOW TABLES;

CREATE TABLE fact_vulnerability (
    Fact_ID INT AUTO_INCREMENT PRIMARY KEY,
    CVE_ID VARCHAR(50) NOT NULL,
    Date_ID INT,
    Vendor_ID INT,
    Product_ID INT,
    CWE_ID INT,
    Source_ID INT,
    Threat_ID INT,
    Known_Ransomware VARCHAR(20),
    CVSS_Score DECIMAL(4,1),
    Severity VARCHAR(20),
    FOREIGN KEY (Date_ID)
        REFERENCES dim_date(Date_ID),
    FOREIGN KEY (Vendor_ID)
        REFERENCES dim_vendor(Vendor_ID),
    FOREIGN KEY (Product_ID)
        REFERENCES dim_product(Product_ID),
    FOREIGN KEY (CWE_ID)
        REFERENCES dim_cwe(CWE_ID),
    FOREIGN KEY (Source_ID)
        REFERENCES dim_source(Source_ID),
    FOREIGN KEY (Threat_ID)
        REFERENCES dim_threat(Threat_ID)
);
DESCRIBE fact_vulnerability;
SELECT COUNT(*) FROM fact_vulnerability;
SELECT * FROM fact_vulnerability LIMIT 10;
SELECT COUNT(*) FROM dim_date;

SET SQL_SAFE_UPDATES = 0;
DELETE FROM fact_vulnerability;
ALTER TABLE fact_vulnerability AUTO_INCREMENT = 1;

SELECT COUNT(*) FROM dim_date;
SELECT COUNT(*) FROM fact_vulnerability;
SELECT * FROM fact_vulnerability LIMIT 10;

SELECT Severity, COUNT(*) AS Total
FROM fact_vulnerability
GROUP BY Severity;

SELECT Severity, COUNT(*) AS Total
FROM fact_vulnerability
GROUP BY Severity;

SELECT CVE_ID, Severity
FROM fact_vulnerability
LIMIT 10;

SHOW TABLES;
DESCRIBE fact_vulnerability;
DESCRIBE dim_vendor;
DESCRIBE dim_product;
DESCRIBE dim_cwe;
SELECT COUNT(*) FROM dim_product;
SELECT Severity, COUNT(*) AS Total
FROM fact_vulnerability
GROUP BY Severity;
SELECT CVSS_Score
FROM fact_vulnerability
LIMIT 10;
SELECT COUNT(*) FROM dim_threat;
SELECT Threat_ID, Threat_Name
FROM dim_threat
LIMIT 10;
SELECT * 
FROM fact_vulnerability
LIMIT 5;
DESCRIBE dim_source;
SELECT * FROM dim_source LIMIT 10;
SELECT Source_ID, COUNT(*) AS Total
FROM fact_vulnerability
GROUP BY Source_ID;