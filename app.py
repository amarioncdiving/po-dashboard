import os
import sys
import site
import csv
import io
from datetime import datetime, date
from decimal import Decimal, InvalidOperation

from flask import Flask, render_template_string, jsonify, request


# Add local package path for Azure App Service deployments
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PACKAGES_DIR = os.path.join(BASE_DIR, ".python_packages", "lib", "site-packages")

if os.path.isdir(PACKAGES_DIR):
    site.addsitedir(PACKAGES_DIR)
    sys.path.append(PACKAGES_DIR)


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit


# Azure App Settings
APP_ENVIRONMENT = os.getenv("APP_ENVIRONMENT", "Not set")
SQL_SERVER_NAME = os.getenv("SQL_SERVER_NAME", "Not set")
SQL_DATABASE_NAME = os.getenv("SQL_DATABASE_NAME", "Not set")
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "Not set")


# Prefer the App Setting version first.
# This should be set in Azure App Service as an App Setting named PODASHBOARD_SQL.
SQL_CONNECTION = (
    os.getenv("PODASHBOARD_SQL")
    or os.getenv("SQLAZURECONNSTR_PODASHBOARD_SQL")
    or os.getenv("CUSTOMCONNSTR_PODASHBOARD_SQL")
    or ""
)


REQUIRED_PO_COLUMNS = [
    "PONumber",
    "VendorName",
    "ProjectName",
    "Department",
    "PODate",
    "POStatus",
    "Description",
    "Unit",
    "UnitCost",
    "Qty",
    "LineAmount",
    "OriginalAmount",
    "RevisedAmount",
    "RemainingAmount",
    "Requestor",
]


def get_sql_connection():
    if not SQL_CONNECTION:
        raise RuntimeError("SQL connection string was not found.")

    connection_string = SQL_CONNECTION

    if "Driver=" not in connection_string and "DRIVER=" not in connection_string:
        connection_string = "Driver={ODBC Driver 18 for SQL Server};" + connection_string

    import pyodbc

    return pyodbc.connect(connection_string, timeout=20)


def clean_text(value):
    if value is None:
        return None

    value = str(value).strip()

    if value == "":
        return None

    return value


def clean_decimal(value):
    if value is None:
        return None

    if isinstance(value, Decimal):
        return value

    value = str(value).strip()

    if value == "":
        return None

    value = value.replace("$", "").replace(",", "")

    try:
        return Decimal(value)
    except InvalidOperation:
        return None


def clean_date(value):
    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        return value.date()

    if isinstance(value, date):
        return value

    value = str(value).strip()

    if value == "":
        return None

    formats = [
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%m/%d/%y",
        "%Y/%m/%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            pass

    return None


def normalize_header(header):
    if header is None:
        return ""

    return str(header).strip()


def read_uploaded_po_file(uploaded_file):
    filename = uploaded_file.filename or ""

    if filename.lower().endswith(".csv"):
        raw = uploaded_file.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(raw))
        rows = []

        for row in reader:
            rows.append({normalize_header(k): v for k, v in row.items()})

        return rows

    if filename.lower().endswith(".xlsx"):
        from openpyxl import load_workbook

        workbook = load_workbook(uploaded_file, data_only=True)
        sheet = workbook.active

        headers = []
        for cell in sheet[1]:
            headers.append(normalize_header(cell.value))

        rows = []

        for row in sheet.iter_rows(min_row=2, values_only=True):
            row_dict = {}

            for index, value in enumerate(row):
                if index < len(headers):
                    row_dict[headers[index]] = value

            if any(value not in [None, ""] for value in row_dict.values()):
                rows.append(row_dict)

        return rows

    raise ValueError("Unsupported file type. Please upload a .xlsx or .csv file.")


def validate_po_rows(rows):
    errors = []

    if not rows:
        errors.append("The file has no data rows.")
        return errors

    actual_columns = set(rows[0].keys())
    missing_columns = [col for col in REQUIRED_PO_COLUMNS if col not in actual_columns]

    if missing_columns:
        errors.append("Missing required columns: " + ", ".join(missing_columns))

    for index, row in enumerate(rows, start=2):
        po_number = clean_text(row.get("PONumber"))
        vendor_name = clean_text(row.get("VendorName"))
        project_name = clean_text(row.get("ProjectName"))
        line_amount = clean_decimal(row.get("LineAmount"))

        if not po_number:
            errors.append(f"Row {index}: PONumber is required.")

        if not vendor_name:
            errors.append(f"Row {index}: VendorName is required.")

        if not project_name:
            errors.append(f"Row {index}: ProjectName is required.")

        if line_amount is None:
            errors.append(f"Row {index}: LineAmount is required and must be a number.")

    return errors


def get_or_create_vendor(cursor, vendor_name):
    cursor.execute(
        "SELECT VendorId FROM dbo.Vendors WHERE VendorName = ?",
        vendor_name,
    )
    row = cursor.fetchone()

    if row:
        return row.VendorId

    cursor.execute(
        """
        INSERT INTO dbo.Vendors (VendorName, IsActive)
        OUTPUT INSERTED.VendorId
        VALUES (?, 1)
        """,
        vendor_name,
    )

    return cursor.fetchone().VendorId


def get_or_create_project(cursor, project_name, department):
    cursor.execute(
        "SELECT ProjectId FROM dbo.Projects WHERE ProjectName = ?",
        project_name,
    )
    row = cursor.fetchone()

    if row:
        return row.ProjectId

    cursor.execute(
        """
        INSERT INTO dbo.Projects (ProjectName, Department, IsActive)
        OUTPUT INSERTED.ProjectId
        VALUES (?, ?, 1)
        """,
        project_name,
        department,
    )

    return cursor.fetchone().ProjectId


def upsert_purchase_order(
    cursor,
    po_number,
    vendor_id,
    project_id,
    department,
    requestor,
    po_date,
    po_status,
    original_amount,
    revised_amount,
    remaining_amount,
    import_batch_id,
):
    cursor.execute(
        "SELECT PurchaseOrderId FROM dbo.PurchaseOrders WHERE PONumber = ?",
        po_number,
    )
    row = cursor.fetchone()

    if row:
        purchase_order_id = row.PurchaseOrderId

        cursor.execute(
            """
            UPDATE dbo.PurchaseOrders
            SET
                VendorId = ?,
                ProjectId = ?,
                Department = ?,
                Requestor = ?,
                PODate = ?,
                POStatus = ?,
                OriginalAmount = ?,
                RevisedAmount = ?,
                RemainingAmount = ?,
                LastImportBatchId = ?,
                UpdatedAt = SYSUTCDATETIME()
            WHERE PurchaseOrderId = ?
            """,
            vendor_id,
            project_id,
            department,
            requestor,
            po_date,
            po_status,
            original_amount,
            revised_amount,
            remaining_amount,
            import_batch_id,
            purchase_order_id,
        )

        return purchase_order_id

    cursor.execute(
        """
        INSERT INTO dbo.PurchaseOrders
            (
                PONumber,
                VendorId,
                ProjectId,
                Department,
                Requestor,
                PODate,
                POStatus,
                OriginalAmount,
                RevisedAmount,
                PaidAmount,
                RemainingAmount,
                LastImportBatchId
            )
        OUTPUT INSERTED.PurchaseOrderId
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        po_number,
        vendor_id,
        project_id,
        department,
        requestor,
        po_date,
        po_status,
        original_amount,
        revised_amount,
        remaining_amount,
        import_batch_id,
    )

    return cursor.fetchone().PurchaseOrderId


def import_po_rows(rows, filename):
    conn = get_sql_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO dbo.ImportBatches
                (
                    FileName,
                    SourceSystem,
                    UploadedBy,
                    TotalRows,
                    SuccessCount,
                    ErrorCount,
                    ImportStatus
                )
            OUTPUT INSERTED.ImportBatchId
            VALUES (?, 'PO Upload', 'Manual Upload', ?, 0, 0, 'Processing')
            """,
            filename,
            len(rows),
        )

        import_batch_id = cursor.fetchone().ImportBatchId
        success_count = 0
        error_count = 0

        # Remove prior line rows for POs included in this upload.
        # This lets a re-upload replace the current line-item detail for those POs.
        po_numbers = sorted(
            set(clean_text(row.get("PONumber")) for row in rows if clean_text(row.get("PONumber")))
        )

        for po_number in po_numbers:
            cursor.execute(
                "DELETE FROM dbo.IssuedPOLines WHERE PONumber = ?",
                po_number,
            )

        for index, row in enumerate(rows, start=2):
            try:
                po_number = clean_text(row.get("PONumber"))
                vendor_name = clean_text(row.get("VendorName"))
                project_name = clean_text(row.get("ProjectName"))
                department = clean_text(row.get("Department"))
                po_date = clean_date(row.get("PODate"))
                po_status = clean_text(row.get("POStatus"))
                description = clean_text(row.get("Description"))
                unit = clean_text(row.get("Unit"))
                unit_cost = clean_decimal(row.get("UnitCost"))
                qty = clean_decimal(row.get("Qty"))
                line_amount = clean_decimal(row.get("LineAmount"))
                original_amount = clean_decimal(row.get("OriginalAmount"))
                revised_amount = clean_decimal(row.get("RevisedAmount"))
                remaining_amount = clean_decimal(row.get("RemainingAmount"))
                requestor = clean_text(row.get("Requestor"))

                vendor_id = get_or_create_vendor(cursor, vendor_name)
                project_id = get_or_create_project(cursor, project_name, department)

                purchase_order_id = upsert_purchase_order(
                    cursor=cursor,
                    po_number=po_number,
                    vendor_id=vendor_id,
                    project_id=project_id,
                    department=department,
                    requestor=requestor,
                    po_date=po_date,
                    po_status=po_status,
                    original_amount=original_amount,
                    revised_amount=revised_amount,
                    remaining_amount=remaining_amount,
                    import_batch_id=import_batch_id,
                )

                cursor.execute(
                    """
                    INSERT INTO dbo.IssuedPOLines
                        (
                            PurchaseOrderId,
                            ImportBatchId,
                            PONumber,
                            VendorName,
                            ProjectName,
                            Department,
                            PODate,
                            POStatus,
                            LineDescription,
                            Unit,
                            UnitCost,
                            Qty,
                            LineAmount,
                            OriginalAmount,
                            RevisedAmount,
                            RemainingAmount,
                            Requestor
                        )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    purchase_order_id,
                    import_batch_id,
                    po_number,
                    vendor_name,
                    project_name,
                    department,
                    po_date,
                    po_status,
                    description,
                    unit,
                    unit_cost,
                    qty,
                    line_amount,
                    original_amount,
                    revised_amount,
                    remaining_amount,
                    requestor,
                )

                success_count += 1

            except Exception as row_error:
                error_count += 1

                cursor.execute(
                    """
                    INSERT INTO dbo.ImportErrors
                        (
                            ImportBatchId,
                            RowNumber,
                            ErrorMessage,
                            RawRow
                        )
                    VALUES (?, ?, ?, ?)
                    """,
                    import_batch_id,
                    index,
                    str(row_error),
                    str(row),
                )

        final_status = "Completed" if error_count == 0 else "Completed With Errors"

        cursor.execute(
            """
            UPDATE dbo.ImportBatches
            SET
                SuccessCount = ?,
                ErrorCount = ?,
                ImportStatus = ?
            WHERE ImportBatchId = ?
            """,
            success_count,
            error_count,
            final_status,
            import_batch_id,
        )

        conn.commit()

        return {
            "import_batch_id": import_batch_id,
            "total_rows": len(rows),
            "success_count": success_count,
            "error_count": error_count,
            "status": final_status,
        }

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


BASE_PAGE_STYLE = """
<style>
    body {
        font-family: Arial, sans-serif;
        margin: 40px;
        background: #f5f7fa;
        color: #222;
    }
    .card {
        background: white;
        border-radius: 10px;
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    }
    .status {
        padding: 8px 12px;
        border-radius: 6px;
        display: inline-block;
        font-weight: bold;
    }
    .ok {
        background: #d4edda;
        color: #155724;
    }
    .warn {
        background: #fff3cd;
        color: #856404;
    }
    .error {
        background: #f8d7da;
        color: #721c24;
    }
    code {
        background: #f0f0f0;
        padding: 2px 5px;
        border-radius: 4px;
    }
    ul {
        line-height: 1.6;
    }
    input[type=file] {
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 6px;
        background: #fff;
    }
    button {
        background: #1f6feb;
        color: white;
        border: none;
        padding: 10px 16px;
        border-radius: 6px;
        font-weight: bold;
        cursor: pointer;
    }
    button:hover {
        background: #174ea6;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 12px;
    }
    th, td {
        border-bottom: 1px solid #ddd;
        padding: 8px;
        text-align: left;
    }
</style>
"""


HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>PO Dashboard</title>
    """ + BASE_PAGE_STYLE + """
</head>
<body>
    <div class="card">
        <h1>PO Dashboard</h1>
        <p>Starter procurement dashboard app is running.</p>
        <p>
            <span class="status ok">App Online</span>
        </p>
        <p>
            <a href="/upload-po">Upload Issued POs</a> |
            <a href="/po-summary">PO Summary</a> |
            <a href="/health">Health</a> |
            <a href="/db-test">DB Test</a>
        </p>
    </div>

    <div class="card">
        <h2>Azure App Settings</h2>
        <p><strong>Environment:</strong> {{ app_environment }}</p>
        <p><strong>SQL Server:</strong> {{ sql_server }}</p>
        <p><strong>SQL Database:</strong> {{ sql_database }}</p>
        <p><strong>Allowed Email Domain:</strong> {{ allowed_domain }}</p>
        <p><strong>SQL Connection String Found:</strong> {{ sql_connection_found }}</p>
    </div>

    <div class="card">
        <h2>Next Build Items</h2>
        <ul>
            <li>Issued PO upload</li>
            <li>Import history</li>
            <li>PO summary dashboard</li>
            <li>Expense upload</li>
            <li>Role-based access</li>
        </ul>
    </div>
</body>
</html>
"""

PO_SUMMARY_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>PO Summary</title>
    """ + BASE_PAGE_STYLE + """
</head>
<body>
    <div class="card">
        <h1>PO Summary Dashboard</h1>
        <p><a href="/">Back to Dashboard Home</a> | <a href="/upload-po">Upload Issued POs</a></p>
    </div>

    {% if error %}
    <div class="card">
        <p><span class="status error">Error loading PO summary: {{ error }}</span></p>
    </div>
    {% else %}

    <div class="card">
        <h2>Overall Summary</h2>
        <table>
            <tr><th>Total Unique POs</th><td>{{ overall.total_pos }}</td></tr>
            <tr><th>Open POs</th><td>{{ overall.open_pos }}</td></tr>
            <tr><th>Total PO Value</th><td>${{ "{:,.2f}".format(overall.total_po_value or 0) }}</td></tr>
            <tr><th>Total Line Amount</th><td>${{ "{:,.2f}".format(overall.total_line_amount or 0) }}</td></tr>
            <tr><th>Total Remaining Amount</th><td>${{ "{:,.2f}".format(overall.total_remaining_amount or 0) }}</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>POs by Vendor</h2>
        <table>
            <tr>
                <th>Vendor</th>
                <th>PO Count</th>
                <th>Total PO Value</th>
                <th>Total Line Amount</th>
                <th>Remaining Amount</th>
            </tr>
            {% for row in vendors %}
            <tr>
                <td>{{ row.VendorName }}</td>
                <td>{{ row.POCount }}</td>
                <td>${{ "{:,.2f}".format(row.TotalPOValue or 0) }}</td>
                <td>${{ "{:,.2f}".format(row.TotalLineAmount or 0) }}</td>
                <td>${{ "{:,.2f}".format(row.TotalRemainingAmount or 0) }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <h2>POs by Project</h2>
        <table>
            <tr>
                <th>Project</th>
                <th>PO Count</th>
                <th>Total PO Value</th>
                <th>Total Line Amount</th>
                <th>Remaining Amount</th>
            </tr>
            {% for row in projects %}
            <tr>
                <td>{{ row.ProjectName }}</td>
                <td>{{ row.POCount }}</td>
                <td>${{ "{:,.2f}".format(row.TotalPOValue or 0) }}</td>
                <td>${{ "{:,.2f}".format(row.TotalLineAmount or 0) }}</td>
                <td>${{ "{:,.2f}".format(row.TotalRemainingAmount or 0) }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <h2>Recent Import Batches</h2>
        <table>
            <tr>
                <th>Batch ID</th>
                <th>File Name</th>
                <th>Uploaded At</th>
                <th>Total Rows</th>
                <th>Success</th>
                <th>Errors</th>
                <th>Status</th>
            </tr>
            {% for row in imports %}
            <tr>
                <td>{{ row.ImportBatchId }}</td>
                <td>{{ row.FileName }}</td>
                <td>{{ row.UploadedAt }}</td>
                <td>{{ row.TotalRows }}</td>
                <td>{{ row.SuccessCount }}</td>
                <td>{{ row.ErrorCount }}</td>
                <td>{{ row.ImportStatus }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    {% endif %}
</body>
</html>
"""
UPLOAD_PO_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Upload Issued POs</title>
    """ + BASE_PAGE_STYLE + """
</head>
<body>
    <div class="card">
        <h1>Upload Issued POs</h1>
        <p>Upload the cleaned issued PO template as <strong>.xlsx</strong> or <strong>.csv</strong>.</p>
        <p><a href="/">Back to Dashboard Home</a></p>
    </div>

    {% if message %}
    <div class="card">
        <p><span class="status {{ message_class }}">{{ message }}</span></p>
    </div>
    {% endif %}

    {% if result %}
    <div class="card">
        <h2>Import Result</h2>
        <table>
            <tr><th>Import Batch ID</th><td>{{ result.import_batch_id }}</td></tr>
            <tr><th>Total Rows</th><td>{{ result.total_rows }}</td></tr>
            <tr><th>Success Count</th><td>{{ result.success_count }}</td></tr>
            <tr><th>Error Count</th><td>{{ result.error_count }}</td></tr>
            <tr><th>Status</th><td>{{ result.status }}</td></tr>
        </table>
    </div>
    {% endif %}

    {% if errors %}
    <div class="card">
        <h2>Validation Errors</h2>
        <ul>
            {% for error in errors %}
            <li>{{ error }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}

    <div class="card">
        <h2>Select File</h2>
        <form method="post" enctype="multipart/form-data">
            <p>
                <input type="file" name="po_file" accept=".xlsx,.csv" required>
            </p>
            <p>
                <button type="submit">Upload Issued POs</button>
            </p>
        </form>
    </div>

    <div class="card">
        <h2>Expected Columns</h2>
        <p>The upload must include these exact headers:</p>
        <code>{{ expected_columns }}</code>
    </div>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(
        HOME_PAGE,
        app_environment=APP_ENVIRONMENT,
        sql_server=SQL_SERVER_NAME,
        sql_database=SQL_DATABASE_NAME,
        allowed_domain=ALLOWED_EMAIL_DOMAIN,
        sql_connection_found="Yes" if SQL_CONNECTION else "No",
    )


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "environment": APP_ENVIRONMENT,
            "sql_server": SQL_SERVER_NAME,
            "database": SQL_DATABASE_NAME,
            "connection_string_found": bool(SQL_CONNECTION),
        }
    )

@app.route("/po-summary")
def po_summary():
    try:
        conn = get_sql_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            WITH UniquePOs AS (
                SELECT
                    PONumber,
                    MAX(VendorName) AS VendorName,
                    MAX(ProjectName) AS ProjectName,
                    MAX(POStatus) AS POStatus,
                    MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                    MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
                FROM dbo.IssuedPOLines
                GROUP BY PONumber
            ),
            LineTotals AS (
                SELECT
                    SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
                FROM dbo.IssuedPOLines
            )
            SELECT
                COUNT(*) AS TotalPOs,
                SUM(CASE WHEN UPPER(COALESCE(POStatus, '')) = 'OPEN' THEN 1 ELSE 0 END) AS OpenPOs,
                SUM(POValue) AS TotalPOValue,
                (SELECT TotalLineAmount FROM LineTotals) AS TotalLineAmount,
                SUM(RemainingAmount) AS TotalRemainingAmount
            FROM UniquePOs;
            """
        )
        overall_row = cursor.fetchone()

        overall = {
            "total_pos": overall_row.TotalPOs or 0,
            "open_pos": overall_row.OpenPOs or 0,
            "total_po_value": float(overall_row.TotalPOValue or 0),
            "total_line_amount": float(overall_row.TotalLineAmount or 0),
            "total_remaining_amount": float(overall_row.TotalRemainingAmount or 0),
        }

        cursor.execute(
            """
            WITH UniquePOs AS (
                SELECT
                    PONumber,
                    MAX(VendorName) AS VendorName,
                    MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                    MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
                FROM dbo.IssuedPOLines
                GROUP BY PONumber
            ),
            VendorLines AS (
                SELECT
                    VendorName,
                    SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
                FROM dbo.IssuedPOLines
                GROUP BY VendorName
            )
            SELECT
                u.VendorName,
                COUNT(*) AS POCount,
                SUM(u.POValue) AS TotalPOValue,
                COALESCE(MAX(v.TotalLineAmount), 0) AS TotalLineAmount,
                SUM(u.RemainingAmount) AS TotalRemainingAmount
            FROM UniquePOs u
            LEFT JOIN VendorLines v ON u.VendorName = v.VendorName
            GROUP BY u.VendorName
            ORDER BY TotalPOValue DESC;
            """
        )
        vendors = cursor.fetchall()

        cursor.execute(
            """
            WITH UniquePOs AS (
                SELECT
                    PONumber,
                    MAX(ProjectName) AS ProjectName,
                    MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                    MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
                FROM dbo.IssuedPOLines
                GROUP BY PONumber
            ),
            ProjectLines AS (
                SELECT
                    ProjectName,
                    SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
                FROM dbo.IssuedPOLines
                GROUP BY ProjectName
            )
            SELECT
                u.ProjectName,
                COUNT(*) AS POCount,
                SUM(u.POValue) AS TotalPOValue,
                COALESCE(MAX(p.TotalLineAmount), 0) AS TotalLineAmount,
                SUM(u.RemainingAmount) AS TotalRemainingAmount
            FROM UniquePOs u
            LEFT JOIN ProjectLines p ON u.ProjectName = p.ProjectName
            GROUP BY u.ProjectName
            ORDER BY TotalPOValue DESC;
            """
        )
        projects = cursor.fetchall()

        cursor.execute(
            """
            SELECT TOP 10
                ImportBatchId,
                FileName,
                UploadedAt,
                TotalRows,
                SuccessCount,
                ErrorCount,
                ImportStatus
            FROM dbo.ImportBatches
            ORDER BY UploadedAt DESC;
            """
        )
        imports = cursor.fetchall()

        conn.close()

        return render_template_string(
            PO_SUMMARY_PAGE,
            overall=overall,
            vendors=vendors,
            projects=projects,
            imports=imports,
            error=None,
        )

    except Exception as e:
        return render_template_string(
            PO_SUMMARY_PAGE,
            overall=None,
            vendors=[],
            projects=[],
            imports=[],
            error=str(e),
        ), 500
@app.route("/db-test")
def db_test():
    if not SQL_CONNECTION:
        return jsonify(
            {
                "status": "error",
                "step": "connection_string",
                "message": "SQL connection string was not found.",
            }
        ), 500

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DB_NAME() AS DatabaseName, GETUTCDATE() AS ServerTime")
        row = cursor.fetchone()
        conn.close()

        return jsonify(
            {
                "status": "success",
                "database": row.DatabaseName,
                "server_time_utc": str(row.ServerTime),
            }
        )

    except Exception as e:
        return jsonify(
            {
                "status": "error",
                "step": "connect_to_sql",
                "message": str(e),
            }
        ), 500


@app.route("/upload-po", methods=["GET", "POST"])
def upload_po():
    if request.method == "GET":
        return render_template_string(
            UPLOAD_PO_PAGE,
            message=None,
            message_class=None,
            result=None,
            errors=None,
            expected_columns=", ".join(REQUIRED_PO_COLUMNS),
        )

    uploaded_file = request.files.get("po_file")

    if not uploaded_file or uploaded_file.filename == "":
        return render_template_string(
            UPLOAD_PO_PAGE,
            message="No file selected.",
            message_class="error",
            result=None,
            errors=None,
            expected_columns=", ".join(REQUIRED_PO_COLUMNS),
        )

    try:
        rows = read_uploaded_po_file(uploaded_file)
        validation_errors = validate_po_rows(rows)

        if validation_errors:
            return render_template_string(
                UPLOAD_PO_PAGE,
                message="The file could not be imported because validation errors were found.",
                message_class="error",
                result=None,
                errors=validation_errors,
                expected_columns=", ".join(REQUIRED_PO_COLUMNS),
            )

        result = import_po_rows(rows, uploaded_file.filename)

        return render_template_string(
            UPLOAD_PO_PAGE,
            message="Issued PO import completed.",
            message_class="ok",
            result=result,
            errors=None,
            expected_columns=", ".join(REQUIRED_PO_COLUMNS),
        )

    except Exception as e:
        return render_template_string(
            UPLOAD_PO_PAGE,
            message="Import failed.",
            message_class="error",
            result=None,
            errors=[str(e)],
            expected_columns=", ".join(REQUIRED_PO_COLUMNS),
        ), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("HTTP_PLATFORM_PORT", 8000)))
    app.run(host="0.0.0.0", port=port)
