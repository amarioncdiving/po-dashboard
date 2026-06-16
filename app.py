import os
import sys
import site
import csv
import io
import html
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from urllib.parse import quote_plus

from flask import Flask, jsonify, request, Response, redirect


# ------------------------------------------------------------
# Azure / package setup
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PACKAGES_DIR = os.path.join(BASE_DIR, ".python_packages", "lib", "site-packages")

if os.path.isdir(PACKAGES_DIR):
    site.addsitedir(PACKAGES_DIR)
    sys.path.append(PACKAGES_DIR)


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


APP_ENVIRONMENT = os.getenv("APP_ENVIRONMENT", "Not set")
SQL_SERVER_NAME = os.getenv("SQL_SERVER_NAME", "Not set")
SQL_DATABASE_NAME = os.getenv("SQL_DATABASE_NAME", "Not set")
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "c-diving.com")

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


VALID_ROLES = [
    "Admin",
    "Executive",
    "Accounting",
    "Project Manager",
    "Viewer",
    "No Access",
]


PAGE_ACCESS = {
    "Dashboard": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "My Dashboard": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "New Purchase Request": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "Purchase Requests": ["Admin", "Executive", "Accounting"],
    "PO Summary": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "PO List": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "PO Detail": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "Upload Issued POs": ["Admin", "Accounting"],
    "Import History": ["Admin", "Accounting"],
    "Exceptions": ["Admin", "Executive", "Accounting"],
    "Exports": ["Admin", "Executive", "Accounting"],
    "User Access": ["Admin"],
    "Who Am I": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
}


# ------------------------------------------------------------
# General helpers
# ------------------------------------------------------------

def h(value):
    if value is None:
        return ""
    return html.escape(str(value))


def currency(value):
    try:
        return "${:,.2f}".format(float(value or 0))
    except Exception:
        return "$0.00"


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
    return value if value else None


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

    for fmt in ["%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%Y/%m/%d"]:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            pass

    return None


def normalize_header(header):
    if header is None:
        return ""
    return str(header).strip()


# ------------------------------------------------------------
# Authentication / role helpers
# ------------------------------------------------------------

def get_current_user():
    user_email = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME", "")
    user_id = request.headers.get("X-MS-CLIENT-PRINCIPAL-ID", "")
    identity_provider = request.headers.get("X-MS-CLIENT-PRINCIPAL-IDP", "")

    user_email = (user_email or "").strip().lower()

    email_domain = ""
    if "@" in user_email:
        email_domain = user_email.split("@")[-1].lower()

    allowed_domain = (ALLOWED_EMAIL_DOMAIN or "").strip().lower()

    return {
        "email": user_email,
        "user_id": user_id,
        "identity_provider": identity_provider,
        "email_domain": email_domain,
        "allowed_domain": allowed_domain,
        "is_authenticated": bool(user_email),
        "is_allowed_domain": bool(email_domain) and email_domain == allowed_domain,
    }


def get_user_access():
    user = get_current_user()

    access = {
        "email": user["email"],
        "display_name": "",
        "role": "No Access",
        "is_active": False,
        "found_in_sql": False,
        "lookup_error": "",
    }

    if not user["email"]:
        return access

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT TOP 1
                Email,
                DisplayName,
                RoleName,
                IsActive
            FROM dbo.DashboardUsers
            WHERE LOWER(Email) = LOWER(?);
            """,
            user["email"],
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            access["display_name"] = row.DisplayName or ""
            access["role"] = row.RoleName or "No Access"
            access["is_active"] = bool(row.IsActive)
            access["found_in_sql"] = True

            if not access["is_active"]:
                access["role"] = "No Access"

        return access

    except Exception as e:
        access["lookup_error"] = str(e)
        return access


def role_can_access(role_name, page_name):
    allowed_roles = PAGE_ACCESS.get(page_name, [])
    return role_name in allowed_roles


def require_page_access(page_name):
    user = get_current_user()
    access = get_user_access()

    if not user["is_authenticated"]:
        return False, "Microsoft login was not detected."

    if not user["is_allowed_domain"]:
        return False, f"Your email domain is not allowed. Expected @{user['allowed_domain']}."

    if not access["found_in_sql"]:
        return False, "Your account has not been added to the dashboard access list."

    if not access["is_active"]:
        return False, "Your dashboard account is inactive."

    if not role_can_access(access["role"], page_name):
        return False, f"Your role, {access['role']}, does not have access to {page_name}."

    return True, ""


def access_denied_response(page_name, reason):
    content = """
    <div class="notice error">Access denied.</div>

    <div class="card">
        <h3>You do not have access to this dashboard</h3>
        <p class="card-subtitle">
            Your Microsoft account is signed in, but it has not been approved for this procurement dashboard.
        </p>

        <p>
            Contact a dashboard Admin if you believe you should have access.
        </p>
    </div>
    """

    return shell(
        title="Access Denied",
        subtitle="Your account is not approved for this dashboard.",
        active="",
        content=content,
    ), 403


# ------------------------------------------------------------
# File upload / import helpers
# ------------------------------------------------------------

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

        headers = [normalize_header(cell.value) for cell in sheet[1]]
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
    cursor.execute("SELECT VendorId FROM dbo.Vendors WHERE VendorName = ?", vendor_name)
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
    cursor.execute("SELECT ProjectId FROM dbo.Projects WHERE ProjectName = ?", project_name)
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
            VALUES (?, 'PO Upload', ?, ?, 0, 0, 'Processing')
            """,
            filename,
            get_current_user()["email"] or "Manual Upload",
            len(rows),
        )

        import_batch_id = cursor.fetchone().ImportBatchId
        success_count = 0
        error_count = 0

        po_numbers = sorted(
            set(clean_text(row.get("PONumber")) for row in rows if clean_text(row.get("PONumber")))
        )

        for po_number in po_numbers:
            cursor.execute("DELETE FROM dbo.IssuedPOLines WHERE PONumber = ?", po_number)

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


# ------------------------------------------------------------
# Data loaders
# ------------------------------------------------------------

def load_summary_data():
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
            SELECT SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
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
    row = cursor.fetchone()

    overall = {
        "total_pos": row.TotalPOs or 0,
        "open_pos": row.OpenPOs or 0,
        "total_po_value": float(row.TotalPOValue or 0),
        "total_line_amount": float(row.TotalLineAmount or 0),
        "total_remaining_amount": float(row.TotalRemainingAmount or 0),
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
            SELECT VendorName, SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
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
            SELECT ProjectName, SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
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
    return overall, vendors, projects, imports


def load_personal_dashboard_data():
    conn = get_sql_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        WITH UniquePOs AS (
            SELECT
                PONumber,
                MAX(VendorName) AS VendorName,
                MAX(ProjectName) AS ProjectName,
                MAX(Department) AS Department,
                MAX(POStatus) AS POStatus,
                MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount,
                MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
            FROM dbo.IssuedPOLines
            GROUP BY PONumber
        )
        SELECT
            COUNT(*) AS TotalPOs,
            SUM(CASE WHEN UPPER(COALESCE(POStatus, '')) = 'OPEN' THEN 1 ELSE 0 END) AS OpenPOs,
            SUM(CASE WHEN UPPER(COALESCE(POStatus, '')) IN ('CLOSED', 'COMPLETE', 'COMPLETED') THEN 1 ELSE 0 END) AS ClosedPOs,
            SUM(POValue) AS TotalPOValue,
            SUM(TotalLineAmount) AS TotalLineAmount,
            SUM(RemainingAmount) AS TotalRemainingAmount,
            SUM(CASE WHEN ABS(COALESCE(POValue, 0) - COALESCE(TotalLineAmount, 0)) > 0.01 THEN 1 ELSE 0 END) AS AmountMismatchCount
        FROM UniquePOs;
        """
    )
    row = cursor.fetchone()

    overall = {
        "total_pos": row.TotalPOs or 0,
        "open_pos": row.OpenPOs or 0,
        "closed_pos": row.ClosedPOs or 0,
        "total_po_value": row.TotalPOValue or 0,
        "total_line_amount": row.TotalLineAmount or 0,
        "total_remaining_amount": row.TotalRemainingAmount or 0,
        "amount_mismatch_count": row.AmountMismatchCount or 0,
    }

    cursor.execute(
        """
        SELECT TOP 5
            VendorName,
            COUNT(DISTINCT PONumber) AS POCount,
            SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
        FROM dbo.IssuedPOLines
        GROUP BY VendorName
        ORDER BY TotalLineAmount DESC;
        """
    )
    top_vendors = cursor.fetchall()

    cursor.execute(
        """
        SELECT TOP 5
            ProjectName,
            COUNT(DISTINCT PONumber) AS POCount,
            SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
        FROM dbo.IssuedPOLines
        GROUP BY ProjectName
        ORDER BY TotalLineAmount DESC;
        """
    )
    top_projects = cursor.fetchall()

    cursor.execute(
        """
        SELECT TOP 5
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
    recent_imports = cursor.fetchall()

    cursor.execute(
        """
        SELECT COUNT(*) AS ActiveUserCount
        FROM dbo.DashboardUsers
        WHERE IsActive = 1;
        """
    )
    user_row = cursor.fetchone()
    active_user_count = user_row.ActiveUserCount or 0

    cursor.execute(
        """
        SELECT COUNT(*) AS ErrorCount
        FROM dbo.ImportErrors;
        """
    )
    error_row = cursor.fetchone()
    import_error_count = error_row.ErrorCount or 0

    conn.close()

    return {
        "overall": overall,
        "top_vendors": top_vendors,
        "top_projects": top_projects,
        "recent_imports": recent_imports,
        "active_user_count": active_user_count,
        "import_error_count": import_error_count,
    }


# ------------------------------------------------------------
# Purchase request helpers
# ------------------------------------------------------------

def purchase_request_status_badge(status):
    status = status or "Submitted"
    status_lower = status.lower()
    badge_class = "blue"

    if status_lower in ["submitted", "under review"]:
        badge_class = "amber"
    elif status_lower in ["approved", "converted to po"]:
        badge_class = "green"
    elif status_lower in ["rejected", "cancelled", "canceled"]:
        badge_class = "red"

    return f'<span class="badge {badge_class}">{h(status)}</span>'


def can_review_purchase_requests(role):
    return role in ["Admin", "Executive", "Accounting"]


def generate_purchase_request_number(cursor):
    today_prefix = datetime.utcnow().strftime("PR-%Y%m%d")

    cursor.execute(
        """
        SELECT COUNT(*) AS RequestCount
        FROM dbo.PurchaseRequests
        WHERE RequestNumber LIKE ?;
        """,
        today_prefix + "-%",
    )

    row = cursor.fetchone()
    next_number = (row.RequestCount or 0) + 1

    return f"{today_prefix}-{next_number:04d}"


def load_purchase_request_stats():
    conn = get_sql_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            COUNT(*) AS TotalRequests,
            SUM(CASE WHEN RequestStatus = 'Submitted' THEN 1 ELSE 0 END) AS SubmittedRequests,
            SUM(CASE WHEN RequestStatus = 'Under Review' THEN 1 ELSE 0 END) AS UnderReviewRequests,
            SUM(CASE WHEN RequestStatus = 'Approved' THEN 1 ELSE 0 END) AS ApprovedRequests,
            SUM(CASE WHEN RequestStatus = 'Rejected' THEN 1 ELSE 0 END) AS RejectedRequests,
            SUM(CASE WHEN RequestStatus = 'Converted to PO' THEN 1 ELSE 0 END) AS ConvertedRequests,
            SUM(COALESCE(EstimatedAmount, 0)) AS TotalEstimatedAmount
        FROM dbo.PurchaseRequests;
        """
    )

    row = cursor.fetchone()
    conn.close()

    return {
        "total_requests": row.TotalRequests or 0,
        "submitted_requests": row.SubmittedRequests or 0,
        "under_review_requests": row.UnderReviewRequests or 0,
        "approved_requests": row.ApprovedRequests or 0,
        "rejected_requests": row.RejectedRequests or 0,
        "converted_requests": row.ConvertedRequests or 0,
        "total_estimated_amount": row.TotalEstimatedAmount or 0,
    }


def load_purchase_requests(limit=100):
    conn = get_sql_connection()
    cursor = conn.cursor()

    cursor.execute(
        f"""
        SELECT TOP {int(limit)}
            PurchaseRequestId,
            RequestNumber,
            RequestedByEmail,
            RequestedByName,
            RequestedAt,
            NeededByDate,
            VendorName,
            ProjectName,
            Department,
            RequestTitle,
            RequestDescription,
            EstimatedAmount,
            Priority,
            RequestStatus,
            ReviewerEmail,
            ReviewedAt,
            ReviewNotes,
            ConvertedPONumber,
            UpdatedAt
        FROM dbo.PurchaseRequests
        ORDER BY RequestedAt DESC;
        """
    )

    rows = cursor.fetchall()
    conn.close()

    return rows


def create_purchase_request(form):
    user = get_current_user()
    access = get_user_access()

    request_title = clean_text(form.get("request_title"))
    vendor_name = clean_text(form.get("vendor_name"))
    project_name = clean_text(form.get("project_name"))
    department = clean_text(form.get("department"))
    needed_by_date = clean_date(form.get("needed_by_date"))
    estimated_amount = clean_decimal(form.get("estimated_amount"))
    priority = clean_text(form.get("priority"))
    request_description = clean_text(form.get("request_description"))

    if not request_title:
        raise ValueError("Request Title is required.")

    conn = get_sql_connection()
    cursor = conn.cursor()

    try:
        request_number = generate_purchase_request_number(cursor)

        cursor.execute(
            """
            INSERT INTO dbo.PurchaseRequests
                (
                    RequestNumber,
                    RequestedByEmail,
                    RequestedByName,
                    NeededByDate,
                    VendorName,
                    ProjectName,
                    Department,
                    RequestTitle,
                    RequestDescription,
                    EstimatedAmount,
                    Priority,
                    RequestStatus
                )
            OUTPUT INSERTED.PurchaseRequestId
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Submitted');
            """,
            request_number,
            user["email"],
            access["display_name"] or user["email"],
            needed_by_date,
            vendor_name,
            project_name,
            department,
            request_title,
            request_description,
            estimated_amount,
            priority,
        )

        purchase_request_id = cursor.fetchone().PurchaseRequestId
        conn.commit()

        return {
            "purchase_request_id": purchase_request_id,
            "request_number": request_number,
        }

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def update_purchase_request_status(form):
    user = get_current_user()

    purchase_request_id = clean_text(form.get("purchase_request_id"))
    request_status = clean_text(form.get("request_status"))
    review_notes = clean_text(form.get("review_notes"))
    converted_po_number = clean_text(form.get("converted_po_number"))

    valid_statuses = [
        "Submitted",
        "Under Review",
        "Approved",
        "Rejected",
        "Converted to PO",
    ]

    if request_status not in valid_statuses:
        raise ValueError("Invalid request status.")

    if not purchase_request_id:
        raise ValueError("Purchase Request ID is required.")

    conn = get_sql_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE dbo.PurchaseRequests
            SET
                RequestStatus = ?,
                ReviewerEmail = ?,
                ReviewedAt = SYSUTCDATETIME(),
                ReviewNotes = ?,
                ConvertedPONumber = ?,
                UpdatedAt = SYSUTCDATETIME()
            WHERE PurchaseRequestId = ?;
            """,
            request_status,
            user["email"],
            review_notes,
            converted_po_number,
            purchase_request_id,
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# ------------------------------------------------------------
# Branding / layout
# ------------------------------------------------------------

BRANDED_STYLE = """
<style>
:root {
  --navy: #061b36;
  --blue: #2563eb;
  --green: #16a34a;
  --amber: #f59e0b;
  --red: #dc2626;
  --bg: #f5f7fb;
  --card: #ffffff;
  --text: #0f172a;
  --muted: #64748b;
  --line: #e2e8f0;
  --shadow: 0 14px 30px rgba(15, 23, 42, 0.08);
  --radius: 16px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:
    radial-gradient(circle at 15% 20%, rgba(56, 189, 248, 0.18), transparent 28%),
    radial-gradient(circle at 85% 15%, rgba(37, 99, 235, 0.12), transparent 30%),
    linear-gradient(180deg, #eef7ff 0%, #f5f7fb 44%, #eef6fb 100%);
  color: var(--text);
  min-height: 100vh;
  position: relative;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: -1;
  background:
    url("data:image/svg+xml,%3Csvg width='1600' height='900' viewBox='0 0 1600 900' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M0 620 C 240 520 360 730 620 620 C 860 520 1000 690 1240 600 C 1420 530 1510 560 1600 520 L1600 900 L0 900 Z' fill='%232563eb' fill-opacity='0.055'/%3E%3Cpath d='M0 690 C 220 590 430 770 680 660 C 920 555 1070 740 1310 650 C 1450 600 1530 610 1600 590 L1600 900 L0 900 Z' fill='%23061b36' fill-opacity='0.045'/%3E%3Cpath d='M0 760 C 260 650 420 820 700 720 C 930 640 1120 790 1360 720 C 1480 685 1540 690 1600 670 L1600 900 L0 900 Z' fill='%2338bdf8' fill-opacity='0.08'/%3E%3C/svg%3E");
  background-size: cover;
  background-position: bottom center;
}
.sidebar {
  width: 270px;
  background: linear-gradient(180deg, var(--navy), #020617);
  color: white;
  padding: 24px 16px;
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  overflow-y: auto;
}
.brand { display:flex; gap:12px; align-items:center; margin-bottom:28px; padding:0 8px; }
.logo { width:42px; height:42px; border-radius:12px; display:grid; place-items:center; background: linear-gradient(135deg, #38bdf8, #2563eb); font-weight:900; }
.brand h1 { font-size:18px; line-height:1; margin:0 0 5px; }
.brand p { margin:0; font-size:12px; color:#bfdbfe; }
.nav-section { margin: 18px 8px 8px; color: #93c5fd; font-size: 11px; font-weight: 900; letter-spacing: .12em; text-transform: uppercase; }
.nav-divider { height: 1px; background: rgba(191, 219, 254, 0.18); margin: 16px 8px 10px; }
.nav-item { display:flex; gap:12px; align-items:center; color:#e2e8f0; text-decoration:none; padding:13px 14px; border-radius:11px; margin:4px 0; font-size:14px; }
.nav-item:hover { background: rgba(255,255,255,.09); }
.nav-item.active { background: linear-gradient(135deg, #2563eb, #1d4ed8); color:white; box-shadow: 0 10px 18px rgba(37,99,235,.25); }
.sync-card { margin-top: 22px; background:rgba(37,99,235,.16); border:1px solid rgba(191,219,254,.15); border-radius:16px; padding:15px; }
.status-dot { width:9px; height:9px; border-radius:99px; background:#22c55e; display:inline-block; margin-right:8px; box-shadow:0 0 0 5px rgba(34,197,94,.12); }
.main { margin-left:270px; padding:26px; position: relative; z-index: 1; }
.topbar { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; margin-bottom:20px; }
.topbar h2 { margin:0; font-size:28px; letter-spacing:-.04em; }
.topbar p { margin:8px 0 0; color:var(--muted); }
.top-actions { display:flex; gap:12px; align-items:center; color:var(--muted); font-size:13px; }
.button, button { border:1px solid var(--line); background:white; border-radius:12px; padding:10px 14px; cursor:pointer; font-weight:700; text-decoration:none; color:var(--text); display:inline-block; }
.primary { background: var(--blue); color:white; border-color:var(--blue); }
.grid { display:grid; gap:16px; }
.kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.two { grid-template-columns: 1fr 1fr; }
.card { background:rgba(255, 255, 255, 0.92); backdrop-filter: blur(10px); border:1px solid rgba(226, 232, 240, 0.86); border-radius:var(--radius); box-shadow:var(--shadow); padding:18px; overflow:hidden; margin-bottom:16px; }
.card h3 { margin:0 0 15px; font-size:16px; letter-spacing:-.02em; }
.card-subtitle { margin:-8px 0 15px; color:var(--muted); font-size:13px; }
.kpi { position:relative; min-height:125px; }
.kpi .label { color:var(--muted); font-size:12px; font-weight:700; }
.kpi .value { margin:9px 0 4px; font-size:25px; font-weight:900; letter-spacing:-.04em; }
.kpi .trend { font-size:12px; color:var(--muted); }
.badge { border-radius:999px; font-size:11px; font-weight:800; padding:4px 8px; display:inline-flex; align-items:center; }
.badge.green { background:#dcfce7; color:#166534; }
.badge.blue { background:#dbeafe; color:#1e40af; }
.badge.amber { background:#fef3c7; color:#92400e; }
.badge.red { background:#fee2e2; color:#991b1b; }
.table-wrap { max-height:560px; overflow:auto; border:1px solid var(--line); border-radius:14px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { text-align:left; border-bottom:1px solid var(--line); padding:10px 8px; vertical-align:top; }
th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; background:white; }
.right { text-align:right; }
input[type=file], input[type=text], input[type=date], input[type=number], select, textarea { padding:12px; border:1px solid var(--line); border-radius:12px; background:white; width:100%; max-width:520px; font-family: inherit; }
textarea { min-height: 110px; resize: vertical; }
.notice { padding:13px 15px; border-radius:13px; font-weight:700; margin-bottom:16px; }
.notice.ok { background:#dcfce7; color:#166534; }
.notice.error { background:#fee2e2; color:#991b1b; }
code { background:#f1f5f9; padding:8px 10px; display:block; border-radius:12px; white-space:normal; }
@media (max-width: 1000px) { .sidebar { position:relative; width:100%; bottom:auto; } .main { margin-left:0; } .kpis, .two { grid-template-columns: 1fr; } }
</style>
"""


def shell(title, subtitle, active, content):
    access = get_user_access()
    role = access["role"]

    po_nav_items = [
        ("Dashboard", "/", "📊"),
        ("My Dashboard", "/my-dashboard", "🏠"),
        ("New Purchase Request", "/purchase-request", "📝"),
        ("Purchase Requests", "/purchase-requests", "✅"),
        ("PO Summary", "/po-summary", "📋"),
        ("PO List", "/po-list", "📄"),
        ("PO Detail", "/po-detail", "🔎"),
        ("Upload Issued POs", "/upload-po", "⬆️"),
        ("Import History", "/import-history", "🕘"),
        ("Exceptions", "/exceptions", "⚠️"),
        ("Exports", "/exports", "⬇️"),
    ]

    admin_nav_items = [
        ("User Access", "/user-access", "🔐"),
        ("Who Am I", "/whoami", "👤"),
    ]

    account_nav_items = [
        ("Who Am I", "/whoami", "👤"),
    ]

    def build_nav_item(label, href, icon):
        active_class = " active" if active == label else ""
        return f'<a class="nav-item{active_class}" href="{href}"><span>{icon}</span>{h(label)}</a>'

    nav_html = ""

    po_nav_html = ""
    for label, href, icon in po_nav_items:
        if role_can_access(role, label):
            po_nav_html += build_nav_item(label, href, icon)

    if po_nav_html:
        nav_html += '<div class="nav-section">PO Apps</div>'
        nav_html += po_nav_html

    if role == "Admin":
        admin_nav_html = ""

        for label, href, icon in admin_nav_items:
            if label == "Who Am I" or role_can_access(role, label):
                admin_nav_html += build_nav_item(label, href, icon)

        if admin_nav_html:
            nav_html += '<div class="nav-divider"></div>'
            nav_html += '<div class="nav-section">Admin</div>'
            nav_html += admin_nav_html

    else:
        account_nav_html = ""

        for label, href, icon in account_nav_items:
            if role_can_access(role, label):
                account_nav_html += build_nav_item(label, href, icon)

        if account_nav_html:
            nav_html += '<div class="nav-divider"></div>'
            nav_html += '<div class="nav-section">Account</div>'
            nav_html += account_nav_html

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{h(title)}</title>
    {BRANDED_STYLE}
</head>
<body>
    <aside class="sidebar">
        <div class="brand">
            <div class="logo">CE</div>
            <div>
                <h1>Coastal Engineering</h1>
                <p>Procurement App</p>
            </div>
        </div>
        <nav>{nav_html}</nav>
        <div class="sync-card">
            <div style="font-weight:800; font-size:13px; margin-bottom:10px;">Signed-In Role</div>
            <div><span class="status-dot"></span>{h(role)}</div>
            <div style="margin-top:14px; color:#bfdbfe; font-size:12px;">
                User<br>
                <strong style="color:white;">{h(access["email"] or "Not detected")}</strong>
            </div>
        </div>
    </aside>

    <main class="main">
        <header class="topbar">
            <div>
                <h2>{h(title)}</h2>
                <p>{h(subtitle)}</p>
            </div>
            <div class="top-actions">
                <span>Role: {h(role)}</span>
                <span>Database: {h(SQL_DATABASE_NAME)}</span>
            </div>
        </header>

        {content}
    </main>
</body>
</html>
"""


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------

@app.route("/")
def home():
    return redirect("/my-dashboard")


@app.route("/purchase-request", methods=["GET", "POST"])
def purchase_request():
    allowed, reason = require_page_access("New Purchase Request")
    if not allowed:
        return access_denied_response("New Purchase Request", reason)

    message_html = ""

    if request.method == "POST":
        try:
            result = create_purchase_request(request.form)
            message_html = f"""
            <div class="notice ok">
                Purchase request submitted successfully. Request Number: {h(result["request_number"])}
            </div>
            """
        except Exception as e:
            message_html = f'<div class="notice error">Error submitting purchase request: {h(e)}</div>'

    content = f"""
    {message_html}

    <div class="card">
        <h3>New Purchase Request</h3>
        <p class="card-subtitle">Submit a request before a purchase order is issued.</p>

        <form method="post" action="/purchase-request">
            <p><label>Request Title</label><br><input type="text" name="request_title" placeholder="Example: Dive equipment rental for project 26-204" required></p>
            <p><label>Vendor Name</label><br><input type="text" name="vendor_name" placeholder="Vendor or supplier name"></p>
            <p><label>Project Name</label><br><input type="text" name="project_name" placeholder="Project name or number"></p>
            <p><label>Department</label><br><input type="text" name="department" placeholder="Department"></p>
            <p><label>Needed By Date</label><br><input type="date" name="needed_by_date"></p>
            <p><label>Estimated Amount</label><br><input type="number" name="estimated_amount" step="0.01" min="0" placeholder="0.00"></p>
            <p>
                <label>Priority</label><br>
                <select name="priority">
                    <option value="">Select priority</option>
                    <option value="Low">Low</option>
                    <option value="Normal">Normal</option>
                    <option value="High">High</option>
                    <option value="Urgent">Urgent</option>
                </select>
            </p>
            <p><label>Description / Notes</label><br><textarea name="request_description" placeholder="Describe what is needed, why it is needed, and any important details."></textarea></p>
            <p><button class="primary" type="submit">Submit Purchase Request</button></p>
        </form>
    </div>

    <div class="card">
        <h3>What happens next?</h3>
        <table>
            <tr><th>Step</th><th>Status</th></tr>
            <tr><td>Request submitted</td><td><span class="badge green">This page</span></td></tr>
            <tr><td>Admin / Accounting review</td><td><span class="badge amber">Next</span></td></tr>
            <tr><td>Request approved or rejected</td><td><span class="badge blue">Review step</span></td></tr>
            <tr><td>PO is issued</td><td><span class="badge blue">Future workflow</span></td></tr>
        </table>
    </div>
    """

    return shell("New Purchase Request", "Submit a new purchase request for review before a PO is issued.", "New Purchase Request", content)


@app.route("/purchase-requests", methods=["GET", "POST"])
def purchase_requests():
    allowed, reason = require_page_access("Purchase Requests")
    if not allowed:
        return access_denied_response("Purchase Requests", reason)

    access = get_user_access()
    role = access["role"]
    message_html = ""

    if request.method == "POST":
        if not can_review_purchase_requests(role):
            message_html = '<div class="notice error">You do not have permission to update purchase requests.</div>'
        else:
            try:
                update_purchase_request_status(request.form)
                message_html = '<div class="notice ok">Purchase request status was updated.</div>'
            except Exception as e:
                message_html = f'<div class="notice error">Error updating purchase request: {h(e)}</div>'

    try:
        stats = load_purchase_request_stats()
        requests = load_purchase_requests()

        request_rows = ""

        for row in requests:
            description = row.RequestDescription or ""
            if len(description) > 160:
                description = description[:160] + "..."

            status_options = ""
            for status in ["Submitted", "Under Review", "Approved", "Rejected", "Converted to PO"]:
                selected = " selected" if status == row.RequestStatus else ""
                status_options += f'<option value="{h(status)}"{selected}>{h(status)}</option>'

            review_form = ""
            if can_review_purchase_requests(role):
                review_form = f"""
                <form method="post" action="/purchase-requests">
                    <input type="hidden" name="purchase_request_id" value="{h(row.PurchaseRequestId)}">
                    <p><select name="request_status">{status_options}</select></p>
                    <p><input type="text" name="converted_po_number" value="{h(row.ConvertedPONumber)}" placeholder="PO number if converted"></p>
                    <p><textarea name="review_notes" placeholder="Review notes">{h(row.ReviewNotes)}</textarea></p>
                    <p><button type="submit">Update</button></p>
                </form>
                """

            request_rows += f"""
            <tr>
                <td><strong>{h(row.RequestNumber)}</strong><br><span style="color:var(--muted);">{h(row.RequestedAt)}</span></td>
                <td><strong>{h(row.RequestTitle)}</strong><br><span style="color:var(--muted);">{h(description)}</span></td>
                <td>{h(row.VendorName)}</td>
                <td>{h(row.ProjectName)}</td>
                <td>{h(row.Department)}</td>
                <td>{h(row.NeededByDate)}</td>
                <td class="right">{currency(row.EstimatedAmount)}</td>
                <td>{h(row.Priority)}</td>
                <td>{purchase_request_status_badge(row.RequestStatus)}</td>
                <td>{h(row.RequestedByName or row.RequestedByEmail)}</td>
                <td>{review_form}</td>
            </tr>
            """

        if not request_rows:
            request_rows = '<tr><td colspan="11">No purchase requests found yet.</td></tr>'

        content = f"""
        {message_html}

        <div class="grid kpis">
            <div class="card kpi"><div class="label">Total Requests</div><div class="value">{stats["total_requests"]}</div><div class="trend">All purchase requests</div></div>
            <div class="card kpi"><div class="label">Submitted</div><div class="value">{stats["submitted_requests"]}</div><div class="trend">Waiting for review</div></div>
            <div class="card kpi"><div class="label">Under Review</div><div class="value">{stats["under_review_requests"]}</div><div class="trend">Currently being reviewed</div></div>
            <div class="card kpi"><div class="label">Approved</div><div class="value">{stats["approved_requests"]}</div><div class="trend">Approved requests</div></div>
            <div class="card kpi"><div class="label">Estimated Total</div><div class="value">{currency(stats["total_estimated_amount"])}</div><div class="trend">All request estimates</div></div>
            <div class="card kpi"><div class="label">Converted to PO</div><div class="value">{stats["converted_requests"]}</div><div class="trend">Requests linked to POs</div></div>
        </div>

        <div class="card">
            <h3>Purchase Requests</h3>
            <p class="card-subtitle">Review submitted purchase requests and update their status.</p>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>Request #</th><th>Title / Description</th><th>Vendor</th><th>Project</th><th>Department</th><th>Needed By</th>
                        <th class="right">Estimate</th><th>Priority</th><th>Status</th><th>Requested By</th><th>Review</th>
                    </tr>
                    {request_rows}
                </table>
            </div>
        </div>
        """

        return shell("Purchase Requests", "Review submitted purchase requests before they become issued POs.", "Purchase Requests", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading purchase requests: {h(e)}</div>'
        return shell("Purchase Requests", "Unable to load purchase requests.", "Purchase Requests", content), 500


@app.route("/my-dashboard")
def my_dashboard():
    allowed, reason = require_page_access("My Dashboard")
    if not allowed:
        return access_denied_response("My Dashboard", reason)

    access = get_user_access()
    role = access["role"]
    display_name = access["display_name"] or access["email"] or "User"

    try:
        data = load_personal_dashboard_data()
        overall = data["overall"]
        pr_stats = load_purchase_request_stats()

        vendor_rows = ""
        for row in data["top_vendors"]:
            vendor_rows += f"<tr><td>{h(row.VendorName)}</td><td class=\"right\">{row.POCount}</td><td class=\"right\">{currency(row.TotalLineAmount)}</td></tr>"
        if not vendor_rows:
            vendor_rows = '<tr><td colspan="3">No vendor data found.</td></tr>'

        project_rows = ""
        for row in data["top_projects"]:
            project_rows += f"<tr><td>{h(row.ProjectName)}</td><td class=\"right\">{row.POCount}</td><td class=\"right\">{currency(row.TotalLineAmount)}</td></tr>"
        if not project_rows:
            project_rows = '<tr><td colspan="3">No project data found.</td></tr>'

        import_rows = ""
        for row in data["recent_imports"]:
            badge_class = "green"
            if row.ErrorCount and row.ErrorCount > 0:
                badge_class = "amber"
            if row.ImportStatus and "fail" in row.ImportStatus.lower():
                badge_class = "red"
            import_rows += f"<tr><td>{row.ImportBatchId}</td><td>{h(row.FileName)}</td><td>{h(row.UploadedAt)}</td><td>{row.TotalRows}</td><td>{row.SuccessCount}</td><td>{row.ErrorCount}</td><td><span class=\"badge {badge_class}\">{h(row.ImportStatus)}</span></td></tr>"
        if not import_rows:
            import_rows = '<tr><td colspan="7">No imports found.</td></tr>'

        common_kpis = f"""
        <div class="grid kpis">
            <div class="card kpi"><div class="label">Total POs</div><div class="value">{overall["total_pos"]}</div><div class="trend">Unique PO numbers</div></div>
            <div class="card kpi"><div class="label">Open POs</div><div class="value">{overall["open_pos"]}</div><div class="trend">Currently open</div></div>
            <div class="card kpi"><div class="label">Total PO Value</div><div class="value">{currency(overall["total_po_value"])}</div><div class="trend">Revised/original PO value</div></div>
            <div class="card kpi"><div class="label">Line Item Total</div><div class="value">{currency(overall["total_line_amount"])}</div><div class="trend">Imported line total</div></div>
            <div class="card kpi"><div class="label">Remaining</div><div class="value">{currency(overall["total_remaining_amount"])}</div><div class="trend">Current PO balance</div></div>
            <div class="card kpi"><div class="label">Purchase Requests</div><div class="value">{pr_stats["submitted_requests"]}</div><div class="trend">Submitted and waiting</div></div>
        </div>
        """

        if role == "Admin":
            role_content = f"""
            {common_kpis}
            <div class="grid two">
                <div class="card">
                    <h3>Admin Control Center</h3>
                    <p class="card-subtitle">Security, user access, uploads, purchase requests, and exports.</p>
                    <p><a class="button primary" href="/user-access">Manage User Access</a></p>
                    <p><a class="button" href="/purchase-requests">Review Purchase Requests</a></p>
                    <p><a class="button" href="/purchase-request">Create Purchase Request</a></p>
                    <p><a class="button" href="/upload-po">Upload Issued POs</a></p>
                    <p><a class="button" href="/import-history">Review Import History</a></p>
                    <p><a class="button" href="/exports">Download CSV Exports</a></p>
                </div>
                <div class="card">
                    <h3>Admin Health Snapshot</h3>
                    <table>
                        <tr><th>Active Dashboard Users</th><td>{data["active_user_count"]}</td></tr>
                        <tr><th>Import Errors</th><td>{data["import_error_count"]}</td></tr>
                        <tr><th>Submitted Purchase Requests</th><td>{pr_stats["submitted_requests"]}</td></tr>
                        <tr><th>Amount Mismatch Flags</th><td>{overall["amount_mismatch_count"]}</td></tr>
                    </table>
                </div>
            </div>
            <div class="card"><h3>Recent Imports</h3><div class="table-wrap"><table><tr><th>Batch ID</th><th>File Name</th><th>Uploaded At</th><th>Total Rows</th><th>Success</th><th>Errors</th><th>Status</th></tr>{import_rows}</table></div></div>
            """
        elif role == "Executive":
            role_content = f"""
            {common_kpis}
            <div class="grid two">
                <div class="card">
                    <h3>Executive Actions</h3>
                    <p class="card-subtitle">High-level procurement and request review tools.</p>
                    <p><a class="button primary" href="/po-summary">Open PO Summary</a></p>
                    <p><a class="button" href="/purchase-requests">Review Purchase Requests</a></p>
                    <p><a class="button" href="/purchase-request">Create Purchase Request</a></p>
                    <p><a class="button" href="/exceptions">Review Exceptions</a></p>
                    <p><a class="button" href="/exports">Download Exports</a></p>
                </div>
                <div class="card">
                    <h3>Risk Snapshot</h3>
                    <table>
                        <tr><th>Submitted Requests</th><td>{pr_stats["submitted_requests"]}</td></tr>
                        <tr><th>Amount Mismatch Flags</th><td>{overall["amount_mismatch_count"]}</td></tr>
                        <tr><th>Import Errors</th><td>{data["import_error_count"]}</td></tr>
                        <tr><th>Open POs</th><td>{overall["open_pos"]}</td></tr>
                    </table>
                </div>
            </div>
            """
        elif role == "Accounting":
            role_content = f"""
            {common_kpis}
            <div class="grid two">
                <div class="card">
                    <h3>Accounting Workspace</h3>
                    <p class="card-subtitle">Upload, review requests, resolve exceptions, and export records.</p>
                    <p><a class="button primary" href="/upload-po">Upload Issued POs</a></p>
                    <p><a class="button" href="/purchase-requests">Review Purchase Requests</a></p>
                    <p><a class="button" href="/purchase-request">Create Purchase Request</a></p>
                    <p><a class="button" href="/import-history">Review Import History</a></p>
                    <p><a class="button" href="/exceptions">Review Exceptions</a></p>
                    <p><a class="button" href="/exports">Download Exports</a></p>
                </div>
                <div class="card">
                    <h3>Import / Request Snapshot</h3>
                    <table>
                        <tr><th>Submitted Requests</th><td>{pr_stats["submitted_requests"]}</td></tr>
                        <tr><th>Import Errors</th><td>{data["import_error_count"]}</td></tr>
                        <tr><th>Amount Mismatch Flags</th><td>{overall["amount_mismatch_count"]}</td></tr>
                        <tr><th>Total POs</th><td>{overall["total_pos"]}</td></tr>
                    </table>
                </div>
            </div>
            <div class="card"><h3>Recent Imports</h3><div class="table-wrap"><table><tr><th>Batch ID</th><th>File Name</th><th>Uploaded At</th><th>Total Rows</th><th>Success</th><th>Errors</th><th>Status</th></tr>{import_rows}</table></div></div>
            """
        elif role == "Project Manager":
            role_content = f"""
            {common_kpis}
            <div class="grid two">
                <div class="card">
                    <h3>Project Manager Workspace</h3>
                    <p class="card-subtitle">Submit purchase requests and review issued POs.</p>
                    <p><a class="button primary" href="/purchase-request">Create Purchase Request</a></p>
                    <p><a class="button" href="/po-list">Browse PO List</a></p>
                    <p><a class="button" href="/po-detail">Search PO Detail</a></p>
                    <p><a class="button" href="/po-summary">Open PO Summary</a></p>
                </div>
                <div class="card"><h3>Top Projects</h3><div class="table-wrap"><table><tr><th>Project</th><th class="right">POs</th><th class="right">Line Total</th></tr>{project_rows}</table></div></div>
            </div>
            """
        else:
            role_content = f"""
            {common_kpis}
            <div class="grid two">
                <div class="card">
                    <h3>Viewer Dashboard</h3>
                    <p class="card-subtitle">Submit requests and view read-only PO information.</p>
                    <p><a class="button primary" href="/purchase-request">Create Purchase Request</a></p>
                    <p><a class="button" href="/po-summary">Open PO Summary</a></p>
                    <p><a class="button" href="/po-list">Browse PO List</a></p>
                    <p><a class="button" href="/po-detail">Search PO Detail</a></p>
                </div>
                <div class="card"><h3>Top Vendors</h3><div class="table-wrap"><table><tr><th>Vendor</th><th class="right">POs</th><th class="right">Line Total</th></tr>{vendor_rows}</table></div></div>
            </div>
            """

        content = f"""
        <div class="card"><h3>Welcome, {h(display_name)}</h3><p class="card-subtitle">This dashboard is customized for your role: <strong>{h(role)}</strong>.</p></div>
        {role_content}
        <div class="grid two">
            <div class="card"><h3>Top Vendors</h3><div class="table-wrap"><table><tr><th>Vendor</th><th class="right">POs</th><th class="right">Line Total</th></tr>{vendor_rows}</table></div></div>
            <div class="card"><h3>Top Projects</h3><div class="table-wrap"><table><tr><th>Project</th><th class="right">POs</th><th class="right">Line Total</th></tr>{project_rows}</table></div></div>
        </div>
        """

        return shell("My Dashboard", f"Personalized procurement dashboard for {role}.", "My Dashboard", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading personal dashboard: {h(e)}</div>'
        return shell("My Dashboard", "Unable to load personalized dashboard.", "My Dashboard", content), 500

@app.route("/po-summary")
def po_summary():
    allowed, reason = require_page_access("PO Summary")
    if not allowed:
        return access_denied_response("PO Summary", reason)

    try:
        overall, vendors, projects, imports = load_summary_data()

        vendor_rows = ""
        for row in vendors:
            vendor_rows += f"""
            <tr>
                <td>{h(row.VendorName)}</td>
                <td>{row.POCount}</td>
                <td class="right">{currency(row.TotalPOValue)}</td>
                <td class="right">{currency(row.TotalLineAmount)}</td>
                <td class="right">{currency(row.TotalRemainingAmount)}</td>
            </tr>
            """

        project_rows = ""
        for row in projects:
            project_rows += f"""
            <tr>
                <td>{h(row.ProjectName)}</td>
                <td>{row.POCount}</td>
                <td class="right">{currency(row.TotalPOValue)}</td>
                <td class="right">{currency(row.TotalLineAmount)}</td>
                <td class="right">{currency(row.TotalRemainingAmount)}</td>
            </tr>
            """

        import_rows = ""
        for row in imports:
            import_rows += f"""
            <tr>
                <td>{row.ImportBatchId}</td>
                <td>{h(row.FileName)}</td>
                <td>{h(row.UploadedAt)}</td>
                <td>{row.TotalRows}</td>
                <td>{row.SuccessCount}</td>
                <td>{row.ErrorCount}</td>
                <td>{h(row.ImportStatus)}</td>
            </tr>
            """

        content = f"""
        <div class="grid kpis">
            <div class="card kpi"><div class="label">Total Unique POs</div><div class="value">{overall["total_pos"]}</div><div class="trend">Grouped by PO number</div></div>
            <div class="card kpi"><div class="label">Open POs</div><div class="value">{overall["open_pos"]}</div><div class="trend">Status = Open</div></div>
            <div class="card kpi"><div class="label">Total PO Value</div><div class="value">{currency(overall["total_po_value"])}</div><div class="trend">Unique PO totals</div></div>
            <div class="card kpi"><div class="label">Line Item Total</div><div class="value">{currency(overall["total_line_amount"])}</div><div class="trend">Sum of line amounts</div></div>
            <div class="card kpi"><div class="label">Remaining</div><div class="value">{currency(overall["total_remaining_amount"])}</div><div class="trend">Unique PO remaining</div></div>
        </div>

        <div class="grid two">
            <div class="card"><h3>POs by Vendor</h3><p class="card-subtitle">Vendor-level committed value and remaining balance.</p><div class="table-wrap"><table><tr><th>Vendor</th><th>PO Count</th><th class="right">PO Value</th><th class="right">Line Amount</th><th class="right">Remaining</th></tr>{vendor_rows}</table></div></div>
            <div class="card"><h3>POs by Project</h3><p class="card-subtitle">Project-level committed value and remaining balance.</p><div class="table-wrap"><table><tr><th>Project</th><th>PO Count</th><th class="right">PO Value</th><th class="right">Line Amount</th><th class="right">Remaining</th></tr>{project_rows}</table></div></div>
        </div>

        <div class="card"><h3>Recent Import Batches</h3><p class="card-subtitle">Latest PO upload activity.</p><div class="table-wrap"><table><tr><th>Batch ID</th><th>File Name</th><th>Uploaded At</th><th>Total Rows</th><th>Success</th><th>Errors</th><th>Status</th></tr>{import_rows}</table></div></div>
        """

        return shell("PO Summary", "Live issued PO summary grouped by vendor, project, and import batch.", "PO Summary", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading PO summary: {h(e)}</div>'
        return shell("PO Summary", "Unable to load summary.", "PO Summary", content), 500


@app.route("/po-list")
def po_list():
    allowed, reason = require_page_access("PO List")
    if not allowed:
        return access_denied_response("PO List", reason)

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            WITH POList AS (
                SELECT
                    PONumber,
                    MAX(VendorName) AS VendorName,
                    MAX(ProjectName) AS ProjectName,
                    MAX(Department) AS Department,
                    MAX(POStatus) AS POStatus,
                    MAX(PODate) AS PODate,
                    COUNT(*) AS LineCount,
                    MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                    SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount,
                    MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
                FROM dbo.IssuedPOLines
                GROUP BY PONumber
            )
            SELECT
                PONumber,
                VendorName,
                ProjectName,
                Department,
                POStatus,
                PODate,
                LineCount,
                POValue,
                TotalLineAmount,
                RemainingAmount,
                CASE WHEN ABS(COALESCE(POValue, 0) - COALESCE(TotalLineAmount, 0)) > 0.01 THEN 1 ELSE 0 END AS AmountMismatch
            FROM POList
            ORDER BY PODate DESC, PONumber DESC;
            """
        )

        pos = cursor.fetchall()
        conn.close()

        po_rows = ""

        for row in pos:
            status_text = str(row.POStatus or "")
            status_lower = status_text.lower()

            status_class = "blue"
            if status_lower == "open":
                status_class = "green"
            elif status_lower in ["closed", "complete", "completed"]:
                status_class = "blue"
            elif status_lower in ["cancelled", "canceled"]:
                status_class = "red"
            elif status_lower in ["pending", "draft"]:
                status_class = "amber"

            mismatch_badge = ""
            if row.AmountMismatch:
                mismatch_badge = '<span class="badge amber">Check totals</span>'

            po_url = "/po-detail?po_number=" + quote_plus(str(row.PONumber or ""))

            po_rows += f"""
            <tr>
                <td><a href="{po_url}">{h(row.PONumber)}</a></td>
                <td>{h(row.VendorName)}</td>
                <td>{h(row.ProjectName)}</td>
                <td>{h(row.Department)}</td>
                <td><span class="badge {status_class}">{h(status_text)}</span></td>
                <td>{h(row.PODate)}</td>
                <td class="right">{row.LineCount}</td>
                <td class="right">{currency(row.POValue)}</td>
                <td class="right">{currency(row.TotalLineAmount)}</td>
                <td class="right">{currency(row.RemainingAmount)}</td>
                <td>{mismatch_badge}</td>
            </tr>
            """

        if not po_rows:
            po_rows = '<tr><td colspan="11">No issued POs found yet.</td></tr>'

        content = f"""
        <div class="card">
            <h3>Issued PO List</h3>
            <p class="card-subtitle">Browse all issued POs imported into the dashboard. Click a PO number to view its line items.</p>
            <div class="table-wrap">
                <table>
                    <tr><th>PO Number</th><th>Vendor</th><th>Project</th><th>Department</th><th>Status</th><th>PO Date</th><th class="right">Lines</th><th class="right">PO Value</th><th class="right">Line Total</th><th class="right">Remaining</th><th>Flag</th></tr>
                    {po_rows}
                </table>
            </div>
        </div>
        """

        return shell("PO List", "Browse issued purchase orders and open PO detail records.", "PO List", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading PO list: {h(e)}</div>'
        return shell("PO List", "Unable to load issued PO list.", "PO List", content), 500


@app.route("/po-detail", methods=["GET"])
def po_detail():
    allowed, reason = require_page_access("PO Detail")
    if not allowed:
        return access_denied_response("PO Detail", reason)

    po_number = clean_text(request.args.get("po_number"))
    search_value = h(po_number or "")

    search_form = f"""
    <div class="card">
        <h3>Search Purchase Order</h3>
        <p class="card-subtitle">Enter a PO number to view its line items and totals.</p>
        <form method="get" action="/po-detail">
            <p><input type="text" name="po_number" value="{search_value}" placeholder="Example: 26-204-002" required></p>
            <p><button class="primary" type="submit">Search PO</button></p>
        </form>
    </div>
    """

    if not po_number:
        content = search_form + """
        <div class="card"><h3>PO Detail</h3><p class="card-subtitle">Search for a PO number to see vendor, project, totals, and line items.</p></div>
        """
        return shell("PO Detail", "Search and review issued PO line items.", "PO Detail", content)

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT TOP 1
                PONumber,
                VendorName,
                ProjectName,
                Department,
                PODate,
                POStatus,
                OriginalAmount,
                RevisedAmount,
                RemainingAmount,
                Requestor
            FROM dbo.IssuedPOLines
            WHERE PONumber = ?
            ORDER BY CreatedAt DESC;
            """,
            po_number,
        )

        header = cursor.fetchone()

        if not header:
            conn.close()
            content = search_form + f'<div class="notice error">No PO found for PO number: {h(po_number)}</div>'
            return shell("PO Detail", "PO number was not found.", "PO Detail", content)

        cursor.execute(
            """
            SELECT LineDescription, Unit, UnitCost, Qty, LineAmount
            FROM dbo.IssuedPOLines
            WHERE PONumber = ?
            ORDER BY IssuedPOLineId;
            """,
            po_number,
        )
        lines = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                COUNT(*) AS LineCount,
                SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount,
                MAX(COALESCE(OriginalAmount, 0)) AS OriginalAmount,
                MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS RevisedAmount,
                MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
            FROM dbo.IssuedPOLines
            WHERE PONumber = ?;
            """,
            po_number,
        )
        totals = cursor.fetchone()
        conn.close()

        line_rows = ""
        for row in lines:
            line_rows += f"""
            <tr><td>{h(row.LineDescription)}</td><td>{h(row.Unit)}</td><td class="right">{currency(row.UnitCost)}</td><td class="right">{h(row.Qty)}</td><td class="right">{currency(row.LineAmount)}</td></tr>
            """

        content = search_form + f"""
        <div class="grid kpis">
            <div class="card kpi"><div class="label">PO Number</div><div class="value" style="font-size:22px;">{h(header.PONumber)}</div><div class="trend">{h(header.POStatus)}</div></div>
            <div class="card kpi"><div class="label">Original Amount</div><div class="value">{currency(totals.OriginalAmount)}</div><div class="trend">Original issued value</div></div>
            <div class="card kpi"><div class="label">Revised Amount</div><div class="value">{currency(totals.RevisedAmount)}</div><div class="trend">Current approved value</div></div>
            <div class="card kpi"><div class="label">Line Item Total</div><div class="value">{currency(totals.TotalLineAmount)}</div><div class="trend">{totals.LineCount} line item(s)</div></div>
            <div class="card kpi"><div class="label">Remaining</div><div class="value">{currency(totals.RemainingAmount)}</div><div class="trend">Current PO balance</div></div>
        </div>
        <div class="card"><h3>PO Header</h3><table><tr><th>Vendor</th><td>{h(header.VendorName)}</td></tr><tr><th>Project</th><td>{h(header.ProjectName)}</td></tr><tr><th>Department</th><td>{h(header.Department)}</td></tr><tr><th>PO Date</th><td>{h(header.PODate)}</td></tr><tr><th>Status</th><td>{h(header.POStatus)}</td></tr><tr><th>Requestor</th><td>{h(header.Requestor)}</td></tr></table></div>
        <div class="card"><h3>Line Items</h3><p class="card-subtitle">Issued PO line items imported from the upload document.</p><div class="table-wrap"><table><tr><th>Description</th><th>Unit</th><th class="right">Unit Cost</th><th class="right">Qty</th><th class="right">Line Amount</th></tr>{line_rows}</table></div></div>
        """

        return shell("PO Detail", f"Line item detail for PO {po_number}.", "PO Detail", content)

    except Exception as e:
        content = search_form + f'<div class="notice error">Error loading PO detail: {h(e)}</div>'
        return shell("PO Detail", "Unable to load PO detail.", "PO Detail", content), 500


@app.route("/upload-po", methods=["GET", "POST"])
def upload_po():
    allowed, reason = require_page_access("Upload Issued POs")
    if not allowed:
        return access_denied_response("Upload Issued POs", reason)

    message_html = ""
    result_html = ""
    errors_html = ""

    if request.method == "POST":
        uploaded_file = request.files.get("po_file")

        if not uploaded_file or uploaded_file.filename == "":
            message_html = '<div class="notice error">No file selected.</div>'
        else:
            try:
                rows = read_uploaded_po_file(uploaded_file)
                validation_errors = validate_po_rows(rows)

                if validation_errors:
                    message_html = '<div class="notice error">The file could not be imported because validation errors were found.</div>'
                    error_items = "".join(f"<li>{h(error)}</li>" for error in validation_errors)
                    errors_html = f'<div class="card"><h3>Validation Errors</h3><ul>{error_items}</ul></div>'
                else:
                    result = import_po_rows(rows, uploaded_file.filename)
                    message_html = '<div class="notice ok">Issued PO import completed.</div>'
                    result_html = f"""
                    <div class="card"><h3>Import Result</h3><table><tr><th>Import Batch ID</th><td>{result["import_batch_id"]}</td></tr><tr><th>Total Rows</th><td>{result["total_rows"]}</td></tr><tr><th>Success Count</th><td>{result["success_count"]}</td></tr><tr><th>Error Count</th><td>{result["error_count"]}</td></tr><tr><th>Status</th><td>{h(result["status"])}</td></tr></table></div>
                    """

            except Exception as e:
                message_html = '<div class="notice error">Import failed.</div>'
                errors_html = f'<div class="card"><h3>Error Details</h3><p>{h(e)}</p></div>'

    content = f"""
    {message_html}{result_html}{errors_html}
    <div class="card"><h3>Select Issued PO File</h3><p class="card-subtitle">Upload the cleaned issued PO template as .xlsx or .csv.</p><form method="post" enctype="multipart/form-data"><p><input type="file" name="po_file" accept=".xlsx,.csv" required></p><p><button class="primary" type="submit">Upload Issued POs</button></p></form></div>
    <div class="card"><h3>Expected Columns</h3><p class="card-subtitle">The upload must include these exact headers.</p><code>{h(", ".join(REQUIRED_PO_COLUMNS))}</code></div>
    """

    return shell("Upload Issued POs", "Import issued purchase orders and line items into Azure SQL.", "Upload Issued POs", content)

@app.route("/import-history")
def import_history():
    allowed, reason = require_page_access("Import History")
    if not allowed:
        return access_denied_response("Import History", reason)

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT TOP 50
                ImportBatchId,
                FileName,
                SourceSystem,
                UploadedBy,
                UploadedAt,
                TotalRows,
                SuccessCount,
                ErrorCount,
                ImportStatus,
                ErrorMessage
            FROM dbo.ImportBatches
            ORDER BY UploadedAt DESC;
            """
        )
        batches = cursor.fetchall()

        cursor.execute(
            """
            SELECT TOP 100
                e.ImportErrorId,
                e.ImportBatchId,
                b.FileName,
                e.RowNumber,
                e.ErrorMessage,
                e.RawRow,
                e.CreatedAt
            FROM dbo.ImportErrors e
            LEFT JOIN dbo.ImportBatches b ON e.ImportBatchId = b.ImportBatchId
            ORDER BY e.CreatedAt DESC;
            """
        )
        errors = cursor.fetchall()
        conn.close()

        batch_rows = ""
        for row in batches:
            status_badge = "green"
            if row.ErrorCount and row.ErrorCount > 0:
                status_badge = "amber"
            if row.ImportStatus and "fail" in row.ImportStatus.lower():
                status_badge = "red"

            batch_rows += f"""
            <tr><td>{row.ImportBatchId}</td><td>{h(row.FileName)}</td><td>{h(row.UploadedAt)}</td><td>{h(row.SourceSystem)}</td><td>{h(row.UploadedBy)}</td><td>{row.TotalRows}</td><td>{row.SuccessCount}</td><td>{row.ErrorCount}</td><td><span class="badge {status_badge}">{h(row.ImportStatus)}</span></td></tr>
            """

        if not batch_rows:
            batch_rows = '<tr><td colspan="9">No import batches found yet.</td></tr>'

        error_rows = ""
        for row in errors:
            raw_row = row.RawRow or ""
            if len(raw_row) > 300:
                raw_row = raw_row[:300] + "..."

            error_rows += f"""
            <tr><td>{row.ImportErrorId}</td><td>{row.ImportBatchId}</td><td>{h(row.FileName)}</td><td>{h(row.RowNumber)}</td><td>{h(row.ErrorMessage)}</td><td>{h(raw_row)}</td><td>{h(row.CreatedAt)}</td></tr>
            """

        if not error_rows:
            error_rows = '<tr><td colspan="7">No import errors found.</td></tr>'

        content = f"""
        <div class="card"><h3>Import Batches</h3><p class="card-subtitle">Latest uploaded PO files and processing results.</p><div class="table-wrap"><table><tr><th>Batch ID</th><th>File Name</th><th>Uploaded At</th><th>Source</th><th>Uploaded By</th><th>Total Rows</th><th>Success</th><th>Errors</th><th>Status</th></tr>{batch_rows}</table></div></div>
        <div class="card"><h3>Recent Import Errors</h3><p class="card-subtitle">Rows that failed validation or import processing.</p><div class="table-wrap"><table><tr><th>Error ID</th><th>Batch ID</th><th>File Name</th><th>Row Number</th><th>Error Message</th><th>Raw Row</th><th>Created At</th></tr>{error_rows}</table></div></div>
        """

        return shell("Import History", "Review uploaded files, row counts, import status, and row-level errors.", "Import History", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading import history: {h(e)}</div>'
        return shell("Import History", "Unable to load import history.", "Import History", content), 500


@app.route("/exceptions")
def exceptions():
    allowed, reason = require_page_access("Exceptions")
    if not allowed:
        return access_denied_response("Exceptions", reason)

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            WITH POList AS (
                SELECT
                    PONumber,
                    MAX(VendorName) AS VendorName,
                    MAX(ProjectName) AS ProjectName,
                    MAX(Department) AS Department,
                    MAX(POStatus) AS POStatus,
                    COUNT(*) AS LineCount,
                    MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                    SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount,
                    MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
                FROM dbo.IssuedPOLines
                GROUP BY PONumber
            )
            SELECT 'Amount Mismatch' AS ExceptionType, PONumber, VendorName, ProjectName, Department, POStatus,
                   'Line total does not match revised/original PO value.' AS Message, POValue, TotalLineAmount, RemainingAmount
            FROM POList
            WHERE ABS(COALESCE(POValue, 0) - COALESCE(TotalLineAmount, 0)) > 0.01
            UNION ALL
            SELECT 'Closed With Remaining Balance' AS ExceptionType, PONumber, VendorName, ProjectName, Department, POStatus,
                   'PO appears closed but still has remaining balance.' AS Message, POValue, TotalLineAmount, RemainingAmount
            FROM POList
            WHERE UPPER(COALESCE(POStatus, '')) IN ('CLOSED', 'COMPLETE', 'COMPLETED') AND COALESCE(RemainingAmount, 0) > 0.01
            UNION ALL
            SELECT 'Open With Zero Remaining' AS ExceptionType, PONumber, VendorName, ProjectName, Department, POStatus,
                   'PO appears open but has zero remaining balance.' AS Message, POValue, TotalLineAmount, RemainingAmount
            FROM POList
            WHERE UPPER(COALESCE(POStatus, '')) = 'OPEN' AND COALESCE(RemainingAmount, 0) = 0
            UNION ALL
            SELECT 'Missing Department' AS ExceptionType, PONumber, VendorName, ProjectName, Department, POStatus,
                   'PO is missing a department, which may affect role-based filtering.' AS Message, POValue, TotalLineAmount, RemainingAmount
            FROM POList
            WHERE Department IS NULL OR LTRIM(RTRIM(Department)) = ''
            UNION ALL
            SELECT 'Missing Revised Amount' AS ExceptionType, PONumber, VendorName, ProjectName, Department, POStatus,
                   'PO is missing RevisedAmount. OriginalAmount is being used as fallback.' AS Message, POValue, TotalLineAmount, RemainingAmount
            FROM POList
            WHERE PONumber IN (
                SELECT PONumber FROM dbo.IssuedPOLines GROUP BY PONumber HAVING MAX(RevisedAmount) IS NULL
            )
            ORDER BY ExceptionType, PONumber;
            """
        )

        rows = cursor.fetchall()
        conn.close()

        exception_rows = ""
        count_by_type = {}

        for row in rows:
            count_by_type[row.ExceptionType] = count_by_type.get(row.ExceptionType, 0) + 1
            po_url = "/po-detail?po_number=" + quote_plus(str(row.PONumber or ""))
            badge_class = "red" if row.ExceptionType == "Amount Mismatch" else "amber"

            exception_rows += f"""
            <tr><td><span class="badge {badge_class}">{h(row.ExceptionType)}</span></td><td><a href="{po_url}">{h(row.PONumber)}</a></td><td>{h(row.VendorName)}</td><td>{h(row.ProjectName)}</td><td>{h(row.Department)}</td><td>{h(row.POStatus)}</td><td>{h(row.Message)}</td><td class="right">{currency(row.POValue)}</td><td class="right">{currency(row.TotalLineAmount)}</td><td class="right">{currency(row.RemainingAmount)}</td></tr>
            """

        if not exception_rows:
            exception_rows = '<tr><td colspan="10">No exceptions found. Your issued PO data looks clean.</td></tr>'

        kpi_cards = ""
        if count_by_type:
            for exception_type, count in sorted(count_by_type.items()):
                kpi_cards += f'<div class="card kpi"><div class="label">{h(exception_type)}</div><div class="value">{count}</div><div class="trend">Exception count</div></div>'
        else:
            kpi_cards = '<div class="card kpi"><div class="label">Exceptions</div><div class="value">0</div><div class="trend"><span class="badge green">Clean</span></div></div>'

        content = f"""
        <div class="grid kpis">{kpi_cards}</div>
        <div class="card"><h3>Data Quality Exceptions</h3><p class="card-subtitle">Review issued POs that may need correction before expense tracking begins.</p><div class="table-wrap"><table><tr><th>Type</th><th>PO Number</th><th>Vendor</th><th>Project</th><th>Department</th><th>Status</th><th>Message</th><th class="right">PO Value</th><th class="right">Line Total</th><th class="right">Remaining</th></tr>{exception_rows}</table></div></div>
        """

        return shell("Exceptions", "Data quality checks for issued purchase orders.", "Exceptions", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading exceptions: {h(e)}</div>'
        return shell("Exceptions", "Unable to load exceptions.", "Exceptions", content), 500


@app.route("/exports")
def exports():
    allowed, reason = require_page_access("Exports")
    if not allowed:
        return access_denied_response("Exports", reason)

    content = """
    <div class="grid two">
        <div class="card"><h3>PO List Export</h3><p class="card-subtitle">Download one row per issued PO with totals and status.</p><p><a class="button primary" href="/export-po-list.csv">Download PO List CSV</a></p></div>
        <div class="card"><h3>Issued Line Items Export</h3><p class="card-subtitle">Download all issued PO line items from the upload data.</p><p><a class="button primary" href="/export-issued-lines.csv">Download Line Items CSV</a></p></div>
    </div>
    """

    return shell("Exports", "Download procurement dashboard data as CSV files.", "Exports", content)


@app.route("/export-po-list.csv")
def export_po_list_csv():
    allowed, reason = require_page_access("Exports")
    if not allowed:
        return access_denied_response("Exports", reason)

    conn = get_sql_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        WITH POList AS (
            SELECT
                PONumber,
                MAX(VendorName) AS VendorName,
                MAX(ProjectName) AS ProjectName,
                MAX(Department) AS Department,
                MAX(POStatus) AS POStatus,
                MAX(PODate) AS PODate,
                COUNT(*) AS LineCount,
                MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount,
                MAX(COALESCE(RemainingAmount, 0)) AS RemainingAmount
            FROM dbo.IssuedPOLines
            GROUP BY PONumber
        )
        SELECT PONumber, VendorName, ProjectName, Department, POStatus, PODate, LineCount, POValue, TotalLineAmount, RemainingAmount
        FROM POList
        ORDER BY PODate DESC, PONumber DESC;
        """
    )

    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["PONumber", "VendorName", "ProjectName", "Department", "POStatus", "PODate", "LineCount", "POValue", "TotalLineAmount", "RemainingAmount"])

    for row in rows:
        writer.writerow([row.PONumber, row.VendorName, row.ProjectName, row.Department, row.POStatus, row.PODate, row.LineCount, row.POValue, row.TotalLineAmount, row.RemainingAmount])

    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=po_list_export.csv"})


@app.route("/export-issued-lines.csv")
def export_issued_lines_csv():
    allowed, reason = require_page_access("Exports")
    if not allowed:
        return access_denied_response("Exports", reason)

    conn = get_sql_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT PONumber, VendorName, ProjectName, Department, PODate, POStatus, LineDescription, Unit, UnitCost, Qty, LineAmount, OriginalAmount, RevisedAmount, RemainingAmount, Requestor, CreatedAt
        FROM dbo.IssuedPOLines
        ORDER BY PONumber, IssuedPOLineId;
        """
    )

    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["PONumber", "VendorName", "ProjectName", "Department", "PODate", "POStatus", "Description", "Unit", "UnitCost", "Qty", "LineAmount", "OriginalAmount", "RevisedAmount", "RemainingAmount", "Requestor", "CreatedAt"])

    for row in rows:
        writer.writerow([row.PONumber, row.VendorName, row.ProjectName, row.Department, row.PODate, row.POStatus, row.LineDescription, row.Unit, row.UnitCost, row.Qty, row.LineAmount, row.OriginalAmount, row.RevisedAmount, row.RemainingAmount, row.Requestor, row.CreatedAt])

    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=issued_po_lines_export.csv"})

@app.route("/user-access", methods=["GET", "POST"])
def user_access():
    allowed, reason = require_page_access("User Access")
    if not allowed:
        return access_denied_response("User Access", reason)

    message_html = ""

    if request.method == "POST":
        email = clean_text(request.form.get("email"))
        display_name = clean_text(request.form.get("display_name"))
        role_name = clean_text(request.form.get("role_name"))
        is_active_raw = clean_text(request.form.get("is_active"))

        is_active = 1 if is_active_raw == "1" else 0

        if email:
            email = email.lower()

        if not email or "@" not in email:
            message_html = '<div class="notice error">Email is required.</div>'
        elif role_name not in VALID_ROLES:
            message_html = '<div class="notice error">Invalid role selected.</div>'
        else:
            try:
                conn = get_sql_connection()
                cursor = conn.cursor()

                cursor.execute(
                    """
                    IF EXISTS (SELECT 1 FROM dbo.DashboardUsers WHERE LOWER(Email) = LOWER(?))
                    BEGIN
                        UPDATE dbo.DashboardUsers
                        SET DisplayName = ?, RoleName = ?, IsActive = ?, UpdatedAt = SYSUTCDATETIME()
                        WHERE LOWER(Email) = LOWER(?);
                    END
                    ELSE
                    BEGIN
                        INSERT INTO dbo.DashboardUsers (Email, DisplayName, RoleName, IsActive)
                        VALUES (?, ?, ?, ?);
                    END
                    """,
                    email,
                    display_name,
                    role_name,
                    is_active,
                    email,
                    email,
                    display_name,
                    role_name,
                    is_active,
                )

                conn.commit()
                conn.close()
                message_html = '<div class="notice ok">User access was saved.</div>'

            except Exception as e:
                message_html = f'<div class="notice error">Error saving user access: {h(e)}</div>'

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT DashboardUserId, Email, DisplayName, RoleName, IsActive, CreatedAt, UpdatedAt
            FROM dbo.DashboardUsers
            ORDER BY Email;
            """
        )

        users = cursor.fetchall()
        conn.close()

        user_rows = ""
        for row in users:
            active_badge = '<span class="badge green">Active</span>' if row.IsActive else '<span class="badge red">Inactive</span>'
            user_rows += f"<tr><td>{h(row.Email)}</td><td>{h(row.DisplayName)}</td><td><span class=\"badge blue\">{h(row.RoleName)}</span></td><td>{active_badge}</td><td>{h(row.UpdatedAt)}</td></tr>"

        if not user_rows:
            user_rows = '<tr><td colspan="5">No users found.</td></tr>'

        role_options = ""
        for role in VALID_ROLES:
            role_options += f'<option value="{h(role)}">{h(role)}</option>'

        content = f"""
        {message_html}
        <div class="card">
            <h3>Add or Update User Access</h3>
            <p class="card-subtitle">Admins can add users or update their dashboard role. Use the exact Microsoft 365 email address.</p>
            <form method="post" action="/user-access">
                <p><label>Email</label><br><input type="text" name="email" placeholder="person@c-diving.com" required></p>
                <p><label>Display Name</label><br><input type="text" name="display_name" placeholder="Person Name"></p>
                <p><label>Role</label><br><select name="role_name" required>{role_options}</select></p>
                <p><label>Status</label><br><select name="is_active"><option value="1">Active</option><option value="0">Inactive</option></select></p>
                <p><button class="primary" type="submit">Save User Access</button></p>
            </form>
        </div>
        <div class="card"><h3>Current Dashboard Users</h3><p class="card-subtitle">Users listed here can be assigned roles for the procurement dashboard.</p><div class="table-wrap"><table><tr><th>Email</th><th>Display Name</th><th>Role</th><th>Status</th><th>Updated At</th></tr>{user_rows}</table></div></div>
        <div class="card"><h3>Role Guide</h3><table><tr><th>Role</th><th>Access</th></tr><tr><td>Admin</td><td>Everything, including User Access</td></tr><tr><td>Executive</td><td>Summary, PO pages, purchase request review, Exceptions, Exports</td></tr><tr><td>Accounting</td><td>PO pages, request review, Uploads, Import History, Exceptions, Exports</td></tr><tr><td>Project Manager</td><td>Submit requests, PO Summary, PO List, PO Detail</td></tr><tr><td>Viewer</td><td>Submit requests, read-only PO Summary/List/Detail</td></tr><tr><td>No Access</td><td>Can sign in through Microsoft, but cannot view dashboard data</td></tr></table></div>
        """

        return shell("User Access", "Manage SQL-backed dashboard roles and permissions.", "User Access", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading user access: {h(e)}</div>'
        return shell("User Access", "Unable to load user access.", "User Access", content), 500


@app.route("/whoami")
def whoami():
    allowed, reason = require_page_access("Who Am I")
    if not allowed:
        return access_denied_response("Who Am I", reason)

    user = get_current_user()
    access = get_user_access()
    principal = request.headers.get("X-MS-CLIENT-PRINCIPAL", "")
    principal_preview = principal[:500]
    if len(principal) > 500:
        principal_preview += "..."

    auth_status_badge = '<span class="badge green">Authenticated</span>' if user["is_authenticated"] else '<span class="badge amber">Not Detected</span>'
    domain_status_badge = '<span class="badge green">Allowed Domain</span>' if user["is_allowed_domain"] else '<span class="badge amber">Domain Not Confirmed</span>'
    sql_status_badge = '<span class="badge green">Found</span>' if access["found_in_sql"] else '<span class="badge amber">Not Found</span>'
    active_badge = '<span class="badge green">Active</span>' if access["is_active"] else '<span class="badge red">Inactive / No Access</span>'

    content = f"""
    <div class="grid two">
        <div class="card">
            <h3>Signed-In User</h3>
            <p class="card-subtitle">This page reads the Microsoft login headers provided by Azure App Service Authentication.</p>
            <table>
                <tr><th>Authentication Status</th><td>{auth_status_badge}</td></tr>
                <tr><th>Email / User Principal Name</th><td>{h(user["email"])}</td></tr>
                <tr><th>Email Domain</th><td>{h(user["email_domain"])}</td></tr>
                <tr><th>Allowed Domain Setting</th><td>{h(user["allowed_domain"])}</td></tr>
                <tr><th>Domain Check</th><td>{domain_status_badge}</td></tr>
                <tr><th>Identity Provider</th><td>{h(user["identity_provider"])}</td></tr>
                <tr><th>Azure User ID</th><td>{h(user["user_id"])}</td></tr>
            </table>
        </div>
        <div class="card">
            <h3>Dashboard Access</h3>
            <p class="card-subtitle">This is the SQL-backed dashboard permission result.</p>
            <table>
                <tr><th>Found In DashboardUsers</th><td>{sql_status_badge}</td></tr>
                <tr><th>Display Name</th><td>{h(access["display_name"])}</td></tr>
                <tr><th>Role</th><td><span class="badge blue">{h(access["role"])}</span></td></tr>
                <tr><th>Status</th><td>{active_badge}</td></tr>
                <tr><th>Lookup Error</th><td>{h(access["lookup_error"])}</td></tr>
            </table>
        </div>
    </div>
    <div class="card">
        <h3>Raw Azure Authentication Headers</h3>
        <p class="card-subtitle">Useful for troubleshooting.</p>
        <table>
            <tr><th>Header</th><th>Value</th></tr>
            <tr><td>X-MS-CLIENT-PRINCIPAL-NAME</td><td>{h(user["email"])}</td></tr>
            <tr><td>X-MS-CLIENT-PRINCIPAL-ID</td><td>{h(user["user_id"])}</td></tr>
            <tr><td>X-MS-CLIENT-PRINCIPAL-IDP</td><td>{h(user["identity_provider"])}</td></tr>
            <tr><td>X-MS-CLIENT-PRINCIPAL</td><td>{h(principal_preview)}</td></tr>
        </table>
    </div>
    """

    return shell("Who Am I", "View the signed-in Microsoft user and SQL-backed dashboard role.", "Who Am I", content)


@app.route("/access-denied")
def access_denied():
    return access_denied_response("Unknown", "Access denied.")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "environment": APP_ENVIRONMENT, "sql_server": SQL_SERVER_NAME, "database": SQL_DATABASE_NAME, "connection_string_found": bool(SQL_CONNECTION)})


@app.route("/db-test")
def db_test():
    if not SQL_CONNECTION:
        return jsonify({"status": "error", "step": "connection_string", "message": "SQL connection string was not found."}), 500

    try:
        conn = get_sql_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DB_NAME() AS DatabaseName, GETUTCDATE() AS ServerTime")
        row = cursor.fetchone()
        conn.close()
        return jsonify({"status": "success", "database": row.DatabaseName, "server_time_utc": str(row.ServerTime)})
    except Exception as e:
        return jsonify({"status": "error", "step": "connect_to_sql", "message": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("HTTP_PLATFORM_PORT", 8000)))
    app.run(host="0.0.0.0", port=port)
