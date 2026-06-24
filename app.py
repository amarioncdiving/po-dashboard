import os
import sys
import site
import csv
import io
import html
import re
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from urllib.parse import quote_plus
from werkzeug.utils import secure_filename

from flask import Flask, jsonify, request, Response, redirect, make_response, send_from_directory


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
    "ProjectCode",
    "ProjectName",
    "PONumber",
    "VendorName",
    "PODate",
    "Description",
    "Unit",
    "UnitCost",
    "Qty",
    "LineAmount",
]

DEPARTMENT_OPTIONS = [
    "Engineering",
    "Marine Construction",
    "Commercial Diving",
    "Dredging",
    "Marine Services",
]


REQUEST_ATTACHMENT_ROOT = os.getenv("REQUEST_ATTACHMENT_ROOT", "/home/site/wwwroot/request_attachments")
ALLOWED_ATTACHMENT_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx", "csv", "txt", "eml", "msg"}


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
    "Approver Queue": ["Admin", "Executive", "Accounting"],
    "POs & Balances": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "Projects": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "Forecasting": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "Project PO Setup": ["Admin", "Executive", "Accounting", "Project Manager"],
    "PO Setup Review": ["Admin", "Executive", "Accounting", "Project Manager"],
    "Missing PO Review": ["Admin", "Executive", "Accounting", "Project Manager"],
    "PO Summary": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "PO List": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "PO Detail": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "Upload Issued POs": ["Admin", "Accounting"],
    "Expense Upload / PO Matching": ["Admin", "Accounting"],
    "Expenses": ["Admin", "Executive", "Accounting", "Project Manager"],
    "Missing PO Review": ["Admin", "Executive", "Accounting", "Project Manager"],
    "Vendors": ["Admin", "Executive", "Accounting", "Project Manager", "Viewer"],
    "POs in PM Comments": ["Admin", "Executive", "Accounting", "Project Manager"],
    "Import History": ["Admin", "Accounting"],
    "Exceptions": ["Admin", "Executive", "Accounting"],
    "Exports": ["Admin", "Executive", "Accounting"],
    "User Access": ["Admin", "Executive"],
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


def select_option(value, selected_value):
    selected = " selected" if str(value or "") == str(selected_value or "") else ""
    return f'<option value="{h(value)}"{selected}>{h(value)}</option>'


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


def load_assignable_users():
    """Return active named users for assignment dropdowns."""
    conn = get_sql_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT Email, DisplayName, RoleName
        FROM dbo.DashboardUsers
        WHERE IsActive = 1
        ORDER BY
            CASE WHEN COALESCE(DisplayName, '') = '' THEN Email ELSE DisplayName END;
        """
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


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

    raise ValueError("Unsupported file type. Please upload a .csv file.")


def validate_po_rows(rows, selected_department=None, selected_requestor=None, valid_requestors=None):
    errors = []

    if not rows:
        errors.append("The file has no data rows.")
        return errors

    selected_department = clean_text(selected_department)
    selected_requestor = clean_text(selected_requestor)
    valid_requestors = set(valid_requestors or [])

    if selected_department not in DEPARTMENT_OPTIONS:
        errors.append("Select a department before uploading. Department must be one of: " + ", ".join(DEPARTMENT_OPTIONS) + ".")

    if not selected_requestor:
        errors.append("Select a requestor before uploading.")
    elif valid_requestors and selected_requestor not in valid_requestors:
        errors.append("Selected requestor is not an active user in User Access.")

    actual_columns = set(rows[0].keys())
    missing_columns = [col for col in REQUIRED_PO_COLUMNS if col not in actual_columns]

    if missing_columns:
        errors.append("Missing required columns: " + ", ".join(missing_columns))

    for index, row in enumerate(rows, start=2):
        project_code = clean_text(row.get("ProjectCode"))
        po_number = clean_text(row.get("PONumber"))
        vendor_name = clean_text(row.get("VendorName"))
        project_name = clean_text(row.get("ProjectName"))
        line_amount = clean_decimal(row.get("LineAmount"))

        if not project_code:
            errors.append(f"Row {index}: ProjectCode is required.")

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


def ensure_project_code_columns(cursor):
    """Add ProjectCode to project/PO tables for the Phase 1 setup template."""
    for table_name in ["Projects", "PurchaseOrders", "IssuedPOLines"]:
        cursor.execute(
            f"""
            IF COL_LENGTH('dbo.{table_name}', 'ProjectCode') IS NULL
            BEGIN
                ALTER TABLE dbo.{table_name} ADD ProjectCode NVARCHAR(100) NULL;
            END
            """
        )


def get_or_create_project(cursor, project_name, department, project_code=None):
    project_code = clean_text(project_code)
    project_name = clean_text(project_name)

    ensure_project_code_columns(cursor)

    if project_code:
        cursor.execute(
            "SELECT ProjectId FROM dbo.Projects WHERE ProjectCode = ? OR ProjectName = ?",
            project_code,
            project_name,
        )
    else:
        cursor.execute("SELECT ProjectId FROM dbo.Projects WHERE ProjectName = ?", project_name)

    row = cursor.fetchone()

    if row:
        cursor.execute(
            """
            UPDATE dbo.Projects
            SET ProjectCode = COALESCE(NULLIF(ProjectCode, ''), ?),
                Department = COALESCE(NULLIF(Department, ''), ?)
            WHERE ProjectId = ?
            """,
            project_code,
            department,
            row.ProjectId,
        )
        return row.ProjectId

    cursor.execute(
        """
        INSERT INTO dbo.Projects (ProjectCode, ProjectName, Department, IsActive)
        OUTPUT INSERTED.ProjectId
        VALUES (?, ?, ?, 1)
        """,
        project_code,
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
    project_code=None,
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
                ProjectCode = ?,
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
            project_code,
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
                ProjectCode,
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        po_number,
        vendor_id,
        project_id,
        project_code,
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


def import_po_rows(rows, filename, selected_department=None, selected_requestor=None):
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

        ensure_project_code_columns(cursor)

        po_numbers = sorted(
            set(clean_text(row.get("PONumber")) for row in rows if clean_text(row.get("PONumber")))
        )

        po_totals = {}
        for source_row in rows:
            source_po = clean_text(source_row.get("PONumber"))
            source_amount = clean_decimal(source_row.get("LineAmount")) or Decimal("0")
            if source_po:
                po_totals[source_po] = po_totals.get(source_po, Decimal("0")) + source_amount

        for po_number in po_numbers:
            cursor.execute("DELETE FROM dbo.IssuedPOLines WHERE PONumber = ?", po_number)

        for index, row in enumerate(rows, start=2):
            try:
                project_code = clean_text(row.get("ProjectCode"))
                po_number = clean_text(row.get("PONumber"))
                vendor_name = clean_text(row.get("VendorName"))
                project_name = clean_text(row.get("ProjectName"))
                department = clean_text(selected_department)
                po_date = clean_date(row.get("PODate"))
                po_status = "Open"
                description = clean_text(row.get("Description"))
                unit = clean_text(row.get("Unit"))
                unit_cost = clean_decimal(row.get("UnitCost"))
                qty = clean_decimal(row.get("Qty"))
                line_amount = clean_decimal(row.get("LineAmount"))
                original_amount = po_totals.get(po_number, Decimal("0"))
                revised_amount = original_amount
                remaining_amount = original_amount
                requestor = clean_text(selected_requestor)

                vendor_id = get_or_create_vendor(cursor, vendor_name)
                project_id = get_or_create_project(cursor, project_name, department, project_code)

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
                    project_code=project_code,
                )

                cursor.execute(
                    """
                    INSERT INTO dbo.IssuedPOLines
                        (
                            PurchaseOrderId,
                            ImportBatchId,
                            PONumber,
                            VendorName,
                            ProjectCode,
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    purchase_order_id,
                    import_batch_id,
                    po_number,
                    vendor_name,
                    project_code,
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
# Expense upload / PO matching helpers
# ------------------------------------------------------------

REQUIRED_EXPENSE_COLUMNS = [
    "ExpenseId",
    "ProjectName",
    "TxDate",
    "TxType",
    "VendorName",
    "Amount",
    "Description",
    "PMComments",
]


def row_value(row, aliases):
    """Return the first populated value from a row using several possible column names."""
    normalized = {str(k or "").strip().lower(): v for k, v in row.items()}
    for alias in aliases:
        key = alias.strip().lower()
        if key in normalized and normalized[key] not in [None, ""]:
            return normalized[key]
    return None


def compact_match_text(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def ensure_expense_review_tables():
    conn = get_sql_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        IF OBJECT_ID('dbo.ExpenseUploadBatches', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.ExpenseUploadBatches (
                ExpenseBatchId INT IDENTITY(1,1) PRIMARY KEY,
                FileName NVARCHAR(255) NOT NULL,
                UploadedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
                UploadedBy NVARCHAR(255) NULL,
                TotalRows INT NOT NULL DEFAULT 0,
                AutoMatchedCount INT NOT NULL DEFAULT 0,
                NeedsReviewCount INT NOT NULL DEFAULT 0,
                NoMatchCount INT NOT NULL DEFAULT 0,
                ImportStatus NVARCHAR(100) NOT NULL DEFAULT 'Completed'
            );
        END;

        IF OBJECT_ID('dbo.ExpenseReviewItems', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.ExpenseReviewItems (
                ExpenseReviewItemId INT IDENTITY(1,1) PRIMARY KEY,
                ExpenseBatchId INT NOT NULL,
                SourceRowNumber INT NULL,
                ExpenseId NVARCHAR(100) NULL,
                ProjectName NVARCHAR(255) NULL,
                TxDate DATE NULL,
                TxType NVARCHAR(100) NULL,
                VendorName NVARCHAR(255) NULL,
                Description NVARCHAR(MAX) NULL,
                Amount DECIMAL(18,2) NULL,
                PMComments NVARCHAR(MAX) NULL,
                ExtractedPONumber NVARCHAR(100) NULL,
                MatchedPONumber NVARCHAR(100) NULL,
                MatchStatus NVARCHAR(100) NOT NULL DEFAULT 'Needs Review',
                MatchConfidence NVARCHAR(50) NULL,
                MatchReason NVARCHAR(MAX) NULL,
                ReviewDecision NVARCHAR(100) NULL,
                CorrectPONumber NVARCHAR(100) NULL,
                ReviewerNotes NVARCHAR(MAX) NULL,
                CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
                UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
            );
            CREATE INDEX IX_ExpenseReviewItems_Status ON dbo.ExpenseReviewItems(MatchStatus);
            CREATE INDEX IX_ExpenseReviewItems_Project ON dbo.ExpenseReviewItems(ProjectName);
            CREATE INDEX IX_ExpenseReviewItems_PO ON dbo.ExpenseReviewItems(MatchedPONumber);
        END;
        """
    )
    # Add rollout balance-posting/audit columns to existing databases.
    rollout_columns = [
        ("ExpenseReviewItems", "ExpenseUniqueKey", "NVARCHAR(500) NULL"),
        ("ExpenseReviewItems", "ReviewerEmail", "NVARCHAR(255) NULL"),
        ("ExpenseReviewItems", "ReviewedAt", "DATETIME2 NULL"),
        ("ExpenseReviewItems", "PostedToPO", "BIT NOT NULL CONSTRAINT DF_ExpenseReviewItems_PostedToPO DEFAULT 0"),
        ("ExpenseReviewItems", "PostedPONumber", "NVARCHAR(100) NULL"),
        ("ExpenseReviewItems", "PostedAmount", "DECIMAL(18,2) NULL"),
        ("ExpenseReviewItems", "PostedAt", "DATETIME2 NULL"),
        ("ExpenseReviewItems", "PostedBy", "NVARCHAR(255) NULL"),
        ("ExpenseReviewItems", "PostingBatchId", "INT NULL"),
        ("ExpenseReviewItems", "IsDuplicate", "BIT NOT NULL CONSTRAINT DF_ExpenseReviewItems_IsDuplicate DEFAULT 0"),
        ("ExpenseUploadBatches", "DuplicateCount", "INT NOT NULL CONSTRAINT DF_ExpenseUploadBatches_DuplicateCount DEFAULT 0"),
        ("ExpenseUploadBatches", "PostedCount", "INT NOT NULL CONSTRAINT DF_ExpenseUploadBatches_PostedCount DEFAULT 0"),
        ("ExpenseUploadBatches", "PostedAmount", "DECIMAL(18,2) NOT NULL CONSTRAINT DF_ExpenseUploadBatches_PostedAmount DEFAULT 0"),
    ]
    for table_name, column_name, column_type in rollout_columns:
        cursor.execute(f"""
            IF COL_LENGTH('dbo.{table_name}', '{column_name}') IS NULL
            BEGIN
                ALTER TABLE dbo.{table_name} ADD {column_name} {column_type};
            END
        """)

    cursor.execute("""
        IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ExpenseReviewItems_PostedPO' AND object_id = OBJECT_ID('dbo.ExpenseReviewItems'))
        BEGIN
            CREATE INDEX IX_ExpenseReviewItems_PostedPO ON dbo.ExpenseReviewItems(PostedToPO, PostedPONumber);
        END;
        IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ExpenseReviewItems_UniqueKey' AND object_id = OBJECT_ID('dbo.ExpenseReviewItems'))
        BEGIN
            CREATE INDEX IX_ExpenseReviewItems_UniqueKey ON dbo.ExpenseReviewItems(ExpenseUniqueKey);
        END;
    """)

    # Backfill existing reviewed/auto-matched rows so current uploaded expenses begin reducing balances after deployment.
    cursor.execute("""
        UPDATE dbo.ExpenseReviewItems
        SET PostedToPO = 1,
            PostedPONumber = COALESCE(NULLIF(CorrectPONumber, ''), NULLIF(MatchedPONumber, '')),
            PostedAmount = COALESCE(Amount, 0),
            PostedAt = COALESCE(PostedAt, UpdatedAt, SYSUTCDATETIME()),
            PostedBy = COALESCE(NULLIF(ReviewerEmail, ''), 'System Backfill'),
            UpdatedAt = SYSUTCDATETIME()
        WHERE COALESCE(PostedToPO, 0) = 0
          AND COALESCE(NULLIF(CorrectPONumber, ''), NULLIF(MatchedPONumber, '')) IS NOT NULL
          AND (
                ReviewDecision = 'Matched to PO'
                OR (
                    MatchStatus = 'Auto Matched'
                    AND LOWER(COALESCE(TxType, '')) NOT LIKE '%time sheet%'
                    AND LOWER(COALESCE(TxType, '')) NOT LIKE '%labor%'
                    AND LOWER(COALESCE(TxType, '')) NOT LIKE '%per diem%'
                    AND LOWER(COALESCE(TxType, '')) NOT LIKE '%perdiem%'
                    AND LOWER(COALESCE(TxType, '')) NOT LIKE '%mileage%'
                    AND LOWER(COALESCE(TxType, '')) NOT LIKE '%travel stipend%'
                    AND (LOWER(COALESCE(TxType, '')) LIKE '%purchase%' OR LOWER(COALESCE(TxType, '')) LIKE '%disbursement%')
                )
          );
    """)
    conn.commit()
    conn.close()


def expense_unique_key(project_name, tx_date, tx_type, vendor_name, amount, expense_id, pm_comments):
    parts = [
        compact_match_text(project_name),
        str(tx_date or ''),
        compact_match_text(tx_type),
        compact_match_text(vendor_name),
        str(clean_decimal(amount) or Decimal('0')),
        compact_match_text(expense_id),
        compact_match_text(str(pm_comments or '')[:80]),
    ]
    return '|'.join(parts)[:500]


def expense_type_auto_posts(tx_type):
    text = str(tx_type or '').strip().lower()
    if not text:
        return False
    excluded = ['time sheet', 'labor', 'per diem', 'perdiem', 'mileage', 'travel stipend']
    if any(term in text for term in excluded):
        return False
    return any(term in text for term in ['purchase', 'disbursement'])


def sync_expense_posting(cursor, item_id, posted_by=None):
    """Synchronize whether one expense review item reduces an app PO balance.

    POs are uploaded once at project setup. From that point forward, current app
    balance is calculated as issued PO amount minus review items where PostedToPO=1.
    This function is idempotent and prevents the same review row from being counted
    more than once.
    """
    posted_by = posted_by or (get_current_user().get('email') or 'System')
    cursor.execute(
        """
        SELECT ExpenseReviewItemId, TxType, Amount, MatchedPONumber, CorrectPONumber,
               MatchStatus, ReviewDecision, PostedToPO
        FROM dbo.ExpenseReviewItems
        WHERE ExpenseReviewItemId = ?;
        """,
        item_id,
    )
    row = cursor.fetchone()
    if not row:
        return False

    decision = clean_text(row.ReviewDecision) or 'Pending Review'
    match_status = clean_text(row.MatchStatus) or ''
    correct_po = clean_text(row.CorrectPONumber)
    matched_po = clean_text(row.MatchedPONumber)
    po_to_post = correct_po or matched_po

    should_post = False
    if decision == 'Matched to PO' and po_to_post:
        # Manual review decisions are allowed to post, including reimbursables if Accounting deliberately matches them.
        should_post = True
    elif match_status == 'Auto Matched' and po_to_post and expense_type_auto_posts(row.TxType):
        # Safe automatic posting: a non-labor Purchase/Disbursement found an exact PO in PM comments.
        should_post = True

    if should_post:
        cursor.execute(
            """
            UPDATE dbo.ExpenseReviewItems
            SET PostedToPO = 1,
                PostedPONumber = ?,
                PostedAmount = COALESCE(Amount, 0),
                PostedAt = COALESCE(PostedAt, SYSUTCDATETIME()),
                PostedBy = COALESCE(PostedBy, ?),
                UpdatedAt = SYSUTCDATETIME()
            WHERE ExpenseReviewItemId = ?;
            """,
            po_to_post,
            posted_by,
            item_id,
        )
        return True

    cursor.execute(
        """
        UPDATE dbo.ExpenseReviewItems
        SET PostedToPO = 0,
            PostedPONumber = NULL,
            PostedAmount = NULL,
            PostedAt = NULL,
            PostedBy = NULL,
            UpdatedAt = SYSUTCDATETIME()
        WHERE ExpenseReviewItemId = ?;
        """,
        item_id,
    )
    return False


def load_po_match_candidates(cursor):
    cursor.execute(
        """
        SELECT
            po.PONumber,
            COALESCE(v.VendorName, '') AS VendorName,
            COALESCE(p.ProjectName, '') AS ProjectName,
            COALESCE(po.RemainingAmount, po.RevisedAmount, po.OriginalAmount, 0) AS RemainingAmount
        FROM dbo.PurchaseOrders po
        LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
        LEFT JOIN dbo.Projects p ON po.ProjectId = p.ProjectId
        ORDER BY po.PONumber;
        """
    )
    return cursor.fetchall()


def choose_expense_match(project_name, vendor_name, amount, pm_comments, po_candidates):
    comments_key = compact_match_text(pm_comments)
    project_key = compact_match_text(project_name)
    vendor_key = compact_match_text(vendor_name)
    amount_float = float(amount or 0)

    # First: exact PO reference in PM comments.
    for po in po_candidates:
        po_number = po.PONumber or ""
        if po_number and compact_match_text(po_number) and compact_match_text(po_number) in comments_key:
            return {
                "status": "Auto Matched",
                "confidence": "High",
                "extracted_po": po_number,
                "matched_po": po_number,
                "reason": "PO number was found directly in PM Comments.",
            }

    # Second: a project + vendor candidate. This should be reviewed before it affects balances.
    candidate_matches = []
    for po in po_candidates:
        po_project = compact_match_text(po.ProjectName)
        po_vendor = compact_match_text(po.VendorName)
        project_match = bool(project_key and (project_key in po_project or po_project in project_key))
        vendor_match = bool(vendor_key and (vendor_key in po_vendor or po_vendor in vendor_key))
        if project_match and vendor_match:
            candidate_matches.append(po)

    if len(candidate_matches) == 1:
        po = candidate_matches[0]
        remaining = float(po.RemainingAmount or 0)
        amount_note = " Remaining balance appears sufficient." if remaining >= amount_float else " Remaining balance may be insufficient."
        return {
            "status": "Needs Review",
            "confidence": "Medium",
            "extracted_po": "",
            "matched_po": po.PONumber,
            "reason": "One PO matched by project and vendor." + amount_note,
        }

    if len(candidate_matches) > 1:
        return {
            "status": "Needs Review",
            "confidence": "Low",
            "extracted_po": "",
            "matched_po": "",
            "reason": f"{len(candidate_matches)} possible POs matched by project/vendor. Select the correct PO manually.",
        }

    # Fallback: try to extract a PO-looking token from comments so the reviewer can see it.
    extracted = ""
    token_match = re.search(r"\b(?:PO[-\s#:]*)?([A-Z]{0,3}-?\d{2,3}-\d{3}(?:-\d{3})?)\b", str(pm_comments or ""), re.IGNORECASE)
    if token_match:
        extracted = token_match.group(1).upper()

    return {
        "status": "No Match",
        "confidence": "None",
        "extracted_po": extracted,
        "matched_po": "",
        "reason": "No exact PO comment match or unique project/vendor PO match was found.",
    }


def import_expense_rows(rows, filename):
    ensure_expense_review_tables()
    conn = get_sql_connection()
    cursor = conn.cursor()
    try:
        po_candidates = load_po_match_candidates(cursor)
        cursor.execute(
            """
            INSERT INTO dbo.ExpenseUploadBatches (FileName, UploadedBy, TotalRows, ImportStatus)
            OUTPUT INSERTED.ExpenseBatchId
            VALUES (?, ?, ?, 'Completed')
            """,
            filename,
            get_current_user()["email"] or "Manual Upload",
            len(rows),
        )
        batch_id = cursor.fetchone().ExpenseBatchId
        counts = {"Auto Matched": 0, "Needs Review": 0, "No Match": 0}
        duplicate_count = 0
        posted_count = 0
        posted_amount = Decimal("0")

        for index, row in enumerate(rows, start=2):
            expense_id = clean_text(row_value(row, ["ExpenseId", "Expense ID", "Transaction ID", "Tx ID", "Track No."]))
            project_name = clean_text(row_value(row, ["ProjectName", "Project Name", "Project", "Project Short Name", "Project Code"]))
            tx_date = clean_date(row_value(row, ["TxDate", "Tx Date", "Transaction Date", "Date"]));
            tx_type = clean_text(row_value(row, ["TxType", "Tx Type", "Transaction Type", "Type"]));
            # Rollout rule: timesheet/labor expense rows are ignored during upload and do not enter PO matching or reduce balances.
            tx_type_lc = str(tx_type or "").strip().lower()
            if "time sheet" in tx_type_lc or "timesheet" in tx_type_lc:
                continue
            vendor_name = clean_text(row_value(row, ["VendorName", "Vendor Name", "Vendor", "Vendor/Purchaser", "Charger Name", "Purchaser"]));
            description = clean_text(row_value(row, ["Description", "Charge Code", "Memo", "Notes"]));
            amount = clean_decimal(row_value(row, ["Amount", "Transaction Amount", "Cost", "Total"]));
            pm_comments = clean_text(row_value(row, ["PMComments", "PM Comments", "Project Manager Comments", "Comments"]));

            unique_key = expense_unique_key(project_name, tx_date, tx_type, vendor_name, amount, expense_id, pm_comments)
            cursor.execute(
                """
                SELECT TOP 1 ExpenseReviewItemId
                FROM dbo.ExpenseReviewItems
                WHERE ExpenseUniqueKey = ? AND COALESCE(IsDuplicate, 0) = 0;
                """,
                unique_key,
            )
            existing = cursor.fetchone()
            if existing:
                duplicate_count += 1
                continue

            match = choose_expense_match(project_name, vendor_name, amount, pm_comments, po_candidates)
            counts[match["status"]] = counts.get(match["status"], 0) + 1
            review_decision = "Matched to PO" if match["status"] == "Auto Matched" else "Pending Review"

            cursor.execute(
                """
                INSERT INTO dbo.ExpenseReviewItems
                    (ExpenseBatchId, SourceRowNumber, ExpenseId, ExpenseUniqueKey, ProjectName, TxDate, TxType, VendorName,
                     Description, Amount, PMComments, ExtractedPONumber, MatchedPONumber, MatchStatus,
                     MatchConfidence, MatchReason, ReviewDecision, CorrectPONumber)
                OUTPUT INSERTED.ExpenseReviewItemId
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                batch_id,
                index,
                expense_id,
                unique_key,
                project_name,
                tx_date,
                tx_type,
                vendor_name,
                description,
                amount,
                pm_comments,
                match["extracted_po"],
                match["matched_po"],
                match["status"],
                match["confidence"],
                match["reason"],
                review_decision,
                match["matched_po"] if match["status"] == "Auto Matched" else None,
            )
            new_item_id = cursor.fetchone().ExpenseReviewItemId
            if sync_expense_posting(cursor, new_item_id, posted_by=get_current_user()["email"] or "Manual Upload"):
                posted_count += 1
                posted_amount += Decimal(str(amount or 0))

        cursor.execute(
            """
            UPDATE dbo.ExpenseUploadBatches
            SET AutoMatchedCount = ?, NeedsReviewCount = ?, NoMatchCount = ?,
                DuplicateCount = ?, PostedCount = ?, PostedAmount = ?
            WHERE ExpenseBatchId = ?
            """,
            counts.get("Auto Matched", 0),
            counts.get("Needs Review", 0),
            counts.get("No Match", 0),
            duplicate_count,
            posted_count,
            posted_amount,
            batch_id,
        )
        conn.commit()
        return {"batch_id": batch_id, "total_rows": len(rows), "auto": counts.get("Auto Matched", 0), "review": counts.get("Needs Review", 0), "no_match": counts.get("No Match", 0), "duplicates": duplicate_count, "posted": posted_count, "posted_amount": posted_amount}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def load_expense_upload_page_data(status_filter="All"):
    ensure_expense_review_tables()
    conn = get_sql_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            COUNT(*) AS TotalRows,
            SUM(CASE WHEN MatchStatus = 'Auto Matched' THEN 1 ELSE 0 END) AS AutoMatched,
            SUM(CASE WHEN MatchStatus = 'Manually Matched' THEN 1 ELSE 0 END) AS ManuallyMatched,
            SUM(CASE WHEN MatchStatus = 'Needs Review' THEN 1 ELSE 0 END) AS NeedsReview,
            SUM(CASE WHEN MatchStatus = 'No Match' THEN 1 ELSE 0 END) AS NoMatch,
            SUM(CASE WHEN ReviewDecision IS NOT NULL AND ReviewDecision <> 'Pending Review' THEN 1 ELSE 0 END) AS ReviewedRows,
            SUM(CASE WHEN COALESCE(PostedToPO, 0) = 1 THEN 1 ELSE 0 END) AS PostedRows,
            SUM(CASE WHEN COALESCE(PostedToPO, 0) = 1 THEN COALESCE(PostedAmount, Amount, 0) ELSE 0 END) AS PostedAmount
        FROM dbo.ExpenseReviewItems;
        """
    )
    stats = cursor.fetchone()

    where = ""
    params = []
    if status_filter and status_filter != "All":
        where = "WHERE MatchStatus = ?"
        params.append(status_filter)

    cursor.execute(
        f"""
        SELECT TOP 250
            ExpenseReviewItemId, ExpenseBatchId, ExpenseId, ProjectName, TxDate, TxType, VendorName,
            Description, Amount, PMComments, ExtractedPONumber, MatchedPONumber, MatchStatus,
            MatchConfidence, MatchReason, ReviewDecision, CorrectPONumber, ReviewerNotes, PostedToPO, PostedPONumber, PostedAmount, CreatedAt, UpdatedAt
        FROM dbo.ExpenseReviewItems
        {where}
        ORDER BY CreatedAt DESC, ExpenseReviewItemId DESC;
        """,
        *params,
    )
    rows = cursor.fetchall()

    cursor.execute(
        """
        SELECT TOP 6 ExpenseBatchId, FileName, UploadedAt, UploadedBy, TotalRows,
               AutoMatchedCount, NeedsReviewCount, NoMatchCount, DuplicateCount, PostedCount, PostedAmount, ImportStatus
        FROM dbo.ExpenseUploadBatches
        ORDER BY UploadedAt DESC;
        """
    )
    batches = cursor.fetchall()

    cursor.execute("SELECT PONumber FROM dbo.PurchaseOrders ORDER BY PONumber;")
    po_numbers = [r.PONumber for r in cursor.fetchall() if r.PONumber]
    conn.close()
    return stats, rows, batches, po_numbers


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

    if status_lower in ["submitted", "under review", "needs more info"]:
        badge_class = "amber"
    elif status_lower in ["approved", "converted to po", "auto approved"]:
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
            SUM(CASE WHEN RequestStatus = 'Needs More Info' THEN 1 ELSE 0 END) AS NeedsMoreInfoRequests,
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
        "needs_more_info_requests": row.NeedsMoreInfoRequests or 0,
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


def create_purchase_request(form, files=None):
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

    estimated_purchase_date = clean_text(form.get("estimated_purchase_date"))
    requested_by = clean_text(form.get("requested_by"))
    business_justification = clean_text(form.get("business_justification"))
    payment_type = clean_text(form.get("payment_type"))
    selected_issued_items = clean_text(form.get("selected_issued_items"))
    other_items = clean_text(form.get("other_items"))
    quote_backup = clean_text(form.get("quote_backup"))

    if not request_title:
        raise ValueError("Request Title is required.")

    detail_parts = []
    if request_description:
        detail_parts.append("Description: " + request_description)
    if business_justification:
        detail_parts.append("Business Justification: " + business_justification)
    if estimated_purchase_date:
        detail_parts.append("Estimated Purchase Date: " + estimated_purchase_date)
    if payment_type:
        detail_parts.append("Payment Type: " + payment_type)
    if selected_issued_items:
        detail_parts.append("Selected Issued PO Items: " + selected_issued_items)
    if other_items:
        detail_parts.append("Other Items: " + other_items)
    if quote_backup:
        detail_parts.append("Quote / Backup: " + quote_backup)

    request_description = "\n\n".join(detail_parts) if detail_parts else request_description

    requested_by_name = requested_by or access["display_name"] or user["email"]

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
            requested_by_name,
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
        saved_attachments = save_purchase_request_attachments(cursor, purchase_request_id, request_number, files or [])
        conn.commit()

        return {
            "purchase_request_id": purchase_request_id,
            "request_number": request_number,
            "saved_attachments": saved_attachments,
        }

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def generate_app_po_number(cursor):
    today_prefix = datetime.utcnow().strftime("APP-PO-%Y%m%d")
    cursor.execute(
        """
        SELECT COUNT(*) AS POCount
        FROM dbo.PurchaseOrders
        WHERE PONumber LIKE ?;
        """,
        today_prefix + "-%",
    )
    row = cursor.fetchone()
    next_number = (row.POCount or 0) + 1
    while True:
        po_number = f"{today_prefix}-{next_number:04d}"
        cursor.execute("SELECT COUNT(*) AS ExistingCount FROM dbo.PurchaseOrders WHERE PONumber = ?", po_number)
        existing = cursor.fetchone()
        if not (existing.ExistingCount or 0):
            return po_number
        next_number += 1


def create_or_update_po_from_purchase_request(cursor, purchase_request_id, requested_po_number=None):
    cursor.execute(
        """
        SELECT
            PurchaseRequestId,
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
            ConvertedPONumber
        FROM dbo.PurchaseRequests
        WHERE PurchaseRequestId = ?;
        """,
        purchase_request_id,
    )
    req = cursor.fetchone()
    if not req:
        raise ValueError("Purchase request was not found.")

    po_number = clean_text(requested_po_number) or clean_text(req.ConvertedPONumber) or generate_app_po_number(cursor)
    vendor_name = clean_text(req.VendorName) or "Vendor TBD"
    project_name = clean_text(req.ProjectName) or "Project TBD"
    department = clean_text(req.Department)
    requestor = clean_text(req.RequestedByName) or clean_text(req.RequestedByEmail)
    amount = clean_decimal(req.EstimatedAmount)
    today = datetime.utcnow().date()

    vendor_id = get_or_create_vendor(cursor, vendor_name)
    project_id = get_or_create_project(cursor, project_name, department)

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
        VALUES (?, 'Purchase Request Auto PO', ?, 1, 1, 0, 'Complete');
        """,
        f"Auto-created from {clean_text(req.RequestNumber) or 'purchase request'}",
        get_current_user()["email"] or "Purchase Request Approval",
    )
    import_batch_id = cursor.fetchone().ImportBatchId

    purchase_order_id = upsert_purchase_order(
        cursor=cursor,
        po_number=po_number,
        vendor_id=vendor_id,
        project_id=project_id,
        department=department,
        requestor=requestor,
        po_date=today,
        po_status="Open",
        original_amount=amount,
        revised_amount=amount,
        remaining_amount=amount,
        import_batch_id=import_batch_id,
    )

    cursor.execute(
        """
        SELECT COUNT(*) AS LineCount
        FROM dbo.IssuedPOLines
        WHERE PONumber = ?;
        """,
        po_number,
    )
    line_count = cursor.fetchone().LineCount or 0
    if line_count == 0:
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
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', ?, 'LS', ?, 1, ?, ?, ?, ?, ?);
            """,
            purchase_order_id,
            import_batch_id,
            po_number,
            vendor_name,
            project_name,
            department,
            today,
            clean_text(req.RequestTitle) or clean_text(req.RequestDescription) or "Purchase request approved item",
            amount,
            amount,
            amount,
            amount,
            amount,
            requestor,
        )


    try:
        ensure_request_attachment_table(cursor)
        cursor.execute(
            """
            UPDATE dbo.PurchaseRequestAttachments
            SET PONumber = ?
            WHERE PurchaseRequestId = ?;
            """,
            po_number,
            purchase_request_id,
        )
    except Exception:
        pass

    return po_number


def update_purchase_request_status(form):
    user = get_current_user()

    purchase_request_id = clean_text(form.get("purchase_request_id"))
    request_status = clean_text(form.get("request_status"))
    reviewer_email = clean_text(form.get("reviewer_email")) or user["email"]
    review_notes = clean_text(form.get("review_notes"))
    converted_po_number = clean_text(form.get("converted_po_number"))

    valid_statuses = [
        "Submitted",
        "Under Review",
        "Needs More Info",
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
        if request_status in ["Approved", "Converted to PO"]:
            converted_po_number = create_or_update_po_from_purchase_request(cursor, purchase_request_id, converted_po_number)
            request_status = "Converted to PO"
            auto_note = f"Approved and auto-created PO {converted_po_number}."
            if review_notes:
                if auto_note not in review_notes:
                    review_notes = review_notes + "\n" + auto_note
            else:
                review_notes = auto_note
        else:
            converted_po_number = ""

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
            reviewer_email,
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


CE_LOGO_DATA_URI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAM8AAADSCAYAAADtyZQaAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAXraVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49J++7vycgaWQ9J1c1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCc/Pg0KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyI+DQoJPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4NCgkJPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6QXR0cmliPSJodHRwOi8vbnMuYXR0cmlidXRpb24uY29tL2Fkcy8xLjAvIj4NCgkJCTxBdHRyaWI6QWRzPg0KCQkJCTxyZGY6U2VxPg0KCQkJCQk8cmRmOmxpIHJkZjpwYXJzZVR5cGU9IlJlc291cmNlIj4NCgkJCQkJCTxBdHRyaWI6Q3JlYXRlZD4yMDI2LTA2LTAxPC9BdHRyaWI6Q3JlYXRlZD4NCgkJCQkJCTxBdHRyaWI6RGF0YT57ImRvYyI6IkRBRzVQOWE4dXdrIiwidXNlciI6IlVBRnQzeXZUMWxnIiwiYnJhbmQiOiJCQUZ0Mzk3bzJ2byJ9PC9BdHRyaWI6RGF0YT4NCgkJCQkJCTxBdHRyaWI6RXh0SWQ+OGNiZGQ2ZDYtZDIyZi00MTlhLTg0YTctZDNhYzU1ZGUzMDUwPC9BdHRyaWI6RXh0SWQ+DQoJCQkJCQk8QXR0cmliOkZiSWQ+NTI1MjY1OTE0MTc5NTgwPC9BdHRyaWI6RmJJZD4NCgkJCQkJCTxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+DQoJCQkJCTwvcmRmOmxpPg0KCQkJCTwvcmRmOlNlcT4NCgkJCTwvQXR0cmliOkFkcz4NCgkJPC9yZGY6RGVzY3JpcHRpb24+DQoJCTxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyI+DQoJ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"

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

.logo {
  width:54px;
  height:54px;
  border-radius:14px;
  display:grid;
  place-items:center;
  background:white;
  overflow:hidden;
  box-shadow:0 10px 18px rgba(0,0,0,.18);
  flex:0 0 auto;
}
.logo img {
  width:100%;
  height:100%;
  object-fit:contain;
  display:block;
}
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
.column-filter-row th {
  padding:6px 8px 10px;
  background:#f8fafc;
  position:sticky;
  top:0;
  z-index:2;
}
.column-filter-row input,
.column-filter-row select {
  width:100%;
  max-width:none;
  padding:7px 8px;
  border:1px solid var(--line);
  border-radius:9px;
  background:white;
  font-size:12px;
  text-transform:none;
  letter-spacing:normal;
  color:var(--text);
}
.filter-hint {
  display:flex;
  justify-content:space-between;
  gap:12px;
  flex-wrap:wrap;
  align-items:center;
  margin-bottom:12px;
  color:var(--muted);
  font-size:13px;
}
.filter-hint button {
  border:1px solid var(--line);
  background:white;
  border-radius:10px;
  padding:8px 10px;
  font-weight:800;
  cursor:pointer;
}
input[type=file], input[type=text], input[type=date], input[type=number], select, textarea { padding:12px; border:1px solid var(--line); border-radius:12px; background:white; width:100%; max-width:520px; font-family: inherit; }
textarea { min-height: 110px; resize: vertical; }
.notice { padding:13px 15px; border-radius:13px; font-weight:700; margin-bottom:16px; }
.notice.ok { background:#dcfce7; color:#166534; }
.notice.error { background:#fee2e2; color:#991b1b; }
code { background:#f1f5f9; padding:8px 10px; display:block; border-radius:12px; white-space:normal; }
@media (max-width: 1000px) { .sidebar { position:relative; width:100%; bottom:auto; } .main { margin-left:0; } .kpis, .two { grid-template-columns: 1fr; } }


/* Prototype-style purchase request page */
.page-hero {
  display:flex;
  gap:16px;
  align-items:center;
  margin-bottom:16px;
  padding:18px;
  border-radius:18px;
  border:1px solid rgba(226,232,240,.9);
  background:linear-gradient(135deg, rgba(22,163,74,.13), rgba(37,99,235,.10));
  box-shadow:var(--shadow);
}
.page-hero-icon {
  width:54px;
  height:54px;
  border-radius:16px;
  display:grid;
  place-items:center;
  color:white;
  font-size:26px;
  background:linear-gradient(135deg, #16a34a, #2563eb);
}
.page-hero h2 { margin:0 0 5px; font-size:24px; letter-spacing:-.03em; }
.page-hero p { margin:0; color:var(--muted); }
.form-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:14px; }
.form-field label { display:block; font-weight:800; font-size:12px; color:var(--muted); margin-bottom:7px; }
.form-field input, .form-field select, .form-field textarea { width:100%; max-width:none; border:1px solid var(--line); border-radius:11px; padding:11px; background:white; font-family:inherit; }
.form-field.full { grid-column:1 / -1; }
.form-field textarea { min-height:88px; resize:vertical; }
.request-actions { display:flex; gap:10px; justify-content:flex-end; margin-top:16px; flex-wrap:wrap; }
.workflow { display:grid; gap:0; }
.workflow-step { display:grid; grid-template-columns:44px 1fr; gap:12px; align-items:center; padding:10px; border:1px solid var(--line); border-radius:14px; background:#fff; }
.workflow-circle { width:36px; height:36px; border-radius:999px; display:grid; place-items:center; font-weight:900; color:white; background:#94a3b8; }
.workflow-step.done .workflow-circle { background:#16a34a; }
.workflow-step.active .workflow-circle { background:#2563eb; }
.workflow-step.warning .workflow-circle { background:#f59e0b; }
.workflow-step.info .workflow-circle { background:#7c3aed; }
.workflow-step.future .workflow-circle { background:#64748b; }
.workflow-text strong { display:block; font-size:14px; }
.workflow-text span { display:block; color:var(--muted); font-size:12px; margin-top:3px; }
.workflow-line { width:2px; height:16px; background:var(--line); margin-left:27px; }
.role-card { display:grid; gap:14px; }
.role-meta { display:flex; gap:12px; flex-wrap:wrap; color:var(--muted); font-size:13px; }
.role-meta span { background:#f8fafc; border:1px solid var(--line); border-radius:999px; padding:7px 10px; }
.issued-items-box { border:1px solid var(--line); border-radius:13px; background:#f8fafc; padding:10px; display:grid; gap:8px; }
.empty-issued-items { color:var(--muted); font-size:13px; padding:10px; }
.other-items-header, .other-item-row { display:grid; grid-template-columns:1fr 90px 130px 90px; gap:8px; align-items:center; }
.other-items-header { color:var(--muted); font-size:11px; font-weight:800; margin-bottom:6px; }
.other-items-box { display:grid; gap:8px; margin-bottom:10px; }
.other-item-row input { width:100%; max-width:none; border:1px solid var(--line); border-radius:10px; padding:9px; }
.match-summary { margin-top:14px; border:1px solid var(--line); background:#f8fafc; border-radius:14px; padding:13px; display:grid; gap:6px; font-size:13px; }
.match-summary strong { font-size:14px; }
.match-summary span { color:var(--muted); }
.form-field input[type="file"] { width:100%; border:1px dashed var(--line); border-radius:11px; padding:10px; background:#f8fafc; }
.validation-banner { background:#fff7ed; border:1px solid #fed7aa; color:#7c2d12; border-radius:13px; padding:12px 14px; margin:12px 0 14px; font-size:13px; }
.submit-status-box { border-radius:13px; padding:12px 14px; margin:0 0 16px; font-size:13px; }
.submit-status-box.success { background:#dcfce7; border:1px solid #bbf7d0; color:#166534; }
.submit-status-box.error { background:#fee2e2; border:1px solid #fecaca; color:#991b1b; }
@media (max-width:820px) { .form-grid, .issued-item-option, .other-items-header, .other-item-row { grid-template-columns:1fr; } }

/* Keep links visually consistent after click; no purple/gray visited-state shift */
a, a:visited { color:#1d4ed8; }
.sidebar a, .sidebar a:visited, a.button, a.button:visited, .button, .button:visited, .status-card, .status-card:visited, .action-card, .action-card:visited, .filter-chip, .filter-chip:visited, .status-pill-row a, .status-pill-row a:visited { color:inherit; }
.po-review-id .po-link, .po-review-id .po-link:visited { color:#1d4ed8; }


/* Consolidated dashboard and forecasting additions */
.action-card {
  display:block;
  text-decoration:none;
  color:inherit;
  border:1px solid var(--line);
  border-radius:16px;
  background:linear-gradient(180deg,#ffffff,#f8fafc);
  padding:16px;
  box-shadow:var(--shadow);
  transition:transform .15s ease, box-shadow .15s ease, border-color .15s ease;
}
.action-card:hover { transform:translateY(-2px); border-color:#93c5fd; box-shadow:0 18px 38px rgba(15,23,42,.12); }
.action-card .icon { width:42px; height:42px; border-radius:14px; display:grid; place-items:center; color:white; font-size:21px; margin-bottom:12px; }
.action-card.blue .icon { background:linear-gradient(135deg,#38bdf8,#2563eb); }
.action-card.green .icon { background:linear-gradient(135deg,#22c55e,#16a34a); }
.action-card.amber .icon { background:linear-gradient(135deg,#fbbf24,#f59e0b); }
.action-card.purple .icon { background:linear-gradient(135deg,#a78bfa,#7c3aed); }
.action-card.red .icon { background:linear-gradient(135deg,#fb7185,#dc2626); }
.action-card strong { display:block; font-size:15px; margin-bottom:4px; }
.action-card span { color:var(--muted); font-size:12px; line-height:1.35; }
.visual-chart-row { align-items:start; }
.mini-chart-card { background:white; border:1px solid var(--line); border-radius:var(--radius); box-shadow:var(--shadow); padding:18px; }
.mini-chart-card h4 { margin:0 0 14px; font-size:15px; }
.mini-bar-row { display:grid; grid-template-columns:155px 1fr 105px; gap:10px; align-items:center; margin:10px 0; font-size:12px; }
.mini-bar-row span { color:var(--text); font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.mini-bar-row div { height:12px; background:#e2e8f0; border-radius:99px; overflow:hidden; }
.mini-bar-row b { display:block; height:100%; border-radius:99px; background:linear-gradient(90deg,#93c5fd,#2563eb); }
.mini-bar-row em { font-style:normal; color:var(--muted); font-weight:800; text-align:right; }
.project-bucket-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; }
.project-bucket-item { background:#fff; border:1px solid var(--line); border-radius:16px; padding:14px; text-align:center; }
.project-bucket-item .bucket-label { font-size:12px; font-weight:900; margin-bottom:8px; }
.project-bucket-item.red .bucket-label { color:#dc2626; }
.project-bucket-item.orange .bucket-label { color:#f97316; }
.project-bucket-item.amber .bucket-label { color:#f59e0b; }
.project-bucket-item.lime .bucket-label { color:#65a30d; }
.project-bucket-item.green .bucket-label { color:#16a34a; }
.project-bucket-item .donut { width:96px; height:96px; margin:8px auto; border-radius:50%; display:grid; place-items:center; background:conic-gradient(#2563eb calc(var(--pct,0) * 1%), #e5e7eb 0); }
.project-bucket-item .donut > div { width:64px; height:64px; background:white; border-radius:50%; display:grid; place-items:center; line-height:1.05; }
.project-bucket-item .donut strong { display:block; font-size:20px; }
.project-bucket-item .donut span { display:block; font-size:10px; color:var(--muted); font-weight:800; }
.bucket-metric { display:flex; justify-content:space-between; gap:8px; border-top:1px solid var(--line); padding-top:8px; margin-top:8px; font-size:11px; color:var(--muted); }
.bucket-metric strong { color:var(--text); font-size:12px; }
.forecast-row { display:grid; grid-template-columns:repeat(7,minmax(0,1fr)); border:1px solid var(--line); border-radius:16px; overflow:hidden; }
.forecast-bucket { padding:14px; border-right:1px solid var(--line); min-height:145px; background:white; }
.forecast-bucket:last-child { border-right:none; }
.forecast-bucket strong { display:block; font-size:12px; }
.forecast-bucket .amount { color:#1d4ed8; font-size:19px; font-weight:900; margin-top:8px; }
.forecast-bucket .bucket-note { color:var(--muted); font-size:11px; margin-top:4px; }
.forecast-bucket .bars { display:flex; align-items:flex-end; height:54px; margin-top:14px; }
.forecast-bucket .bar { width:100%; min-height:7px; border-radius:6px 6px 0 0; background:linear-gradient(180deg,#93c5fd,#2563eb); }
.clickable-kpi { cursor:pointer; }
.filter-chip-row { display:flex; gap:8px; flex-wrap:wrap; margin:10px 0 14px; }
.filter-chip { border:1px solid var(--line); background:white; color:var(--text); border-radius:999px; padding:7px 10px; font-size:12px; font-weight:800; text-decoration:none; }
.filter-chip:hover { border-color:#93c5fd; }
.status-chip { border-radius:999px; padding:4px 8px; font-size:11px; font-weight:900; display:inline-flex; align-items:center; gap:4px; line-height:1.2; }
.status-chip.submitted, .status-chip.under-review, .status-chip.pending-approval { background:#fef3c7; color:#92400e; }
.status-chip.approved, .status-chip.converted-to-po, .status-chip.complete { background:#dcfce7; color:#166534; }
.status-chip.rejected, .status-chip.needs-info { background:#fee2e2; color:#991b1b; }
.status-chip.needs-payment-schedule { background:#ffedd5; color:#9a3412; }
.status-chip.assigned-to-pm { background:#dbeafe; color:#1e40af; }
.status-chip.in-progress { background:#ede9fe; color:#5b21b6; }
.status-chip.not-required { background:#e2e8f0; color:#334155; }
.status-chip.open { background:#ecfeff; color:#155e75; }
.status-chip.closed { background:#e2e8f0; color:#334155; }
.status-chip.default { background:#f1f5f9; color:#334155; }
@media (max-width:1200px) { .project-bucket-grid, .forecast-row { grid-template-columns:1fr 1fr; } .mini-bar-row { grid-template-columns:1fr; } }
@media (max-width:820px) { .project-bucket-grid, .forecast-row { grid-template-columns:1fr; } }


/* Mobile off-canvas navigation and phone-friendly layout */
.mobile-menu-button,
.mobile-nav-close,
.mobile-menu-overlay {
  display: none;
}

@media (max-width: 820px) {
  html, body {
    max-width: 100%;
    overflow-x: hidden;
  }

  body {
    display: block;
  }

  .mobile-menu-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    min-height: 44px;
    border: 1px solid var(--line);
    background: #ffffff;
    color: var(--text);
    border-radius: 12px;
    padding: 10px 13px;
    font-weight: 900;
    box-shadow: 0 8px 18px rgba(15, 23, 42, 0.08);
  }

  .mobile-nav-close {
    display: grid;
    place-items: center;
    position: absolute;
    top: 14px;
    right: 14px;
    width: 42px;
    height: 42px;
    border-radius: 12px;
    border: 1px solid rgba(255,255,255,.22);
    background: rgba(255,255,255,.08);
    color: #ffffff;
    font-size: 28px;
    line-height: 1;
    cursor: pointer;
  }

  .mobile-menu-overlay {
    display: block;
    position: fixed;
    inset: 0;
    background: rgba(2, 6, 23, 0.56);
    opacity: 0;
    pointer-events: none;
    transition: opacity .2s ease;
    z-index: 998;
  }

  body.mobile-nav-open .mobile-menu-overlay {
    opacity: 1;
    pointer-events: auto;
  }

  .sidebar {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    width: min(88vw, 330px);
    min-height: 100vh;
    z-index: 999;
    transform: translateX(-104%);
    transition: transform .22s ease;
    overflow-y: auto;
    padding: 22px 16px 18px;
    box-shadow: 18px 0 44px rgba(2, 6, 23, 0.35);
  }

  body.mobile-nav-open .sidebar {
    transform: translateX(0);
  }

  .brand {
    padding-right: 48px;
    margin-bottom: 18px;
  }

  .brand h1 {
    font-size: 16px;
  }

  .brand p {
    font-size: 11px;
  }

  .nav-section {
    margin-top: 14px;
  }

  .nav-item {
    min-height: 44px;
    font-size: 15px;
    margin: 5px 0;
  }

  .sync-card {
    margin-top: 18px;
  }

  .main {
    margin-left: 0;
    width: 100%;
    padding: 12px;
  }

  .topbar {
    position: sticky;
    top: 0;
    z-index: 20;
    background: rgba(245, 247, 251, 0.94);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(226, 232, 240, 0.85);
    border-radius: 16px;
    padding: 12px;
    margin-bottom: 12px;
    flex-direction: column;
    gap: 10px;
  }

  .topbar > div:first-of-type {
    width: 100%;
  }

  .topbar h2 {
    font-size: 22px;
    line-height: 1.12;
  }

  .topbar p {
    font-size: 13px;
    margin-top: 5px;
  }

  .top-actions {
    width: 100%;
    flex-direction: column;
    align-items: stretch;
    gap: 6px;
    font-size: 12px;
  }

  .grid,
  .grid.kpis,
  .grid.two,
  .grid.three,
  .grid.four,
  .two,
  .kpis,
  .form-grid,
  .project-bucket-grid,
  .forecast-row,
  .visual-chart-row {
    grid-template-columns: 1fr !important;
  }

  .card,
  .mini-chart-card,
  .action-card,
  .project-bucket-item,
  .forecast-bucket {
    padding: 14px;
    border-radius: 14px;
  }

  .card h3 {
    font-size: 15px;
    margin-bottom: 11px;
  }

  .card-subtitle {
    font-size: 12px;
  }

  .filterbar,
  .filters,
  .search-row,
  .request-actions,
  .role-buttons,
  .filter-chip-row {
    flex-direction: column;
    align-items: stretch;
  }

  .filters select,
  .filters input,
  .search-row input,
  .search-row select,
  .form-field input,
  .form-field select,
  .form-field textarea,
  button,
  .primary,
  .secondary,
  .filter-chip {
    width: 100%;
    min-width: 0;
    min-height: 44px;
    font-size: 15px;
  }

  .form-field textarea {
    min-height: 110px;
  }

  .table-wrap {
    width: 100%;
    max-width: 100%;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    border-radius: 14px;
  }

  .table-wrap table,
  table {
    min-width: 860px;
  }

  th, td {
    padding: 9px 8px;
    font-size: 12px;
  }

  .kpi {
    min-height: 105px;
  }

  .kpi .value {
    font-size: 23px;
  }

  .mini-bar-row,
  .bar-row,
  .waterfall-row,
  .approval-item,
  .detail-grid,
  .other-items-header,
  .other-item-row,
  .issued-item-option {
    grid-template-columns: 1fr !important;
  }

  .forecast-bucket {
    border-right: 0;
    border-bottom: 1px solid var(--line);
    min-height: 116px;
  }

  .forecast-bucket:last-child {
    border-bottom: 0;
  }

  .project-bucket-item .donut {
    width: 86px;
    height: 86px;
  }

  .bucket-metric {
    font-size: 12px;
  }

  .page-hero {
    grid-template-columns: 44px 1fr;
    padding: 14px;
  }

  .page-hero h2 {
    font-size: 20px;
  }

  .page-hero p {
    font-size: 12px;
  }
}


/* Feature phase: packets, dashboard cards, timelines, toasts, empty states */
.app-toast {
  position:fixed; right:24px; bottom:24px; z-index:2000;
  background:#020617; color:white; padding:13px 16px; border-radius:14px;
  box-shadow:0 16px 34px rgba(2,6,23,.25); opacity:0; transform:translateY(10px);
  pointer-events:none; transition:all .2s ease; font-weight:800; font-size:13px;
}
.app-toast.show { opacity:1; transform:translateY(0); }
.app-toast.error { background:#991b1b; }
.status-card-grid { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:14px; margin-bottom:18px; }
.status-card { text-decoration:none; color:inherit; display:block; background:#fff; border:1px solid var(--line); border-radius:16px; padding:16px; box-shadow:var(--shadow); transition:transform .15s ease, border-color .15s ease; }
.status-card:hover, .status-card.active { transform:translateY(-2px); border-color:#93c5fd; }
.status-card .label { color:var(--muted); font-size:12px; font-weight:900; }
.status-card .value { font-size:25px; font-weight:950; letter-spacing:-.04em; margin:6px 0; }
.status-card .trend { color:var(--muted); font-size:12px; }
.status-card.amber { border-top:4px solid #f59e0b; }
.status-card.green { border-top:4px solid #16a34a; }
.status-card.red { border-top:4px solid #dc2626; }
.status-card.blue { border-top:4px solid #2563eb; }
.status-card.purple { border-top:4px solid #7c3aed; }
.status-card.slate { border-top:4px solid #64748b; }
.empty-state { border:1px dashed #cbd5e1; background:#f8fafc; border-radius:16px; padding:24px; text-align:center; color:var(--muted); }
.empty-state strong { display:block; color:var(--text); font-size:16px; margin-bottom:4px; }
.timeline { border-left:3px solid #dbeafe; padding-left:16px; display:grid; gap:12px; margin-top:14px; }
.timeline-item { position:relative; background:#fff; border:1px solid var(--line); border-radius:14px; padding:12px; }
.timeline-item:before { content:''; position:absolute; left:-26px; top:14px; width:14px; height:14px; border-radius:50%; background:#2563eb; border:3px solid white; box-shadow:0 0 0 2px #bfdbfe; }
.timeline-item strong { display:block; font-size:13px; }
.timeline-item span { display:block; color:var(--muted); font-size:12px; margin-top:3px; }
.packet-header { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; border-bottom:2px solid #e2e8f0; padding-bottom:18px; margin-bottom:18px; }
.packet-logo { width:86px; height:86px; object-fit:contain; }
.packet-title h1 { margin:0; font-size:30px; letter-spacing:-.04em; }
.packet-title p { margin:6px 0 0; color:var(--muted); }
.packet-meta { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:18px 0; }
.packet-field { background:#f8fafc; border:1px solid var(--line); border-radius:13px; padding:12px; }
.packet-field span { display:block; color:var(--muted); font-size:11px; font-weight:900; text-transform:uppercase; letter-spacing:.05em; }
.packet-field strong { display:block; margin-top:5px; font-size:14px; }
.packet-actions { display:flex; gap:10px; justify-content:flex-end; margin-bottom:14px; }
.approval-action-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-top:14px; }
.approval-action-grid form { margin:0; }
.approval-action-grid button { width:100%; }
.setup-card-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; }
.setup-card { background:#fff; border:1px solid var(--line); border-radius:16px; box-shadow:var(--shadow); padding:16px; display:grid; gap:8px; }
.setup-card h4 { margin:0; font-size:15px; }
.setup-card .meta { color:var(--muted); font-size:12px; }
@media print {
  .sidebar, .topbar, .packet-actions, .mobile-menu-overlay, .app-toast { display:none !important; }
  .main { margin:0 !important; width:100% !important; padding:0 !important; }
  .card { box-shadow:none !important; border:0 !important; }
  body { background:white !important; }
}
@media (max-width:1200px) { .status-card-grid, .setup-card-grid, .packet-meta, .approval-action-grid { grid-template-columns:1fr 1fr; } }
@media (max-width:820px) { .status-card-grid, .setup-card-grid, .packet-meta, .approval-action-grid { grid-template-columns:1fr; } .packet-header { flex-direction:column; } }


/* Functional PO setup / missing information review */
.setup-table input, .setup-table select, .setup-table textarea { width:100%; min-width:150px; border:1px solid var(--line); border-radius:10px; padding:8px 9px; background:#fff; font-size:12px; }
.setup-table textarea { min-width:220px; min-height:58px; resize:vertical; }
.setup-table .po-number-cell { min-width:145px; font-weight:900; }
.po-review-id { display:grid; gap:8px; align-items:start; }
.po-review-id .po-link { font-size:15px; font-weight:950; color:#1d4ed8; text-decoration:underline; text-underline-offset:2px; }
.po-review-id .po-status-row { display:block; }
.po-review-id .status-chip { white-space:normal; text-align:left; max-width:120px; justify-content:center; }
.setup-table .payment-schedule-cell { min-width:520px; }
.setup-table .assign-cell { min-width:240px; }
.payment-schedule-builder { display:grid; gap:6px; }
.payment-schedule-row { display:grid; grid-template-columns:82px 128px 115px 1fr; gap:6px; align-items:center; }
.payment-row-label { color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.04em; }
.payment-schedule-row input { min-width:0; }
.payment-schedule-help { color:var(--muted); font-size:11px; line-height:1.35; }
.inline-actions { display:grid; gap:7px; min-width:110px; }
.inline-actions button { width:100%; padding:8px 9px; border-radius:9px; font-size:12px; }
.action-required-card { border-left:5px solid #f59e0b; }
.info-callout { background:#eff6ff; border:1px solid #bfdbfe; color:#1e3a8a; border-radius:16px; padding:14px 16px; margin-bottom:16px; }
.info-callout strong { display:block; margin-bottom:4px; }
.status-pill-row { display:flex; flex-wrap:wrap; gap:8px; margin:10px 0 0; }
.status-pill-row a { text-decoration:none; display:inline-flex; }
.status-pill-row a.active .status-chip { box-shadow:0 0 0 3px rgba(37,99,235,.15); }
.status-pill-row .status-chip.all { background:#e2e8f0; color:#334155; }
@media (max-width:820px) { .setup-table table { min-width:1550px; } .payment-schedule-row { grid-template-columns:1fr; } }


.project-filter-th { min-width:220px; }
.project-filter-head { display:flex; align-items:center; gap:8px; }
.project-filter-button {
  border:1px solid #cbd5e1;
  background:#f8fafc;
  color:#0f2e5c;
  border-radius:8px;
  width:28px;
  height:28px;
  display:inline-grid;
  place-items:center;
  cursor:pointer;
  font-size:13px;
}
.project-filter-button:hover { background:#eaf4ff; border-color:#93c5fd; }
.filter-icon { font-size:16px; line-height:1; transform:rotate(45deg); display:inline-block; }
.project-filter-select {
  display:none;
  margin-top:8px;
  width:100%;
  border:1px solid #cbd5e1;
  border-radius:10px;
  background:white;
  padding:8px 10px;
  min-height:38px;
  font-size:12px;
  text-transform:none;
  letter-spacing:0;
  color:#0f172a;
}
.project-filter-select.show { display:block; }


/* Expense upload / PO matching */
.expense-upload-layout { display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:start; margin-bottom:16px; }
.expense-review-table table { min-width:1500px; }
.expense-review-table .comments-cell { max-width:320px; white-space:normal; color:#334155; font-size:12px; line-height:1.35; }
.expense-review-table .match-reason-cell { max-width:280px; white-space:normal; color:#64748b; font-size:12px; line-height:1.35; }
.expense-review-table select, .expense-review-table input, .expense-review-table textarea { width:100%; border:1px solid var(--line); border-radius:10px; padding:8px 9px; background:#fff; font-size:12px; }
.expense-review-table textarea { min-height:58px; resize:vertical; }
.expense-action-cell { min-width:240px; }
.expense-match-form { display:grid; gap:7px; }
.expense-match-form button { width:100%; }
.expense-batch-list { display:grid; gap:8px; }
.expense-batch-item { border:1px solid var(--line); border-radius:13px; padding:10px; background:#f8fafc; display:grid; gap:3px; }
.expense-batch-item strong { font-size:13px; }
.expense-batch-item span { color:var(--muted); font-size:12px; }
.status-chip.auto-matched { background:#dcfce7; color:#166534; }
.status-chip.manually-matched { background:#dbeafe; color:#1e40af; }
.status-chip.needs-review { background:#fef3c7; color:#92400e; }
.status-chip.no-match { background:#fee2e2; color:#991b1b; }
.status-chip.no-po-needed { background:#e2e8f0; color:#334155; }
.status-chip.needs-pm-review { background:#ede9fe; color:#5b21b6; }
@media (max-width:1000px) { .expense-upload-layout { grid-template-columns:1fr; } }


.purchase-review-panel {
    display: grid;
    gap: 7px;
    min-width: 230px;
}
.purchase-review-panel label {
    color: var(--muted);
    font-size: 11px;
    font-weight: 900;
    text-transform: uppercase;
    letter-spacing: .04em;
}
.purchase-review-panel select,
.purchase-review-panel input,
.purchase-review-panel textarea {
    width: 100%;
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 8px 9px;
    background: #fff;
    font-size: 12px;
}
.purchase-review-panel textarea {
    min-height: 76px;
    resize: vertical;
}
.purchase-review-panel button {
    border: 0;
    background: var(--blue);
    color: #fff;
    border-radius: 10px;
    padding: 9px 10px;
    font-weight: 900;
    cursor: pointer;
}
.notice.info {
    background: #eff6ff;
    border-color: #bfdbfe;
    color: #1e3a8a;
}

.rollout-filter-bar { border:1px solid var(--line); border-radius:16px; background:#fff; padding:14px; margin:0 0 16px; box-shadow:var(--shadow); }
.rollout-filter-fields { display:grid; grid-template-columns:repeat(5, minmax(140px, 1fr)); gap:10px; }
.rollout-filter-fields label { display:grid; gap:5px; color:var(--muted); font-size:11px; font-weight:900; text-transform:uppercase; letter-spacing:.04em; }
.rollout-filter-fields input, .rollout-filter-fields select { border:1px solid var(--line); border-radius:10px; padding:9px 10px; background:#fff; color:var(--text); text-transform:none; letter-spacing:0; font-weight:600; }
.rollout-filter-actions { display:flex; gap:10px; justify-content:flex-end; margin-top:12px; flex-wrap:wrap; }
.data-freshness-banner { margin-bottom:16px; }
.posting-audit-cell { min-width:210px; font-size:12px; color:var(--muted); line-height:1.35; }
.status-chip.posted { background:#dcfce7; color:#166534; }
.status-chip.not-posted { background:#e2e8f0; color:#334155; }
.status-chip.duplicate { background:#fee2e2; color:#991b1b; }
.readiness-list { display:grid; gap:8px; margin-top:10px; }
.readiness-item { display:flex; justify-content:space-between; gap:12px; border:1px solid var(--line); border-radius:12px; padding:10px; background:#f8fafc; }
@media (max-width:1100px) { .rollout-filter-fields { grid-template-columns:repeat(2, minmax(0, 1fr)); } }
@media (max-width:760px) { .rollout-filter-fields { grid-template-columns:1fr; } }

/* Rollout-standard KPI cards: consistent top-page card design across pages */
.grid.kpis .card.kpi, .status-card-grid .status-card {
  border-top: 5px solid #2563eb;
  min-height: 122px;
}
.grid.kpis .card.kpi:nth-child(2), .status-card-grid .status-card.green { border-top-color:#16a34a; }
.grid.kpis .card.kpi:nth-child(3), .status-card-grid .status-card.amber { border-top-color:#f59e0b; }
.grid.kpis .card.kpi:nth-child(4), .status-card-grid .status-card.red { border-top-color:#dc2626; }
.grid.kpis .card.kpi:nth-child(5) { border-top-color:#7c3aed; }
.grid.kpis .card.kpi:nth-child(6) { border-top-color:#0ea5e9; }
.po-link { font-weight:900; color:#1d4ed8; text-decoration:underline; text-underline-offset:2px; }
.po-link:visited { color:#1d4ed8; }
.view-as-banner { margin-bottom:16px; background:#eef6ff; border:1px solid #bfdbfe; border-radius:14px; padding:12px 14px; color:#1e3a8a; }
.vendor-detail-link { font-weight:900; color:#1d4ed8; text-decoration:underline; }
.vendor-detail-link:visited { color:#1d4ed8; }

</style>
"""


def get_view_as_email():
    """Admin/Executive helper for viewing user-specific context while keeping the real admin/executive sidebar."""
    access = get_user_access()
    if access.get("role") not in ["Admin", "Executive"]:
        return ""
    return clean_text(request.cookies.get("PO_DASHBOARD_VIEW_AS")) or ""

def current_working_email():
    return get_view_as_email() or get_current_user().get("email") or ""



def lookup_dashboard_user_by_email(email):
    email = clean_text(email)
    if not email:
        return None
    try:
        conn = get_sql_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT TOP 1 Email, DisplayName, RoleName, IsActive
            FROM dbo.DashboardUsers
            WHERE LOWER(Email) = LOWER(?);
            """,
            email,
        )
        row = cursor.fetchone()
        conn.close()
        return row
    except Exception:
        return None


def current_data_role():
    view_email = get_view_as_email()
    if view_email:
        row = lookup_dashboard_user_by_email(view_email)
        if row and getattr(row, "IsActive", 0):
            return clean_text(row.RoleName) or "No Access"
    return get_user_access().get("role") or "No Access"


def current_data_email():
    return current_working_email()


def should_filter_pos_to_requestor():
    return current_data_role() == "Project Manager" and bool(current_data_email())


def requestor_filter_sql(alias):
    if should_filter_pos_to_requestor():
        return f"LOWER(COALESCE({alias}.Requestor, '')) = LOWER(?)", [current_data_email()]
    return "1=1", []


def allowed_attachment(filename):
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_ATTACHMENT_EXTENSIONS


def ensure_request_attachment_table(cursor):
    cursor.execute(
        """
        IF OBJECT_ID('dbo.PurchaseRequestAttachments', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.PurchaseRequestAttachments (
                AttachmentId INT IDENTITY(1,1) PRIMARY KEY,
                PurchaseRequestId INT NOT NULL,
                RequestNumber NVARCHAR(100) NULL,
                PONumber NVARCHAR(100) NULL,
                OriginalFileName NVARCHAR(260) NOT NULL,
                StoredFileName NVARCHAR(260) NOT NULL,
                StoragePath NVARCHAR(1000) NOT NULL,
                ContentType NVARCHAR(200) NULL,
                FileSize BIGINT NULL,
                UploadedBy NVARCHAR(255) NULL,
                UploadedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
            );
        END
        """
    )


def save_purchase_request_attachments(cursor, purchase_request_id, request_number, files):
    files = files or []
    saved = []
    if not files:
        return saved
    ensure_request_attachment_table(cursor)
    request_folder = secure_filename(str(request_number or purchase_request_id)) or str(purchase_request_id)
    target_dir = os.path.join(REQUEST_ATTACHMENT_ROOT, request_folder)
    os.makedirs(target_dir, exist_ok=True)
    user_email = get_current_user().get("email") or "Unknown"
    for uploaded in files:
        if not uploaded or not uploaded.filename:
            continue
        if not allowed_attachment(uploaded.filename):
            raise ValueError(f"Attachment type not allowed: {uploaded.filename}")
        original_name = uploaded.filename
        safe_name = secure_filename(original_name)
        stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        stored_name = f"{stamp}_{safe_name}"
        storage_path = os.path.join(target_dir, stored_name)
        uploaded.save(storage_path)
        file_size = os.path.getsize(storage_path) if os.path.exists(storage_path) else None
        cursor.execute(
            """
            INSERT INTO dbo.PurchaseRequestAttachments
                (PurchaseRequestId, RequestNumber, OriginalFileName, StoredFileName, StoragePath, ContentType, FileSize, UploadedBy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            purchase_request_id,
            request_number,
            original_name,
            stored_name,
            storage_path,
            uploaded.content_type,
            file_size,
            user_email,
        )
        saved.append(original_name)
    return saved


def load_po_attachments(po_number):
    po_number = clean_text(po_number)
    if not po_number:
        return []
    try:
        conn = get_sql_connection()
        cursor = conn.cursor()
        ensure_request_attachment_table(cursor)
        cursor.execute(
            """
            SELECT AttachmentId, RequestNumber, PONumber, OriginalFileName, ContentType, FileSize, UploadedBy, UploadedAt
            FROM dbo.PurchaseRequestAttachments
            WHERE PONumber = ?
            ORDER BY UploadedAt DESC, AttachmentId DESC;
            """,
            po_number,
        )
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def attachment_card(po_number):
    rows = load_po_attachments(po_number)
    table_rows = ""
    for r in rows:
        size = getattr(r, "FileSize", 0) or 0
        size_label = f"{size / 1024:.1f} KB" if size else ""
        table_rows += f"""
        <tr>
            <td><a class="po-link" href="/purchase-request-attachment/{r.AttachmentId}" target="_blank">{h(r.OriginalFileName)}</a></td>
            <td>{h(r.RequestNumber)}</td>
            <td>{h(r.ContentType or '')}</td>
            <td>{h(size_label)}</td>
            <td>{h(r.UploadedBy)}</td>
            <td>{h(r.UploadedAt)}</td>
        </tr>
        """
    if not table_rows:
        table_rows = '<tr><td colspan="6"><div class="empty-state"><strong>No quote or backup files linked.</strong><span>Files uploaded with the purchase request will appear here after the request is converted to a PO.</span></div></td></tr>'
    return f"""
    <div class="card">
        <h3>Quote / Backup Files</h3>
        <div class="table-wrap"><table><tr><th>File</th><th>Request</th><th>Type</th><th>Size</th><th>Uploaded By</th><th>Uploaded At</th></tr>{table_rows}</table></div>
    </div>
    """

def view_as_notice():
    view_email = get_view_as_email()
    if not view_email:
        return ""
    return f'<div class="view-as-banner"><strong>Viewing as:</strong> {h(view_email)} <a class="button secondary" href="/clear-view-as">Clear view-as</a></div>'


def shell(title, subtitle, active, content):
    access = get_user_access()
    role = access["role"]

    procurement_nav_items = [
        ("My Dashboard", "/my-dashboard", "🏠"),
        ("New Purchase Request", "/purchase-request", "📝"),
        ("Purchase Requests", "/purchase-requests", "📋"),
        ("POs & Balances", "/pos-balances", "💳"),
        ("Projects", "/projects", "📁"),
        ("PO Setup Review", "/project-po-setup", "🧭"),
    ]

    accounting_nav_items = [
        ("Upload Issued POs", "/upload-po", "⬆️"),
        ("Expense Upload / PO Matching", "/expense-upload", "🧾"),
        ("Expenses", "/expenses", "📄"),
        ("Missing PO Review", "/missing-po-review", "⚠️"),
        ("Vendors", "/vendors", "🏢"),
        # PM Comment PO Audit remains available by direct URL from reporting, but is hidden from main rollout navigation to reduce overlap.
        ("Import History", "/import-history", "🕘"),
        # Dormant for July 1 rollout: Exceptions and Exports hidden from main navigation.

    ]

    admin_nav_items = [
        ("User Access", "/user-access", "🔐"),
        ("Who Am I", "/whoami", "👤"),
    ]

    def build_nav_item(label, href, icon):
        active_class = " active" if active == label else ""
        return f'<a class="nav-item{active_class}" href="{href}"><span>{icon}</span>{h(label)}</a>'

    def build_nav_section(section_title, items):
        section_html = ""
        for label, href, icon in items:
            if role_can_access(role, label):
                section_html += build_nav_item(label, href, icon)
        if not section_html:
            return ""
        return f'<div class="nav-divider"></div><div class="nav-section">{h(section_title)}</div>' + section_html

    nav_sections = [
        build_nav_section("Procurement", procurement_nav_items),
        build_nav_section("Accounting", accounting_nav_items),
        build_nav_section("Admin", admin_nav_items),
    ]
    nav_html = "".join(section for section in nav_sections if section)
    if nav_html.startswith('<div class="nav-divider"></div>'):
        nav_html = nav_html.replace('<div class="nav-divider"></div>', '', 1)

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{h(title)}</title>
    {BRANDED_STYLE}
</head>
<body>
    <div class="mobile-menu-overlay" onclick="closeMobileMenu()" aria-hidden="true"></div>
    <aside class="sidebar" id="sidebarNav">
        <div class="brand">
            <div class="logo"><img src="{CE_LOGO_DATA_URI}" alt="Coastal Engineering logo"></div>
            <div>
                <h1>Coastal Engineering</h1>
                <p>Procurement App</p>
            </div>
        </div>
        <button type="button" class="mobile-nav-close" onclick="closeMobileMenu()" aria-label="Close menu">&times;</button>
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
            <button type="button" class="mobile-menu-button" onclick="toggleMobileMenu()" aria-label="Open menu">☰ Menu</button>
            <div>
                <h2>{h(title)}</h2>
                <p>{h(subtitle)}</p>
            </div>
            <div class="top-actions">
                <span>Role: {h(role)}</span>
                <span>Database: {h(SQL_DATABASE_NAME)}</span>
            </div>
        </header>

        {view_as_notice()}
        {content}
    </main>
    <div id="appToast" class="app-toast"></div>
    <script>
        function toggleMobileMenu() {{
            document.body.classList.toggle('mobile-nav-open');
        }}
        function closeMobileMenu() {{
            document.body.classList.remove('mobile-nav-open');
        }}
        document.addEventListener('keydown', function(event) {{
            if (event.key === 'Escape') closeMobileMenu();
        }});
        window.addEventListener('resize', function() {{
            if (window.innerWidth > 820) closeMobileMenu();
        }});
    </script>
</body>
</html>
"""



def status_chip(value):
    text = value or "Unknown"
    cls = str(text).lower().replace(" ", "-").replace("/", "-")
    allowed = {"all", "submitted", "under-review", "needs-more-info", "pending-approval", "approved", "converted-to-po", "rejected", "open", "closed", "needs-pm-info", "needs-forecast-date", "needs-payment-schedule", "assigned-to-pm", "in-progress", "needs-info", "complete", "not-required", "auto-matched", "manually-matched", "needs-review", "no-match", "no-po-needed", "needs-pm-review", "posted", "not-posted", "duplicate"}
    if cls not in allowed:
        cls = "default"
    return f'<span class="status-chip {cls}">{h(text)}</span>'


def percent(value):
    try:
        return "{:.1f}%".format(float(value or 0) * 100)
    except Exception:
        return "0.0%"


def build_simple_filter_bar(filters, action, fields):
    """Reusable rollout filter form for high-volume operational pages."""
    pieces = []
    for name, label, placeholder in fields:
        value = filters.get(name) or ""
        pieces.append(f'<label><span>{h(label)}</span><input name="{h(name)}" value="{h(value)}" placeholder="{h(placeholder)}"></label>')
    return (
        f'<form class="rollout-filter-bar" method="get" action="{h(action)}">'
        f'<div class="rollout-filter-fields">{"".join(pieces)}</div>'
        f'<div class="rollout-filter-actions"><button class="primary" type="submit">Apply Filters</button><a class="button secondary" href="{h(action)}">Clear</a></div>'
        f'</form>'
    )


def add_like_filter(where, params, column_sql, value):
    value = clean_text(value)
    if value:
        where.append(f"LOWER(COALESCE({column_sql}, '')) LIKE LOWER(?)")
        params.append(f"%{value}%")


def latest_data_freshness_banner():
    """Show users whether PO and expense data are current enough to trust."""
    po_bits = "PO upload: no upload found"
    expense_bits = "Expense upload: no upload found"
    try:
        conn = get_sql_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT TOP 1 FileName, UploadedAt, UploadedBy, TotalRows, SuccessCount, ErrorCount, ImportStatus
            FROM dbo.ImportBatches
            ORDER BY UploadedAt DESC;
        """)
        r = cursor.fetchone()
        if r:
            po_bits = f"PO upload: {h(r.FileName)} · {h(r.UploadedAt)} · {h(r.TotalRows)} rows · {h(r.ImportStatus)}"
        try:
            cursor.execute("""
                SELECT TOP 1 FileName, UploadedAt, UploadedBy, TotalRows, AutoMatchedCount, NeedsReviewCount, NoMatchCount, ImportStatus
                FROM dbo.ExpenseUploadBatches
                ORDER BY UploadedAt DESC;
            """)
            e = cursor.fetchone()
            if e:
                expense_bits = f"Expense upload: {h(e.FileName)} · {h(e.UploadedAt)} · {h(e.TotalRows)} rows · {h(e.ImportStatus)}"
        except Exception:
            pass
        conn.close()
    except Exception:
        pass
    return (
        f'<div class="notice info data-freshness-banner">'
        f'<strong>Data freshness:</strong> {po_bits}<br>{expense_bits}<br>'
        f'<small>Rollout balance method: current app balance equals issued PO amount minus posted matched expenses. The app does not write back to Unanet or the ERP.</small>'
        f'</div>'
    )


def posting_status_chip(row):
    posted = bool(getattr(row, "PostedToPO", 0))
    duplicate = bool(getattr(row, "IsDuplicate", 0))
    if posted:
        return status_chip("Posted")
    if duplicate:
        return status_chip("Duplicate")
    return status_chip("Not Posted")


def posting_reason(row):
    if bool(getattr(row, "PostedToPO", 0)):
        if (clean_text(getattr(row, "ReviewDecision", "")) or "") == "Matched to PO":
            return "Posted after manual review."
        return "Auto-posted from a valid PO match."
    if bool(getattr(row, "IsDuplicate", 0)):
        return "Not posted because this looks like a duplicate uploaded expense."
    decision = clean_text(getattr(row, "ReviewDecision", "")) or "Pending Review"
    if decision == "No PO Needed":
        return "Not posted because reviewer marked No PO Needed."
    if decision in ["Needs PM Review", "Hold for More Info", "Pending Review"]:
        return "Not posted because review is not final."
    if not (clean_text(getattr(row, "CorrectPONumber", "")) or clean_text(getattr(row, "MatchedPONumber", "")) or clean_text(getattr(row, "ExtractedPONumber", ""))):
        return "Not posted because no valid PO number is linked."
    return "Not posted because posting rules were not met."


def load_pos_balances_data():
    ensure_expense_review_tables()
    conn = get_sql_connection()
    cursor = conn.cursor()
    req_where, req_params = requestor_filter_sql("l")

    posted_cte = """
        PostedExpenses AS (
            SELECT
                PostedPONumber AS PONumber,
                SUM(COALESCE(PostedAmount, Amount, 0)) AS PostedExpenseAmount,
                COUNT(*) AS PostedExpenseCount
            FROM dbo.ExpenseReviewItems
            WHERE COALESCE(PostedToPO, 0) = 1 AND COALESCE(PostedPONumber, '') <> ''
            GROUP BY PostedPONumber
        )
    """

    unique_po_cte = f"""
        WITH LinePOs AS (
            SELECT
                PONumber,
                MAX(VendorName) AS VendorName,
                MAX(ProjectName) AS ProjectName,
                MAX(Department) AS Department,
                MAX(POStatus) AS POStatus,
                MAX(PODate) AS PODate,
                MAX(COALESCE(RevisedAmount, OriginalAmount, 0)) AS POValue,
                SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount,
                MAX(COALESCE(RemainingAmount, 0)) AS UploadedRemainingAmount,
                COUNT(*) AS LineCount
            FROM dbo.IssuedPOLines
            GROUP BY PONumber
        ),
        {posted_cte},
        UniquePOs AS (
            SELECT
                l.*,
                COALESCE(pe.PostedExpenseAmount, 0) AS PostedExpenseAmount,
                COALESCE(pe.PostedExpenseCount, 0) AS PostedExpenseCount,
                CASE
                    WHEN COALESCE(l.POValue, 0) - COALESCE(pe.PostedExpenseAmount, 0) < 0 THEN 0
                    ELSE COALESCE(l.POValue, 0) - COALESCE(pe.PostedExpenseAmount, 0)
                END AS CurrentAppBalance
            FROM LinePOs l
            LEFT JOIN PostedExpenses pe ON pe.PONumber = l.PONumber
        )
    """

    cursor.execute(
        unique_po_cte + """
        SELECT
            COUNT(*) AS TotalPOs,
            SUM(CASE WHEN UPPER(COALESCE(POStatus, '')) = 'OPEN' THEN 1 ELSE 0 END) AS OpenPOs,
            SUM(POValue) AS TotalPOValue,
            SUM(TotalLineAmount) AS TotalLineAmount,
            SUM(UploadedRemainingAmount) AS UploadedRemainingAmount,
            SUM(PostedExpenseAmount) AS PostedExpenseAmount,
            SUM(CurrentAppBalance) AS TotalRemainingAmount,
            SUM(CASE WHEN ABS(COALESCE(POValue, 0) - COALESCE(TotalLineAmount, 0)) > 0.01 THEN 1 ELSE 0 END) AS AmountMismatchCount
        FROM UniquePOs;
        """,
        *req_params,
    )
    row = cursor.fetchone()
    overall = {
        "total_pos": row.TotalPOs or 0,
        "open_pos": row.OpenPOs or 0,
        "total_po_value": row.TotalPOValue or 0,
        "total_line_amount": row.TotalLineAmount or 0,
        "uploaded_remaining_amount": getattr(row, "UploadedRemainingAmount", 0) or 0,
        "posted_expense_amount": getattr(row, "PostedExpenseAmount", 0) or 0,
        "total_remaining_amount": row.TotalRemainingAmount or 0,
        "amount_mismatch_count": row.AmountMismatchCount or 0,
    }

    cursor.execute(
        unique_po_cte + """
        SELECT
            ProjectName,
            COUNT(*) AS POCount,
            SUM(POValue) AS POValue,
            SUM(TotalLineAmount) AS TotalLineAmount,
            SUM(UploadedRemainingAmount) AS UploadedRemainingAmount,
            SUM(PostedExpenseAmount) AS PostedExpenseAmount,
            SUM(CurrentAppBalance) AS RemainingAmount,
            CASE WHEN SUM(POValue) = 0 THEN 0 ELSE SUM(CurrentAppBalance) / SUM(POValue) END AS PercentOpen
        FROM UniquePOs
        GROUP BY ProjectName
        ORDER BY POValue DESC;
        """,
        *req_params,
    )
    projects = cursor.fetchall()

    cursor.execute(
        unique_po_cte + """
        SELECT TOP 10
            VendorName,
            COUNT(*) AS POCount,
            SUM(POValue) AS POValue,
            SUM(TotalLineAmount) AS TotalLineAmount,
            SUM(UploadedRemainingAmount) AS UploadedRemainingAmount,
            SUM(PostedExpenseAmount) AS PostedExpenseAmount,
            SUM(CurrentAppBalance) AS RemainingAmount
        FROM UniquePOs
        GROUP BY VendorName
        ORDER BY POValue DESC;
        """,
        *req_params,
    )
    vendors = cursor.fetchall()

    cursor.execute(
        unique_po_cte + """
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
            UploadedRemainingAmount,
            PostedExpenseAmount,
            PostedExpenseCount,
            CurrentAppBalance AS RemainingAmount,
            CASE WHEN ABS(COALESCE(POValue, 0) - COALESCE(TotalLineAmount, 0)) > 0.01 THEN 1 ELSE 0 END AS AmountMismatch
        FROM UniquePOs
        ORDER BY PODate DESC, PONumber DESC;
        """,
        *req_params,
    )
    pos = cursor.fetchall()

    cursor.execute(
        """
        SELECT TOP 200
            PONumber,
            VendorName,
            ProjectName,
            Department,
            LineDescription,
            Unit,
            UnitCost,
            Qty,
            LineAmount,
            RemainingAmount
        FROM dbo.IssuedPOLines l
        WHERE {req_where}
        ORDER BY CreatedAt DESC, IssuedPOLineId DESC;
        """.format(req_where=req_where),
        *req_params,
    )
    lines = cursor.fetchall()
    conn.close()

    return {
        "overall": overall,
        "projects": projects,
        "vendors": vendors,
        "pos": pos,
        "lines": lines,
    }

def open_balance_bucket_rows(projects):
    definitions = [
        ("Less than 20%", float("-inf"), 0.20, "red"),
        ("20% - 40%", 0.20, 0.40, "orange"),
        ("40% - 60%", 0.40, 0.60, "amber"),
        ("60% - 80%", 0.60, 0.80, "lime"),
        ("80% - 100%", 0.80, float("inf"), "green"),
    ]
    rows = []
    for label, min_value, max_value, tone in definitions:
        rows.append({"label": label, "min": min_value, "max": max_value, "tone": tone, "projects": 0, "open": Decimal("0"), "issued": Decimal("0")})

    for p in projects:
        pct_open = float(p.PercentOpen or 0)
        for bucket in rows:
            if pct_open >= bucket["min"] and pct_open < bucket["max"]:
                bucket["projects"] += 1
                bucket["open"] += Decimal(str(p.RemainingAmount or 0))
                bucket["issued"] += Decimal(str(p.POValue or 0))
                break
    return rows


def render_open_balance_buckets(projects):
    buckets = open_balance_bucket_rows(projects)
    total_projects = sum(b["projects"] for b in buckets) or 1
    html_parts = []
    for bucket in buckets:
        pct_value = min(100, max(0, (bucket["projects"] / total_projects) * 100))
        html_parts.append(f"""
        <div class="project-bucket-item {h(bucket['tone'])}">
            <div class="bucket-label">{h(bucket['label'])}</div>
            <div class="donut" style="--pct:{pct_value};"><div><strong>{bucket['projects']}</strong><span>Projects</span></div></div>
            <div class="bucket-metric"><span>Open Balance</span><strong>{currency(bucket['open'])}</strong></div>
            <div class="bucket-metric"><span>Issued PO</span><strong>{currency(bucket['issued'])}</strong></div>
        </div>
        """)
    return "".join(html_parts)



def parse_payment_schedule_for_forecast(payment_schedule, total_amount):
    """Return dated payment schedule entries from PO Info Review.

    The PO Info Review form saves one line per payment. Lines may be as simple
    as a date, or they may include an amount/percent and a note, separated by
    dashes or other text. If payment dates exist but no amounts are entered,
    the open PO amount is allocated evenly across the dated rows so Forecasting
    bucket totals move with the schedule.
    """
    text = str(payment_schedule or "").strip()
    if not text:
        return []

    total = Decimal(str(total_amount or 0))
    entries = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        date_match = re.search(r"(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{2,4})", line)
        schedule_date = clean_date(date_match.group(1)) if date_match else None
        if not schedule_date:
            continue

        # Remove the date from the line before looking for an amount so we do
        # not accidentally treat the year/month/day as the payment amount.
        amount_source = line
        if date_match:
            amount_source = (line[:date_match.start()] + " " + line[date_match.end():]).strip()

        schedule_amount = None
        percent_match = re.search(r"(\d+(?:\.\d+)?)\s*%", amount_source)
        if percent_match:
            try:
                schedule_amount = total * Decimal(percent_match.group(1)) / Decimal("100")
            except Exception:
                schedule_amount = None
        else:
            # Prefer explicit currency-like amounts after the date. This handles
            # entries such as "2026-07-01 - $10,000 - Deposit".
            money_matches = re.findall(r"\$?\s*(\d{1,3}(?:,\d{3})*(?:\.\d+)?|\d+(?:\.\d+)?)", amount_source)
            if money_matches:
                # Avoid tiny row labels like "1" or "2" when a real amount is present.
                candidates = []
                for m in money_matches:
                    val = clean_decimal(m)
                    if val is not None:
                        candidates.append(val)
                larger = [v for v in candidates if abs(v) >= Decimal("10")]
                if larger:
                    schedule_amount = larger[-1]
                elif candidates:
                    schedule_amount = candidates[-1]

        entries.append({
            "date": schedule_date,
            "amount": schedule_amount,
            "description": line,
        })

    if not entries:
        return []

    unspecified = [entry for entry in entries if entry["amount"] is None]
    assigned_total = sum((entry["amount"] or Decimal("0")) for entry in entries)

    if unspecified:
        remaining = total - assigned_total
        if remaining < 0:
            remaining = Decimal("0")
        even_amount = remaining / Decimal(len(unspecified)) if total else Decimal("0")
        for entry in unspecified:
            entry["amount"] = even_amount

    return entries

def load_forecast_data():
    conn = get_sql_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            RequestNumber AS SourceId,
            'Purchase Request' AS SourceType,
            ProjectName,
            VendorName,
            NeededByDate AS ForecastDate,
            RequestStatus AS Status,
            Priority,
            EstimatedAmount AS Amount,
            RequestTitle AS Description
        FROM dbo.PurchaseRequests
        WHERE EstimatedAmount IS NOT NULL
        ORDER BY NeededByDate ASC, RequestedAt DESC;
        """
    )
    request_rows = cursor.fetchall()

    ensure_po_setup_columns(cursor)
    conn.commit()

    cursor.execute(
        """
        SELECT
            po.PONumber AS SourceId,
            'Open PO Balance' AS SourceType,
            pr.ProjectName,
            v.VendorName,
            po.ExpectedPaymentDate AS ForecastDate,
            po.PaymentType,
            po.PaymentSchedule,
            COALESCE(NULLIF(po.SetupStatus, ''), po.POStatus) AS Status,
            NULL AS Priority,
            COALESCE(
                NULLIF(po.RemainingAmount, 0),
                NULLIF(po.RevisedAmount, 0),
                NULLIF(po.OriginalAmount, 0),
                NULLIF(lines.TotalLineAmount, 0),
                0
            ) AS Amount,
            COALESCE(lines.TotalLineAmount, 0) AS TotalLineAmount,
            CASE
                WHEN COALESCE(po.PaymentSchedule, '') <> '' THEN po.PaymentSchedule
                WHEN po.ExpectedPaymentDate IS NULL THEN 'Open PO balance without expected payment date'
                ELSE 'Open PO balance with expected payment date'
            END AS Description
        FROM dbo.PurchaseOrders po
        LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
        LEFT JOIN dbo.Projects pr ON po.ProjectId = pr.ProjectId
        LEFT JOIN (
            SELECT PONumber, SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount
            FROM dbo.IssuedPOLines
            GROUP BY PONumber
        ) lines ON lines.PONumber = po.PONumber
        WHERE COALESCE(
                NULLIF(po.RemainingAmount, 0),
                NULLIF(po.RevisedAmount, 0),
                NULLIF(po.OriginalAmount, 0),
                NULLIF(lines.TotalLineAmount, 0),
                0
            ) > 0
        ORDER BY
            CASE WHEN po.ExpectedPaymentDate IS NULL AND COALESCE(po.PaymentSchedule, '') = '' THEN 1 ELSE 0 END,
            po.ExpectedPaymentDate ASC,
            COALESCE(
                NULLIF(po.RemainingAmount, 0),
                NULLIF(po.RevisedAmount, 0),
                NULLIF(po.OriginalAmount, 0),
                NULLIF(lines.TotalLineAmount, 0),
                0
            ) DESC;
        """
    )
    po_rows = cursor.fetchall()
    conn.close()

    items = []

    for row in request_rows:
        forecast_date = getattr(row, "ForecastDate", None)
        bucket = forecast_bucket(forecast_date)
        items.append({
            "source_id": row.SourceId,
            "source_type": row.SourceType,
            "project": row.ProjectName,
            "vendor": row.VendorName,
            "forecast_date": forecast_date,
            "status": row.Status,
            "priority": row.Priority,
            "amount": row.Amount or 0,
            "description": row.Description,
            "bucket": bucket,
        })

    for row in po_rows:
        po_amount = Decimal(str(row.Amount or 0))
        schedule_entries = parse_payment_schedule_for_forecast(getattr(row, "PaymentSchedule", ""), po_amount)

        if schedule_entries:
            for idx, entry in enumerate(schedule_entries, start=1):
                forecast_date = entry["date"]
                bucket = forecast_bucket(forecast_date)
                items.append({
                    "source_id": f"{row.SourceId} Pmt {idx}",
                    "source_type": "Scheduled PO Payment",
                    "project": row.ProjectName,
                    "vendor": row.VendorName,
                    "forecast_date": forecast_date,
                    "status": row.Status,
                    "priority": row.Priority,
                    "amount": entry["amount"] or Decimal("0"),
                    "description": entry["description"],
                    "bucket": bucket,
                })
        else:
            forecast_date = getattr(row, "ForecastDate", None)
            bucket = forecast_bucket(forecast_date)
            items.append({
                "source_id": row.SourceId,
                "source_type": row.SourceType,
                "project": row.ProjectName,
                "vendor": row.VendorName,
                "forecast_date": forecast_date,
                "status": row.Status,
                "priority": row.Priority,
                "amount": row.Amount or 0,
                "description": row.Description,
                "bucket": bucket,
            })

    return items


def forecast_bucket(forecast_date):
    if not forecast_date:
        return "Unscheduled"
    if isinstance(forecast_date, datetime):
        forecast_date = forecast_date.date()
    today = date.today()
    delta = (forecast_date - today).days
    if delta < 0:
        return "Past Due"
    if delta <= 7:
        return "Next 7 Days"
    if delta <= 14:
        return "8-14 Days"
    if delta <= 30:
        return "15-30 Days"
    if delta <= 60:
        return "31-60 Days"
    if delta <= 90:
        return "61-90 Days"
    return "90+ Days"


def forecast_bucket_summary(items):
    labels = ["Past Due", "Next 7 Days", "8-14 Days", "15-30 Days", "31-60 Days", "61-90 Days", "90+ Days", "Unscheduled"]
    summary = {label: {"count": 0, "amount": Decimal("0")} for label in labels}
    for item in items:
        label = item["bucket"]
        if label not in summary:
            summary[label] = {"count": 0, "amount": Decimal("0")}
        summary[label]["count"] += 1
        summary[label]["amount"] += Decimal(str(item["amount"] or 0))
    return [(label, summary[label]["count"], summary[label]["amount"]) for label in labels]


def aggregate_items(items, key_name):
    buckets = {}
    for item in items:
        key = item.get(key_name) or "Unassigned"
        if key not in buckets:
            buckets[key] = {"count": 0, "amount": Decimal("0"), "next_date": None}
        buckets[key]["count"] += 1
        buckets[key]["amount"] += Decimal(str(item["amount"] or 0))
        fd = item.get("forecast_date")
        if fd and (buckets[key]["next_date"] is None or fd < buckets[key]["next_date"]):
            buckets[key]["next_date"] = fd
    return sorted(buckets.items(), key=lambda x: x[1]["amount"], reverse=True)


# ------------------------------------------------------------
# Feature phase helpers: PO packets and project setup
# ------------------------------------------------------------

def render_payment_schedule_for_packet(payment_schedule):
    lines = [line.strip() for line in str(payment_schedule or "").splitlines() if line.strip()]
    if not lines:
        return '<div class="empty-state"><strong>No payment schedule entered.</strong><span>Use PO Setup Review to add expected payment dates and schedule details.</span></div>'
    items = "".join(f'<div class="timeline-item"><strong>Payment {idx}</strong><span>{h(line)}</span></div>' for idx, line in enumerate(lines, start=1))
    return f'<div class="timeline">{items}</div>'


def load_po_packet_data(po_number):
    conn = get_sql_connection()
    cursor = conn.cursor()
    req_where, req_params = requestor_filter_sql("po")
    line_req_where, line_req_params = requestor_filter_sql("IssuedPOLines")
    ensure_po_setup_columns(cursor)
    conn.commit()
    cursor.execute(
        """
        SELECT
            po.PONumber,
            v.VendorName,
            pr.ProjectName,
            po.Department,
            po.POStatus,
            po.PODate,
            po.Requestor,
            COALESCE(po.RevisedAmount, po.OriginalAmount, 0) AS POValue,
            COALESCE(lines.TotalLineAmount, COALESCE(po.RevisedAmount, po.OriginalAmount, 0)) AS TotalLineAmount,
            COALESCE(posted.PostedExpenseAmount, 0) AS PostedExpenseAmount,
            COALESCE(posted.PostedExpenseCount, 0) AS PostedExpenseCount,
            CASE WHEN COALESCE(po.RevisedAmount, po.OriginalAmount, 0) - COALESCE(posted.PostedExpenseAmount, 0) < 0 THEN 0 ELSE COALESCE(po.RevisedAmount, po.OriginalAmount, 0) - COALESCE(posted.PostedExpenseAmount, 0) END AS RemainingAmount,
            COALESCE(lines.LineCount, 0) AS LineCount,
            po.PaymentType,
            po.ExpectedPaymentDate,
            po.PaymentSchedule,
            po.SetupStatus,
            po.SetupAssignedTo,
            po.SetupUpdatedBy,
            po.SetupUpdatedAt
        FROM dbo.PurchaseOrders po
        LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
        LEFT JOIN dbo.Projects pr ON po.ProjectId = pr.ProjectId
        LEFT JOIN (
            SELECT PONumber, SUM(COALESCE(LineAmount, 0)) AS TotalLineAmount, COUNT(*) AS LineCount
            FROM dbo.IssuedPOLines
            WHERE PONumber = ? AND {line_req_where}
            GROUP BY PONumber
        ) lines ON lines.PONumber = po.PONumber
        LEFT JOIN (
            SELECT PostedPONumber, SUM(COALESCE(PostedAmount, Amount, 0)) AS PostedExpenseAmount, COUNT(*) AS PostedExpenseCount
            FROM dbo.ExpenseReviewItems
            WHERE COALESCE(PostedToPO, 0) = 1 AND PostedPONumber = ?
            GROUP BY PostedPONumber
        ) posted ON posted.PostedPONumber = po.PONumber
        WHERE po.PONumber = ? AND {req_where};
        """.format(line_req_where=line_req_where, req_where=req_where),
        po_number,
        *line_req_params,
        po_number,
        po_number,
        *req_params,
    )
    po = cursor.fetchone()
    cursor.execute(
        """
        SELECT
            LineDescription,
            Unit,
            UnitCost,
            Qty,
            LineAmount,
            RemainingAmount,
            CreatedAt
        FROM dbo.IssuedPOLines
        WHERE PONumber = ? AND {line_req_where}
        ORDER BY IssuedPOLineId;
        """.format(line_req_where=line_req_where),
        po_number,
        *line_req_params,
    )
    lines = cursor.fetchall()
    cursor.execute(
        """
        SELECT TOP 200 ExpenseReviewItemId, ExpenseId, TxDate, TxType, VendorName, Description,
               Amount, PostedAmount, PostedAt, PostedBy, ReviewDecision, ReviewerEmail, PMComments
        FROM dbo.ExpenseReviewItems
        WHERE COALESCE(PostedToPO, 0) = 1 AND PostedPONumber = ?
        ORDER BY COALESCE(PostedAt, UpdatedAt) DESC, ExpenseReviewItemId DESC;
        """,
        po_number,
    )
    posted_expenses = cursor.fetchall()
    conn.close()
    return po, lines, posted_expenses


def ensure_po_setup_columns(cursor):
    setup_columns = [
        ("PaymentType", "NVARCHAR(100) NULL"),
        ("ExpectedPaymentDate", "DATE NULL"),
        ("PaymentSchedule", "NVARCHAR(MAX) NULL"),
        ("SetupStatus", "NVARCHAR(100) NULL"),
        ("SetupAssignedTo", "NVARCHAR(255) NULL"),
        ("SetupNotes", "NVARCHAR(MAX) NULL"),
        ("SetupUpdatedBy", "NVARCHAR(255) NULL"),
        ("SetupUpdatedAt", "DATETIME2 NULL"),
    ]
    for column_name, column_type in setup_columns:
        cursor.execute(
            f"""
            IF COL_LENGTH('dbo.PurchaseOrders', '{column_name}') IS NULL
            BEGIN
                ALTER TABLE dbo.PurchaseOrders ADD {column_name} {column_type};
            END
            """
        )


def load_project_po_setup_items(status_filter=None, assigned_filter=None):
    conn = get_sql_connection()
    cursor = conn.cursor()
    ensure_po_setup_columns(cursor)
    conn.commit()

    where_clauses = []
    params = []
    req_where, req_params = requestor_filter_sql("po")
    if req_where != "1=1":
        where_clauses.append(req_where)
        params.extend(req_params)

    if status_filter and status_filter != "All":
        where_clauses.append("COALESCE(NULLIF(po.SetupStatus, ''), CASE WHEN COALESCE(po.PaymentSchedule, '') = '' THEN 'Needs Payment Schedule' ELSE 'Complete' END) = ?")
        params.append(status_filter)

    if assigned_filter:
        where_clauses.append("LOWER(COALESCE(po.SetupAssignedTo, '')) = LOWER(?)")
        params.append(assigned_filter)

    if not where_clauses:
        where_clauses.append("(COALESCE(NULLIF(po.SetupStatus, ''), CASE WHEN COALESCE(po.PaymentSchedule, '') = '' THEN 'Needs Payment Schedule' ELSE 'Complete' END) <> 'Complete' OR COALESCE(po.PaymentSchedule, '') = '' OR COALESCE(po.PaymentType, '') = '' OR po.ExpectedPaymentDate IS NULL OR COALESCE(v.VendorName, '') = '')")

    where_sql = " AND ".join(where_clauses)

    cursor.execute(
        f"""
        SELECT TOP 250
            po.PurchaseOrderId,
            po.PONumber,
            v.VendorName,
            pr.ProjectName,
            po.Department,
            po.POStatus,
            po.PODate,
            po.Requestor,
            COALESCE(po.RevisedAmount, po.OriginalAmount, 0) AS POValue,
            po.RemainingAmount,
            po.PaymentType,
            po.ExpectedPaymentDate,
            po.PaymentSchedule,
            COALESCE(NULLIF(po.SetupStatus, ''), CASE WHEN COALESCE(po.PaymentSchedule, '') = '' THEN 'Needs Payment Schedule' ELSE 'Complete' END) AS SetupStatus,
            po.SetupAssignedTo,
            po.SetupNotes,
            po.SetupUpdatedBy,
            po.SetupUpdatedAt,
            CASE WHEN COALESCE(po.PaymentSchedule, '') = '' THEN 1 ELSE 0 END AS MissingPaymentSchedule,
            CASE WHEN COALESCE(po.PaymentType, '') = '' THEN 1 ELSE 0 END AS MissingPaymentType,
            CASE WHEN po.ExpectedPaymentDate IS NULL THEN 1 ELSE 0 END AS MissingExpectedPaymentDate,
            CASE WHEN COALESCE(v.VendorName, '') = '' THEN 1 ELSE 0 END AS MissingVendor
        FROM dbo.PurchaseOrders po
        LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
        LEFT JOIN dbo.Projects pr ON po.ProjectId = pr.ProjectId
        WHERE {where_sql}
        ORDER BY
            CASE COALESCE(NULLIF(po.SetupStatus, ''), CASE WHEN COALESCE(po.PaymentSchedule, '') = '' THEN 'Needs Payment Schedule' ELSE 'Complete' END)
                WHEN 'Needs Payment Schedule' THEN 0
                WHEN 'Assigned to PM' THEN 1
                WHEN 'In Progress' THEN 2
                WHEN 'Needs Info' THEN 3
                ELSE 4
            END,
            pr.ProjectName,
            po.PONumber;
        """,
        *params,
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def count_po_setup_actions_for_current_user():
    user = get_current_user()
    view_email = current_working_email()
    access = get_user_access()
    conn = get_sql_connection()
    cursor = conn.cursor()
    ensure_po_setup_columns(cursor)
    conn.commit()

    if get_view_as_email():
        cursor.execute(
            """
            SELECT COUNT(*) AS ActionCount
            FROM dbo.PurchaseOrders
            WHERE LOWER(COALESCE(SetupAssignedTo, '')) = LOWER(?)
              AND COALESCE(NULLIF(SetupStatus, ''), 'Needs Payment Schedule') <> 'Complete';
            """,
            view_email,
        )
    elif access["role"] == "Project Manager" and user["email"]:
        cursor.execute(
            """
            SELECT COUNT(*) AS ActionCount
            FROM dbo.PurchaseOrders
            WHERE LOWER(COALESCE(SetupAssignedTo, '')) = LOWER(?)
              AND COALESCE(NULLIF(SetupStatus, ''), 'Needs Payment Schedule') <> 'Complete';
            """,
            user["email"],
        )
    elif access["role"] in ["Admin", "Executive", "Accounting"]:
        cursor.execute(
            """
            SELECT COUNT(*) AS ActionCount
            FROM dbo.PurchaseOrders
            WHERE COALESCE(NULLIF(SetupStatus, ''), CASE WHEN COALESCE(PaymentSchedule, '') = '' THEN 'Needs Payment Schedule' ELSE 'Complete' END) <> 'Complete'
               OR COALESCE(PaymentSchedule, '') = ''
               OR COALESCE(PaymentType, '') = ''
               OR ExpectedPaymentDate IS NULL;
            """
        )
    else:
        conn.close()
        return 0

    row = cursor.fetchone()
    conn.close()
    return int(row.ActionCount or 0) if row else 0


def update_po_setup_info(form):
    user = get_current_user()
    po_number = clean_text(form.get("po_number"))
    if not po_number:
        raise ValueError("PO Number is required.")

    payment_type = clean_text(form.get("payment_type")) or "Single Payment"
    setup_status = clean_text(form.get("setup_status")) or "Needs Payment Schedule"
    setup_assigned_to = clean_text(form.get("setup_assigned_to"))
    vendor_name = clean_text(form.get("vendor_name"))
    action = clean_text(form.get("setup_action")) or "save"

    schedule_lines = []
    first_expected_payment_date = None
    for idx in range(1, 5):
        date_raw = clean_text(form.get(f"payment_{idx}_date"))
        amount_raw = clean_text(form.get(f"payment_{idx}_amount"))
        note_raw = clean_text(form.get(f"payment_{idx}_note"))
        date_value = clean_date(date_raw)
        if date_value and first_expected_payment_date is None:
            first_expected_payment_date = date_value
        if date_raw or amount_raw or note_raw:
            parts = []
            if date_raw:
                parts.append(date_raw)
            if amount_raw:
                parts.append(amount_raw)
            if note_raw:
                parts.append(note_raw)
            schedule_lines.append(" - ".join(parts))

    payment_schedule = "\n".join(schedule_lines) or clean_text(form.get("payment_schedule"))
    expected_payment_date = first_expected_payment_date or clean_date(form.get("expected_payment_date"))

    if action == "assign":
        if not setup_assigned_to:
            raise ValueError("Assigned To is required when assigning this PO.")
        setup_status = "Assigned to PM"

    if action == "complete":
        setup_status = "Complete"

    conn = get_sql_connection()
    cursor = conn.cursor()
    try:
        ensure_po_setup_columns(cursor)
        cursor.execute("""
            SELECT po.PONumber, v.VendorName
            FROM dbo.PurchaseOrders po
            LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
            WHERE po.PONumber = ?;
        """, po_number)
        current_po = cursor.fetchone()
        existing_vendor = clean_text(current_po.VendorName) if current_po else None
        effective_vendor = vendor_name or existing_vendor
        if setup_status == "Complete":
            missing = []
            if not effective_vendor:
                missing.append("vendor")
            if not payment_type:
                missing.append("payment type")
            if not payment_schedule:
                missing.append("payment schedule")
            if not expected_payment_date:
                missing.append("expected payment date")
            if missing:
                raise ValueError("Cannot mark Complete. Missing: " + ", ".join(missing) + ".")
        vendor_id = get_or_create_vendor(cursor, vendor_name) if vendor_name else None
        cursor.execute(
            """
            UPDATE dbo.PurchaseOrders
            SET
                VendorId = COALESCE(?, VendorId),
                PaymentType = ?,
                ExpectedPaymentDate = ?,
                PaymentSchedule = ?,
                SetupStatus = ?,
                SetupAssignedTo = ?,
                SetupUpdatedBy = ?,
                SetupUpdatedAt = SYSUTCDATETIME(),
                UpdatedAt = SYSUTCDATETIME()
            WHERE PONumber = ?;
            """,
            vendor_id,
            payment_type,
            expected_payment_date,
            payment_schedule,
            setup_status,
            setup_assigned_to,
            user["email"] or "Unknown",
            po_number,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def action_form(request_id, status, label, css_class="secondary", extra_fields=""):
    return f"""
    <form method="post">
        <input type="hidden" name="purchase_request_id" value="{h(request_id)}">
        <input type="hidden" name="request_status" value="{h(status)}">
        {extra_fields}
        <input type="hidden" name="review_notes" value="Quick action: {h(label)}">
        <button class="{h(css_class)}" type="submit">{h(label)}</button>
    </form>
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

    user = get_current_user()
    access = get_user_access()
    display_name = access["display_name"] or user["email"] or "Current User"
    role = access["role"]

    message_html = ""

    if request.method == "POST":
        try:
            result = create_purchase_request(request.form, request.files.getlist("quote_files"))
            message_html = f"""
            <div class="submit-status-box success">
                <strong>Purchase request submitted successfully.</strong><br>
                Request Number: {h(result["request_number"])}
            </div>
            """
        except Exception as e:
            message_html = f"""
            <div class="submit-status-box error">
                <strong>Error submitting purchase request.</strong><br>{h(e)}
            </div>
            """

    content = f"""
    {message_html}

    <form method="post" action="/purchase-request" enctype="multipart/form-data">
        <div class="grid two">
            <div>
                <div class="card">
                    <h3>Request Basics</h3>
                    <p class="card-subtitle">Start with a clear request name and short scope. These details help reviewers understand what is needed.</p>
                    <div class="form-grid">
                        <div class="form-field full">
                            <label>What are you requesting? *</label>
                            <input type="text" name="request_title" placeholder="Example: Pump rental extension for Round Valley" required>
                        </div>
                        <div class="form-field full">
                            <label>Description / Scope *</label>
                            <textarea name="request_description" placeholder="Example: Extend pump rental for two additional weeks due to schedule delay." required></textarea>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Project Details</h3>
                    <p class="card-subtitle">Tell us which project and department this request belongs to.</p>
                    <div class="form-grid">
                        <div class="form-field">
                            <label>Project *</label>
                            <input type="text" name="project_name" placeholder="Project name or number" required>
                        </div>
                        <div class="form-field">
                            <label>Department *</label>
                            <select name="department" required>
                                <option value="">Select department</option>
                                <option value="Engineering">Engineering</option>
                                <option value="Marine Construction">Marine Construction</option>
                                <option value="Commercial Diving">Commercial Diving</option>
                                <option value="Dredging">Dredging</option>
                                <option value="Marine Services">Marine Services</option>
                            </select>
                        </div>
                        <div class="form-field">
                            <label>Needed By *</label>
                            <input type="date" name="needed_by_date" required>
                        </div>
                        <div class="form-field">
                            <label>Requested By</label>
                            <input type="text" name="requested_by" value="{h(display_name)}" readonly>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Vendor & Cost</h3>
                    <p class="card-subtitle">Vendor can be left blank if the requester does not know it yet. Estimated cost is required for review routing.</p>
                    <div class="form-grid">
                        <div class="form-field">
                            <label>Vendor</label>
                            <input type="text" name="vendor_name" placeholder="United Rentals, Grainger, Home Depot, or leave blank if unknown">
                        </div>
                        <div class="form-field">
                            <label>Estimated Cost *</label>
                            <input type="number" name="estimated_amount" step="0.01" min="0" placeholder="8500" required>
                        </div>
                        <div class="form-field">
                            <label>Priority</label>
                            <select name="priority">
                                <option value="Normal">Normal</option>
                                <option value="Low">Low</option>
                                <option value="High">High</option>
                                <option value="Urgent">Urgent</option>
                                <option value="Critical">Critical</option>
                            </select>
                        </div>
                        <div class="form-field">
                            <label>Quote / Backup Reference</label>
                            <input type="text" name="quote_backup" placeholder="Quote #12345, vendor email, or note">
                            <p class="field-help">Optional note to help identify the backup.</p>
                        </div>
                        <div class="form-field">
                            <label>Upload Quote / Backup</label>
                            <input type="file" name="quote_files" multiple accept=".pdf,.png,.jpg,.jpeg,.doc,.docx,.xls,.xlsx,.csv,.txt,.eml,.msg">
                            <p class="field-help">Files are stored with the request and linked to the PO when approved.</p>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Review & Submit</h3>
                    <p class="card-subtitle">Your request will be saved and routed for review. Accounting or management may update the status or request more information.</p>
                    <div class="match-summary">
                        <strong>Required field checklist</strong>
                        <span>• What are you requesting?</span>
                        <span>• Description / Scope</span>
                        <span>• Project</span>
                        <span>• Department</span>
                        <span>• Needed By</span>
                        <span>• Estimated Cost</span>
                    </div>
                    <div class="request-actions">
                        <a class="button" href="/my-dashboard">Cancel</a>
                        <button class="primary" type="submit">Submit Purchase Request</button>
                    </div>
                </div>
            </div>

            <div>
                <div class="card role-card">
                    <h3>Requester</h3>
                    <p class="card-subtitle">Pulled from Microsoft login and dashboard role access.</p>
                    <div class="role-meta">
                        <span><strong>User:</strong> {h(display_name)}</span>
                        <span><strong>Role:</strong> {h(role)}</span>
                        <span><strong>Email:</strong> {h(user["email"])}</span>
                    </div>
                </div>

                <div class="card">
                    <h3>Estimated Approval Route</h3>
                    <p class="card-subtitle">Routing can become more detailed later based on dollar amount, department, and project.</p>
                    <div class="workflow">
                        <div class="workflow-step done"><div class="workflow-circle">1</div><div class="workflow-text"><strong>Submitted</strong><span>Request is created by the requester.</span></div></div>
                        <div class="workflow-line"></div>
                        <div class="workflow-step active"><div class="workflow-circle">2</div><div class="workflow-text"><strong>Review</strong><span>Accounting, Admin, or management validates the request.</span></div></div>
                        <div class="workflow-line"></div>
                        <div class="workflow-step warning"><div class="workflow-circle">3</div><div class="workflow-text"><strong>Decision</strong><span>Approve, reject, or request more information.</span></div></div>
                        <div class="workflow-line"></div>
                        <div class="workflow-step future"><div class="workflow-circle">4</div><div class="workflow-text"><strong>PO Follow-Up</strong><span>Approved requests can later be converted to a PO.</span></div></div>
                    </div>
                </div>

                <div class="card">
                    <h3>Cost Guidance</h3>
                    <table>
                        <tr><th>Estimated Cost</th><th>Likely Review</th></tr>
                        <tr><td>Under $500</td><td><span class="badge green">Quick review</span></td></tr>
                        <tr><td>$500 - $3,000</td><td><span class="badge blue">PM / Accounting</span></td></tr>
                        <tr><td>$3,000 - $10,000</td><td><span class="badge amber">PM + Accounting</span></td></tr>
                        <tr><td>Over $10,000</td><td><span class="badge purple">Executive likely</span></td></tr>
                    </table>
                </div>

            </div>
        </div>
    </form>
    """

    return shell("New Purchase Request", "Submit a new purchase request for review before a PO is issued.", "New Purchase Request", content)



@app.route("/purchase-requests", methods=["GET", "POST"])
def purchase_requests():
    allowed, reason = require_page_access("Purchase Requests")
    if not allowed:
        return access_denied_response("Purchase Requests", reason)

    access = get_user_access()
    role = access["role"]

    if request.method == "POST":
        if not can_review_purchase_requests(role):
            return redirect("/purchase-requests?toast=You+do+not+have+permission+to+update+purchase+requests&toast_type=error")
        try:
            update_purchase_request_status(request.form)
            return redirect("/purchase-requests?toast=Purchase+request+updated")
        except Exception as e:
            return redirect("/purchase-requests?toast=" + quote_plus("Error updating request: " + str(e)) + "&toast_type=error")

    try:
        stats = load_purchase_request_stats()
        requests = load_purchase_requests()
        reviewer_users = load_assignable_users()
        selected_status = clean_text(request.args.get("status")) or "All"

        def status_card(label, value, status_filter, tone, trend):
            active = " active" if selected_status == status_filter else ""
            href = "/purchase-requests" if status_filter == "All" else "/purchase-requests?status=" + quote_plus(status_filter)
            return f"""
            <a class="status-card {tone}{active}" href="{href}">
                <div class="label">{h(label)}</div>
                <div class="value">{h(value)}</div>
                <div class="trend">{h(trend)}</div>
            </a>
            """

        manual_review_notice = """
        <div class="notice info">
            <strong>Purchase request review for July 1 rollout.</strong><br>
            Purchase requests are reviewed by Accounting/Admin. When a request is approved, the app automatically creates an internal PO, links it to the request, and adds it to PO tracking/balances. The app does not write the PO back to the ERP.
        </div>
        """

        dashboard_cards = f"""
        <div class="status-card-grid">
            {status_card("All Requests", stats["total_requests"], "All", "blue", "Full request queue")}
            {status_card("Submitted", stats["submitted_requests"], "Submitted", "amber", "Waiting for action")}
            {status_card("Under Review", stats["under_review_requests"], "Under Review", "purple", "Currently being reviewed")}
            {status_card("Needs More Info", stats.get("needs_more_info_requests", 0), "Needs More Info", "amber", "Returned for clarification")}
            {status_card("Approved", stats["approved_requests"], "Approved", "green", "Ready for PO action")}
            {status_card("Converted", stats["converted_requests"], "Converted to PO", "green", "Linked to issued PO")}
        </div>
        """

        request_rows = ""
        visible_requests = requests if selected_status == "All" else [r for r in requests if (r.RequestStatus or "Submitted") == selected_status]

        for row in visible_requests:
            description = row.RequestDescription or ""
            if len(description) > 160:
                description = description[:160] + "..."

            status_options = ""
            for status in ["Submitted", "Under Review", "Needs More Info", "Approved", "Rejected", "Converted to PO"]:
                selected = " selected" if status == row.RequestStatus else ""
                status_options += f'<option value="{h(status)}"{selected}>{h(status)}</option>'

            review_form = ""
            if can_review_purchase_requests(role):
                reviewer_value = clean_text(row.ReviewerEmail) or access["email"]
                reviewer_options = ""
                seen_reviewers = set()
                for reviewer in reviewer_users:
                    reviewer_email = clean_text(reviewer.Email)
                    if not reviewer_email:
                        continue
                    reviewer_label = clean_text(reviewer.DisplayName) or reviewer_email
                    reviewer_role = clean_text(reviewer.RoleName)
                    label = reviewer_label + (f" ({reviewer_role})" if reviewer_role else "")
                    selected = " selected" if reviewer_email.lower() == reviewer_value.lower() else ""
                    reviewer_options += f'<option value="{h(reviewer_email)}"{selected}>{h(label)}</option>'
                    seen_reviewers.add(reviewer_email.lower())
                if reviewer_value and reviewer_value.lower() not in seen_reviewers:
                    reviewer_options = f'<option value="{h(reviewer_value)}" selected>{h(reviewer_value)}</option>' + reviewer_options
                converted_display = "block" if (row.RequestStatus or "Submitted") == "Converted to PO" else "none"
                review_form = f"""
                <form method="post" action="/purchase-requests" class="purchase-review-panel">
                    <input type="hidden" name="purchase_request_id" value="{h(row.PurchaseRequestId)}">
                    <label>Status</label>
                    <select name="request_status" onchange="toggleConvertedPOField(this)">{status_options}</select>
                    <small class="field-help">Selecting Approved will automatically create and link an internal app PO.</small>
                    <label>Reviewer</label>
                    <select name="reviewer_email">{reviewer_options}</select>
                    <div class="converted-po-field" style="display:{converted_display};">
                        <label>Converted PO Number</label>
                        <input type="text" name="converted_po_number" value="{h(row.ConvertedPONumber)}" placeholder="Leave blank to auto-generate">
                    </div>
                    <label>Review Notes</label>
                    <textarea name="review_notes" placeholder="Add review notes, approval comments, rejection reason, or follow-up needed">{h(row.ReviewNotes)}</textarea>
                    <button type="submit">Save Review</button>
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
            request_rows = '<tr><td colspan="11"><div class="empty-state"><strong>No requests found for this filter.</strong><span>Use another status card or clear the filter.</span></div></td></tr>'

        total_requests = max(stats["total_requests"], 1)
        content = f"""
        {manual_review_notice}
        {dashboard_cards}

        <div class="grid two visual-chart-row" style="margin-bottom:24px;">
            <div class="mini-chart-card">
                <h4>Request Status Mix</h4>
                <div class="mini-bar-row"><span>Submitted</span><div><b style="width:{max(5, stats["submitted_requests"] / total_requests * 100)}%"></b></div><em>{stats["submitted_requests"]}</em></div>
                <div class="mini-bar-row"><span>Under Review</span><div><b style="width:{max(5, stats["under_review_requests"] / total_requests * 100)}%"></b></div><em>{stats["under_review_requests"]}</em></div>
                <div class="mini-bar-row"><span>Needs More Info</span><div><b style="width:{max(5, stats.get("needs_more_info_requests",0) / total_requests * 100)}%"></b></div><em>{stats.get("needs_more_info_requests",0)}</em></div>
                <div class="mini-bar-row"><span>Approved</span><div><b style="width:{max(5, stats["approved_requests"] / total_requests * 100)}%"></b></div><em>{stats["approved_requests"]}</em></div>
                <div class="mini-bar-row"><span>Converted</span><div><b style="width:{max(5, stats["converted_requests"] / total_requests * 100)}%"></b></div><em>{stats["converted_requests"]}</em></div>
            </div>
            <div class="card">
                <h3>Request Workflow Timeline</h3>
                <p class="card-subtitle">Simple manual workflow; automatic approval routing is intentionally not included in this version.</p>
                <div class="timeline">
                    <div class="timeline-item"><strong>Submitted</strong><span>Requester submits required details.</span></div>
                    <div class="timeline-item"><strong>Under Review / Needs More Info</strong><span>Accounting or management reviews and follows up.</span></div>
                    <div class="timeline-item"><strong>Approved</strong><span>Request is ready for PO action.</span></div>
                    <div class="timeline-item"><strong>Converted to PO</strong><span>PO number is linked when issued.</span></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>Request Dashboard</h3>
            <p class="card-subtitle">Current status filter: <strong>{h(selected_status)}</strong>. Click a status card above to filter the queue.</p>
            <div class="filter-hint"><span>Filter by request number, title, vendor, project, department, status, requester, or other visible text.</span><button type="button" onclick="clearRequestDashboardFilters()">Clear Column Filters</button></div>
            <div class="table-wrap"><table id="requestDashboardTable"><thead><tr><th>Request #</th><th>Title / Description</th><th>Vendor</th><th>Project</th><th>Department</th><th>Needed By</th><th class="right">Estimate</th><th>Priority</th><th>Status</th><th>Requested By</th><th>Review</th></tr><tr class="column-filter-row"><th><input data-col="0" oninput="filterRequestDashboard()" placeholder="Request"></th><th><input data-col="1" oninput="filterRequestDashboard()" placeholder="Title"></th><th><input data-col="2" oninput="filterRequestDashboard()" placeholder="Vendor"></th><th><input data-col="3" oninput="filterRequestDashboard()" placeholder="Project"></th><th><input data-col="4" oninput="filterRequestDashboard()" placeholder="Dept"></th><th><input data-col="5" oninput="filterRequestDashboard()" placeholder="Date"></th><th><input data-col="6" oninput="filterRequestDashboard()" placeholder="Estimate"></th><th><input data-col="7" oninput="filterRequestDashboard()" placeholder="Priority"></th><th><input data-col="8" oninput="filterRequestDashboard()" placeholder="Status"></th><th><input data-col="9" oninput="filterRequestDashboard()" placeholder="Requester"></th><th><input data-col="10" oninput="filterRequestDashboard()" placeholder="Review"></th></tr></thead><tbody>{request_rows}</tbody></table></div>
        </div>
        <script>
        function filterRequestDashboard() {{
            const table = document.getElementById('requestDashboardTable'); if (!table) return;
            const filters = Array.from(table.querySelectorAll('.column-filter-row input')).map(input => {{ return {{ col: Number(input.dataset.col), value: input.value.trim().toLowerCase() }}; }});
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            rows.forEach(row => {{ const cells = Array.from(row.children); const show = filters.every(filter => {{ if (!filter.value) return true; const cell = cells[filter.col]; return cell && cell.textContent.toLowerCase().includes(filter.value); }}); row.style.display = show ? '' : 'none'; }});
        }}
        function clearRequestDashboardFilters() {{ const table = document.getElementById('requestDashboardTable'); if (!table) return; table.querySelectorAll('.column-filter-row input').forEach(input => input.value = ''); filterRequestDashboard(); }}
        function toggleConvertedPOField(select) {{
            const form = select.closest('form');
            if (!form) return;
            const field = form.querySelector('.converted-po-field');
            if (!field) return;
            const input = field.querySelector('input');
            const show = select.value === 'Converted to PO';
            field.style.display = show ? 'block' : 'none';
            if (!show && input) input.value = '';
        }}
        document.querySelectorAll('.purchase-review-panel select[name="request_status"]').forEach(toggleConvertedPOField);
        </script>
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
        po_setup_action_count = count_po_setup_actions_for_current_user()

        po_setup_action_card = ""
        if po_setup_action_count:
            po_setup_action_card = f"""
            <div class="card action-required-card">
                <h3>Actions Required</h3>
                <p class="card-subtitle">You have <strong>{po_setup_action_count}</strong> PO information item(s) that need payment schedule or planning details.</p>
                <p><a class="button primary" href="/project-po-setup?mine=1">Open My PO Info Tasks</a></p>
            </div>
            """

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
                    <p><a class="button" href="/project-po-setup">PO Info Review</a></p>
                    <p><a class="button" href="/exceptions">Review Data Exceptions</a></p>
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
                    <p><a class="button" href="/project-po-setup">PO Info Review</a></p>
                    <p><a class="button" href="/exceptions">Review Data Exceptions</a></p>
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
                    <p><a class="button" href="/pos-balances">Open POs & Balances</a></p>
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
                    <p><a class="button" href="/pos-balances">Open POs & Balances</a></p>
                    <p><a class="button" href="/po-list">Browse PO List</a></p>
                    <p><a class="button" href="/po-detail">Search PO Detail</a></p>
                </div>
                <div class="card"><h3>Top Vendors</h3><div class="table-wrap"><table><tr><th>Vendor</th><th class="right">POs</th><th class="right">Line Total</th></tr>{vendor_rows}</table></div></div>
            </div>
            """

        content = f"""
        <div class="card"><h3>Welcome, {h(display_name)}</h3><p class="card-subtitle">This dashboard is customized for your role: <strong>{h(role)}</strong>.</p></div>
        {po_setup_action_card}
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
            <div class="filter-hint">
                <span>Use the filters below each column heading to narrow the issued PO list.</span>
                <button type="button" onclick="clearPOListFilters()">Clear Filters</button>
            </div>
            <div class="table-wrap">
                <table id="issuedPOListTable">
                    <thead>
                        <tr><th>PO Number</th><th>Vendor</th><th>Project</th><th>Department</th><th>Status</th><th>PO Date</th><th class="right">Lines</th><th class="right">PO Value</th><th class="right">Line Total</th><th class="right">Remaining</th><th>Flag</th><th>Packets</th></tr>
                        <tr class="column-filter-row">
                            <th><input data-col="0" oninput="filterIssuedPOList()" placeholder="Filter PO"></th>
                            <th><input data-col="1" oninput="filterIssuedPOList()" placeholder="Filter vendor"></th>
                            <th><input data-col="2" oninput="filterIssuedPOList()" placeholder="Filter project"></th>
                            <th><input data-col="3" oninput="filterIssuedPOList()" placeholder="Filter dept"></th>
                            <th><input data-col="4" oninput="filterIssuedPOList()" placeholder="Filter status"></th>
                            <th><input data-col="5" oninput="filterIssuedPOList()" placeholder="Filter date"></th>
                            <th><input data-col="6" oninput="filterIssuedPOList()" placeholder="Lines"></th>
                            <th><input data-col="7" oninput="filterIssuedPOList()" placeholder="PO value"></th>
                            <th><input data-col="8" oninput="filterIssuedPOList()" placeholder="Line total"></th>
                            <th><input data-col="9" oninput="filterIssuedPOList()" placeholder="Remaining"></th>
                            <th><input data-col="10" oninput="filterIssuedPOList()" placeholder="Flag"></th>
                        </tr>
                    </thead>
                    <tbody>
                        {po_rows}
                    </tbody>
                </table>
            </div>
        </div>
        <script>
        function filterIssuedPOList() {{
            const table = document.getElementById('issuedPOListTable');
            if (!table) return;
            const filters = Array.from(table.querySelectorAll('.column-filter-row input')).map(input => {{
                return {{ col: Number(input.dataset.col), value: input.value.trim().toLowerCase() }};
            }});
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            rows.forEach(row => {{
                const cells = Array.from(row.children);
                const show = filters.every(filter => {{
                    if (!filter.value) return true;
                    const cell = cells[filter.col];
                    return cell && cell.textContent.toLowerCase().includes(filter.value);
                }});
                row.style.display = show ? '' : 'none';
            }});
        }}
        function clearPOListFilters() {{
            const table = document.getElementById('issuedPOListTable');
            if (!table) return;
            table.querySelectorAll('.column-filter-row input').forEach(input => input.value = '');
            filterIssuedPOList();
        }}
        </script>
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
        req_where, req_params = requestor_filter_sql("IssuedPOLines")

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
            WHERE PONumber = ? AND {req_where}
            ORDER BY CreatedAt DESC;
            """.format(req_where=req_where),
            po_number,
            *req_params,
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
            WHERE PONumber = ? AND {req_where}
            ORDER BY IssuedPOLineId;
            """.format(req_where=req_where),
            po_number,
            *req_params,
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
            WHERE PONumber = ? AND {req_where};
            """.format(req_where=req_where),
            po_number,
            *req_params,
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




@app.route("/projects")
def projects_page():
    allowed, reason = require_page_access("Projects")
    if not allowed:
        return access_denied_response("Projects", reason)

    selected_project = clean_text(request.args.get("project")) or ""
    try:
        conn = get_sql_connection()
        cursor = conn.cursor()
        ensure_project_code_columns(cursor)
        conn.commit()
        req_where_po, req_params_po = requestor_filter_sql("po")
        req_where_line, req_params_line = requestor_filter_sql("l")

        cursor.execute(
            f"""
            SELECT DISTINCT
                COALESCE(pr.ProjectCode, '') AS ProjectCode,
                COALESCE(pr.ProjectName, l.ProjectName, '') AS ProjectName
            FROM dbo.IssuedPOLines l
            LEFT JOIN dbo.PurchaseOrders po ON l.PurchaseOrderId = po.PurchaseOrderId
            LEFT JOIN dbo.Projects pr ON po.ProjectId = pr.ProjectId
            WHERE {req_where_line}
            ORDER BY COALESCE(pr.ProjectCode, ''), COALESCE(pr.ProjectName, l.ProjectName, '');
            """,
            *req_params_line,
        )
        projects = cursor.fetchall()

        if not selected_project and projects:
            first = projects[0]
            selected_project = clean_text(first.ProjectCode) or clean_text(first.ProjectName) or ""

        options = ""
        for pr in projects:
            value = clean_text(pr.ProjectCode) or clean_text(pr.ProjectName) or ""
            label = (clean_text(pr.ProjectCode) + " - " if clean_text(pr.ProjectCode) else "") + (clean_text(pr.ProjectName) or "Unnamed Project")
            sel = " selected" if value == selected_project else ""
            options += f'<option value="{h(value)}"{sel}>{h(label)}</option>'

        project_filter_sql = "1=0"
        params_po = []
        params_line = []
        if selected_project:
            project_filter_sql = "(LOWER(COALESCE(pr.ProjectCode, '')) = LOWER(?) OR LOWER(COALESCE(pr.ProjectName, l.ProjectName, '')) = LOWER(?))"
            params_po = [selected_project, selected_project]
            params_line = [selected_project, selected_project]

        cursor.execute(
            f"""
            WITH PostedExpenses AS (
                SELECT PostedPONumber AS PONumber, SUM(COALESCE(PostedAmount, Amount, 0)) AS PostedExpenseAmount
                FROM dbo.ExpenseReviewItems
                WHERE COALESCE(PostedToPO, 0) = 1 AND COALESCE(PostedPONumber, '') <> ''
                GROUP BY PostedPONumber
            ), LineRollup AS (
                SELECT PONumber, SUM(COALESCE(LineAmount, 0)) AS LineAmount, COUNT(*) AS LineCount
                FROM dbo.IssuedPOLines
                GROUP BY PONumber
            )
            SELECT
                po.PONumber,
                COALESCE(v.VendorName, 'Missing Vendor') AS VendorName,
                COALESCE(pr.ProjectCode, '') AS ProjectCode,
                COALESCE(pr.ProjectName, '') AS ProjectName,
                po.Department,
                po.POStatus,
                po.PODate,
                po.Requestor,
                COALESCE(po.RevisedAmount, po.OriginalAmount, lr.LineAmount, 0) AS POValue,
                COALESCE(pe.PostedExpenseAmount, 0) AS PostedExpenseAmount,
                CASE WHEN COALESCE(po.RevisedAmount, po.OriginalAmount, lr.LineAmount, 0) - COALESCE(pe.PostedExpenseAmount, 0) < 0 THEN 0 ELSE COALESCE(po.RevisedAmount, po.OriginalAmount, lr.LineAmount, 0) - COALESCE(pe.PostedExpenseAmount, 0) END AS CurrentAppBalance,
                COALESCE(lr.LineCount, 0) AS LineCount
            FROM dbo.PurchaseOrders po
            LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
            LEFT JOIN dbo.Projects pr ON po.ProjectId = pr.ProjectId
            LEFT JOIN LineRollup lr ON lr.PONumber = po.PONumber
            LEFT JOIN PostedExpenses pe ON pe.PONumber = po.PONumber
            LEFT JOIN dbo.IssuedPOLines l ON l.PONumber = po.PONumber
            WHERE {project_filter_sql} AND {req_where_po}
            GROUP BY po.PONumber, v.VendorName, pr.ProjectCode, pr.ProjectName, po.Department, po.POStatus, po.PODate, po.Requestor, po.RevisedAmount, po.OriginalAmount, lr.LineAmount, pe.PostedExpenseAmount, lr.LineCount
            ORDER BY po.PONumber;
            """,
            *(params_po + req_params_po),
        )
        po_rows_raw = cursor.fetchall()

        cursor.execute(
            f"""
            SELECT TOP 1000
                l.PONumber,
                l.VendorName,
                COALESCE(pr.ProjectCode, '') AS ProjectCode,
                COALESCE(pr.ProjectName, l.ProjectName, '') AS ProjectName,
                l.Department,
                l.LineDescription,
                l.Unit,
                l.UnitCost,
                l.Qty,
                l.LineAmount
            FROM dbo.IssuedPOLines l
            LEFT JOIN dbo.PurchaseOrders po ON l.PurchaseOrderId = po.PurchaseOrderId
            LEFT JOIN dbo.Projects pr ON po.ProjectId = pr.ProjectId
            WHERE {project_filter_sql} AND {req_where_line}
            ORDER BY l.PONumber, l.IssuedPOLineId;
            """,
            *(params_line + req_params_line),
        )
        line_rows_raw = cursor.fetchall()
        conn.close()

        po_rows = ""
        for row in po_rows_raw:
            po_rows += f"""
            <tr>
                <td><a class="po-link" href="/po-detail?po_number={quote_plus(str(row.PONumber or ''))}">{h(row.PONumber)}</a></td>
                <td>{h(row.VendorName)}</td>
                <td>{status_chip(row.POStatus or 'Open')}</td>
                <td>{h(row.PODate)}</td>
                <td>{h(row.Requestor)}</td>
                <td class="right">{currency(row.POValue)}</td>
                <td class="right">{currency(row.PostedExpenseAmount)}</td>
                <td class="right">{currency(row.CurrentAppBalance)}</td>
                <td class="right">{h(row.LineCount)}</td>
            </tr>
            """
        if not po_rows:
            po_rows = '<tr><td colspan="9"><div class="empty-state"><strong>No POs found for this project.</strong></div></td></tr>'

        line_rows = ""
        for row in line_rows_raw:
            line_rows += f"""
            <tr>
                <td><a class="po-link" href="/po-detail?po_number={quote_plus(str(row.PONumber or ''))}">{h(row.PONumber)}</a></td>
                <td>{h(row.VendorName)}</td>
                <td>{h(row.Department)}</td>
                <td>{h(row.LineDescription)}</td>
                <td>{h(row.Unit)}</td>
                <td class="right">{currency(row.UnitCost)}</td>
                <td class="right">{h(row.Qty)}</td>
                <td class="right">{currency(row.LineAmount)}</td>
            </tr>
            """
        if not line_rows:
            line_rows = '<tr><td colspan="8"><div class="empty-state"><strong>No line items found for this project.</strong></div></td></tr>'

        content = f"""
        <div class="card">
            <h3>Select Project</h3>
            <form method="get" action="/projects" class="filters">
                <select name="project" onchange="this.form.submit()">{options}</select>
                <noscript><button class="primary" type="submit">Open Project</button></noscript>
            </form>
        </div>
        <div class="card">
            <h3>Project POs</h3>
            <p class="card-subtitle">POs for the selected project. Click a PO number to open the full PO.</p>
            <div class="filter-hint"><span>Filter the PO table below.</span><button type="button" onclick="clearPOListFilters('projectPOTable')">Clear Filters</button></div>
            <div class="table-wrap"><table id="projectPOTable"><thead><tr><th>PO</th><th>Vendor</th><th>Status</th><th>PO Date</th><th>Requestor</th><th class="right">PO Value</th><th class="right">Posted Expenses</th><th class="right">Current Balance</th><th class="right">Lines</th></tr><tr class="column-filter-row"><th><input data-col="0" oninput="filterPOListTable('projectPOTable')" placeholder="PO"></th><th><input data-col="1" oninput="filterPOListTable('projectPOTable')" placeholder="Vendor"></th><th><input data-col="2" oninput="filterPOListTable('projectPOTable')" placeholder="Status"></th><th><input data-col="3" oninput="filterPOListTable('projectPOTable')" placeholder="Date"></th><th><input data-col="4" oninput="filterPOListTable('projectPOTable')" placeholder="Requestor"></th><th><input data-col="5" oninput="filterPOListTable('projectPOTable')" placeholder="Value"></th><th><input data-col="6" oninput="filterPOListTable('projectPOTable')" placeholder="Posted"></th><th><input data-col="7" oninput="filterPOListTable('projectPOTable')" placeholder="Balance"></th><th><input data-col="8" oninput="filterPOListTable('projectPOTable')" placeholder="Lines"></th></tr></thead><tbody>{po_rows}</tbody></table></div>
        </div>
        <div class="card">
            <h3>Project PO Line Items</h3>
            <p class="card-subtitle">Line-item drilldown for the selected project.</p>
            <div class="filter-hint"><span>Filter the line-item table below.</span><button type="button" onclick="clearPOListFilters('projectLineTable')">Clear Filters</button></div>
            <div class="table-wrap"><table id="projectLineTable"><thead><tr><th>PO</th><th>Vendor</th><th>Department</th><th>Description</th><th>Unit</th><th class="right">Unit Cost</th><th class="right">Qty</th><th class="right">Line Amount</th></tr><tr class="column-filter-row"><th><input data-col="0" oninput="filterPOListTable('projectLineTable')" placeholder="PO"></th><th><input data-col="1" oninput="filterPOListTable('projectLineTable')" placeholder="Vendor"></th><th><input data-col="2" oninput="filterPOListTable('projectLineTable')" placeholder="Dept"></th><th><input data-col="3" oninput="filterPOListTable('projectLineTable')" placeholder="Description"></th><th><input data-col="4" oninput="filterPOListTable('projectLineTable')" placeholder="Unit"></th><th><input data-col="5" oninput="filterPOListTable('projectLineTable')" placeholder="Unit cost"></th><th><input data-col="6" oninput="filterPOListTable('projectLineTable')" placeholder="Qty"></th><th><input data-col="7" oninput="filterPOListTable('projectLineTable')" placeholder="Amount"></th></tr></thead><tbody>{line_rows}</tbody></table></div>
        </div>
        <script>
        function filterPOListTable(tableId) {{ const table = document.getElementById(tableId); if (!table) return; const filters = Array.from(table.querySelectorAll('.column-filter-row input')).map(input => {{ return {{ col: Number(input.dataset.col), value: input.value.trim().toLowerCase() }}; }}); Array.from(table.querySelectorAll('tbody tr')).forEach(row => {{ const cells = Array.from(row.children); const show = filters.every(filter => !filter.value || ((cells[filter.col] || {{textContent:''}}).textContent.toLowerCase().includes(filter.value))); row.style.display = show ? '' : 'none'; }}); }}
        function clearPOListFilters(tableId) {{ const table = document.getElementById(tableId); if (!table) return; table.querySelectorAll('.column-filter-row input').forEach(input => input.value = ''); filterPOListTable(tableId); }}
        </script>
        """
        return shell("Projects", "Review project POs and line-item detail.", "Projects", content)
    except Exception as e:
        return shell("Projects", "Unable to load projects.", "Projects", f'<div class="notice error">Error loading Projects: {h(e)}</div>'), 500

@app.route("/pos-balances")
def pos_balances():
    allowed, reason = require_page_access("POs & Balances")
    if not allowed:
        return access_denied_response("POs & Balances", reason)

    try:
        data = load_pos_balances_data()
        overall = data["overall"]

        project_rows = ""
        max_project_value = max([float(row.POValue or 0) for row in data["projects"]] or [1])
        for row in data["projects"]:
            bar_width = 0 if max_project_value == 0 else max(5, float(row.POValue or 0) / max_project_value * 100)
            project_rows += f"""
            <tr>
                <td><strong>{h(row.ProjectName)}</strong></td>
                <td class="right">{row.POCount}</td>
                <td class="right">{currency(row.POValue)}</td>
                <td class="right">{currency(row.TotalLineAmount)}</td>
                <td class="right">{currency(getattr(row, 'PostedExpenseAmount', 0))}</td>
                <td class="right">{currency(row.RemainingAmount)}</td>
                <td class="right">{percent(row.PercentOpen)}</td>
                <td><div class="bar-track"><div class="bar-fill" style="width:{bar_width}%"></div></div></td>
            </tr>
            """
        if not project_rows:
            project_rows = '<tr><td colspan="7">No project PO data found.</td></tr>'

        vendor_bar_rows = ""
        max_vendor_value = max([float(row.POValue or 0) for row in data["vendors"]] or [1])
        for row in data["vendors"]:
            bar_width = 0 if max_vendor_value == 0 else max(5, float(row.POValue or 0) / max_vendor_value * 100)
            vendor_bar_rows += f"""
            <div class="mini-bar-row"><span>{h(row.VendorName)}</span><div><b style="width:{bar_width}%"></b></div><em>{currency(row.POValue)}</em></div>
            """
        if not vendor_bar_rows:
            vendor_bar_rows = '<p class="card-subtitle">No vendor data found.</p>'

        po_rows = ""
        for row in data["pos"]:
            status_text = row.POStatus or "Unknown"
            flag = '<span class="badge amber">Mismatch</span>' if row.AmountMismatch else '<span class="badge green">OK</span>'
            po_url = "/po-detail?po_number=" + quote_plus(str(row.PONumber or ""))
            internal_packet_url = "/po-packet/" + quote_plus(str(row.PONumber or "")) + "?type=internal"
            vendor_packet_url = "/po-packet/" + quote_plus(str(row.PONumber or "")) + "?type=vendor"
            po_rows += f"""
            <tr>
                <td><a href="{po_url}">{h(row.PONumber)}</a></td>
                <td>{h(row.VendorName)}</td>
                <td>{h(row.ProjectName)}</td>
                <td>{h(row.Department)}</td>
                <td>{status_chip(status_text)}</td>
                <td>{h(row.PODate)}</td>
                <td class="right">{row.LineCount}</td>
                <td class="right">{currency(row.POValue)}</td>
                <td class="right">{currency(row.TotalLineAmount)}</td>
                <td class="right">{currency(getattr(row, 'PostedExpenseAmount', 0))}<br><small>{int(getattr(row, 'PostedExpenseCount', 0) or 0)} expense(s)</small></td>
                <td class="right">{currency(row.RemainingAmount)}</td>
                <td>{flag}</td>
                <td><a class="secondary" href="{internal_packet_url}">Internal</a><br><a class="secondary" href="{vendor_packet_url}">Vendor</a></td>
            </tr>
            """
        if not po_rows:
            po_rows = '<tr><td colspan="12">No issued POs found.</td></tr>'

        line_rows = ""
        for row in data["lines"]:
            line_rows += f"""
            <tr>
                <td><a class="po-link" href="/po-detail?po_number={quote_plus(str(row.PONumber or ''))}">{h(row.PONumber)}</a></td>
                <td>{h(row.VendorName)}</td>
                <td>{h(row.ProjectName)}</td>
                <td>{h(row.Department)}</td>
                <td>{h(row.LineDescription)}</td>
                <td>{h(row.Unit)}</td>
                <td class="right">{currency(row.UnitCost)}</td>
                <td class="right">{h(row.Qty)}</td>
                <td class="right">{currency(row.LineAmount)}</td>
            </tr>
            """
        if not line_rows:
            line_rows = '<tr><td colspan="9">No line items found.</td></tr>'

        content = f"""
        <div class="grid kpis">
            <a class="card kpi action-card blue" href="#posBalancesPOListTable"><div class="label">Issued PO Count</div><div class="value">{overall['total_pos']}</div><div class="trend">Unique issued POs</div></a>
            <a class="card kpi action-card green" href="#posBalancesPOListTable"><div class="label">Open POs</div><div class="value">{overall['open_pos']}</div><div class="trend">Currently open</div></a>
            <div class="card kpi"><div class="label">Issued PO Amount</div><div class="value">{currency(overall['total_po_value'])}</div><div class="trend">Revised/original value</div></div>
            <div class="card kpi"><div class="label">Posted Expenses</div><div class="value">{currency(overall.get('posted_expense_amount', 0))}</div><div class="trend">Matched expenses reducing balances</div></div>
            <a class="card kpi action-card amber" href="/project-po-setup"><div class="label">Current App Balance</div><div class="value">{currency(overall['total_remaining_amount'])}</div><div class="trend">Issued POs minus posted matched expenses</div></a>
            <div class="card kpi"><div class="label">Review Flags</div><div class="value">{overall['amount_mismatch_count']}</div><div class="trend">PO value vs. line total</div></div>
        </div>


        <div class="card project-bucket-card">
            <h3>Project Open Balance Buckets</h3>
            <p class="card-subtitle">Projects grouped by remaining open PO balance percentage. Green means stronger remaining balance; red means lower remaining balance.</p>
            <div class="project-bucket-grid">{render_open_balance_buckets(data['projects'])}</div>
        </div>

        <div class="grid two visual-chart-row" style="margin-bottom:24px;">
            <div class="card">
                <h3>PO Exposure by Project</h3>
                <p class="card-subtitle">Issued value, line totals, and remaining balances by project.</p>
                <div class="table-wrap"><table><tr><th>Project</th><th class="right">POs</th><th class="right">Issued</th><th class="right">Line Total</th><th class="right">Remaining</th><th class="right">% Open</th><th>Scale</th></tr>{project_rows}</table></div>
            </div>
            <div class="mini-chart-card">
                <h4>Top Vendors by Issued PO Amount</h4>
                {vendor_bar_rows}
            </div>
        </div>

        <div class="card">
            <h3>Issued PO List</h3>
            <p class="card-subtitle">Consolidated list formerly shown on the separate PO List page. Click a PO number for full PO detail.</p>
            <div class="filter-hint"><span>Use the filters below each column heading to narrow the PO list.</span><button type="button" onclick="clearPOListFilters('posBalancesPOListTable')">Clear Filters</button></div>
            <div class="table-wrap">
                <table id="posBalancesPOListTable">
                    <thead>
                        <tr><th>PO Number</th><th>Vendor</th><th>Project</th><th>Department</th><th>Status</th><th>PO Date</th><th class="right">Lines</th><th class="right">PO Value</th><th class="right">Line Total</th><th class="right">Remaining</th><th>Flag</th><th>Packets</th></tr>
                        <tr class="column-filter-row">
                            <th><input data-col="0" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Filter PO"></th>
                            <th><input data-col="1" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Filter vendor"></th>
                            <th><input data-col="2" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Filter project"></th>
                            <th><input data-col="3" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Filter dept"></th>
                            <th><input data-col="4" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Filter status"></th>
                            <th><input data-col="5" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Filter date"></th>
                            <th><input data-col="6" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Lines"></th>
                            <th><input data-col="7" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="PO value"></th>
                            <th><input data-col="8" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Line total"></th>
                            <th><input data-col="9" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Remaining"></th>
                            <th><input data-col="10" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Flag"></th>
                            <th><input data-col="11" oninput="filterPOListTable('posBalancesPOListTable')" placeholder="Packets"></th>
                        </tr>
                    </thead>
                    <tbody>{po_rows}</tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h3>Recent PO Line Items</h3>
            <p class="card-subtitle">Line-level detail from issued PO imports. This brings PO Detail visibility into the combined page.</p>
            <div class="table-wrap"><table><tr><th>PO</th><th>Vendor</th><th>Project</th><th>Department</th><th>Description</th><th>Unit</th><th class="right">Unit Cost</th><th class="right">Qty</th><th class="right">Line Amount</th></tr>{line_rows}</table></div>
        </div>

        <script>
        function filterPOListTable(tableId) {{
            const table = document.getElementById(tableId);
            if (!table) return;
            const filters = Array.from(table.querySelectorAll('.column-filter-row input')).map(input => {{ return {{ col: Number(input.dataset.col), value: input.value.trim().toLowerCase() }}; }});
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            rows.forEach(row => {{
                const cells = Array.from(row.children);
                const show = filters.every(filter => {{
                    if (!filter.value) return true;
                    const cell = cells[filter.col];
                    return cell && cell.textContent.toLowerCase().includes(filter.value);
                }});
                row.style.display = show ? '' : 'none';
            }});
        }}
        function clearPOListFilters(tableId) {{
            const table = document.getElementById(tableId);
            if (!table) return;
            table.querySelectorAll('.column-filter-row input').forEach(input => input.value = '');
            filterPOListTable(tableId);
        }}
        </script>
        """

        return shell("POs & Balances", "Issued PO value, open balances, project buckets, vendor exposure, and line details in one view.", "POs & Balances", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading POs & Balances: {h(e)}</div>'
        return shell("POs & Balances", "Unable to load consolidated PO view.", "POs & Balances", content), 500


@app.route("/forecasting")
def forecasting():
    allowed, reason = require_page_access("Forecasting")
    if not allowed:
        return access_denied_response("Forecasting", reason)

    try:
        items = load_forecast_data()
        selected_bucket = clean_text(request.args.get("bucket")) or "All Buckets"
        visible_items = items if selected_bucket == "All Buckets" else [item for item in items if item["bucket"] == selected_bucket]
        bucket_summary = forecast_bucket_summary(items)
        total_forecast = sum(Decimal(str(item["amount"] or 0)) for item in items)
        scheduled_total = sum(Decimal(str(item["amount"] or 0)) for item in items if item["bucket"] != "Unscheduled")
        unscheduled_total = total_forecast - scheduled_total
        past_due_count = len([item for item in items if item["bucket"] == "Past Due"])
        next_30_total = sum(Decimal(str(item["amount"] or 0)) for item in items if item["bucket"] in ["Past Due", "Next 7 Days", "8-14 Days", "15-30 Days"])

        max_bucket = max([float(amount or 0) for _, _, amount in bucket_summary] or [1])
        forecast_bucket_cards = ""
        for label, count, amount in bucket_summary:
            bar_height = 8 if max_bucket == 0 else max(8, float(amount or 0) / max_bucket * 100)
            forecast_bucket_cards += f"""
            <a class="forecast-bucket" href="/forecasting?bucket={quote_plus(label)}" style="text-decoration:none;color:inherit;">
                <strong>{h(label)}</strong>
                <div class="amount">{currency(amount)}</div>
                <div class="bucket-note">{count} item(s)</div>
                <div class="bars"><span class="bar" style="height:{bar_height}%"></span></div>
            </a>
            """

        project_rows = ""
        for project, values in aggregate_items(items, "project")[:8]:
            project_rows += f"<tr><td>{h(project)}</td><td class='right'>{values['count']}</td><td>{h(values['next_date'])}</td><td class='right'>{currency(values['amount'])}</td></tr>"
        if not project_rows:
            project_rows = '<tr><td colspan="4">No forecast project data found.</td></tr>'

        vendor_rows = ""
        for vendor, values in aggregate_items(items, "vendor")[:8]:
            vendor_rows += f"<tr><td>{h(vendor)}</td><td class='right'>{values['count']}</td><td>{h(values['next_date'])}</td><td class='right'>{currency(values['amount'])}</td></tr>"
        if not vendor_rows:
            vendor_rows = '<tr><td colspan="4">No forecast vendor data found.</td></tr>'

        detail_rows = ""
        for item in visible_items:
            detail_rows += f"""
            <tr>
                <td>{h(item['source_type'])}</td>
                <td>{h(item['source_id'])}</td>
                <td>{h(item['project'])}</td>
                <td>{h(item['vendor'])}</td>
                <td>{h(item['forecast_date'])}</td>
                <td>{status_chip(item['status'])}</td>
                <td>{h(item['bucket'])}</td>
                <td>{h(item['description'])}</td>
                <td class="right">{currency(item['amount'])}</td>
            </tr>
            """
        if not detail_rows:
            detail_rows = '<tr><td colspan="9">No forecast detail found for this filter.</td></tr>'

        content = f"""
        <div class="grid kpis">
            <a class="card kpi action-card blue" href="/forecasting?bucket=All+Buckets"><div class="label">Total Forecast Exposure</div><div class="value">{currency(total_forecast)}</div><div class="trend">Requests + open PO balances</div></a>
            <a class="card kpi action-card green" href="/forecasting?bucket=Next+7+Days"><div class="label">Scheduled Forecast</div><div class="value">{currency(scheduled_total)}</div><div class="trend">Items with dates</div></a>
            <a class="card kpi action-card amber" href="/forecasting?bucket=Unscheduled"><div class="label">Unscheduled</div><div class="value">{currency(unscheduled_total)}</div><div class="trend">Needs forecast date</div></a>
            <a class="card kpi action-card red" href="/forecasting?bucket=Past+Due"><div class="label">Past Due Items</div><div class="value">{past_due_count}</div><div class="trend">Needed-by date has passed</div></a>
            <a class="card kpi action-card purple" href="/forecasting?bucket=15-30+Days"><div class="label">Next 30 Days</div><div class="value">{currency(next_30_total)}</div><div class="trend">Past due through 30 days</div></a>
            <div class="card kpi"><div class="label">Detail Items</div><div class="value">{len(items)}</div><div class="trend">Forecast rows</div></div>
        </div>

        <div class="card">
            <h3>Forecast Buckets</h3>
            <p class="card-subtitle">Expected purchase/payment timing from purchase requests and currently open PO balances. Click a bucket to filter the detail list.</p>
            <div class="forecast-row">{forecast_bucket_cards}</div>
        </div>

        <div class="grid two">
            <div class="card"><h3>Forecast by Project</h3><div class="table-wrap"><table><tr><th>Project</th><th class="right">Items</th><th>Next Date</th><th class="right">Amount</th></tr>{project_rows}</table></div></div>
            <div class="card"><h3>Top Vendors by Forecast Amount</h3><div class="table-wrap"><table><tr><th>Vendor</th><th class="right">Items</th><th>Next Date</th><th class="right">Amount</th></tr>{vendor_rows}</table></div></div>
        </div>

        <div class="card" id="forecast-detail-section">
            <h3>Forecast Detail</h3>
            <p class="card-subtitle">Current filter: <strong>{h(selected_bucket)}</strong>. Add expected payment or due dates later to make the forecast stronger.</p>
            <div class="filter-chip-row">
                <a class="filter-chip" href="/forecasting?bucket=All+Buckets">All Buckets</a>
                {''.join(f'<a class="filter-chip" href="/forecasting?bucket={quote_plus(label)}">{h(label)}</a>' for label, _, _ in bucket_summary)}
            </div>
            <div class="table-wrap"><table><tr><th>Source</th><th>ID</th><th>Project</th><th>Vendor</th><th>Forecast Date</th><th>Status</th><th>Bucket</th><th>Description</th><th class="right">Amount</th></tr>{detail_rows}</table></div>
        </div>
        """

        return shell("Forecasting", "Upcoming purchase request needs, open PO exposure, and unscheduled forecast gaps.", "Forecasting", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading forecasting page: {h(e)}</div>'
        return shell("Forecasting", "Unable to load forecasting.", "Forecasting", content), 500



@app.route("/approver-queue", methods=["GET", "POST"])
def approver_queue():
    allowed, reason = require_page_access("Approver Queue")
    if not allowed:
        return access_denied_response("Approver Queue", reason)

    access = get_user_access()
    role = access["role"]

    if request.method == "POST":
        if not can_review_purchase_requests(role):
            return redirect("/approver-queue?toast=You+do+not+have+permission+to+update+approval+items&toast_type=error")
        try:
            update_purchase_request_status(request.form)
            return redirect("/approver-queue?toast=Approver+queue+updated")
        except Exception as e:
            return redirect("/approver-queue?toast=" + quote_plus("Error updating approval item: " + str(e)) + "&toast_type=error")

    try:
        rows = [row for row in load_purchase_requests(200) if (row.RequestStatus or "Submitted") in ["Submitted", "Under Review", "Needs More Info"]]
        selected_id = clean_text(request.args.get("request_id"))
        selected = None
        if selected_id:
            for row in rows:
                if str(row.PurchaseRequestId) == selected_id:
                    selected = row
                    break
        if selected is None and rows:
            selected = rows[0]

        list_items = ""
        total_open_amount = Decimal("0")
        for row in rows:
            total_open_amount += Decimal(str(row.EstimatedAmount or 0))
            active_class = " active" if selected and row.PurchaseRequestId == selected.PurchaseRequestId else ""
            list_items += f"""
            <a class="approval-item{active_class}" href="/approver-queue?request_id={row.PurchaseRequestId}">
                <strong>{h(row.RequestNumber)}</strong>
                <span>{h(row.RequestTitle)}<br>{h(row.ProjectName)} / {h(row.VendorName)}<br>{purchase_request_status_badge(row.RequestStatus)}</span>
                <em>{currency(row.EstimatedAmount)}</em>
            </a>
            """
        if not list_items:
            list_items = '<div class="empty-state"><strong>No open approval items.</strong><span>Submitted, Under Review, and Needs More Info requests will appear here.</span></div>'

        detail_html = ""
        if selected:
            status_options = ""
            for status in ["Submitted", "Under Review", "Needs More Info", "Approved", "Rejected", "Converted to PO"]:
                selected_option = " selected" if status == selected.RequestStatus else ""
                status_options += f'<option value="{h(status)}"{selected_option}>{h(status)}</option>'
            approve_form = action_form(selected.PurchaseRequestId, "Approved", "Approve", "primary")
            reject_form = action_form(selected.PurchaseRequestId, "Rejected", "Reject", "secondary")
            more_info_form = action_form(selected.PurchaseRequestId, "Needs More Info", "Request Info", "secondary")
            review_form = action_form(selected.PurchaseRequestId, "Under Review", "Mark Reviewing", "secondary")
            detail_html = f"""
            <div class="card">
                <h3>Approval Detail</h3>
                <div class="detail-grid">
                    <div><span>Request</span><strong>{h(selected.RequestNumber)}</strong></div>
                    <div><span>Status</span><strong>{status_chip(selected.RequestStatus)}</strong></div>
                    <div><span>Project</span><strong>{h(selected.ProjectName)}</strong></div>
                    <div><span>Vendor</span><strong>{h(selected.VendorName)}</strong></div>
                    <div><span>Needed By</span><strong>{h(selected.NeededByDate)}</strong></div>
                    <div><span>Estimate</span><strong>{currency(selected.EstimatedAmount)}</strong></div>
                </div>
                <p class="card-subtitle" style="margin-top:14px;">{h(selected.RequestDescription)}</p>
                <div class="approval-action-grid">{review_form}{more_info_form}{approve_form}{reject_form}</div>
                <div class="timeline">
                    <div class="timeline-item"><strong>Submitted</strong><span>{h(selected.RequestedByName or selected.RequestedByEmail)} submitted this request.</span></div>
                    <div class="timeline-item"><strong>Current Status</strong><span>{h(selected.RequestStatus or 'Submitted')}</span></div>
                    <div class="timeline-item"><strong>Last Review Note</strong><span>{h(selected.ReviewNotes or 'No review notes yet.')}</span></div>
                </div>
                <form method="post" action="/approver-queue" style="margin-top:16px;">
                    <input type="hidden" name="purchase_request_id" value="{h(selected.PurchaseRequestId)}">
                    <div class="form-grid">
                        <div class="form-field"><label>Status</label><select name="request_status">{status_options}</select></div>
                        <div class="form-field"><label>Converted PO Number</label><input type="text" name="converted_po_number" value="{h(selected.ConvertedPONumber)}" placeholder="PO number if converted"></div>
                        <div class="form-field full"><label>Review Notes</label><textarea name="review_notes" placeholder="Review notes">{h(selected.ReviewNotes)}</textarea></div>
                    </div>
                    <div class="request-actions"><button class="primary" type="submit">Save Detailed Update</button></div>
                </form>
            </div>
            """
        else:
            detail_html = '<div class="card"><h3>Approval Detail</h3><div class="empty-state"><strong>No request selected.</strong><span>Open approval items will appear when requests are submitted.</span></div></div>'

        content = f"""
        <div class="grid kpis">
            <div class="card kpi"><div class="label">Open Approval Items</div><div class="value">{len(rows)}</div><div class="trend">Submitted / under review / needs info</div></div>
            <div class="card kpi"><div class="label">Open Approval Value</div><div class="value">{currency(total_open_amount)}</div><div class="trend">Estimated request value</div></div>
            <a class="card kpi action-card blue" href="/purchase-requests?status=Submitted"><div class="label">Submitted</div><div class="value">View</div><div class="trend">Filter request dashboard</div></a>
            <a class="card kpi action-card amber" href="/purchase-requests?status=Needs+More+Info"><div class="label">Needs Info</div><div class="value">View</div><div class="trend">Follow-up requests</div></a>
        </div>
        <div class="grid two">
            <div class="card"><h3>Open Approver Queue</h3><p class="card-subtitle">Requests waiting for review or currently under review.</p><div class="approval-list">{list_items}</div></div>
            {detail_html}
        </div>
        """
        return shell("Approver Queue", "Approve, reject, or request more information for open purchase requests.", "Approver Queue", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading approver queue: {h(e)}</div>'
        return shell("Approver Queue", "Unable to load approval queue.", "Approver Queue", content), 500



def posted_expense_card(rows):
    table_rows = ""
    for r in rows:
        table_rows += f"""
        <tr>
            <td><strong>{h(r.ExpenseId or r.ExpenseReviewItemId)}</strong><br><small>{h(r.TxDate)}</small></td>
            <td>{h(r.TxType)}</td>
            <td>{h(r.VendorName)}</td>
            <td>{h(r.Description)}<br><small>{h(r.PMComments)}</small></td>
            <td class="right">{currency(r.PostedAmount or r.Amount)}</td>
            <td>{h(r.ReviewDecision)}<br><small>{h(r.PostedBy or r.ReviewerEmail)}</small></td>
            <td>{h(r.PostedAt)}</td>
        </tr>
        """
    if not table_rows:
        table_rows = '<tr><td colspan="7"><div class="empty-state"><strong>No posted expenses yet.</strong><span>Matched expenses will appear here once they reduce this PO balance.</span></div></td></tr>'
    return f"""
    <div class="card">
        <h3>Posted Expenses Reducing This PO</h3>
        <p class="card-subtitle">These reviewed expense rows reduce the current app PO balance. They do not write back to Unanet or the ERP.</p>
        <div class="table-wrap"><table>
            <tr><th>Expense</th><th>Type</th><th>Vendor / Purchaser</th><th>Description / PM Comments</th><th class="right">Posted Amount</th><th>Decision / Posted By</th><th>Posted At</th></tr>
            {table_rows}
        </table></div>
    </div>
    """


@app.route("/po-packet/<path:po_number>")
def po_packet(po_number):
    allowed, reason = require_page_access("POs & Balances")
    if not allowed:
        return access_denied_response("POs & Balances", reason)

    packet_type = clean_text(request.args.get("type")) or "internal"
    if packet_type not in ["internal", "vendor"]:
        packet_type = "internal"

    try:
        po, lines, posted_expenses = load_po_packet_data(po_number)
        if not po:
            content = '<div class="notice error">PO was not found.</div>'
            return shell("PO Packet", "Unable to find this PO.", "POs & Balances", content), 404

        line_rows = ""
        for line in lines:
            if packet_type == "vendor":
                line_rows += f"""
                <tr>
                    <td>{h(line.LineDescription)}</td>
                    <td>{h(line.Unit)}</td>
                    <td class="right">{h(line.Qty)}</td>
                    <td class="right">{currency(line.UnitCost)}</td>
                    <td class="right">{currency(line.LineAmount)}</td>
                </tr>
                """
            else:
                line_rows += f"""
                <tr>
                    <td>{h(line.LineDescription)}</td>
                    <td>{h(line.Unit)}</td>
                    <td class="right">{h(line.Qty)}</td>
                    <td class="right">{currency(line.UnitCost)}</td>
                    <td class="right">{currency(line.LineAmount)}</td>
                    <td class="right">{currency(line.RemainingAmount)}</td>
                </tr>
                """

        if not line_rows:
            colspan = 5 if packet_type == "vendor" else 6
            line_rows = f'<tr><td colspan="{colspan}"><div class="empty-state"><strong>No line items found.</strong><span>This packet has no imported line detail yet.</span></div></td></tr>'

        internal_link = "/po-packet/" + quote_plus(str(po.PONumber or "")) + "?type=internal"
        vendor_link = "/po-packet/" + quote_plus(str(po.PONumber or "")) + "?type=vendor"
        subtitle = "Vendor-facing purchase order packet" if packet_type == "vendor" else "Internal purchase order packet with balances and audit context"
        balance_fields = "" if packet_type == "vendor" else f"""
            <div class="packet-field"><span>Total Line Amount</span><strong>{currency(po.TotalLineAmount)}</strong></div>
            <div class="packet-field"><span>Posted Expenses</span><strong>{currency(getattr(po, 'PostedExpenseAmount', 0))}</strong></div>
            <div class="packet-field"><span>Current App Balance</span><strong>{currency(po.RemainingAmount)}</strong></div>
            <div class="packet-field"><span>Line Count</span><strong>{h(po.LineCount)}</strong></div>
        """
        internal_timeline = "" if packet_type == "vendor" else f"""
        <div class="card">
            <h3>Internal Audit Timeline</h3>
            <div class="timeline">
                <div class="timeline-item"><strong>Issued PO Imported</strong><span>PO data loaded from the issued PO import file.</span></div>
                <div class="timeline-item"><strong>Balance Tracking</strong><span>Open balance and line totals are calculated from imported PO rows.</span></div>
                <div class="timeline-item"><strong>Next Action</strong><span>Use this packet for internal review, backup, and reconciliation.</span></div>
            </div>
        </div>
        """

        line_headers = "<th>Description</th><th>Unit</th><th class=\"right\">Qty</th><th class=\"right\">Unit Cost</th><th class=\"right\">Line Amount</th>"
        if packet_type == "internal":
            line_headers += "<th class=\"right\">Remaining</th>"

        content = f"""
        <div class="packet-actions">
            <a class="secondary" href="/pos-balances">Back to POs & Balances</a>
            <a class="secondary" href="{internal_link}">Internal Packet</a>
            <a class="secondary" href="{vendor_link}">Vendor Packet</a>
            <button class="primary" onclick="window.print()">Print / Save PDF</button>
        </div>
        <div class="card">
            <div class="packet-header">
                <div class="packet-title">
                    <p class="eyebrow">Coastal Engineering Procurement</p>
                    <h1>{h('Vendor PO Packet' if packet_type == 'vendor' else 'Internal PO Packet')}</h1>
                    <p>{h(subtitle)}</p>
                </div>
                <img class="packet-logo" src="{CE_LOGO_DATA_URI}" alt="Coastal Engineering logo">
            </div>
            <div class="packet-meta">
                <div class="packet-field"><span>PO Number</span><strong>{h(po.PONumber)}</strong></div>
                <div class="packet-field"><span>Vendor</span><strong>{h(po.VendorName)}</strong></div>
                <div class="packet-field"><span>Project</span><strong>{h(po.ProjectName)}</strong></div>
                <div class="packet-field"><span>Department</span><strong>{h(po.Department)}</strong></div>
                <div class="packet-field"><span>PO Date</span><strong>{h(po.PODate)}</strong></div>
                <div class="packet-field"><span>Status</span><strong>{status_chip(po.POStatus)}</strong></div>
                <div class="packet-field"><span>Requestor</span><strong>{h(getattr(po, 'Requestor', '') or '')}</strong></div>
                <div class="packet-field"><span>Payment Type</span><strong>{h(getattr(po, 'PaymentType', '') or 'Not set')}</strong></div>
                <div class="packet-field"><span>Expected Payment Date</span><strong>{h(getattr(po, 'ExpectedPaymentDate', '') or 'Not set')}</strong></div>
                <div class="packet-field"><span>PO Value</span><strong>{currency(po.POValue)}</strong></div>
                {balance_fields}
            </div>
        </div>
        <div class="card">
            <h3>Payment Schedule</h3>
            {render_payment_schedule_for_packet(getattr(po, 'PaymentSchedule', '') or '')}
        </div>
        <div class="card">
            <h3>PO Line Items</h3>
            <div class="table-wrap"><table><tr>{line_headers}</tr>{line_rows}</table></div>
        </div>
        {attachment_card(po.PONumber) if packet_type == 'internal' else ''}
        {posted_expense_card(posted_expenses) if packet_type == 'internal' else ''}
        {internal_timeline}
        """
        page_title = "Vendor PO Packet" if packet_type == "vendor" else "Internal PO Packet"
        return shell(page_title, h(po.PONumber), "POs & Balances", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading PO packet: {h(e)}</div>'
        return shell("PO Packet", "Unable to load PO packet.", "POs & Balances", content), 500


@app.route("/project-po-setup", methods=["GET", "POST"])
def project_po_setup():
    allowed, reason = require_page_access("PO Setup Review")
    if not allowed:
        return access_denied_response("PO Setup Review", reason)

    user = get_current_user()

    if request.method == "POST":
        try:
            update_po_setup_info(request.form)
            return redirect("/project-po-setup?toast=" + quote_plus("PO setup information updated."))
        except Exception as e:
            return redirect("/project-po-setup?toast=" + quote_plus("Error updating PO setup: " + str(e)) + "&toast_type=error")

    try:
        status_filter = clean_text(request.args.get("status")) or "All"
        assigned_filter = None
        if request.args.get("mine") == "1":
            assigned_filter = user["email"]

        rows = load_project_po_setup_items(status_filter=status_filter, assigned_filter=assigned_filter)
        assignable_users = load_assignable_users()

        needs_schedule = sum(1 for r in rows if getattr(r, "MissingPaymentSchedule", 0))
        needs_type = sum(1 for r in rows if getattr(r, "MissingPaymentType", 0))
        needs_date = sum(1 for r in rows if getattr(r, "MissingExpectedPaymentDate", 0))
        needs_vendor = sum(1 for r in rows if getattr(r, "MissingVendor", 0))
        assigned = sum(1 for r in rows if (r.SetupAssignedTo or ""))
        total_amount = sum(Decimal(str(r.RemainingAmount or 0)) for r in rows)

        status_links = ""
        for label in ["All", "Needs Payment Schedule", "Assigned to PM", "In Progress", "Needs Info", "Complete"]:
            active_class = " active" if status_filter == label else ""
            href = "/project-po-setup" if label == "All" else "/project-po-setup?status=" + quote_plus(label)
            status_links += f'<a class="{active_class.strip()}" href="{href}">{status_chip(label)}</a>'

        project_names = []
        for r in rows:
            project_name = clean_text(getattr(r, "ProjectName", ""))
            if project_name and project_name not in project_names:
                project_names.append(project_name)
        project_filter_options = '<option value="">All projects</option>'
        for project_name in sorted(project_names):
            project_filter_options += f'<option value="{h(project_name)}">{h(project_name)}</option>'

        table_rows = ""
        for r in rows:
            packet_url = "/po-packet/" + quote_plus(str(r.PONumber or "")) + "?type=internal"
            selected_status = clean_text(r.SetupStatus) or "Needs Payment Schedule"
            selected_type = clean_text(r.PaymentType) or "Single Payment"
            multi_payment_types = {"Multiple Payments", "Deposit + Final", "Progress Payments", "Monthly", "Milestone", "Retainage"}
            payment_type_options = ""
            for opt in ["Single Payment", "Multiple Payments", "Deposit + Final", "Progress Payments", "Monthly", "Milestone", "Retainage", "Other"]:
                sel = " selected" if opt == selected_type else ""
                payment_type_options += f'<option value="{h(opt)}"{sel}>{h(opt)}</option>'

            status_options = ""
            for opt in ["Needs Payment Schedule", "Assigned to PM", "In Progress", "Needs Info", "Complete", "Not Required"]:
                sel = " selected" if opt == selected_status else ""
                status_options += f'<option value="{h(opt)}"{sel}>{h(opt)}</option>'

            missing_bits = []
            if getattr(r, "MissingVendor", 0):
                missing_bits.append("Vendor")
            if getattr(r, "MissingPaymentSchedule", 0):
                missing_bits.append("Payment schedule")
            if getattr(r, "MissingPaymentType", 0):
                missing_bits.append("Payment type")
            if getattr(r, "MissingExpectedPaymentDate", 0):
                missing_bits.append("Expected payment date")
            missing_html = ", ".join(missing_bits) if missing_bits else "No required info missing"

            expected_payment_date = "" if not r.ExpectedPaymentDate else str(r.ExpectedPaymentDate)[:10]

            existing_schedule_lines = [line.strip() for line in str(r.PaymentSchedule or "").splitlines() if line.strip()]
            requires_multiple = selected_type in multi_payment_types or len(existing_schedule_lines) > 1
            schedule_inputs = '<input type="hidden" name="expected_payment_date" value="' + h(expected_payment_date) + '">'
            for idx in range(1, 5):
                existing_line = existing_schedule_lines[idx - 1] if idx - 1 < len(existing_schedule_lines) else ""
                row_style = "" if idx == 1 or requires_multiple else "display:none;"
                date_value = expected_payment_date if idx == 1 and expected_payment_date else ""
                schedule_inputs += f'''
                    <div class="payment-schedule-row" data-payment-row="{idx}" style="{row_style}">
                        <div class="payment-row-label">Payment {idx}</div>
                        <input type="date" name="payment_{idx}_date" value="{h(date_value if idx == 1 else '')}" aria-label="Payment {idx} date">
                        <input type="text" name="payment_{idx}_amount" placeholder="Amount/%" aria-label="Payment {idx} amount or percent">
                        <input type="text" name="payment_{idx}_note" value="{h(existing_line)}" placeholder="Milestone or terms" aria-label="Payment {idx} note">
                    </div>
                '''
            assigned_options = '<option value="">Unassigned</option>'
            selected_assigned = (clean_text(r.SetupAssignedTo) or "").lower()
            for u in assignable_users:
                user_email = (clean_text(u.Email) or "").lower()
                if not user_email:
                    continue
                display = clean_text(u.DisplayName) or user_email
                role = clean_text(u.RoleName)
                label_text = display + (f" ({role})" if role else "")
                sel = " selected" if user_email == selected_assigned else ""
                assigned_options += f'<option value="{h(user_email)}"{sel}>{h(label_text)}</option>'

            table_rows += f"""
            <tr>
                <form method="post" action="/project-po-setup">
                    <input type="hidden" name="po_number" value="{h(r.PONumber)}">
                    <td class="po-number-cell"><div class="po-review-id"><a class="po-link" href="{packet_url}">{h(r.PONumber)}</a><span class="po-status-row">{status_chip(selected_status)}</span></div></td>
                    <td>{h(r.ProjectName)}<br><small>{h(r.Department)}</small></td>
                    <td>{('<input type="text" name="vendor_name" value="" placeholder="Enter vendor" aria-label="Vendor name">' if getattr(r, "MissingVendor", 0) else h(r.VendorName))}<br><small>{currency(r.POValue)}</small></td>
                    <td>{h(r.Requestor or '')}</td>
                    <td><select name="payment_type" onchange="togglePaymentScheduleRows(this)">{payment_type_options}</select></td>
                    <td class="payment-schedule-cell"><div class="payment-schedule-builder">{schedule_inputs}</div></td>
                    <td class="assign-cell"><select name="setup_assigned_to">{assigned_options}</select></td>
                    <td><select name="setup_status">{status_options}</select></td>
                    <td class="inline-actions">
                        <button class="primary" name="setup_action" value="save" type="submit">Update</button>
                        <button class="secondary" name="setup_action" value="assign" type="submit">Assign</button>
                        <button class="secondary" name="setup_action" value="complete" type="submit">Complete</button>
                    </td>
                </form>
            </tr>
            """

        if not table_rows:
            table_rows = '<tr><td colspan="9"><div class="empty-state"><strong>No PO setup items found.</strong><span>POs missing payment schedules, payment type, or expected payment dates will appear here.</span></div></td></tr>'

        mine_link = ""
        if user["email"]:
            mine_link = f'<a class="button secondary" href="/project-po-setup?mine=1">My Assigned PO Info Tasks</a>'

        content = f"""
<div class="card">
            <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap;">
                <div>
                    <h3>PO Setup Review Table</h3>
                    <p class="card-subtitle">Update missing payment schedule information directly, or assign the PO to a project manager so it appears as an action item on their dashboard.</p>
                </div>
                <div>{mine_link}</div>
            </div>
            <div class="table-wrap setup-table">
                <table id="poInfoReviewTable">
                    <thead>
                        <tr>
                            <th>PO</th>
                            <th class="project-filter-th">
                                <div class="project-filter-head"><span>Project</span><button class="project-filter-button" type="button" onclick="togglePOProjectFilter()" title="Filter by project" aria-label="Filter by project"><span class="filter-icon">◇</span></button></div>
                                <select id="poProjectFilter" class="project-filter-select" onchange="filterPOInfoReviewByProject()">{project_filter_options}</select>
                            </th>
                            <th>Vendor / Amount</th><th>Requestor</th><th>Payment Type</th><th>Payment Schedule</th><th>Assigned To</th><th>Status</th><th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                    {table_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """
        content += """
        <script>
        function poSetupPaymentTypeRequiresMultiple(value) {
            return ["Multiple Payments", "Deposit + Final", "Progress Payments", "Monthly", "Milestone", "Retainage"].includes(value || "");
        }
        function togglePaymentScheduleRows(selectEl) {
            const rowContainer = selectEl.closest("tr") || selectEl.closest("form") || document;
            const requiresMultiple = poSetupPaymentTypeRequiresMultiple(selectEl.value);
            rowContainer.querySelectorAll("[data-payment-row]").forEach(function(row) {
                const idx = Number(row.getAttribute("data-payment-row") || "1");
                const show = idx === 1 || requiresMultiple;
                row.style.display = show ? "grid" : "none";
                row.querySelectorAll("input").forEach(function(input) {
                    if (idx > 1 && !show) input.value = "";
                });
            });
        }
        function togglePOProjectFilter() {
            const select = document.getElementById("poProjectFilter");
            if (!select) return;
            select.classList.toggle("show");
            if (select.classList.contains("show")) select.focus();
        }
        function filterPOInfoReviewByProject() {
            const table = document.getElementById("poInfoReviewTable");
            const select = document.getElementById("poProjectFilter");
            if (!table || !select) return;
            const selectedProject = (select.value || "").trim().toLowerCase();
            table.querySelectorAll("tbody tr").forEach(function(row) {
                const cells = row.querySelectorAll("td");
                if (!cells.length) return;
                const projectText = (cells[1] ? cells[1].innerText : "").toLowerCase();
                row.style.display = (!selectedProject || projectText.includes(selectedProject)) ? "" : "none";
            });
        }
        document.addEventListener("DOMContentLoaded", function() {
            document.querySelectorAll('select[name="payment_type"]').forEach(togglePaymentScheduleRows);
            filterPOInfoReviewByProject();
        });
        </script>
        """
        return shell("PO Setup Review", "Update missing PO planning details and assign follow-up work.", "PO Setup Review", content)

    except Exception as e:
        content = f'<div class="notice error">Error loading PO Info Review: {h(e)}</div>'
        return shell("PO Setup Review", "Unable to load setup queue.", "PO Setup Review", content), 500


@app.route("/expenses")
def expenses_page():
    allowed, reason = require_page_access("Expenses")
    if not allowed:
        return access_denied_response("Expenses", reason)
    try:
        ensure_expense_review_tables()
        filters = {
            "project": clean_text(request.args.get("project")) or "",
            "vendor": clean_text(request.args.get("vendor")) or "",
            "type": clean_text(request.args.get("type")) or "",
            "status": clean_text(request.args.get("status")) or "",
            "decision": clean_text(request.args.get("decision")) or "",
            "po": clean_text(request.args.get("po")) or "",
            "search": clean_text(request.args.get("search")) or "",
        }
        where = []
        params = []
        add_like_filter(where, params, "ProjectName", filters["project"])
        add_like_filter(where, params, "VendorName", filters["vendor"])
        add_like_filter(where, params, "TxType", filters["type"])
        add_like_filter(where, params, "MatchStatus", filters["status"])
        add_like_filter(where, params, "ReviewDecision", filters["decision"])
        if filters["po"]:
            where.append("LOWER(COALESCE(CorrectPONumber, MatchedPONumber, ExtractedPONumber, '')) LIKE LOWER(?)")
            params.append("%" + filters["po"] + "%")
        if filters["search"]:
            where.append("LOWER(CONCAT(COALESCE(ExpenseId,''), ' ', COALESCE(ProjectName,''), ' ', COALESCE(TxType,''), ' ', COALESCE(VendorName,''), ' ', COALESCE(Description,''), ' ', COALESCE(PMComments,''))) LIKE LOWER(?)")
            params.append("%" + filters["search"] + "%")
        where_sql = "WHERE " + " AND ".join(where) if where else ""

        conn = get_sql_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                COUNT(*) AS TotalRows,
                SUM(CASE WHEN MatchStatus IN ('Auto Matched','Manually Matched') THEN 1 ELSE 0 END) AS MatchedRows,
                SUM(CASE WHEN MatchStatus IN ('Needs Review','No Match') THEN 1 ELSE 0 END) AS ReviewRows,
                SUM(CASE WHEN COALESCE(PostedToPO, 0) = 1 THEN 1 ELSE 0 END) AS PostedRows,
                SUM(COALESCE(Amount, 0)) AS TotalAmount,
                SUM(CASE WHEN COALESCE(PostedToPO, 0) = 1 THEN COALESCE(PostedAmount, Amount, 0) ELSE 0 END) AS PostedAmount
            FROM dbo.ExpenseReviewItems;
        """)
        stats = cursor.fetchone()
        cursor.execute(
            f"""
            SELECT TOP 750 ExpenseReviewItemId, ExpenseId, ProjectName, TxDate, TxType, VendorName,
                   Description, Amount, PMComments, ExtractedPONumber, MatchedPONumber, MatchStatus,
                   MatchConfidence, ReviewDecision, CorrectPONumber, PostedToPO, PostedPONumber,
                   PostedAmount, PostedAt, PostedBy, ReviewerEmail, ReviewedAt, IsDuplicate
            FROM dbo.ExpenseReviewItems
            {where_sql}
            ORDER BY TxDate DESC, ExpenseReviewItemId DESC;
            """,
            *params,
        )
        rows = cursor.fetchall()
        conn.close()

        table_rows = ""
        for r in rows:
            status_class = str(r.MatchStatus or "").lower().replace(" ", "-")
            po_number = r.CorrectPONumber or r.MatchedPONumber or r.ExtractedPONumber or ""
            posted_po = r.PostedPONumber or po_number
            po_link = f'<a href="/po-detail?po_number={quote_plus(str(posted_po))}">{h(posted_po)}</a>' if posted_po else ""
            unpost_button = ""
            if getattr(r, "PostedToPO", 0):
                unpost_button = (
                    f'<form method="post" action="/expense-review/unpost" onsubmit="return confirm(\'Reverse this posted expense from the PO balance?\');">'
                    f'<input type="hidden" name="item_id" value="{h(r.ExpenseReviewItemId)}">'
                    f'<button class="secondary" type="submit">Unpost</button></form>'
                )
            table_rows += f"""
            <tr>
                <td><span class="status-chip {h(status_class)}">{h(r.MatchStatus)}</span><br>{posting_status_chip(r)}<br><small>{h(r.MatchConfidence)}</small></td>
                <td><strong>{h(r.ExpenseId or r.ExpenseReviewItemId)}</strong><br><small>{h(r.TxDate)}</small></td>
                <td>{h(r.ProjectName)}</td>
                <td>{h(r.TxType)}</td>
                <td>{h(r.VendorName)}</td>
                <td class="right">{currency(r.Amount)}</td>
                <td>{h(r.Description)}<br><small>{h(r.PMComments)}</small></td>
                <td>{po_link}</td>
                <td>{h(r.ReviewDecision)}</td>
                <td class="posting-audit-cell">{h(posting_reason(r))}<br><strong>{currency(getattr(r, 'PostedAmount', 0)) if getattr(r, 'PostedToPO', 0) else ''}</strong><br><small>{h(getattr(r, 'PostedBy', '') or '')} {h(getattr(r, 'PostedAt', '') or '')}</small>{unpost_button}</td>
            </tr>
            """
        if not table_rows:
            table_rows = '<tr><td colspan="10"><div class="empty-state"><strong>No expenses found.</strong><span>Adjust filters or upload a Unanet expense file.</span></div></td></tr>'

        filter_bar = build_simple_filter_bar(filters, "/expenses", [
            ("project", "Project", "Project name/code"),
            ("vendor", "Vendor", "Vendor or purchaser"),
            ("type", "Type", "Purchase, Disbursement..."),
            ("status", "Match Status", "Auto Matched, No Match..."),
            ("decision", "Decision", "Matched to PO, No PO Needed..."),
            ("po", "PO", "PO number"),
            ("search", "Search", "Description or comments"),
        ])
        content = f"""
        <div class="grid kpis">
            <a class="card kpi status-card" href="/expense-upload"><div class="label">Expense Rows</div><div class="value">{int(stats.TotalRows or 0)}</div><div class="trend">Imported from Unanet uploads</div></a>
            <a class="card kpi status-card" href="/expenses"><div class="label">Expense Amount</div><div class="value">{currency(stats.TotalAmount)}</div><div class="trend">Total uploaded expense value</div></a>
            <a class="card kpi status-card" href="/pos-in-pm-comments"><div class="label">Matched / Linked</div><div class="value">{int(stats.MatchedRows or 0)}</div><div class="trend">Auto or manually matched rows</div></a>
            <a class="card kpi status-card" href="/missing-po-review"><div class="label">Needs Review</div><div class="value">{int(stats.ReviewRows or 0)}</div><div class="trend">Rows needing PO decision</div></a>
            <a class="card kpi status-card" href="/pos-balances"><div class="label">Posted to POs</div><div class="value">{currency(stats.PostedAmount)}</div><div class="trend">{int(stats.PostedRows or 0)} rows reducing balances</div></a>
        </div>
        {filter_bar}
        <div class="card">
            <h3>Expenses</h3>
            <p class="card-subtitle">Imported Unanet expense rows with match status, posting status, and audit detail. Posted rows reduce Current App Balance.</p>
            <div class="table-wrap"><table id="expensesTable">
                <tr><th>Status</th><th>Expense</th><th>Project</th><th>Type</th><th>Vendor / Purchaser</th><th class="right">Amount</th><th>Description / PM Comments</th><th>PO</th><th>Decision</th><th>Posting Audit</th></tr>
                {table_rows}
            </table></div>
        </div>
        """
        return shell("Expenses", "Imported Unanet expense rows and PO match status.", "Expenses", content)
    except Exception as e:
        return shell("Expenses", "Unable to load expenses.", "Expenses", f'<div class="notice error">Error loading Expenses: {h(e)}</div>'), 500


@app.route("/missing-po-review")
def missing_po_review():
    allowed, reason = require_page_access("Missing PO Review")
    if not allowed:
        return access_denied_response("Missing PO Review", reason)
    try:
        ensure_expense_review_tables()
        filters = {
            "project": clean_text(request.args.get("project")) or "",
            "vendor": clean_text(request.args.get("vendor")) or "",
            "type": clean_text(request.args.get("type")) or "",
            "status": clean_text(request.args.get("status")) or "",
            "decision": clean_text(request.args.get("decision")) or "",
            "search": clean_text(request.args.get("search")) or "",
        }
        where = ["(COALESCE(ReviewDecision, 'Pending Review') IN ('Pending Review','Needs PM Review','Hold for More Info') OR MatchStatus IN ('Needs Review','No Match'))"]
        params = []
        add_like_filter(where, params, "ProjectName", filters["project"])
        add_like_filter(where, params, "VendorName", filters["vendor"])
        add_like_filter(where, params, "TxType", filters["type"])
        add_like_filter(where, params, "MatchStatus", filters["status"])
        add_like_filter(where, params, "ReviewDecision", filters["decision"])
        if filters["search"]:
            where.append("LOWER(CONCAT(COALESCE(ExpenseId,''), ' ', COALESCE(ProjectName,''), ' ', COALESCE(VendorName,''), ' ', COALESCE(Description,''), ' ', COALESCE(PMComments,''), ' ', COALESCE(MatchReason,''))) LIKE LOWER(?)")
            params.append("%" + filters["search"] + "%")
        where_sql = "WHERE " + " AND ".join(where)
        conn = get_sql_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT PONumber FROM dbo.PurchaseOrders WHERE PONumber IS NOT NULL ORDER BY PONumber")
        po_numbers = [row.PONumber for row in cursor.fetchall()]
        cursor.execute(
            f"""
            SELECT TOP 500 ExpenseReviewItemId, ExpenseId, ProjectName, TxDate, TxType, VendorName,
                   Description, Amount, PMComments, ExtractedPONumber, MatchedPONumber, MatchStatus,
                   MatchConfidence, MatchReason, ReviewDecision, CorrectPONumber, ReviewerNotes,
                   PostedToPO, PostedPONumber, PostedAmount, PostedAt, PostedBy, ReviewerEmail, ReviewedAt, IsDuplicate
            FROM dbo.ExpenseReviewItems
            {where_sql}
            ORDER BY CASE WHEN MatchStatus = 'No Match' THEN 0 WHEN MatchStatus = 'Needs Review' THEN 1 ELSE 2 END,
                     ABS(COALESCE(Amount,0)) DESC, ExpenseReviewItemId DESC;
            """,
            *params,
        )
        rows = cursor.fetchall()
        cursor.execute(
            """
            SELECT COUNT(*) AS TotalOpen,
                   SUM(CASE WHEN MatchStatus = 'No Match' THEN 1 ELSE 0 END) AS NoMatch,
                   SUM(CASE WHEN MatchStatus = 'Needs Review' THEN 1 ELSE 0 END) AS NeedsReview,
                   SUM(COALESCE(Amount, 0)) AS OpenAmount
            FROM dbo.ExpenseReviewItems
            WHERE COALESCE(ReviewDecision, 'Pending Review') IN ('Pending Review','Needs PM Review','Hold for More Info')
               OR MatchStatus IN ('Needs Review','No Match');
            """
        )
        stats = cursor.fetchone()
        conn.close()

        po_options = "".join(f'<option value="{h(po)}">' for po in po_numbers)
        row_html = ""
        for r in rows:
            suggested = r.MatchedPONumber or r.ExtractedPONumber or ""
            status_class = str(r.MatchStatus or "").lower().replace(" ", "-")
            row_html += f"""
            <tr>
                <td><span class="status-chip {h(status_class)}">{h(r.MatchStatus)}</span><br>{posting_status_chip(r)}<br><small>{h(r.MatchConfidence)}</small></td>
                <td><strong>{h(r.ExpenseId or r.ExpenseReviewItemId)}</strong><br><small>{h(r.TxDate)}</small></td>
                <td>{h(r.ProjectName)}</td>
                <td>{h(r.VendorName)}<br><small>{h(r.TxType)}</small></td>
                <td class="right">{currency(r.Amount)}</td>
                <td>{h(r.Description)}<br><small>{h(r.PMComments)}</small></td>
                <td>{h(suggested)}<br><small>{h(r.MatchReason)}</small></td>
                <td class="posting-audit-cell">{h(posting_reason(r))}<br><small>{h(r.PostedPONumber or '')} {currency(r.PostedAmount) if r.PostedToPO else ''}</small></td>
                <td class="expense-action-cell">
                    <form class="expense-match-form" method="post" action="/expense-review/update">
                        <input type="hidden" name="item_id" value="{h(r.ExpenseReviewItemId)}">
                        <input list="poNumberList" name="correct_po_number" value="{h(r.CorrectPONumber or suggested)}" placeholder="Correct PO number">
                        <select name="review_decision">
                            {select_option('Pending Review', r.ReviewDecision or 'Pending Review')}
                            {select_option('Matched to PO', r.ReviewDecision or 'Pending Review')}
                            {select_option('No PO Needed', r.ReviewDecision or 'Pending Review')}
                            {select_option('Needs PM Review', r.ReviewDecision or 'Pending Review')}
                            {select_option('Hold for More Info', r.ReviewDecision or 'Pending Review')}
                        </select>
                        <textarea name="reviewer_notes" placeholder="Reviewer notes">{h(r.ReviewerNotes)}</textarea>
                        <button class="primary" type="submit">Save Decision</button>
                    </form>
                </td>
            </tr>
            """
        if not row_html:
            row_html = '<tr><td colspan="9"><div class="empty-state"><strong>No missing PO review items.</strong><span>Rows needing PO decisions will appear here after expense uploads.</span></div></td></tr>'
        filter_bar = build_simple_filter_bar(filters, "/missing-po-review", [("project", "Project", "Project name/code"), ("vendor", "Vendor", "Vendor or purchaser"), ("type", "Type", "Purchase, Disbursement..."), ("status", "Match Status", "No Match, Needs Review..."), ("decision", "Decision", "Pending Review..."), ("search", "Search", "Description or comments")])
        content = f"""
        <div class="notice info"><strong>Missing PO Review:</strong> Use this page to review expenses that may need a PO or corrected PO reference. Rows only reduce PO balances after they are posted as valid matches.</div>
        <div class="grid kpis">
            <a class="card kpi status-card" href="/missing-po-review"><div class="label">Open Review Items</div><div class="value">{int(stats.TotalOpen or 0)}</div><div class="trend">Rows needing PO decision</div></a>
            <a class="card kpi status-card" href="/missing-po-review?status=No+Match"><div class="label">No Match</div><div class="value">{int(stats.NoMatch or 0)}</div><div class="trend">No clear PO found</div></a>
            <a class="card kpi status-card" href="/missing-po-review?status=Needs+Review"><div class="label">Needs Review</div><div class="value">{int(stats.NeedsReview or 0)}</div><div class="trend">Suggested match needs validation</div></a>
            <a class="card kpi status-card" href="/missing-po-review"><div class="label">Review Amount</div><div class="value">{currency(stats.OpenAmount)}</div><div class="trend">Open review dollar value</div></a>
        </div>
        {filter_bar}
        <div class="card" id="review-table">
            <h3>Missing PO Review</h3>
            <p class="card-subtitle">PMs can help identify the correct PO; Accounting/Admin controls upload and posting oversight.</p>
            <datalist id="poNumberList">{po_options}</datalist>
            <div class="table-wrap expense-review-table"><table>
                <tr><th>Status</th><th>Expense</th><th>Project</th><th>Vendor / Purchaser</th><th class="right">Amount</th><th>Description / PM Comments</th><th>Suggested PO</th><th>Posting</th><th>Review Action</th></tr>
                {row_html}
            </table></div>
        </div>
        """
        return shell("Missing PO Review", "Expense rows that need a PO decision.", "Missing PO Review", content)
    except Exception as e:
        return shell("Missing PO Review", "Unable to load missing PO review.", "Missing PO Review", f'<div class="notice error">Error loading Missing PO Review: {h(e)}</div>'), 500


@app.route("/vendors")
def vendors_page():
    allowed, reason = require_page_access("Vendors")
    if not allowed:
        return access_denied_response("Vendors", reason)
    try:
        ensure_expense_review_tables()
        conn = get_sql_connection()
        cursor = conn.cursor()
        req_where_po, req_params_po = requestor_filter_sql("po")
        cursor.execute(
            f"""
            WITH POVendors AS (
                SELECT COALESCE(v.VendorName, 'Missing Vendor') AS VendorName,
                       COUNT(DISTINCT po.PONumber) AS POCount,
                       SUM(COALESCE(po.RevisedAmount, po.OriginalAmount, 0)) AS POAmount,
                       SUM(COALESCE(po.RemainingAmount, COALESCE(po.RevisedAmount, po.OriginalAmount, 0))) AS RemainingAmount
                FROM dbo.PurchaseOrders po
                LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
                WHERE {req_where_po}
                GROUP BY COALESCE(v.VendorName, 'Missing Vendor')
            ), ExpenseVendors AS (
                SELECT COALESCE(NULLIF(LTRIM(RTRIM(VendorName)), ''), 'Missing Vendor') AS VendorName,
                       COUNT(*) AS ExpenseRows,
                       SUM(COALESCE(Amount,0)) AS ExpenseAmount
                FROM dbo.ExpenseReviewItems
                GROUP BY COALESCE(NULLIF(LTRIM(RTRIM(VendorName)), ''), 'Missing Vendor')
            )
            SELECT COALESCE(p.VendorName, e.VendorName) AS VendorName,
                   COALESCE(p.POCount, 0) AS POCount,
                   COALESCE(p.POAmount, 0) AS POAmount,
                   COALESCE(p.RemainingAmount, 0) AS RemainingAmount,
                   COALESCE(e.ExpenseRows, 0) AS ExpenseRows,
                   COALESCE(e.ExpenseAmount, 0) AS ExpenseAmount
            FROM POVendors p
            FULL OUTER JOIN ExpenseVendors e ON p.VendorName = e.VendorName
            ORDER BY COALESCE(p.POAmount, 0) DESC, COALESCE(e.ExpenseAmount, 0) DESC;
            """,
            *req_params_po,
        )
        rows = cursor.fetchall()

        selected_vendor = clean_text(request.args.get("vendor")) or ""
        vendor_line_rows = ""
        if selected_vendor:
            cursor.execute(
                """
                SELECT TOP 500
                    po.PONumber,
                    COALESCE(pr.ProjectName, '') AS ProjectName,
                    po.Department,
                    l.LineDescription,
                    l.Unit,
                    l.UnitCost,
                    l.Qty,
                    l.LineAmount
                FROM dbo.IssuedPOLines l
                INNER JOIN dbo.PurchaseOrders po ON l.PurchaseOrderId = po.PurchaseOrderId
                LEFT JOIN dbo.Vendors v ON po.VendorId = v.VendorId
                LEFT JOIN dbo.Projects pr ON po.ProjectId = pr.ProjectId
                WHERE LOWER(COALESCE(v.VendorName, 'Missing Vendor')) = LOWER(?) AND {req_where_po}
                ORDER BY po.PONumber, l.IssuedPOLineId;
                """.format(req_where_po=req_where_po),
                selected_vendor,
                *req_params_po,
            )
            vendor_lines = cursor.fetchall()
            for line in vendor_lines:
                vendor_line_rows += f"""
                <tr>
                    <td><a class="po-link" href="/po-detail?po_number={quote_plus(str(line.PONumber or ''))}">{h(line.PONumber)}</a></td>
                    <td>{h(line.ProjectName)}</td>
                    <td>{h(line.Department)}</td>
                    <td>{h(line.LineDescription)}</td>
                    <td>{h(line.Unit)}</td>
                    <td class="right">{currency(line.UnitCost)}</td>
                    <td class="right">{h(line.Qty)}</td>
                    <td class="right">{currency(line.LineAmount)}</td>
                </tr>
                """
            if not vendor_line_rows:
                vendor_line_rows = '<tr><td colspan="8"><div class="empty-state"><strong>No PO line items found for this vendor.</strong></div></td></tr>'

        conn.close()

        total_vendors = len(rows)
        total_po_amount = sum(float(r.POAmount or 0) for r in rows)
        total_expense_amount = sum(float(r.ExpenseAmount or 0) for r in rows)
        table_rows = ""
        top_rows = ""
        max_po = max([float(r.POAmount or 0) for r in rows] or [1])
        for idx, r in enumerate(rows):
            table_rows += f"""
            <tr><td><a class="vendor-detail-link" href="/vendors?vendor={quote_plus(str(r.VendorName or ''))}">{h(r.VendorName)}</a></td><td class="right">{int(r.POCount or 0)}</td><td class="right">{currency(r.POAmount)}</td><td class="right">{currency(r.RemainingAmount)}</td><td class="right">{int(r.ExpenseRows or 0)}</td><td class="right">{currency(r.ExpenseAmount)}</td></tr>
            """
            if idx < 8:
                width = 0 if max_po == 0 else max(5, float(r.POAmount or 0) / max_po * 100)
                top_rows += f"<div class='bar-row'><strong>{h(r.VendorName)}</strong><div class='bar-track'><div class='bar-fill' style='width:{width:.1f}%'></div></div><div class='right'>{currency(r.POAmount)}</div></div>"
        if not table_rows:
            table_rows = '<tr><td colspan="6"><div class="empty-state"><strong>No vendor data found.</strong><span>Vendors will appear after PO or expense uploads.</span></div></td></tr>'
            top_rows = '<p class="card-subtitle">No vendor data found.</p>'

        content = f"""
        <div class="grid kpis">
            <div class="card kpi"><div class="label">Vendors</div><div class="value">{total_vendors}</div><div class="trend">Across POs and expenses</div></div>
            <div class="card kpi"><div class="label">Issued PO Amount</div><div class="value">{currency(total_po_amount)}</div><div class="trend">Vendor commitment value</div></div>
            <div class="card kpi"><div class="label">Expense Amount</div><div class="value">{currency(total_expense_amount)}</div><div class="trend">Uploaded expense value</div></div>
            <a class="card kpi status-card" href="/pos-balances"><div class="label">POs & Balances</div><div class="value">View</div><div class="trend">Open PO detail</div></a>
        </div>
        <div class="grid two">
            <div class="card"><h3>Top Vendors by PO Amount</h3><div class="bar-chart">{top_rows}</div></div>
            <div class="card"><h3>Vendor Summary</h3><p class="card-subtitle">Click a vendor name to view all PO line items for that vendor.</p><div class="table-wrap"><table><tr><th>Vendor / Purchaser</th><th class="right">POs</th><th class="right">PO Amount</th><th class="right">Remaining</th><th class="right">Expense Rows</th><th class="right">Expense Amount</th></tr>{table_rows}</table></div></div>
        </div>
        {f'<div class="card"><h3>PO Line Items for {h(selected_vendor)}</h3><p class="card-subtitle">Click a PO number to open the full PO.</p><div class="table-wrap"><table><tr><th>PO</th><th>Project</th><th>Department</th><th>Description</th><th>Unit</th><th class="right">Unit Cost</th><th class="right">Qty</th><th class="right">Line Amount</th></tr>{vendor_line_rows}</table></div></div>' if selected_vendor else ''}
        """
        return shell("Vendors", "Vendor and purchaser totals across POs and expenses.", "Vendors", content)
    except Exception as e:
        return shell("Vendors", "Unable to load vendors.", "Vendors", f'<div class="notice error">Error loading Vendors: {h(e)}</div>'), 500


@app.route("/pos-in-pm-comments")
def pos_in_pm_comments_page():
    allowed, reason = require_page_access("POs in PM Comments")
    if not allowed:
        return access_denied_response("POs in PM Comments", reason)
    try:
        ensure_expense_review_tables()
        filters = {"project": clean_text(request.args.get("project")) or "", "vendor": clean_text(request.args.get("vendor")) or "", "po": clean_text(request.args.get("po")) or "", "status": clean_text(request.args.get("status")) or "", "decision": clean_text(request.args.get("decision")) or "", "search": clean_text(request.args.get("search")) or ""}
        where = ["(COALESCE(ExtractedPONumber, '') <> '' OR COALESCE(MatchedPONumber, '') <> '' OR PMComments LIKE '%PO%')", "COALESCE(PMComments, '') <> ''"]
        params = []
        add_like_filter(where, params, "ProjectName", filters["project"])
        add_like_filter(where, params, "VendorName", filters["vendor"])
        add_like_filter(where, params, "MatchStatus", filters["status"])
        add_like_filter(where, params, "ReviewDecision", filters["decision"])
        if filters["po"]:
            where.append("LOWER(COALESCE(CorrectPONumber, MatchedPONumber, ExtractedPONumber, '')) LIKE LOWER(?)")
            params.append("%" + filters["po"] + "%")
        if filters["search"]:
            where.append("LOWER(CONCAT(COALESCE(ExpenseId,''), ' ', COALESCE(ProjectName,''), ' ', COALESCE(VendorName,''), ' ', COALESCE(PMComments,''))) LIKE LOWER(?)")
            params.append("%" + filters["search"] + "%")
        where_sql = "WHERE " + " AND ".join(where)
        conn = get_sql_connection(); cursor = conn.cursor()
        cursor.execute(f"""SELECT TOP 500 ExpenseReviewItemId, ExpenseId, ProjectName, TxDate, TxType, VendorName, Amount, PMComments, ExtractedPONumber, MatchedPONumber, CorrectPONumber, MatchStatus, MatchConfidence, ReviewDecision, PostedToPO, PostedPONumber, PostedAmount, PostedAt, PostedBy, IsDuplicate FROM dbo.ExpenseReviewItems {where_sql} ORDER BY TxDate DESC, ExpenseReviewItemId DESC;""", *params)
        rows = cursor.fetchall(); conn.close()
        total_amount = sum(float(r.Amount or 0) for r in rows)
        unique_pos = len(set(str(r.CorrectPONumber or r.MatchedPONumber or r.ExtractedPONumber or '').strip() for r in rows if str(r.CorrectPONumber or r.MatchedPONumber or r.ExtractedPONumber or '').strip()))
        table_rows = ""
        for r in rows:
            po_number = r.CorrectPONumber or r.MatchedPONumber or r.ExtractedPONumber or ""
            po_link = f'<a href="/po-detail?po_number={quote_plus(str(po_number))}">{h(po_number)}</a>' if po_number else ""
            status_class = str(r.MatchStatus or "").lower().replace(" ", "-")
            table_rows += f"""<tr><td><span class="status-chip {h(status_class)}">{h(r.MatchStatus)}</span><br>{posting_status_chip(r)}<br><small>{h(r.MatchConfidence)}</small></td><td><strong>{h(r.ExpenseId or r.ExpenseReviewItemId)}</strong><br><small>{h(r.TxDate)}</small></td><td>{h(r.ProjectName)}</td><td>{h(r.VendorName)}<br><small>{h(r.TxType)}</small></td><td class="right">{currency(r.Amount)}</td><td>{h(r.PMComments)}</td><td>{po_link}</td><td>{h(r.ReviewDecision)}</td><td class="posting-audit-cell">{h(posting_reason(r))}<br><small>{h(r.PostedBy or '')} {h(r.PostedAt or '')}</small></td></tr>"""
        if not table_rows:
            table_rows = '<tr><td colspan="9"><div class="empty-state"><strong>No PO references found in PM comments.</strong><span>Adjust filters or upload expenses with PM comments.</span></div></td></tr>'
        filter_bar = build_simple_filter_bar(filters, "/pos-in-pm-comments", [("project", "Project", "Project name/code"), ("vendor", "Vendor", "Vendor or purchaser"), ("po", "PO", "PO number"), ("status", "Match Status", "Auto Matched..."), ("decision", "Decision", "Matched to PO..."), ("search", "Search", "PM comments")])
        content = f"""
        <div class="notice info"><strong>PM Comment PO Audit:</strong> This read-only page explains where PO references were found in PM Comments. Use Expense Upload / PO Matching or Missing PO Review to change decisions.</div>
        <div class="grid kpis"><div class="card kpi"><div class="label">Rows Found</div><div class="value">{len(rows)}</div><div class="trend">PM comments with PO-like references</div></div><div class="card kpi"><div class="label">Unique POs</div><div class="value">{unique_pos}</div><div class="trend">Referenced or matched POs</div></div><div class="card kpi"><div class="label">Referenced Amount</div><div class="value">{currency(total_amount)}</div><div class="trend">Filtered expense rows</div></div><a class="card kpi status-card" href="/missing-po-review"><div class="label">Review Queue</div><div class="value">Open</div><div class="trend">Validate uncertain matches</div></a></div>
        {filter_bar}
        <div class="card"><h3>PM Comment PO Audit</h3><p class="card-subtitle">Read-only audit view of expense rows where PO numbers or PO-like references were found in PM Comments.</p><div class="table-wrap"><table><tr><th>Status</th><th>Expense</th><th>Project</th><th>Vendor / Purchaser</th><th class="right">Amount</th><th>PM Comments</th><th>PO Reference</th><th>Decision</th><th>Posting</th></tr>{table_rows}</table></div></div>
        """
        return shell("POs in PM Comments", "Rows where PO references were found in PM Comments.", "POs in PM Comments", content)
    except Exception as e:
        return shell("POs in PM Comments", "Unable to load POs in PM Comments.", "POs in PM Comments", f'<div class="notice error">Error loading POs in PM Comments: {h(e)}</div>'), 500



@app.route("/purchase-request-attachment/<int:attachment_id>")
def purchase_request_attachment(attachment_id):
    allowed, reason = require_page_access("POs & Balances")
    if not allowed:
        return access_denied_response("POs & Balances", reason)
    try:
        conn = get_sql_connection()
        cursor = conn.cursor()
        ensure_request_attachment_table(cursor)
        cursor.execute(
            """
            SELECT StoragePath, OriginalFileName
            FROM dbo.PurchaseRequestAttachments
            WHERE AttachmentId = ?;
            """,
            attachment_id,
        )
        row = cursor.fetchone()
        conn.close()
        if not row or not os.path.exists(row.StoragePath):
            return shell("Attachment", "File not found.", "POs & Balances", '<div class="notice error">Attachment file was not found.</div>'), 404
        return send_from_directory(os.path.dirname(row.StoragePath), os.path.basename(row.StoragePath), as_attachment=False, download_name=row.OriginalFileName)
    except Exception as e:
        return shell("Attachment", "Unable to open attachment.", "POs & Balances", f'<div class="notice error">Error opening attachment: {h(e)}</div>'), 500

@app.route("/download-expense-upload-template.csv")
def download_expense_upload_template():
    allowed, reason = require_page_access("Expense Upload / PO Matching")
    if not allowed:
        return access_denied_response("Expense Upload / PO Matching", reason)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(REQUIRED_EXPENSE_COLUMNS)
    writer.writerow(["EXP-1001", "Example Project", "2026-06-22", "Purchase", "Example Vendor", "1250.00", "Materials or service description", "PM comment with PO-XX-XXX-001 if available"])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=unanet_expense_upload_template.csv"},
    )


@app.route("/expense-review/update", methods=["POST"])
def expense_review_update():
    allowed, reason = require_page_access("Expense Upload / PO Matching")
    if not allowed:
        allowed, reason = require_page_access("Missing PO Review")
    if not allowed:
        return access_denied_response("Missing PO Review", reason)
    ensure_expense_review_tables()
    item_id = request.form.get("item_id")
    decision = clean_text(request.form.get("review_decision")) or "Pending Review"
    correct_po = clean_text(request.form.get("correct_po_number"))
    notes = clean_text(request.form.get("reviewer_notes"))
    new_status = None
    if decision == "Matched to PO" and correct_po:
        new_status = "Manually Matched"
    elif decision == "No PO Needed":
        new_status = "No PO Needed"
    elif decision == "Needs PM Review":
        new_status = "Needs PM Review"
    elif decision == "Hold for More Info":
        new_status = "Needs Review"
    else:
        new_status = "Needs Review"

    conn = get_sql_connection()
    cursor = conn.cursor()
    reviewer_email = get_current_user()["email"] or "Manual Review"
    cursor.execute(
        """
        UPDATE dbo.ExpenseReviewItems
        SET ReviewDecision = ?, CorrectPONumber = ?, ReviewerNotes = ?, MatchStatus = ?,
            ReviewerEmail = ?, ReviewedAt = SYSUTCDATETIME(), UpdatedAt = SYSUTCDATETIME()
        WHERE ExpenseReviewItemId = ?;
        """,
        decision,
        correct_po,
        notes,
        new_status,
        reviewer_email,
        item_id,
    )
    sync_expense_posting(cursor, item_id, posted_by=reviewer_email)
    conn.commit()
    conn.close()
    return redirect(request.headers.get("Referer") or "/expense-upload?saved=1#review-table")


@app.route("/expense-review/unpost", methods=["POST"])
def expense_review_unpost():
    allowed, reason = require_page_access("Expense Upload / PO Matching")
    if not allowed:
        return access_denied_response("Expense Upload / PO Matching", reason)
    ensure_expense_review_tables()
    item_id = request.form.get("item_id")
    reviewer_email = get_current_user()["email"] or "Manual Review"
    conn = get_sql_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE dbo.ExpenseReviewItems
        SET PostedToPO = 0,
            PostedPONumber = NULL,
            PostedAmount = NULL,
            PostedAt = NULL,
            PostedBy = NULL,
            ReviewerNotes = CONCAT(COALESCE(ReviewerNotes, ''), CASE WHEN COALESCE(ReviewerNotes, '') = '' THEN '' ELSE CHAR(10) END, 'Posting reversed by ', ?, ' at ', CONVERT(NVARCHAR(30), SYSUTCDATETIME(), 126)),
            UpdatedAt = SYSUTCDATETIME()
        WHERE ExpenseReviewItemId = ?;
        """,
        reviewer_email,
        item_id,
    )
    conn.commit()
    conn.close()
    return redirect(request.headers.get("Referer") or "/expenses")


@app.route("/expense-upload", methods=["GET", "POST"])
def expense_upload():
    allowed, reason = require_page_access("Expense Upload / PO Matching")
    if not allowed:
        return access_denied_response("Expense Upload / PO Matching", reason)

    message_html = ""
    try:
        ensure_expense_review_tables()
        if request.method == "POST":
            uploaded_file = request.files.get("expense_file")
            if not uploaded_file or uploaded_file.filename == "":
                message_html = '<div class="notice error">Please choose a Unanet expense file to upload.</div>'
            else:
                rows = read_uploaded_po_file(uploaded_file)
                result = import_expense_rows(rows, uploaded_file.filename)
                message_html = f"""
                <div class="notice success">
                    Expense upload processed. Batch {h(result['batch_id'])}: timesheet rows ignored, {h(result['auto'])} auto matched, {h(result['review'])} need review, {h(result['no_match'])} no match.
                </div>
                """
        elif request.args.get("saved"):
            message_html = '<div class="notice success">Expense review action saved.</div>'

        status_filter = request.args.get("status", "All")
        stats, rows, batches, po_numbers = load_expense_upload_page_data(status_filter)
        total_rows = stats.TotalRows or 0
        auto_matched = stats.AutoMatched or 0
        manually_matched = stats.ManuallyMatched or 0
        needs_review = stats.NeedsReview or 0
        no_match = stats.NoMatch or 0
        reviewed_rows = stats.ReviewedRows or 0

        def status_card(label, value, status, tone, sub):
            active_cls = " active" if status_filter == status else ""
            href = "/expense-upload" if status == "All" else "/expense-upload?status=" + quote_plus(status)
            return f'<a class="status-card {tone}{active_cls}" href="{href}"><div class="label">{h(label)}</div><div class="value">{h(value)}</div><div class="trend">{h(sub)}</div></a>'

        kpi_html = f"""
        <div class="status-card-grid">
            {status_card('All Rows', total_rows, 'All', 'blue', 'Uploaded expense rows')}
            {status_card('Auto Matched', auto_matched, 'Auto Matched', 'green', 'PO found in comments')}
            {status_card('Manual Matches', manually_matched, 'Manually Matched', 'blue', 'Reviewed and linked')}
            {status_card('Needs Review', needs_review, 'Needs Review', 'amber', 'Possible match or unclear')}
            {status_card('No Match', no_match, 'No Match', 'red', 'Needs PO decision')}
            {status_card('Reviewed', reviewed_rows, 'All', 'slate', 'Rows with decisions')}
        </div>
        """

        batch_html = ""
        if batches:
            batch_html = "".join(
                f"""
                <div class="expense-batch-item">
                    <strong>Batch {h(b.ExpenseBatchId)} · {h(b.FileName)}</strong>
                    <span>{h(b.UploadedAt)} · {h(b.TotalRows)} rows · {h(b.AutoMatchedCount)} auto · {h(b.NeedsReviewCount)} review · {h(b.NoMatchCount)} no match</span>
                </div>
                """ for b in batches
            )
        else:
            batch_html = '<div class="empty-state"><strong>No expense uploads yet.</strong><span>Upload a Unanet expense file to begin matching expenses to POs.</span></div>'

        po_options = "".join(f'<option value="{h(po)}"></option>' for po in po_numbers)
        decision_options = ["Pending Review", "Matched to PO", "No PO Needed", "Needs PM Review", "Hold for More Info"]
        table_rows = ""
        if rows:
            for r in rows:
                current_po = r.CorrectPONumber or r.MatchedPONumber or r.ExtractedPONumber or ""
                decision_select = "".join(f'<option value="{h(opt)}" {"selected" if (r.ReviewDecision or "Pending Review") == opt else ""}>{h(opt)}</option>' for opt in decision_options)
                table_rows += f"""
                <tr>
                    <td>{status_chip(r.MatchStatus)}<div class="muted">{h(r.MatchConfidence or '')}</div></td>
                    <td><strong>{h(r.ExpenseId or 'Expense')}</strong><div class="muted">{h(r.TxDate or '')} · {h(r.TxType or '')}</div></td>
                    <td>{h(r.ProjectName)}</td>
                    <td>{h(r.VendorName)}</td>
                    <td class="right">{currency(r.Amount)}</td>
                    <td class="comments-cell">{h(r.PMComments or r.Description or '')}</td>
                    <td>{h(r.ExtractedPONumber or '')}</td>
                    <td><strong>{h(r.MatchedPONumber or '')}</strong><div class="match-reason-cell">{h(r.MatchReason or '')}</div></td>
                    <td class="expense-action-cell">
                        <form class="expense-match-form" method="post" action="/expense-review/update">
                            <input type="hidden" name="item_id" value="{h(r.ExpenseReviewItemId)}">
                            <select name="review_decision">{decision_select}</select>
                            <input name="correct_po_number" list="poNumberList" placeholder="Correct PO number" value="{h(current_po)}">
                            <textarea name="reviewer_notes" placeholder="Reviewer notes">{h(r.ReviewerNotes or '')}</textarea>
                            <button type="submit" class="primary mini">Save Review</button>
                        </form>
                    </td>
                </tr>
                """
        else:
            table_rows = '<tr><td colspan="9"><div class="empty-state"><strong>No expense rows found.</strong><span>Upload a file or clear the status filter.</span></div></td></tr>'

        content = f"""
        {message_html}
        {kpi_html}
        <div class="expense-upload-layout">
            <div class="card">
                <h3>Upload Unanet Expense File</h3>
                <p class="card-subtitle">Upload a CSV or Excel file exported from Unanet. Timesheet rows are ignored. Purchase/disbursement rows are checked for PO numbers in PM Comments and suggested matches by project/vendor.</p>
                <form method="post" enctype="multipart/form-data">
                    <div class="form-field full">
                        <label>Unanet expense file</label>
                        <input type="file" name="expense_file" accept=".csv,.xlsx" required>
                    </div>
                    <div class="request-actions" style="justify-content:flex-start;">
                        <button class="primary" type="submit">Upload and Match Expenses</button>
                        <a class="button" href="/download-expense-upload-template.csv">Download CSV Template</a>
                    </div>
                </form>
            </div>
            <div class="card">
                <h3>Recent Expense Uploads</h3>
                <p class="card-subtitle">Latest expense batches and match results.</p>
                <div class="expense-batch-list">{batch_html}</div>
            </div>
        </div>
        <div class="card" id="review-table">
            <h3>Expense Review Queue</h3>
            <p class="card-subtitle">Use this as the active work queue for uploaded non-timesheet expenses. Confirm PO matches, correct uncertain rows, or mark a row as no PO required / PM review needed. Posted matched rows reduce Current App Balance.</p>
            <datalist id="poNumberList">{po_options}</datalist>
            <div class="table-wrap expense-review-table">
                <table>
                    <tr>
                        <th>Status</th><th>Expense</th><th>Project</th><th>Vendor / Purchaser</th><th class="right">Amount</th><th>PM Comments / Description</th><th>Extracted PO</th><th>Suggested / Matched PO</th><th>Review Action</th>
                    </tr>
                    {table_rows}
                </table>
            </div>
        </div>
        """
        return shell("Expense Upload / PO Matching", "Upload Unanet expenses, review matches, and link transactions to issued POs.", "Expense Upload / PO Matching", content)
    except Exception as e:
        content = f'<div class="notice error">Error loading Expense Upload / PO Matching: {h(e)}</div>'
        return shell("Expense Upload / PO Matching", "Unable to load expense matching page.", "Expense Upload / PO Matching", content), 500



@app.route("/download-issued-po-template.xlsx")
def download_issued_po_template_xlsx():
    allowed, reason = require_page_access("Upload Issued POs")
    if not allowed:
        return access_denied_response("Upload Issued POs", reason)

    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.worksheet.datavalidation import DataValidation
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Issued PO Setup"
    lists = wb.create_sheet("Lists")

    headers = REQUIRED_PO_COLUMNS
    ws.append(headers)
    ws.append(["25-209", "Round Valley", "25-209-PO-001", "Example Vendor", "Marine Construction", "2026-07-01", "Ashley Marion", "Example line item", "EA", 1000, 2, 2000])
    ws.append(["25-209", "Round Valley", "25-209-PO-001", "Example Vendor", "Marine Construction", "2026-07-01", "Ashley Marion", "Second line item", "LS", 500, 1, 500])

    lists["A1"] = "Department Options"
    for idx, dept in enumerate(DEPARTMENT_OPTIONS, start=2):
        lists[f"A{idx}"] = dept

    header_fill = PatternFill("solid", fgColor="0B1F3A")
    header_font = Font(color="FFFFFF", bold=True)
    thin = Side(style="thin", color="D9E2EC")
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = Border(bottom=thin)

    widths = [14, 24, 18, 26, 24, 14, 22, 36, 12, 14, 10, 14]
    for idx, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(idx)].width = width
    ws.freeze_panes = "A2"

    dv = DataValidation(type="list", formula1="=Lists!$A$2:$A$6", allow_blank=False)
    ws.add_data_validation(dv)
    dv.add("E2:E1000")

    ws["A6"] = "Template notes"
    ws["A6"].fill = PatternFill("solid", fgColor="EAF2FF")
    ws["A6"].font = Font(color="0B1F3A", bold=True)
    ws.merge_cells("A6:L6")
    notes = [
        "ProjectCode is required and should match the project code used internally, such as 25-209.",
        "Department must be selected from the dropdown.",
        "Original/Revised/Remaining Amount and PO Status are intentionally removed. The app calculates PO amount from line amounts and marks uploaded POs Open.",
        "Use one row per PO line item. Repeating the same PO number creates multiple line items under the same PO.",
    ]
    for row_idx, note in enumerate(notes, start=7):
        ws[f"A{row_idx}"] = note
        ws.merge_cells(start_row=row_idx, start_column=1, end_row=row_idx, end_column=12)
        ws[f"A{row_idx}"].alignment = Alignment(wrap_text=True)

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=issued_po_project_setup_template.xlsx"},
    )

@app.route("/download-issued-po-template.csv")
def download_issued_po_template():
    allowed, reason = require_page_access("Upload Issued POs")
    if not allowed:
        return access_denied_response("Upload Issued POs", reason)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(REQUIRED_PO_COLUMNS)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=issued_po_project_setup_template.csv"
        },
    )


@app.route("/upload-po", methods=["GET", "POST"])
def upload_po():
    allowed, reason = require_page_access("Upload Issued POs")
    if not allowed:
        return access_denied_response("Upload Issued POs", reason)

    message_html = ""
    result_html = ""
    errors_html = ""

    assignable_users = load_assignable_users()
    requestor_options = []
    for u in assignable_users:
        display = clean_text(getattr(u, "DisplayName", "") or getattr(u, "Email", ""))
        role = clean_text(getattr(u, "RoleName", ""))
        email = clean_text(getattr(u, "Email", ""))
        if display:
            requestor_options.append((display, role, email))
    valid_requestors = [x[0] for x in requestor_options]

    selected_department = clean_text(request.form.get("default_department")) if request.method == "POST" else ""
    selected_requestor = clean_text(request.form.get("default_requestor")) if request.method == "POST" else ""

    if request.method == "POST":
        uploaded_file = request.files.get("po_file")

        if not uploaded_file or uploaded_file.filename == "":
            message_html = '<div class="notice error">No file selected.</div>'
        elif not uploaded_file.filename.lower().endswith(".csv"):
            message_html = '<div class="notice error">Please upload a CSV file. The issued PO setup upload is CSV-only.</div>'
        else:
            try:
                rows = read_uploaded_po_file(uploaded_file)
                validation_errors = validate_po_rows(rows, selected_department, selected_requestor, valid_requestors)

                if validation_errors:
                    message_html = '<div class="notice error">The file could not be imported because validation errors were found.</div>'
                    error_items = "".join(f"<li>{h(error)}</li>" for error in validation_errors)
                    errors_html = f'<div class="card"><h3>Validation Errors</h3><ul>{error_items}</ul></div>'
                else:
                    result = import_po_rows(rows, uploaded_file.filename, selected_department, selected_requestor)
                    message_html = '<div class="notice ok">Issued PO import completed.</div>'
                    result_html = f"""
                    <div class="card"><h3>Import Result</h3><table><tr><th>Import Batch ID</th><td>{result["import_batch_id"]}</td></tr><tr><th>Total Rows</th><td>{result["total_rows"]}</td></tr><tr><th>Success Count</th><td>{result["success_count"]}</td></tr><tr><th>Error Count</th><td>{result["error_count"]}</td></tr><tr><th>Status</th><td>{h(result["status"])}</td></tr><tr><th>Department Applied</th><td>{h(selected_department)}</td></tr><tr><th>Requestor Applied</th><td>{h(selected_requestor)}</td></tr></table></div>
                    """

            except Exception as e:
                message_html = '<div class="notice error">Import failed.</div>'
                errors_html = f'<div class="card"><h3>Error Details</h3><p>{h(e)}</p></div>'

    department_options_html = "".join(
        f'<option value="{h(dept)}" {"selected" if dept == selected_department else ""}>{h(dept)}</option>'
        for dept in DEPARTMENT_OPTIONS
    )
    requestor_options_html = "".join(
        f'<option value="{h(display)}" {"selected" if display == selected_requestor else ""}>{h(display)}{(" · " + h(role)) if role else ""}</option>'
        for display, role, email in requestor_options
    )

    content = f"""
    {message_html}{result_html}{errors_html}
    <div class="grid two">
        <div class="card">
            <h3>Select Issued PO File</h3>
            <p class="card-subtitle">Upload the first-time project setup PO file as CSV. Department and requestor are selected here and applied to every row in the upload.</p>
            <form method="post" enctype="multipart/form-data">
                <div class="form-grid">
                    <div class="form-field">
                        <label>Department *</label>
                        <select name="default_department" required>
                            <option value="">Select department</option>
                            {department_options_html}
                        </select>
                    </div>
                    <div class="form-field">
                        <label>Requestor *</label>
                        <select name="default_requestor" required>
                            <option value="">Select requestor</option>
                            {requestor_options_html}
                        </select>
                    </div>
                    <div class="form-field full">
                        <label>Issued PO CSV *</label>
                        <input type="file" name="po_file" accept=".csv" required>
                    </div>
                </div>
                <p class="field-help">The selected department and requestor will be stamped onto all POs and PO line items in this upload.</p>
                <p><button class="primary" type="submit">Upload Issued POs</button></p>
            </form>
        </div>
        <div class="card">
            <h3>Project Setup CSV Template</h3>
            <p class="card-subtitle">Download the CSV template for the Phase 1 first-time project PO setup load.</p>
            <p><a class="button primary" href="/download-issued-po-template.csv">Download CSV Template</a></p>
        </div>
    </div>
    """

    return shell("Upload Issued POs", "Import first-time project setup POs and line items into Azure SQL.", "Upload Issued POs", content)

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
            exception_rows = '<tr><td colspan="9">No exceptions found. Your issued PO data looks clean.</td></tr>'

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


@app.route("/set-view-as", methods=["POST"])
def set_view_as():
    access = get_user_access()
    if access.get("role") not in ["Admin", "Executive"]:
        return access_denied_response("User Access", "Only Admin or Executive users can use View As.")
    email = clean_text(request.form.get("view_as_email")) or ""
    resp = make_response(redirect("/user-access"))
    if email:
        resp.set_cookie("PO_DASHBOARD_VIEW_AS", email.lower(), max_age=8*60*60, httponly=True, samesite="Lax")
    else:
        resp.delete_cookie("PO_DASHBOARD_VIEW_AS")
    return resp

@app.route("/clear-view-as")
def clear_view_as():
    resp = make_response(redirect(request.headers.get("Referer") or "/user-access"))
    resp.delete_cookie("PO_DASHBOARD_VIEW_AS")
    return resp

@app.route("/user-access", methods=["GET", "POST"])
def user_access():
    allowed, reason = require_page_access("User Access")
    if not allowed:
        return access_denied_response("User Access", reason)

    message_html = ""

    if request.method == "POST" and get_user_access().get("role") != "Admin":
        message_html = '<div class="notice error">Only Admin users can add or update user access. Executive users can use View As only.</div>'
    elif request.method == "POST":
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
            <h3>View As User</h3>
            <p class="card-subtitle">Admin/Executive users can view user-specific task context while keeping the admin/executive sidebar and permissions.</p>
            <form method="post" action="/set-view-as" class="rollout-filter-bar">
                <div class="rollout-filter-fields">
                    <label>View as<select name="view_as_email"><option value="">Actual signed-in user</option>{''.join(f'<option value="{h(u.Email)}" {"selected" if get_view_as_email().lower() == str(u.Email).lower() else ""}>{h(u.DisplayName or u.Email)} · {h(u.RoleName)}</option>' for u in users if u.IsActive)}</select></label>
                </div>
                <div class="rollout-filter-actions"><button class="primary" type="submit">Apply View As</button><a class="button secondary" href="/clear-view-as">Clear</a></div>
            </form>
        </div>
        <div class="card">
            <h3>Add or Update User Access</h3>
            <p class="card-subtitle">Admins can add users or update their dashboard role. Executive users can use View As but cannot change access.</p>
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
