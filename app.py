import os
import sys
import site
from flask import Flask, render_template_string, jsonify

# Add local package path for Azure App Service deployments
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PACKAGES_DIR = os.path.join(BASE_DIR, ".python_packages", "lib", "site-packages")

if os.path.isdir(PACKAGES_DIR):
    site.addsitedir(PACKAGES_DIR)
    sys.path.append(PACKAGES_DIR)

app = Flask(__name__)

# Azure App Settings
APP_ENVIRONMENT = os.getenv("APP_ENVIRONMENT", "Not set")
SQL_SERVER_NAME = os.getenv("SQL_SERVER_NAME", "Not set")
SQL_DATABASE_NAME = os.getenv("SQL_DATABASE_NAME", "Not set")
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "Not set")

# Azure exposes connection strings differently depending on type.
# SQLAzure type becomes SQLAZURECONNSTR_<name>.
# Custom type becomes CUSTOMCONNSTR_<name>.
SQL_CONNECTION = (
    os.getenv("SQLAZURECONNSTR_PODASHBOARD_SQL")
    or os.getenv("CUSTOMCONNSTR_PODASHBOARD_SQL")
    or os.getenv("PODASHBOARD_SQL")
    or ""
)

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>PO Dashboard</title>
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
        code {
            background: #f0f0f0;
            padding: 2px 5px;
            border-radius: 4px;
        }
        ul {
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>PO Dashboard</h1>
        <p>Starter procurement dashboard app is running.</p>
        <p>
            <span class="status ok">App Online</span>
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
            <li>Database connection test</li>
            <li>Manual CSV upload</li>
            <li>Import history</li>
            <li>PO summary dashboard</li>
            <li>Role-based access</li>
        </ul>
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


@app.route("/db-test")
def db_test():
    """
    Safe database test route.

    This imports pyodbc inside the route instead of at startup.
    That way, if pyodbc or the SQL driver is missing, the homepage still works.
    """
    if not SQL_CONNECTION:
        return jsonify(
            {
                "status": "error",
                "step": "connection_string",
                "message": "SQL connection string was not found.",
            }
        ), 500

    try:
        import pyodbc
    except Exception as e:
        return jsonify(
            {
                "status": "error",
                "step": "import_pyodbc",
                "message": str(e),
            }
        ), 500

    try:
        connection_string = SQL_CONNECTION

        # Azure SQL connection strings from the portal often omit the ODBC driver.
        if "Driver=" not in connection_string and "DRIVER=" not in connection_string:
            connection_string = (
                "Driver={ODBC Driver 18 for SQL Server};"
                + connection_string
            )

        conn = pyodbc.connect(connection_string, timeout=10)
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("HTTP_PLATFORM_PORT", 8000)))
    app.run(host="0.0.0.0", port=port)
