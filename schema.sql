-- ==========================================
-- Daily Security Report Database
-- ==========================================

PRAGMA foreign_keys = ON;


-- ==========================================
-- Reports
-- One row per generated daily report
-- ==========================================

CREATE TABLE IF NOT EXISTS reports (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    report_id TEXT NOT NULL UNIQUE,

    report_date TEXT NOT NULL,

    reporting_from TEXT,

    reporting_to TEXT,

    generated_at TEXT,

    generator_version TEXT,

    schema_version TEXT,

    cyera_count INTEGER DEFAULT 0,

    purview_count INTEGER DEFAULT 0,

    total_alerts INTEGER DEFAULT 0,

    created_at TEXT DEFAULT CURRENT_TIMESTAMP

);


-- ==========================================
-- Cyera Alerts
-- ==========================================

CREATE TABLE IF NOT EXISTS cyera_alerts (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    report_id TEXT NOT NULL,

    alert_id TEXT,

    name TEXT,

    timestamp TEXT,

    updated_at TEXT,

    severity TEXT,

    original_severity TEXT,

    external_severity TEXT,

    status TEXT,

    status_updated_at TEXT,

    assigned_user_email TEXT,

    assigned_user_id TEXT,

    triggering_user TEXT,

    authenticated_user TEXT,

    policy_id TEXT,

    policy_name TEXT,

    policy_type TEXT,

    policy_action TEXT,

    channel TEXT,

    source_activity TEXT,

    actual_action TEXT,

    configured_action TEXT,

    data_type TEXT,

    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (report_id)
        REFERENCES reports(report_id)

);


-- ==========================================
-- Purview Alerts
-- ==========================================

CREATE TABLE IF NOT EXISTS purview_alerts (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    report_id TEXT NOT NULL,

    alert_name TEXT,

    severity TEXT,

    status TEXT,

    time_detected TEXT,

    user TEXT,

    location TEXT,

    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (report_id)
        REFERENCES reports(report_id)

);


-- ==========================================
-- Indexes
-- ==========================================

CREATE INDEX IF NOT EXISTS idx_reports_date
ON reports(report_date);


CREATE INDEX IF NOT EXISTS idx_cyera_report
ON cyera_alerts(report_id);


CREATE INDEX IF NOT EXISTS idx_cyera_severity
ON cyera_alerts(severity);


CREATE INDEX IF NOT EXISTS idx_cyera_status
ON cyera_alerts(status);


CREATE INDEX IF NOT EXISTS idx_cyera_assigned_user
ON cyera_alerts(assigned_user_email);


CREATE INDEX IF NOT EXISTS idx_purview_report
ON purview_alerts(report_id);


CREATE INDEX IF NOT EXISTS idx_purview_severity
ON purview_alerts(severity);


CREATE INDEX IF NOT EXISTS idx_purview_status
ON purview_alerts(status);


CREATE INDEX IF NOT EXISTS idx_purview_user
ON purview_alerts(user);