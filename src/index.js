
export default {

    async fetch(request, env) {

        const url = new URL(request.url);

        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        };

        // CORS preflight
        if (request.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: corsHeaders
            });
        }

        try {

            // ==========================================
            // Health Check
            // ==========================================

            if (
                request.method === "GET" &&
                url.pathname === "/"
            ) {

                return new Response(
                    JSON.stringify({
                        success: true,
                        service: "daily-report-api",
                        database: "connected"
                    }),
                    {
                        status: 200,
                        headers: {
                            "Content-Type": "application/json",
                            ...corsHeaders
                        }
                    }
                );
            }

            // ==========================================
            // CREATE DAILY REPORT
            // ==========================================

            if (
                request.method === "POST" &&
                url.pathname === "/api/v1/reports"
            ) {

                return await handleCreateReport(
                    request,
                    env,
                    corsHeaders
                );
            }


            // ==========================================
            // LIST REPORTS
            // ==========================================

            // Example:
            // /api/v1/reports?page=1&limit=30
            // /api/v1/reports?page=1&limit=30&from=20260801&to=20260831

            if (
                request.method === "GET" &&
                url.pathname === "/api/v1/reports"
            ) {

                return await handleGetReports(
                    url,
                    env,
                    corsHeaders
                );
            }


            // ==========================================
            // ANALYTICS SUMMARY
            // ==========================================

            if (
                request.method === "GET" &&
                url.pathname === "/api/v1/analytics/summary"
            ) {

                return await handleAnalyticsSummary(
                    env,
                    corsHeaders
                );
            }


            // ==========================================
            // ANALYTICS TRENDS
            // ==========================================

            if (
                request.method === "GET" &&
                url.pathname === "/api/v1/analytics/trends"
            ) {

                return await handleAnalyticsTrends(
                    url,
                    env,
                    corsHeaders
                );
            }


            // ==========================================
            // REPORT ALERTS
            // ==========================================

            // Get individual alerts for a report.
            //
            // Example:
            // /api/v1/reports/REP-20260821/alerts
            //
            // Optional:
            // /api/v1/reports/REP-20260821/alerts?source=cyera
            // /api/v1/reports/REP-20260821/alerts?source=purview

            if (
                request.method === "GET" &&
                url.pathname.match(
                    /^\/api\/v1\/reports\/[^/]+\/alerts$/
                )
            ) {

                const parts =
                    url.pathname.split("/");

                const reportId =
                    decodeURIComponent(
                        parts[4]
                    );

                return await handleGetReportAlerts(
                    reportId,
                    url,
                    env,
                    corsHeaders
                );
            }


            // ==========================================
            // REPORT SUMMARY / DETAILS
            // ==========================================

            // Get report summary.
            //
            // Example:
            // /api/v1/reports/REP-20260821

            if (
                request.method === "GET" &&
                url.pathname.startsWith(
                    "/api/v1/reports/"
                )
            ) {

                const reportId =
                    decodeURIComponent(
                        url.pathname.split("/").pop()
                    );

                return await handleGetReports(
                    reportId,
                    url,
                    env,
                    corsHeaders
                );
            }

            /*
            ==========================================
            ROUTE NOT FOUND
            ==========================================
            */

            return jsonResponse(
                {
                    success: false,
                    error: "Route not found"
                },
                404,
                corsHeaders
            );

        } catch (error) {

            console.error(
                "WORKER ERROR:",
                error
            );

            console.error(
                "WORKER ERROR MESSAGE:",
                error?.message
            );

            console.error(
                "WORKER ERROR STACK:",
                error?.stack
            );

            return jsonResponse(
                {
                    success: false,

                    error:
                        error?.message ||
                        String(error),

                    errorName:
                        error?.name || null,

                    stack:
                        error?.stack || null
                },

                500,

                corsHeaders
            );
        }
    }
};


/*
==========================================
CREATE REPORT
==========================================
*/

async function handleCreateReport(
    request,
    env,
    corsHeaders
) {

    let data;

    try {

        data = await request.json();

    } catch {

        return jsonResponse(
            {
                success: false,
                error: "Invalid JSON payload"
            },
            400,
            corsHeaders
        );
    }


    // Validate
    const validation = validateReport(data);

    if (!validation.valid) {

        return jsonResponse(
            {
                success: false,
                error: validation.error
            },
            400,
            corsHeaders
        );
    }


    const report = data.report;

    const reportId = report.reportId;

    const cyeraRecords =
        data.cyera?.records || [];

    const purviewRecords =
        data.purview?.records || [];


    /*
    ==========================================
    CHECK DUPLICATE
    ==========================================
    */

    const existing = await env.DB
        .prepare(`
            SELECT report_id
            FROM reports
            WHERE report_id = ?
        `)
        .bind(reportId)
        .first();


    if (existing) {

        return jsonResponse(
            {
                success: true,
                duplicate: true,
                reportId,
                message: "Report already exists"
            },
            200,
            corsHeaders
        );
    }


    /*
    ==========================================
    INSERT REPORT
    ==========================================
    */

    await env.DB
        .prepare(`
            INSERT INTO reports (
                report_id,
                report_date,
                reporting_from,
                reporting_to,
                generated_at,
                generator_version,
                schema_version,
                cyera_count,
                purview_count,
                total_alerts
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
            reportId,
            report.reportDate,
            report.reportingWindow?.from || null,
            report.reportingWindow?.to || null,
            report.generatedAt || null,
            report.generatorVersion || null,
            data.schemaVersion || null,
            cyeraRecords.length,
            purviewRecords.length,
            cyeraRecords.length +
            purviewRecords.length
        )
        .run();


  /*
==========================================
PROCESS CYERA
==========================================
*/

let newCyera = 0;
let carriedOverCyera = 0;
let resolvedCyera = 0;

for (
    let i = 0;
    i < cyeraRecords.length;
    i++
) {

    const alert =
        cyeraRecords[i];

    const source =
        "cyera";

    const externalAlertId =
        String(
            alert.id || ""
        ).trim();

    if (!externalAlertId) {

        console.warn(
            `Skipping Cyera alert ${i + 1}: missing alert ID`
        );

        continue;
    }

    const observedAt =
        alert.timestamp ||
        alert.updatedAt ||
        new Date().toISOString();

    const severity =
        alert.severity || null;

    const status =
        alert.status || null;

    const assignedUser =
        alert.assignedUserEmail || null;

    /*
    ------------------------------------------
    Save raw report snapshot
    ------------------------------------------
    */

    await env.DB
        .prepare(`
            INSERT INTO cyera_alerts (
                report_id,
                alert_id,
                name,
                timestamp,
                updated_at,
                severity,
                original_severity,
                external_severity,
                status,
                status_updated_at,
                assigned_user_email,
                assigned_user_id,
                triggering_user,
                authenticated_user,
                policy_id,
                policy_name,
                policy_type,
                policy_action,
                channel,
                source_activity,
                actual_action,
                configured_action,
                data_type
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
        `)
        .bind(
            reportId,
            externalAlertId,
            alert.name || null,
            alert.timestamp || null,
            alert.updatedAt || null,
            alert.severity || null,
            alert.originalSeverity || null,
            alert.externalSeverity || null,
            alert.status || null,
            alert.statusUpdatedAt || null,
            alert.assignedUserEmail || null,
            alert.assignedUserId || null,
            alert.triggeringUser || null,
            alert.authenticatedUser || null,
            alert.policy?.id || null,
            alert.policy?.name || null,
            alert.policy?.type || null,
            alert.policy?.action || null,
            alert.channel || null,
            alert.sourceActivity || null,
            alert.actualAction || null,
            alert.configuredAction || null,
            alert.dataType || null
        )
        .run();


    /*
    ------------------------------------------
    Find canonical alert
    ------------------------------------------
    */

    let canonicalAlert =
        await findCanonicalAlert(
            env,
            source,
            externalAlertId
        );


    /*
    ------------------------------------------
    NEW ALERT
    ------------------------------------------
    */

    if (!canonicalAlert) {

        const alertId =
            await createCanonicalAlert(
                env,
                {
                    source,
                    externalAlertId,
                    name: alert.name,
                    severity,
                    status,
                    assignedUser,
                    observedAt
                }
            );

        await insertAlertHistory(
            env,
            {
                alertId,
                reportId,
                observedAt,
                severity,
                status,
                assignedUser
            }
        );

        newCyera++;

        continue;
    }


    /*
    ------------------------------------------
    EXISTING ALERT
    ------------------------------------------
    */

    const previous =
        await getPreviousAlertHistory(
            env,
            canonicalAlert.id,
            reportId
        );


    /*
    Was this alert previously unresolved?
    */
    const wasPreviouslyResolved =
        isResolvedStatus(
            previous?.status
        );


    const currentlyResolved =
        isResolvedStatus(
            status
        );


    /*
    ------------------------------------------
    RESOLVED TODAY
    ------------------------------------------
    */

    if (
        currentlyResolved &&
        previous &&
        !wasPreviouslyResolved
    ) {

        resolvedCyera++;
    }


    /*
    ------------------------------------------
    CARRIED OVER
    ------------------------------------------
    */

    if (
        previous &&
        !currentlyResolved
    ) {

        carriedOverCyera++;
    }


    /*
    ------------------------------------------
    UPDATE CANONICAL ALERT
    ------------------------------------------
    */

    await updateCanonicalAlert(
        env,
        {
            id: canonicalAlert.id,
            name: alert.name,
            severity,
            status,
            assignedUser,
            observedAt,
            resolvedAt:
                currentlyResolved
                    ? observedAt
                    : null
        }
    );


    /*
    ------------------------------------------
    ADD HISTORY
    ------------------------------------------
    */

    await insertAlertHistory(
        env,
        {
            alertId:
                canonicalAlert.id,

            reportId,

            observedAt,

            severity,

            status,

            assignedUser
        }
    );
}


/*
==========================================
PROCESS PURVIEW
==========================================
*/

let newPurview = 0;
let carriedOverPurview = 0;
let resolvedPurview = 0;

for (
    let i = 0;
    i < purviewRecords.length;
    i++
) {

    const alert =
        purviewRecords[i];

    const source =
        "purview";


    /*
    ------------------------------------------
    Generate deterministic Purview ID
    ------------------------------------------
    */

    const externalAlertId =
        await generatePurviewAlertId(
            alert
        );


    const observedAt =
        alert.timeDetected ||
        new Date().toISOString();

    const severity =
        alert.severity || null;

    const status =
        alert.status || null;


    /*
    IMPORTANT:

    Purview's "user" is the person associated
    with the DLP event, NOT our analyst.

    Therefore it must NOT become
    current_assigned_user.
    */

    const assignedUser =
        null;


    /*
    ------------------------------------------
    Save raw report snapshot
    ------------------------------------------
    */

    await env.DB
        .prepare(`
            INSERT INTO purview_alerts (
                report_id,
                external_alert_id,
                alert_name,
                severity,
                status,
                time_detected,
                user,
                location
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
            reportId,
            externalAlertId,
            alert.alertName || null,
            alert.severity || null,
            alert.status || null,
            alert.timeDetected || null,
            alert.user || null,
            alert.location || null
        )
        .run();


    /*
    ------------------------------------------
    Find canonical alert
    ------------------------------------------
    */

    let canonicalAlert =
        await findCanonicalAlert(
            env,
            source,
            externalAlertId
        );


    /*
    ------------------------------------------
    NEW ALERT
    ------------------------------------------
    */

    if (!canonicalAlert) {

        const alertId =
            await createCanonicalAlert(
                env,
                {
                    source,
                    externalAlertId,
                    name: alert.alertName,
                    severity,
                    status,
                    assignedUser,
                    observedAt
                }
            );


        await insertAlertHistory(
            env,
            {
                alertId,
                reportId,
                observedAt,
                severity,
                status,
                assignedUser
            }
        );


        newPurview++;

        continue;
    }


    /*
    ------------------------------------------
    EXISTING ALERT
    ------------------------------------------
    */

    const previous =
        await getPreviousAlertHistory(
            env,
            canonicalAlert.id,
            reportId
        );


    const wasPreviouslyResolved =
        isResolvedStatus(
            previous?.status
        );


    const currentlyResolved =
        isResolvedStatus(
            status
        );


    /*
    ------------------------------------------
    RESOLVED TODAY
    ------------------------------------------
    */

    if (
        currentlyResolved &&
        previous &&
        !wasPreviouslyResolved
    ) {

        resolvedPurview++;
    }


    /*
    ------------------------------------------
    CARRIED OVER
    ------------------------------------------
    */

    if (
        previous &&
        !currentlyResolved
    ) {

        carriedOverPurview++;
    }


    /*
    ------------------------------------------
    UPDATE CANONICAL ALERT
    ------------------------------------------
    */

    await updateCanonicalAlert(
        env,
        {
            id: canonicalAlert.id,
            name: alert.alertName,
            severity,
            status,
            assignedUser,
            observedAt,
            resolvedAt:
                currentlyResolved
                    ? observedAt
                    : null
        }
    );


    /*
    ------------------------------------------
    ADD HISTORY
    ------------------------------------------
    */

    await insertAlertHistory(
        env,
        {
            alertId:
                canonicalAlert.id,

            reportId,

            observedAt,

            severity,

            status,

            assignedUser
        }
    );
}
    /*
==========================================
DAILY HISTORICAL METRICS
==========================================
*/

await upsertHistoricalMetrics(
    env,
    {
        metricDate:
            report.reportDate,

        source: "cyera",

        totalAlerts:
            cyeraRecords.length,

        newCount:
            newCyera,

        carriedOverCount:
            carriedOverCyera,

        resolvedCount:
            resolvedCyera
    }
);


await upsertHistoricalMetrics(
    env,
    {
        metricDate:
            report.reportDate,

        source: "purview",

        totalAlerts:
            purviewRecords.length,

        newCount:
            newPurview,

        carriedOverCount:
            carriedOverPurview,

        resolvedCount:
            resolvedPurview
    }
);
    /*
==========================================
UPSERT HISTORICAL METRICS
==========================================
*/

async function upsertHistoricalMetrics(
    env,
    {
        metricDate,
        source,
        totalAlerts,
        newCount,
        carriedOverCount,
        resolvedCount
    }
) {

    await env.DB
        .prepare(`
            INSERT INTO historical_metrics (
                metric_date,
                source,
                total_alerts,
                new_count,
                carried_over_count,
                resolved_count
            )
            VALUES (?, ?, ?, ?, ?, ?)

            ON CONFLICT (
                metric_date,
                source
            )

            DO UPDATE SET
                total_alerts =
                    excluded.total_alerts,

                new_count =
                    excluded.new_count,

                carried_over_count =
                    excluded.carried_over_count,

                resolved_count =
                    excluded.resolved_count
        `)
        .bind(
            metricDate,
            source,
            totalAlerts || 0,
            newCount || 0,
            carriedOverCount || 0,
            resolvedCount || 0
        )
        .run();
}

    /*
==========================================
90-DAY RETENTION
==========================================
*/

const retentionResult =
    await applyRetentionPolicy(
        env
    );

console.log(
    "RETENTION RESULT:",
    retentionResult
);
    /*
==========================================
90-DAY RETENTION POLICY
==========================================
*/

async function applyRetentionPolicy(
    env
) {

    /*
    Keep the most recent 90 days
    based on report_date.
    */

    const cutoffResult =
        await env.DB
            .prepare(`
                SELECT
                    MIN(report_date) AS cutoff_date
                FROM (
                    SELECT report_date
                    FROM reports
                    ORDER BY report_date DESC
                    LIMIT 90
                )
            `)
            .first();


    const cutoffDate =
        cutoffResult?.cutoff_date;


    if (!cutoffDate) {

        return {
            skipped: true,
            reason: "No reports available"
        };
    }


    /*
    Delete history belonging to
    reports older than cutoff.
    */

    const historyResult =
        await env.DB
            .prepare(`
                DELETE FROM alert_history
                WHERE report_id IN (
                    SELECT report_id
                    FROM reports
                    WHERE report_date < ?
                )
            `)
            .bind(cutoffDate)
            .run();


    /*
    Delete Cyera snapshots.
    */

    const cyeraResult =
        await env.DB
            .prepare(`
                DELETE FROM cyera_alerts
                WHERE report_id IN (
                    SELECT report_id
                    FROM reports
                    WHERE report_date < ?
                )
            `)
            .bind(cutoffDate)
            .run();


    /*
    Delete Purview snapshots.
    */

    const purviewResult =
        await env.DB
            .prepare(`
                DELETE FROM purview_alerts
                WHERE report_id IN (
                    SELECT report_id
                    FROM reports
                    WHERE report_date < ?
                )
            `)
            .bind(cutoffDate)
            .run();


    /*
    Delete old reports.
    */

    const reportsResult =
        await env.DB
            .prepare(`
                DELETE FROM reports
                WHERE report_date < ?
            `)
            .bind(cutoffDate)
            .run();


    /*
    Delete old historical metrics.
    */

    await env.DB
        .prepare(`
            DELETE FROM historical_metrics
            WHERE metric_date < ?
        `)
        .bind(cutoffDate)
        .run();


    /*
    Remove canonical alerts that have
    no remaining history.

    This is important for D1 storage.
    */

    await env.DB
        .prepare(`
            DELETE FROM alerts
            WHERE id NOT IN (
                SELECT DISTINCT alert_id
                FROM alert_history
            )
        `)
        .run();


    /*
    Record cleanup.
    */

    await env.DB
        .prepare(`
            INSERT INTO retention_log (
                cleanup_date,
                cutoff_date,
                reports_deleted,
                cyera_deleted,
                purview_deleted,
                history_deleted
            )
            VALUES (
                CURRENT_TIMESTAMP,
                ?,
                ?,
                ?,
                ?,
                ?
            )
        `)
        .bind(
            cutoffDate,
            reportsResult.meta?.changes || 0,
            cyeraResult.meta?.changes || 0,
            purviewResult.meta?.changes || 0,
            historyResult.meta?.changes || 0
        )
        .run();


    return {
        cutoffDate,
        reportsDeleted:
            reportsResult.meta?.changes || 0,
        cyeraDeleted:
            cyeraResult.meta?.changes || 0,
        purviewDeleted:
            purviewResult.meta?.changes || 0,
        historyDeleted:
            historyResult.meta?.changes || 0
    };
}

    /*
    ==========================================
    SUCCESS
    ==========================================
    */

    return jsonResponse(
        {
            success: true,
            duplicate: false,
            reportId,

            cyeraInserted:
                cyeraRecords.length,

            purviewInserted:
                purviewRecords.length,

            totalInserted:
                cyeraRecords.length +
                purviewRecords.length
        },
        201,
        corsHeaders
    );
}
/*
==========================================
ANALYTICS SUMMARY
==========================================
*/

async function handleAnalyticsSummary(
    env,
    corsHeaders
) {

    /*
    ==========================================
    Overall totals
    ==========================================
    */

    const totals = await env.DB
        .prepare(`
            SELECT

                COUNT(*) AS totalReports,

                COALESCE(
                    SUM(total_alerts),
                    0
                ) AS totalAlerts,

                COALESCE(
                    SUM(cyera_count),
                    0
                ) AS totalCyeraAlerts,

                COALESCE(
                    SUM(purview_count),
                    0
                ) AS totalPurviewAlerts

            FROM reports
        `)
        .first();


    /*
    ==========================================
    Latest report
    ==========================================
    */

    const latestReport = await env.DB
        .prepare(`
            SELECT

                report_id,
                report_date,

                cyera_count,
                purview_count,
                total_alerts,

                generated_at

            FROM reports

            ORDER BY created_at DESC

            LIMIT 1
        `)
        .first();


    /*
    ==========================================
    Cyera severity
    ==========================================
    */

    const cyeraSeverityResult = await env.DB
        .prepare(`
            SELECT

                LOWER(
                    COALESCE(
                        severity,
                        'unknown'
                    )
                ) AS severity,

                COUNT(*) AS count

            FROM cyera_alerts

            GROUP BY LOWER(
                COALESCE(
                    severity,
                    'unknown'
                )
            )

            ORDER BY count DESC
        `)
        .all();


    /*
    ==========================================
    Purview severity
    ==========================================
    */

    const purviewSeverityResult = await env.DB
        .prepare(`
            SELECT

                LOWER(
                    COALESCE(
                        severity,
                        'unknown'
                    )
                ) AS severity,

                COUNT(*) AS count

            FROM purview_alerts

            GROUP BY LOWER(
                COALESCE(
                    severity,
                    'unknown'
                )
            )

            ORDER BY count DESC
        `)
        .all();


    /*
    ==========================================
    Cyera status
    ==========================================
    */

    const cyeraStatusResult = await env.DB
        .prepare(`
            SELECT

                LOWER(
                    COALESCE(
                        status,
                        'unknown'
                    )
                ) AS status,

                COUNT(*) AS count

            FROM cyera_alerts

            GROUP BY LOWER(
                COALESCE(
                    status,
                    'unknown'
                )
            )

            ORDER BY count DESC
        `)
        .all();


    /*
    ==========================================
    Purview status
    ==========================================
    */

    const purviewStatusResult = await env.DB
        .prepare(`
            SELECT

                LOWER(
                    COALESCE(
                        status,
                        'unknown'
                    )
                ) AS status,

                COUNT(*) AS count

            FROM purview_alerts

            GROUP BY LOWER(
                COALESCE(
                    status,
                    'unknown'
                )
            )

            ORDER BY count DESC
        `)
        .all();


    /*
    ==========================================
    Cyera alerts by assigned user
    ==========================================
    */

    const assignedUserResult = await env.DB
        .prepare(`
            SELECT

                COALESCE(
                    assigned_user_email,
                    'Unassigned'
                ) AS assigned_user,

                COUNT(*) AS count

            FROM cyera_alerts

            GROUP BY assigned_user_email

            ORDER BY count DESC
        `)
        .all();


    /*
    ==========================================
    Return analytics
    ==========================================
    */

    return jsonResponse(

        {

            success: true,

            generatedAt:
                new Date().toISOString(),


            totals: {

                reports:
                    Number(
                        totals?.totalReports || 0
                    ),

                alerts:
                    Number(
                        totals?.totalAlerts || 0
                    ),

                cyera:
                    Number(
                        totals?.totalCyeraAlerts || 0
                    ),

                purview:
                    Number(
                        totals?.totalPurviewAlerts || 0
                    )
            },


            latestReport:
                latestReport || null,


            cyera: {

                severity:
                    cyeraSeverityResult.results || [],

                status:
                    cyeraStatusResult.results || [],

                assignedUsers:
                    assignedUserResult.results || []
            },


            purview: {

                severity:
                    purviewSeverityResult.results || [],

                status:
                    purviewStatusResult.results || []
            }

        },

        200,

        corsHeaders
    );
}
/*
==========================================
ANALYTICS TRENDS
==========================================
*/

/*
==========================================
ANALYTICS TRENDS
==========================================
*/

async function handleAnalyticsTrends(
    url,
    env,
    corsHeaders
) {

    /*
    ==========================================
    Period
    ==========================================
    */

    const period =
        (
            url.searchParams.get("period") ||
            "daily"
        ).toLowerCase();


    /*
    ==========================================
    Date Range
    ==========================================
    
    Optional:

    ?from=20260801&to=20260821

    If from/to are not provided,
    all available reports are returned.
    ==========================================
    */

    const from =
        url.searchParams.get("from");

    const to =
        url.searchParams.get("to");


    /*
    ==========================================
    Validate period
    ==========================================
    */

    const allowedPeriods = [
        "daily",
        "monthly",
        "quarterly"
    ];

    if (
        !allowedPeriods.includes(period)
    ) {

        return jsonResponse(
            {
                success: false,

                error:
                    "Invalid period. Use daily, monthly, or quarterly."
            },

            400,

            corsHeaders
        );
    }


    /*
    ==========================================
    Validate date range
    ==========================================
    */

    if (
        (from && !/^\d{8}$/.test(from)) ||
        (to && !/^\d{8}$/.test(to))
    ) {

        return jsonResponse(
            {
                success: false,

                error:
                    "Invalid date format. Use YYYYMMDD."
            },

            400,

            corsHeaders
        );
    }


    if (
        from &&
        to &&
        from > to
    ) {

        return jsonResponse(
            {
                success: false,

                error:
                    "'from' date cannot be greater than 'to' date."
            },

            400,

            corsHeaders
        );
    }


    /*
    ==========================================
    Build Date Filter
    ==========================================
    */

    let dateFilter = "";

    const bindings = [];


    if (from) {

        dateFilter += `
            report_date >= ?
        `;

        bindings.push(from);
    }


    if (to) {

        if (from) {

            dateFilter += `
                AND report_date <= ?
            `;

        } else {

            dateFilter += `
                report_date <= ?
            `;
        }

        bindings.push(to);
    }


    /*
    ==========================================
    DAILY
    ==========================================
    */

    if (period === "daily") {

        const result =
            await env.DB
                .prepare(`
                    SELECT
                        report_date AS date,

                        SUM(total_alerts) AS total,

                        SUM(cyera_count) AS cyera,

                        SUM(purview_count) AS purview

                    FROM reports

                    ${dateFilter
                        ? `WHERE ${dateFilter}`
                        : ""
                    }

                    GROUP BY report_date

                    ORDER BY report_date ASC
                `)
                .bind(...bindings)
                .all();


        return jsonResponse(
            {
                success: true,

                period: "daily",

                ...(from || to
                    ? {
                        dateRange: {
                            from: from || null,
                            to: to || null
                        }
                    }
                    : {}),

                data:
                    (result.results || [])
                        .map(row => ({

                            date:
                                row.date,

                            total:
                                Number(
                                    row.total || 0
                                ),

                            cyera:
                                Number(
                                    row.cyera || 0
                                ),

                            purview:
                                Number(
                                    row.purview || 0
                                )
                        }))
            },

            200,

            corsHeaders
        );
    }


    /*
    ==========================================
    MONTHLY
    ==========================================
    */

    if (period === "monthly") {

        const result =
            await env.DB
                .prepare(`
                    SELECT

                        substr(
                            report_date,
                            1,
                            6
                        ) AS month,

                        SUM(total_alerts) AS total,

                        SUM(cyera_count) AS cyera,

                        SUM(purview_count) AS purview

                    FROM reports

                    ${dateFilter
                        ? `WHERE ${dateFilter}`
                        : ""
                    }

                    GROUP BY
                        substr(
                            report_date,
                            1,
                            6
                        )

                    ORDER BY month ASC
                `)
                .bind(...bindings)
                .all();


        return jsonResponse(
            {
                success: true,

                period: "monthly",

                ...(from || to
                    ? {
                        dateRange: {
                            from: from || null,
                            to: to || null
                        }
                    }
                    : {}),

                data:
                    (result.results || [])
                        .map(row => ({

                            month:
                                row.month,

                            total:
                                Number(
                                    row.total || 0
                                ),

                            cyera:
                                Number(
                                    row.cyera || 0
                                ),

                            purview:
                                Number(
                                    row.purview || 0
                                )
                        }))
            },

            200,

            corsHeaders
        );
    }


    /*
    ==========================================
    QUARTERLY
    ==========================================
    */

    if (period === "quarterly") {

        const result =
            await env.DB
                .prepare(`
                    SELECT

                        substr(
                            report_date,
                            1,
                            4
                        ) AS year,

                        CASE

                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 1 AND 3

                                THEN 'Q1'


                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 4 AND 6

                                THEN 'Q2'


                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 7 AND 9

                                THEN 'Q3'


                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 10 AND 12

                                THEN 'Q4'

                        END AS quarter,


                        SUM(total_alerts) AS total,

                        SUM(cyera_count) AS cyera,

                        SUM(purview_count) AS purview


                    FROM reports


                    ${dateFilter
                        ? `WHERE ${dateFilter}`
                        : ""
                    }


                    GROUP BY

                        substr(
                            report_date,
                            1,
                            4
                        ),

                        CASE

                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 1 AND 3

                                THEN 'Q1'


                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 4 AND 6

                                THEN 'Q2'


                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 7 AND 9

                                THEN 'Q3'


                            WHEN CAST(
                                substr(
                                    report_date,
                                    5,
                                    2
                                ) AS INTEGER
                            ) BETWEEN 10 AND 12

                                THEN 'Q4'

                        END


                    ORDER BY

                        year ASC,

                        quarter ASC
                `)
                .bind(...bindings)
                .all();


        return jsonResponse(
            {
                success: true,

                period: "quarterly",

                ...(from || to
                    ? {
                        dateRange: {
                            from: from || null,
                            to: to || null
                        }
                    }
                    : {}),

                data:
                    (result.results || [])
                        .map(row => ({

                            quarter:
                                `${row.year}-${row.quarter}`,

                            total:
                                Number(
                                    row.total || 0
                                ),

                            cyera:
                                Number(
                                    row.cyera || 0
                                ),

                            purview:
                                Number(
                                    row.purview || 0
                                )
                        }))
            },

            200,

            corsHeaders
        );
    }
}

/*
==========================================
GET REPORT DETAILS
==========================================
*/

/*
==========================================
GET REPORTS
==========================================

GET /api/v1/reports
GET /api/v1/reports?page=1&limit=30
GET /api/v1/reports?page=1&limit=30&from=20260801&to=20260831

Supports:

- Pagination
- Date range filtering
- Safe limit of 100 records
- Total count
- Total pages
- Next/previous page information
==========================================
*/

async function handleGetReports(
    url,
    env,
    corsHeaders
) {

    /*
    ==========================================
    PAGINATION
    ==========================================
    */

    let page =
        parseInt(
            url.searchParams.get("page") || "1",
            10
        );

    let limit =
        parseInt(
            url.searchParams.get("limit") || "30",
            10
        );


    /*
    ==========================================
    VALIDATE PAGINATION
    ==========================================
    */

    if (
        !Number.isInteger(page) ||
        page < 1
    ) {
        page = 1;
    }


    if (
        !Number.isInteger(limit) ||
        limit < 1
    ) {
        limit = 30;
    }


    // Prevent very large requests
    limit = Math.min(limit, 100);


    const offset =
        (page - 1) * limit;


    /*
    ==========================================
    DATE FILTERS
    ==========================================
    
    Supported:

    ?from=20260801
    ?to=20260831

    or:

    ?from=20260801&to=20260831
    ==========================================
    */

    const from =
        url.searchParams.get("from");

    const to =
        url.searchParams.get("to");


    /*
    ==========================================
    VALIDATE DATES
    ==========================================
    */

    if (
        (from && !/^\d{8}$/.test(from)) ||
        (to && !/^\d{8}$/.test(to))
    ) {

        return jsonResponse(
            {
                success: false,

                error:
                    "Invalid date format. Use YYYYMMDD."
            },

            400,

            corsHeaders
        );
    }


    /*
    ==========================================
    VALIDATE DATE RANGE
    ==========================================
    */

    if (
        from &&
        to &&
        from > to
    ) {

        return jsonResponse(
            {
                success: false,

                error:
                    "'from' date cannot be greater than 'to' date."
            },

            400,

            corsHeaders
        );
    }


    /*
    ==========================================
    BUILD WHERE CLAUSE
    ==========================================
    */

    let whereClause = "";

    const filterBindings = [];


    /*
    FROM DATE
    */

    if (from) {

        whereClause += `
            report_date >= ?
        `;

        filterBindings.push(from);
    }


    /*
    TO DATE
    */

    if (to) {

        if (from) {

            whereClause += `
                AND report_date <= ?
            `;

        } else {

            whereClause += `
                report_date <= ?
            `;
        }

        filterBindings.push(to);
    }


    /*
    ==========================================
    FINAL WHERE SQL
    ==========================================
    */

    const whereSQL =
        whereClause
            ? `WHERE ${whereClause}`
            : "";


    /*
    ==========================================
    GET TOTAL COUNT
    ==========================================
    */

    const countResult =
        await env.DB
            .prepare(`
                SELECT
                    COUNT(*) AS total

                FROM reports

                ${whereSQL}
            `)
            .bind(
                ...filterBindings
            )
            .first();


    const total =
        Number(
            countResult?.total || 0
        );


    /*
    ==========================================
    CALCULATE TOTAL PAGES
    ==========================================
    */

    const totalPages =
        total === 0
            ? 0
            : Math.ceil(
                total / limit
            );


    /*
    ==========================================
    GET REPORTS
    ==========================================
    */

    const reportResult =
        await env.DB
            .prepare(`
                SELECT

                    report_id,

                    report_date,

                    cyera_count,

                    purview_count,

                    total_alerts,

                    generated_at

                FROM reports

                ${whereSQL}

                ORDER BY
                    report_date DESC

                LIMIT ?

                OFFSET ?
            `)
            .bind(
                ...filterBindings,
                limit,
                offset
            )
            .all();


    /*
    ==========================================
    FORMAT REPORTS
    ==========================================
    */

    const reports =
        (reportResult.results || [])
            .map(row => ({

                reportId:
                    row.report_id,

                reportDate:
                    row.report_date,

                cyera:
                    Number(
                        row.cyera_count || 0
                    ),

                purview:
                    Number(
                        row.purview_count || 0
                    ),

                total:
                    Number(
                        row.total_alerts || 0
                    ),

                generatedAt:
                    row.generated_at

            }));


    /*
    ==========================================
    RESPONSE
    ==========================================
    */

    return jsonResponse(
        {

            success: true,

            pagination: {

                page,

                limit,

                total,

                totalPages,

                hasNextPage:
                    page < totalPages,

                hasPreviousPage:
                    page > 1 &&
                    totalPages > 0

            },

            /*
            Only include dateRange when
            a date filter was actually used.
            */

            ...(from || to
                ? {

                    dateRange: {

                        from:
                            from || null,

                        to:
                            to || null

                    }

                }
                : {}),

            data:
                reports

        },

        200,

        corsHeaders
    );
}
/*
==========================================
GET REPORT SUMMARY
==========================================
*/
async function handleGetReportAlerts(
    reportId,
    url,
    env,
    corsHeaders
) {

    /*
    ==========================================
    Query parameters
    ==========================================
    */

    const source =
        url.searchParams.get("source");

    const severity =
        url.searchParams.get("severity");

    const status =
        url.searchParams.get("status");

    const assignedUser =
        url.searchParams.get("assignedUser");

    const search =
        url.searchParams.get("search");

    const from =
        url.searchParams.get("from");

    const to =
        url.searchParams.get("to");


    /*
    ==========================================
    Pagination
    ==========================================
    */

    let page =
        parseInt(
            url.searchParams.get("page") || "1",
            10
        );

    let limit =
        parseInt(
            url.searchParams.get("limit") || "50",
            10
        );

    if (page < 1) {
        page = 1;
    }

    if (limit < 1) {
        limit = 50;
    }

    if (limit > 100) {
        limit = 100;
    }

    const offset =
        (page - 1) * limit;


    /*
    ==========================================
    Validate source
    ==========================================
    */

    if (
        source &&
        source.toLowerCase() !== "cyera" &&
        source.toLowerCase() !== "purview"
    ) {

        return jsonResponse(
            {
                success: false,
                error:
                    "Invalid source. Use cyera or purview."
            },
            400,
            corsHeaders
        );
    }


    /*
    ==========================================
    Verify report exists
    ==========================================
    */

    const report =
        await env.DB
            .prepare(`
                SELECT
                    report_id,
                    report_date,
                    reporting_from,
                    reporting_to
                FROM reports
                WHERE report_id = ?
                LIMIT 1
            `)
            .bind(reportId)
            .first();


    if (!report) {

        return jsonResponse(
            {
                success: false,
                error: "Report not found"
            },
            404,
            corsHeaders
        );
    }


    /*
    ==========================================
    Validate date format
    ==========================================
    
    Expected:
    YYYY-MM-DD

    Example:
    from=2026-08-01
    to=2026-08-21

    ==========================================
    */

    const dateRegex =
        /^\d{4}-\d{2}-\d{2}$/;

    if (
        (from && !dateRegex.test(from)) ||
        (to && !dateRegex.test(to))
    ) {

        return jsonResponse(
            {
                success: false,
                error:
                    "Invalid date format. Use YYYY-MM-DD."
            },
            400,
            corsHeaders
        );
    }


    if (from && to && from > to) {

        return jsonResponse(
            {
                success: false,
                error:
                    "The 'from' date cannot be later than the 'to' date."
            },
            400,
            corsHeaders
        );
    }


    /*
    ==========================================
    Variables
    ==========================================
    */

    let alerts = [];

    let total = 0;


    /*
    ==========================================
    CYERA
    ==========================================
    */

    if (
        source &&
        source.toLowerCase() === "cyera"
    ) {

        let where = `
            WHERE report_id = ?
        `;

        const params = [reportId];


        /*
        Severity
        */

        if (severity) {

            where += `
                AND LOWER(severity) = LOWER(?)
            `;

            params.push(severity);
        }


        /*
        Status
        */

        if (status) {

            where += `
                AND LOWER(status) = LOWER(?)
            `;

            params.push(status);
        }


        /*
        Assigned user
        */

        if (assignedUser) {

            if (
                assignedUser.toLowerCase() ===
                "unassigned"
            ) {

                where += `
                    AND assigned_user_email IS NULL
                `;

            } else {

                where += `
                    AND LOWER(
                        assigned_user_email
                    ) = LOWER(?)
                `;

                params.push(assignedUser);
            }
        }


        /*
        Search
        */

        if (search) {

            where += `
                AND (
                    LOWER(name) LIKE LOWER(?)
                    OR LOWER(alert_id) LIKE LOWER(?)
                    OR LOWER(triggering_user) LIKE LOWER(?)
                    OR LOWER(authenticated_user) LIKE LOWER(?)
                    OR LOWER(policy_name) LIKE LOWER(?)
                )
            `;

            const searchValue =
                `%${search}%`;

            params.push(
                searchValue,
                searchValue,
                searchValue,
                searchValue,
                searchValue
            );
        }


        /*
        Date filter

        Cyera uses timestamp.
        */

        if (from) {

            where += `
                AND DATE(timestamp) >= DATE(?)
            `;

            params.push(from);
        }

        if (to) {

            where += `
                AND DATE(timestamp) <= DATE(?)
            `;

            params.push(to);
        }


        /*
        Count
        */

        const countResult =
            await env.DB
                .prepare(`
                    SELECT COUNT(*) AS total
                    FROM cyera_alerts
                    ${where}
                `)
                .bind(...params)
                .first();


        total =
            Number(
                countResult?.total || 0
            );


        /*
        Records
        */

        const result =
            await env.DB
                .prepare(`
                    SELECT *
                    FROM cyera_alerts
                    ${where}
                    ORDER BY id ASC
                    LIMIT ?
                    OFFSET ?
                `)
                .bind(
                    ...params,
                    limit,
                    offset
                )
                .all();


        alerts =
            (result.results || [])
                .map(record => ({
                    source: "cyera",
                    ...record
                }));
    }


    /*
    ==========================================
    PURVIEW
    ==========================================
    */

    if (
        source &&
        source.toLowerCase() === "purview"
    ) {

        let where = `
            WHERE report_id = ?
        `;

        const params = [reportId];


        /*
        Severity
        */

        if (severity) {

            where += `
                AND LOWER(severity) = LOWER(?)
            `;

            params.push(severity);
        }


        /*
        Status
        */

        if (status) {

            where += `
                AND LOWER(status) = LOWER(?)
            `;

            params.push(status);
        }


        /*
        Search
        */

        if (search) {

            where += `
                AND (
                    LOWER(alert_name) LIKE LOWER(?)
                    OR LOWER(user) LIKE LOWER(?)
                    OR LOWER(location) LIKE LOWER(?)
                )
            `;

            const searchValue =
                `%${search}%`;

            params.push(
                searchValue,
                searchValue,
                searchValue
            );
        }


        /*
        Date filter

        Purview uses time_detected.
        */

        if (from) {

            where += `
                AND DATE(time_detected) >= DATE(?)
            `;

            params.push(from);
        }

        if (to) {

            where += `
                AND DATE(time_detected) <= DATE(?)
            `;

            params.push(to);
        }


        /*
        Count
        */

        const countResult =
            await env.DB
                .prepare(`
                    SELECT COUNT(*) AS total
                    FROM purview_alerts
                    ${where}
                `)
                .bind(...params)
                .first();


        total =
            Number(
                countResult?.total || 0
            );


        /*
        Records
        */

        const result =
            await env.DB
                .prepare(`
                    SELECT *
                    FROM purview_alerts
                    ${where}
                    ORDER BY id ASC
                    LIMIT ?
                    OFFSET ?
                `)
                .bind(
                    ...params,
                    limit,
                    offset
                )
                .all();


        alerts =
            (result.results || [])
                .map(record => ({
                    source: "purview",
                    ...record
                }));
    }


    /*
    ==========================================
    Source required
    ==========================================
    */

    if (!source) {

        return jsonResponse(
            {
                success: false,

                error:
                    "source is required. Use source=cyera or source=purview."
            },

            400,

            corsHeaders
        );
    }


    /*
    ==========================================
    Pagination metadata
    ==========================================
    */

    const totalPages =
        Math.ceil(
            total / limit
        );


    /*
    ==========================================
    Response
    ==========================================
    */

    return jsonResponse(
        {

            success: true,

            report: {

                reportId:
                    report.report_id,

                reportDate:
                    report.report_date,

                reportingFrom:
                    report.reporting_from || null,

                reportingTo:
                    report.reporting_to || null
            },

            source:
                source.toLowerCase(),

            filters: {

                severity:
                    severity || null,

                status:
                    status || null,

                assignedUser:
                    assignedUser || null,

                search:
                    search || null,

                from:
                    from || null,

                to:
                    to || null
            },

            pagination: {

                page,

                limit,

                total,

                totalPages,

                hasNextPage:
                    page < totalPages,

                hasPreviousPage:
                    page > 1
            },

            alerts

        },

        200,

        corsHeaders
    );
}

/*
==========================================
ALERT HISTORY HELPERS
==========================================
*/

/*
Generate a stable fingerprint for Purview alerts.

Purview does not provide a stable alert ID in
the source CSV, so we combine the fields that
identify the individual detection.
*/
async function generatePurviewAlertId(alert) {

    const raw = [
        alert.alertName || "",
        alert.timeDetected || "",
        alert.user || "",
        alert.location || ""
    ]
        .map(value => String(value).trim().toLowerCase())
        .join("|");

    const encoder = new TextEncoder();

    const data =
        encoder.encode(raw);

    const hashBuffer =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    const hashArray =
        Array.from(
            new Uint8Array(hashBuffer)
        );

    const hash =
        hashArray
            .map(byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
            )
            .join("");

    return `purview:${hash}`;
}


/*
Normalize status values so that
"Resolved", "resolved", etc. are
treated consistently.
*/
function normalizeAlertStatus(status) {

    return String(
        status || ""
    )
        .trim()
        .toLowerCase();
}


/*
Determine whether an alert is resolved.
*/
function isResolvedStatus(status) {

    const normalized =
        normalizeAlertStatus(status);

    return [
        "resolved",
        "closed",
        "complete",
        "completed"
    ].includes(normalized);
}


/*
Find an existing canonical alert.
*/
async function findCanonicalAlert(
    env,
    source,
    externalAlertId
) {

    return await env.DB
        .prepare(`
            SELECT *
            FROM alerts
            WHERE source = ?
              AND external_alert_id = ?
            LIMIT 1
        `)
        .bind(
            source,
            externalAlertId
        )
        .first();
}


/*
Create a canonical alert.
*/
async function createCanonicalAlert(
    env,
    {
        source,
        externalAlertId,
        name,
        severity,
        status,
        assignedUser,
        observedAt
    }
) {

    const result =
        await env.DB
            .prepare(`
                INSERT INTO alerts (
                    source,
                    external_alert_id,
                    name,
                    current_severity,
                    current_status,
                    current_assigned_user,
                    first_seen_at,
                    last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `)
            .bind(
                source,
                externalAlertId,
                name || null,
                severity || null,
                status || null,
                assignedUser || null,
                observedAt,
                observedAt
            )
            .run();

    return result.meta?.last_row_id;
}


/*
Update an existing canonical alert.
*/
async function updateCanonicalAlert(
    env,
    {
        id,
        name,
        severity,
        status,
        assignedUser,
        observedAt,
        resolvedAt
    }
) {

    await env.DB
        .prepare(`
            UPDATE alerts
            SET
                name = ?,
                current_severity = ?,
                current_status = ?,
                current_assigned_user = ?,
                last_seen_at = ?,
                resolved_at = COALESCE(?, resolved_at),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `)
        .bind(
            name || null,
            severity || null,
            status || null,
            assignedUser || null,
            observedAt,
            resolvedAt || null,
            id
        )
        .run();
}


/*
Add a historical observation.

UNIQUE(alert_id, report_id) prevents the
same alert from being recorded twice for
the same report.
*/
async function insertAlertHistory(
    env,
    {
        alertId,
        reportId,
        observedAt,
        severity,
        status,
        assignedUser
    }
) {

    await env.DB
        .prepare(`
            INSERT OR IGNORE INTO alert_history (
                alert_id,
                report_id,
                observed_at,
                severity,
                status,
                assigned_user
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `)
        .bind(
            alertId,
            reportId,
            observedAt,
            severity || null,
            status || null,
            assignedUser || null
        )
        .run();
}


/*
Get the previous observation for an alert.

This is used to determine whether the
current observation is:

NEW
or
CARRIED OVER
or
RESOLVED
*/
async function getPreviousAlertHistory(
    env,
    alertId,
    reportId
) {

    return await env.DB
        .prepare(`
            SELECT
                severity,
                status,
                assigned_user,
                observed_at,
                report_id
            FROM alert_history
            WHERE alert_id = ?
              AND report_id != ?
            ORDER BY observed_at DESC
            LIMIT 1
        `)
        .bind(
            alertId,
            reportId
        )
        .first();
}

/*
==========================================
VALIDATION
==========================================
*/

function validateReport(data) {

    if (!data) {

        return {
            valid: false,
            error: "Request body is empty"
        };
    }


    if (!data.report) {

        return {
            valid: false,
            error: "Missing report object"
        };
    }


    if (!data.report.reportId) {

        return {
            valid: false,
            error: "Missing report.reportId"
        };
    }


    if (!data.report.reportDate) {

        return {
            valid: false,
            error: "Missing report.reportDate"
        };
    }


    if (
        data.cyera &&
        !Array.isArray(data.cyera.records)
    ) {

        return {
            valid: false,
            error: "cyera.records must be an array"
        };
    }


    if (
        data.purview &&
        !Array.isArray(data.purview.records)
    ) {

        return {
            valid: false,
            error: "purview.records must be an array"
        };
    }


    return {
        valid: true
    };
}


/*
==========================================
JSON RESPONSE
==========================================
*/

function jsonResponse(
    data,
    status,
    additionalHeaders = {}
) {

    return new Response(

        JSON.stringify(data, null, 2),

        {
            status,

            headers: {
                "Content-Type":
                    "application/json",

                ...additionalHeaders
            }
        }
    );
}
