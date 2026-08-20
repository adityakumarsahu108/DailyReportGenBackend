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

            // Health check
            if (
                request.method === "GET" &&
                url.pathname === "/api/v1/health"
            ) {

                return jsonResponse(
                    {
                        success: true,
                        service: "daily-report-api",
                        database: "connected"
                    },
                    200,
                    corsHeaders
                );
            }


            // Create daily report
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


            // Analytics summary
            if (
                request.method === "GET" &&
                url.pathname === "/api/v1/analytics/summary"
            ) {

                return await handleAnalyticsSummary(
                    env,
                    corsHeaders
                );
            }


            // Analytics trends
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


            /*
            ==========================================
            REPORT ALERTS
            ==========================================
            */

            // Get individual alerts for a report
            // Example:
            // /api/v1/reports/REP-21202602/alerts?source=cyera
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


            /*
            ==========================================
            REPORT SUMMARY
            ==========================================
            */

            // Get report summary
            // Example:
            // /api/v1/reports/REP-21202602
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

                return await handleGetReport(
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
                "Worker error:",
                error
            );

            return jsonResponse(
                {
                    success: false,

                    error:
                        error?.message ||
                        String(error)
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
    INSERT CYERA
    ==========================================
    */

    for (let i = 0; i < cyeraRecords.length; i++) {

        const alert = cyeraRecords[i];

        console.log(
            `Processing Cyera alert ${i + 1}/${cyeraRecords.length}`,
            alert.id
        );

        try {

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

                    alert.id || null,
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

        } catch (error) {

            console.error(
                `CYERA INSERT FAILED AT RECORD ${i + 1}`,
                {
                    alertId: alert.id,
                    alertName: alert.name,
                    error: String(error)
                }
            );

            throw error;
        }
    }

    /*
    ==========================================
    INSERT PURVIEW
    ==========================================
    */

    for (const alert of purviewRecords) {

        await env.DB
            .prepare(`
                INSERT INTO purview_alerts (

                    report_id,

                    alert_name,
                    severity,
                    status,

                    time_detected,

                    user,
                    location

                )

                VALUES (?, ?, ?, ?, ?, ?, ?)
            `)
            .bind(

                reportId,

                alert.alertName || null,

                alert.severity || null,

                alert.status || null,

                alert.timeDetected || null,

                alert.user || null,

                alert.location || null

            )
            .run();
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
                    GROUP BY report_date
                    ORDER BY report_date ASC
                `)
                .all();


        return jsonResponse(
            {
                success: true,

                period: "daily",

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
                        substr(report_date, 1, 6) AS month,
                        SUM(total_alerts) AS total,
                        SUM(cyera_count) AS cyera,
                        SUM(purview_count) AS purview
                    FROM reports
                    GROUP BY substr(report_date, 1, 6)
                    ORDER BY month ASC
                `)
                .all();


        return jsonResponse(
            {
                success: true,

                period: "monthly",

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
                    substr(report_date, 1, 4) AS year,

                    CASE
                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 1 AND 3
                            THEN 'Q1'

                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 4 AND 6
                            THEN 'Q2'

                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 7 AND 9
                            THEN 'Q3'

                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 10 AND 12
                            THEN 'Q4'
                    END AS quarter,

                    SUM(total_alerts) AS total,

                    SUM(cyera_count) AS cyera,

                    SUM(purview_count) AS purview

                FROM reports

                GROUP BY
                    substr(report_date, 1, 4),

                    CASE
                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 1 AND 3
                            THEN 'Q1'

                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 4 AND 6
                            THEN 'Q2'

                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 7 AND 9
                            THEN 'Q3'

                        WHEN CAST(
                            substr(report_date, 5, 2)
                            AS INTEGER
                        ) BETWEEN 10 AND 12
                            THEN 'Q4'
                    END

                ORDER BY
                    year ASC,
                    quarter ASC
            `)
            .all();


    return jsonResponse(
        {
            success: true,

            period: "quarterly",

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
/*
==========================================
GET REPORT DETAILS
==========================================
*/
/*
==========================================
GET REPORT SUMMARY
==========================================
*/

async function handleGetReport(
    reportId,
    url,
    env,
    corsHeaders
) {

    /*
    ==========================================
    Get report
    ==========================================
    */

    const report = await env.DB
        .prepare(`
            SELECT
                report_id,
                report_date,
                cyera_count,
                purview_count,
                total_alerts,
                generated_at
            FROM reports
            WHERE report_id = ?
            LIMIT 1
        `)
        .bind(reportId)
        .first();


    /*
    ==========================================
    Report not found
    ==========================================
    */

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
    Cyera severity
    ==========================================
    */

    const cyeraSeverity =
        await env.DB
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
                WHERE report_id = ?
                GROUP BY LOWER(
                    COALESCE(
                        severity,
                        'unknown'
                    )
                )
            `)
            .bind(reportId)
            .all();


    /*
    ==========================================
    Cyera status
    ==========================================
    */

    const cyeraStatus =
        await env.DB
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
                WHERE report_id = ?
                GROUP BY LOWER(
                    COALESCE(
                        status,
                        'unknown'
                    )
                )
            `)
            .bind(reportId)
            .all();


    /*
    ==========================================
    Cyera assigned users
    ==========================================
    */

    const cyeraAssignedUsers =
        await env.DB
            .prepare(`
                SELECT
                    COALESCE(
                        assigned_user_email,
                        'Unassigned'
                    ) AS assigned_user,
                    COUNT(*) AS count
                FROM cyera_alerts
                WHERE report_id = ?
                GROUP BY assigned_user_email
                ORDER BY count DESC
            `)
            .bind(reportId)
            .all();


    /*
    ==========================================
    Purview severity
    ==========================================
    */

    const purviewSeverity =
        await env.DB
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
                WHERE report_id = ?
                GROUP BY LOWER(
                    COALESCE(
                        severity,
                        'unknown'
                    )
                )
            `)
            .bind(reportId)
            .all();


    /*
    ==========================================
    Purview status
    ==========================================
    */

    const purviewStatus =
        await env.DB
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
                WHERE report_id = ?
                GROUP BY LOWER(
                    COALESCE(
                        status,
                        'unknown'
                    )
                )
            `)
            .bind(reportId)
            .all();


    /*
    ==========================================
    Return summary only
    ==========================================
    */

    return jsonResponse(
        {
            success: true,

            report: report,

            cyera: {

                count:
                    Number(
                        report.cyera_count || 0
                    ),

                severity:
                    cyeraSeverity.results || [],

                status:
                    cyeraStatus.results || [],

                assignedUsers:
                    cyeraAssignedUsers.results || []
            },

            purview: {

                count:
                    Number(
                        report.purview_count || 0
                    ),

                severity:
                    purviewSeverity.results || [],

                status:
                    purviewStatus.results || []
            }
        },

        200,

        corsHeaders
    );
}

/*
==========================================
GET REPORT ALERTS
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


    // Safety limits

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
                    report_date
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
    Build queries
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
        !source ||
        source.toLowerCase() === "cyera"
    ) {

        let where = `
            WHERE report_id = ?
        `;

        const params = [reportId];


        if (severity) {

            where += `
                AND LOWER(severity) = LOWER(?)
            `;

            params.push(severity);
        }


        if (status) {

            where += `
                AND LOWER(status) = LOWER(?)
            `;

            params.push(status);
        }


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

                params.push(
                    assignedUser
                );
            }
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


        if (severity) {

            where += `
                AND LOWER(severity) = LOWER(?)
            `;

            params.push(severity);
        }


        if (status) {

            where += `
                AND LOWER(status) = LOWER(?)
            `;

            params.push(status);
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
    No source specified
    ==========================================
    
    For now, don't combine Cyera and Purview.
    The frontend should explicitly request
    one source.
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
                    report.report_date
            },

            source:
                source.toLowerCase(),

            filters: {

                severity:
                    severity || null,

                status:
                    status || null,

                assignedUser:
                    assignedUser || null
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
