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

            return jsonResponse(
                {
                    success: false,
                    error: "Route not found"
                },
                404,
                corsHeaders
            );

        } catch (error) {

            console.error(error);

            return jsonResponse(
                {
                    success: false,
                    error: "Internal server error"
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

    for (const alert of cyeraRecords) {

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
                    ?, ?, ?, ?, ?, ?, ?, ?
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