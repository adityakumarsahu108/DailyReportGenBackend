/*
==========================================
Daily Report API
Cloudflare Worker
==========================================
*/


export default {

    async fetch(request, env) {

        const url =
            new URL(request.url);


        /*
        ==========================================
        CORS
        ==========================================
        */

        const corsHeaders = {

            "Access-Control-Allow-Origin": "*",

            "Access-Control-Allow-Methods":
                "GET, POST, OPTIONS",

            "Access-Control-Allow-Headers":
                "Content-Type, Authorization"

        };


        /*
        ==========================================
        OPTIONS / CORS preflight
        ==========================================
        */

        if (request.method === "OPTIONS") {

            return new Response(
                null,
                {
                    status: 204,
                    headers: corsHeaders
                }
            );

        }


        try {

            /*
            ==========================================
            Health Check
            ==========================================
            */

            if (
                url.pathname ===
                "/api/v1/health"
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


            /*
            ==========================================
            POST /api/v1/reports
            ==========================================
            */

            if (
                request.method === "POST" &&
                url.pathname ===
                "/api/v1/reports"
            ) {

                return await handleCreateReport(
                    request,
                    env,
                    corsHeaders
                );

            }


            /*
            ==========================================
            Unknown Route
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
Create Report
==========================================
*/

async function handleCreateReport(
    request,
    env,
    corsHeaders
) {

    /*
    ==========================================
    Parse JSON
    ==========================================
    */

    let data;

    try {

        data =
            await request.json();

    } catch (error) {

        return jsonResponse(

            {
                success: false,
                error: "Invalid JSON payload"
            },

            400,
            corsHeaders

        );

    }


    /*
    ==========================================
    Validate payload
    ==========================================
    */

    const validation =
        validateReport(data);

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


    const report =
        data.report;

    const reportId =
        report.reportId;


    /*
    ==========================================
    Duplicate Protection
    ==========================================
    */

    const existing =
        await env.DB
            .prepare(
                `
                SELECT report_id
                FROM reports
                WHERE report_id = ?
                `
            )
            .bind(reportId)
            .first();


    if (existing) {

        return jsonResponse(

            {
                success: true,

                duplicate: true,

                reportId,

                message:
                    "Report already exists"

            },

            200,
            corsHeaders

        );

    }


    /*
    ==========================================
    Extract records
    ==========================================
    */

    const cyeraRecords =
        data.cyera?.records || [];

    const purviewRecords =
        data.purview?.records || [];


    /*
    ==========================================
    Insert report
    ==========================================
    */

    await env.DB
        .prepare(
            `
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
            `
        )
        .bind(

            reportId,

            report.reportDate,

            report.reportingWindow?.from ||
                null,

            report.reportingWindow?.to ||
                null,

            report.generatedAt ||
                null,

            report.generatorVersion ||
                null,

            data.schemaVersion ||
                null,

            cyeraRecords.length,

            purviewRecords.length,

            cyeraRecords.length +
            purviewRecords.length

        )
        .run();


    /*
    ==========================================
    Insert Cyera Alerts
    ==========================================
    */

    for (const alert of cyeraRecords) {

        await env.DB
            .prepare(
                `
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
                `
            )
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
    Insert Purview Alerts
    ==========================================
    */

    for (const alert of purviewRecords) {

        await env.DB
            .prepare(
                `
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
                `
            )
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
    Success
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
Payload Validation
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
            error:
                "cyera.records must be an array"
        };

    }


    if (
        data.purview &&
        !Array.isArray(data.purview.records)
    ) {

        return {
            valid: false,
            error:
                "purview.records must be an array"
        };

    }


    return {
        valid: true
    };

}


/*
==========================================
JSON Response Helper
==========================================
*/

function jsonResponse(
    data,
    status,
    additionalHeaders = {}
) {

    return new Response(

        JSON.stringify(
            data,
            null,
            2
        ),

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