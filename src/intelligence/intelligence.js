/*
==========================================
SECURITY INTELLIGENCE ENGINE
==========================================

Phase 1:
Basic Security Intelligence Summary

Uses the existing populated report tables:

    reports
    cyera_alerts
    purview_alerts

No AI.
No scoring.
No anomaly detection yet.
==========================================
*/


export async function generateSecurityIntelligence(env) {

    /*
    ==========================================
    FIND LATEST REPORT
    ==========================================
    */

    const latestReport =
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
                ORDER BY
                    report_date DESC,
                    id DESC
                LIMIT 1
            `)
            .first();


    /*
    ==========================================
    NO REPORTS
    ==========================================
    */

    if (!latestReport) {

        return {

            generatedAt:
                new Date().toISOString(),

            report: null,

            alerts: {

                total: 0,

                cyera: 0,

                purview: 0,

                unassigned: 0,

                severity: {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    unknown: 0
                },

                status: {
                    open: 0,
                    active: 0,
                    investigating: 0,
                    resolved: 0,
                    closed: 0,
                    unknown: 0
                }

            }

        };

    }


    const reportId =
        latestReport.report_id;


    /*
    ==========================================
    CYERA SUMMARY
    ==========================================
    */

    const cyeraRows =
        await env.DB
            .prepare(`
                SELECT
                    LOWER(
                        COALESCE(
                            severity,
                            'unknown'
                        )
                    ) AS severity,

                    LOWER(
                        COALESCE(
                            status,
                            'unknown'
                        )
                    ) AS status,

                    COUNT(*) AS count

                FROM cyera_alerts

                WHERE report_id = ?

                GROUP BY
                    LOWER(
                        COALESCE(
                            severity,
                            'unknown'
                        )
                    ),
                    LOWER(
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
    PURVIEW SUMMARY
    ==========================================
    */

    const purviewRows =
        await env.DB
            .prepare(`
                SELECT
                    LOWER(
                        COALESCE(
                            severity,
                            'unknown'
                        )
                    ) AS severity,

                    LOWER(
                        COALESCE(
                            status,
                            'unknown'
                        )
                    ) AS status,

                    COUNT(*) AS count

                FROM purview_alerts

                WHERE report_id = ?

                GROUP BY
                    LOWER(
                        COALESCE(
                            severity,
                            'unknown'
                        )
                    ),
                    LOWER(
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
    INITIALIZE METRICS
    ==========================================
    */

    const severity = {

        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0

    };


    const status = {

        open: 0,
        active: 0,
        investigating: 0,
        resolved: 0,
        closed: 0,
        unknown: 0

    };


    let cyeraTotal = 0;
    let purviewTotal = 0;


    /*
    ==========================================
    PROCESS CYERA
    ==========================================
    */

    for (
        const row
        of cyeraRows.results || []
    ) {

        const count =
            Number(row.count || 0);


        cyeraTotal += count;


        const severityKey =
            String(
                row.severity || "unknown"
            ).toLowerCase();


        const statusKey =
            String(
                row.status || "unknown"
            ).toLowerCase();


        if (
            Object.prototype.hasOwnProperty
                .call(
                    severity,
                    severityKey
                )
        ) {

            severity[severityKey] += count;

        }


        if (
            Object.prototype.hasOwnProperty
                .call(
                    status,
                    statusKey
                )
        ) {

            status[statusKey] += count;

        }

    }


    /*
    ==========================================
    PROCESS PURVIEW
    ==========================================
    */

    for (
        const row
        of purviewRows.results || []
    ) {

        const count =
            Number(row.count || 0);


        purviewTotal += count;


        const severityKey =
            String(
                row.severity || "unknown"
            ).toLowerCase();


        const statusKey =
            String(
                row.status || "unknown"
            ).toLowerCase();


        if (
            Object.prototype.hasOwnProperty
                .call(
                    severity,
                    severityKey
                )
        ) {

            severity[severityKey] += count;

        }


        if (
            Object.prototype.hasOwnProperty
                .call(
                    status,
                    statusKey
                )
        ) {

            status[statusKey] += count;

        }

    }


    /*
    ==========================================
    UNASSIGNED CYERA ALERTS
    ==========================================

    Cyera:
    assigned_user_email = analyst assignment

    Purview:
    user = person involved in the alert,
    NOT an analyst assignment.

    Therefore we only calculate this from
    Cyera at this stage.
    ==========================================
    */

    const unassignedResult =
        await env.DB
            .prepare(`
                SELECT
                    COUNT(*) AS count

                FROM cyera_alerts

                WHERE
                    report_id = ?

                    AND (
                        assigned_user_email IS NULL
                        OR
                        TRIM(
                            assigned_user_email
                        ) = ''
                    )
            `)
            .bind(reportId)
            .first();


    const unassigned =
        Number(
            unassignedResult?.count || 0
        );


    /*
    ==========================================
    RETURN SECURITY INTELLIGENCE
    ==========================================
    */

    return {

        generatedAt:
            new Date().toISOString(),

        report: {

            reportId:
                latestReport.report_id,

            reportDate:
                latestReport.report_date,

            generatedAt:
                latestReport.generated_at

        },

        alerts: {

            total:
                cyeraTotal +
                purviewTotal,

            cyera:
                cyeraTotal,

            purview:
                purviewTotal,

            unassigned,

            severity,

            status

        }

    };

}