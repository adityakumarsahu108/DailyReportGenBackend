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
GENERATE BASIC INSIGHTS
==========================================
*/

const totalAlerts =
    cyeraTotal +
    purviewTotal;


const insights = [];


/*
------------------------------------------
CRITICAL ALERTS
------------------------------------------
*/

if (severity.critical > 0) {

    insights.push({

        type: "critical",

        priority: "high",

        metric:
            severity.critical,

        message:
            `${severity.critical} critical ${
                severity.critical === 1
                    ? "alert requires"
                    : "alerts require"
            } attention.`

    });

}


/*
------------------------------------------
HIGH-SEVERITY ALERTS
------------------------------------------
*/

if (severity.high > 0) {

    insights.push({

        type: "severity",

        priority: "high",

        metric:
            severity.high,

        message:
            `${severity.high} high-severity ${
                severity.high === 1
                    ? "alert is"
                    : "alerts are"
            } currently present.`

    });

}


/*
------------------------------------------
MEDIUM-SEVERITY CONCENTRATION
------------------------------------------
*/

if (totalAlerts > 0) {

    const mediumPercentage =
        Math.round(
            (
                severity.medium /
                totalAlerts
            ) * 100
        );


    if (mediumPercentage >= 70) {

        insights.push({

            type: "severity_concentration",

            priority: "medium",

            metric: mediumPercentage,

            message:
                `Medium-severity alerts account for approximately ${mediumPercentage}% of the current alert volume.`

        });

    }

}


/*
------------------------------------------
RESOLUTION RATE
------------------------------------------
*/

if (totalAlerts > 0) {

    const resolved =
        status.resolved || 0;


    const resolutionPercentage =
        Math.round(
            (
                resolved /
                totalAlerts
            ) * 100
        );


    if (resolutionPercentage < 25) {

        insights.push({

            type: "resolution",

            priority: "medium",

            metric:
                resolutionPercentage,

            message:
                `Only ${resolved} of ${totalAlerts} alerts are currently resolved (${resolutionPercentage}%).`

        });

    }

}


/*
------------------------------------------
UNASSIGNED ALERTS
------------------------------------------
*/

if (unassigned > 0) {

    insights.push({

        type: "assignment",

        priority:
            unassigned >= 10
                ? "high"
                : "medium",

        metric:
            unassigned,

        message:
            `${unassigned} alerts are currently unassigned to an analyst.`

    });

}


/*
------------------------------------------
NO CRITICAL / HIGH ALERTS
------------------------------------------
*/

if (
    severity.critical === 0 &&
    severity.high === 0 &&
    totalAlerts > 0
) {

    insights.push({

        type: "risk_observation",

        priority: "low",

        metric: 0,

        message:
            "No critical or high-severity alerts are present in the latest report."

    });

}


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
            totalAlerts,

        cyera:
            cyeraTotal,

        purview:
            purviewTotal,

        unassigned,

        severity,

        status

    },

    insights

};
}