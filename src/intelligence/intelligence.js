/*
==========================================
SECURITY INTELLIGENCE ENGINE
==========================================

Phase 1:
Basic Security Intelligence

Phase 1.1:
Explainable observations

Phase 1.2:
Previous-report comparison

Important:
Report-to-report differences are NOT treated
as "new alerts" until alert identity/history
logic is implemented.
==========================================
*/

/*
==========================================
CYERA ALERT LIFECYCLE
NEW VS CARRIED OVER
==========================================
*/

async function getCyeraLifecycle(env, reportId) {

    /*
    ==========================================
    GET CURRENT REPORT ALERTS
    ==========================================
    */

    const currentResult = await env.DB
        .prepare(`
            SELECT DISTINCT
                ah.alert_id
            FROM alert_history ah
            JOIN alerts a
                ON a.id = ah.alert_id
            WHERE
                ah.report_id = ?
                AND a.source = 'cyera'
        `)
        .bind(reportId)
        .all();


    const currentAlerts =
        currentResult.results || [];


    /*
    ==========================================
    FIND PREVIOUS REPORT
    ==========================================
    */

    const previousReport = await env.DB
        .prepare(`
            SELECT
                report_id,
                report_date
            FROM reports
            WHERE report_date < (
                SELECT report_date
                FROM reports
                WHERE report_id = ?
            )
            ORDER BY report_date DESC
            LIMIT 1
        `)
        .bind(reportId)
        .first();


    /*
    ==========================================
    NO PREVIOUS REPORT
    ==========================================
    */

    if (!previousReport) {

        return {
            currentReportId: reportId,
            previousReportId: null,

            currentAlerts: currentAlerts.length,

            new: currentAlerts.length,

            carriedOver: 0,

            newPercentage:
                currentAlerts.length > 0
                    ? 100
                    : 0,

            carriedOverPercentage: 0
        };
    }


    /*
    ==========================================
    GET PREVIOUS REPORT ALERTS
    ==========================================
    */

    const previousResult = await env.DB
        .prepare(`
            SELECT DISTINCT
                ah.alert_id
            FROM alert_history ah
            JOIN alerts a
                ON a.id = ah.alert_id
            WHERE
                ah.report_id = ?
                AND a.source = 'cyera'
        `)
        .bind(previousReport.report_id)
        .all();


    const previousAlerts =
        previousResult.results || [];


    /*
    ==========================================
    CREATE LOOKUP SET
    ==========================================
    */

    const previousAlertIds =
        new Set(
            previousAlerts.map(
                row => String(row.alert_id)
            )
        );


    /*
    ==========================================
    CALCULATE LIFECYCLE
    ==========================================
    */

    let newCount = 0;
    let carriedOverCount = 0;


    for (const alert of currentAlerts) {

        const alertId =
            String(alert.alert_id);


        if (previousAlertIds.has(alertId)) {

            carriedOverCount++;

        } else {

            newCount++;

        }
    }


    const total =
        currentAlerts.length;


    const newPercentage =
        total > 0
            ? Number(
                ((newCount / total) * 100)
                    .toFixed(1)
            )
            : 0;


    const carriedOverPercentage =
        total > 0
            ? Number(
                ((carriedOverCount / total) * 100)
                    .toFixed(1)
            )
            : 0;


    return {

        currentReportId:
            reportId,

        previousReportId:
            previousReport.report_id,

        currentAlerts:
            total,

        new:
            newCount,

        carriedOver:
            carriedOverCount,

        newPercentage,

        carriedOverPercentage
    };
}
export async function generateSecurityIntelligence(env) {

    /*
    ==========================================
    FIND LATEST TWO REPORTS
    ==========================================
    */

    const reportsResult =
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
                LIMIT 2
            `)
            .all();


    const reports =
        reportsResult.results || [];


    const latestReport =
        reports[0] || null;


    const previousReport =
        reports[1] || null;


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

            },

            comparison: null,

            insights: []

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
    user = person involved in alert.

    Therefore unassigned is calculated
    from Cyera only for now.
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
    TOTAL ALERTS
    ==========================================
    */

    const totalAlerts =
        cyeraTotal +
        purviewTotal;


    /*
    ==========================================
    GENERATE BASIC INSIGHTS
    ==========================================
    */

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
                `${severity.critical} critical ${severity.critical === 1
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
                `${severity.high} high-severity ${severity.high === 1
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

                type:
                    "severity_concentration",

                priority:
                    "medium",

                metric:
                    mediumPercentage,

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

                type:
                    "resolution",

                priority:
                    "medium",

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

            type:
                "assignment",

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
    ==========================================
    PHASE 1.2
    PREVIOUS REPORT COMPARISON
    ==========================================
    */

    let comparison = null;


    if (previousReport) {

        const currentTotal =
            totalAlerts;


        const previousTotal =
            Number(
                previousReport.total_alerts || 0
            );


        const totalChange =
            currentTotal -
            previousTotal;


        let percentageChange = 0;


        if (previousTotal > 0) {

            percentageChange =
                Number(
                    (
                        (
                            totalChange /
                            previousTotal
                        ) * 100
                    ).toFixed(1)
                );

        }


        /*
        --------------------------------------
        CYERA CHANGE
        --------------------------------------
        */

        const currentCyera =
            cyeraTotal;


        const previousCyera =
            Number(
                previousReport.cyera_count || 0
            );


        const cyeraChange =
            currentCyera -
            previousCyera;


        let cyeraPercentageChange = 0;


        if (previousCyera > 0) {

            cyeraPercentageChange =
                Number(
                    (
                        (
                            cyeraChange /
                            previousCyera
                        ) * 100
                    ).toFixed(1)
                );

        }


        /*
        --------------------------------------
        PURVIEW CHANGE
        --------------------------------------
        */

        const currentPurview =
            purviewTotal;


        const previousPurview =
            Number(
                previousReport.purview_count || 0
            );


        const purviewChange =
            currentPurview -
            previousPurview;


        let purviewPercentageChange = 0;


        if (previousPurview > 0) {

            purviewPercentageChange =
                Number(
                    (
                        (
                            purviewChange /
                            previousPurview
                        ) * 100
                    ).toFixed(1)
                );

        }


        /*
        --------------------------------------
        BUILD COMPARISON
        --------------------------------------
        */

        comparison = {

            previousReport: {

                reportId:
                    previousReport.report_id,

                reportDate:
                    previousReport.report_date,

                totalAlerts:
                    previousTotal,

                cyera:
                    previousCyera,

                purview:
                    previousPurview

            },

            currentReport: {

                reportId:
                    latestReport.report_id,

                reportDate:
                    latestReport.report_date,

                totalAlerts:
                    currentTotal,

                cyera:
                    currentCyera,

                purview:
                    currentPurview

            },

            change: {

                totalAlerts:
                    totalChange,

                totalPercentage:
                    percentageChange,

                cyera:
                    cyeraChange,

                cyeraPercentage:
                    cyeraPercentageChange,

                purview:
                    purviewChange,

                purviewPercentage:
                    purviewPercentageChange

            }

        };


        /*
        ======================================
        COMPARISON INSIGHTS
        ======================================
        */


        /*
        --------------------------------------
        ALERT VOLUME INCREASE
        --------------------------------------
        */

        if (totalChange > 0) {

            insights.push({

                type:
                    "volume_change",

                priority:
                    percentageChange >= 50
                        ? "high"
                        : "medium",

                metric:
                    percentageChange,

                message:
                    `The latest report contains ${currentTotal} alerts, an increase of ${totalChange} (${percentageChange}%) compared with the previous report.`

            });

        }


        /*
        --------------------------------------
        ALERT VOLUME DECREASE
        --------------------------------------
        */

        else if (totalChange < 0) {

            insights.push({

                type:
                    "volume_change",

                priority:
                    "low",

                metric:
                    percentageChange,

                message:
                    `The latest report contains ${currentTotal} alerts, a decrease of ${Math.abs(totalChange)} (${Math.abs(percentageChange)}%) compared with the previous report.`

            });

        }


        /*
        --------------------------------------
        NO VOLUME CHANGE
        --------------------------------------
        */

        else {

            insights.push({

                type:
                    "volume_change",

                priority:
                    "low",

                metric:
                    0,

                message:
                    "The total alert volume is unchanged compared with the previous report."

            });

        }


        /*
        --------------------------------------
        CYERA SIGNIFICANT CHANGE
        --------------------------------------
        */

        if (
            Math.abs(
                cyeraPercentageChange
            ) >= 25
        ) {

            insights.push({

                type:
                    "source_change",

                priority:
                    cyeraPercentageChange > 0
                        ? "medium"
                        : "low",

                metric:
                    cyeraPercentageChange,

                message:
                    `Cyera alert volume ${cyeraPercentageChange > 0
                        ? "increased"
                        : "decreased"
                    } by ${Math.abs(cyeraPercentageChange)}% compared with the previous report.`

            });

        }


        /*
        --------------------------------------
        PURVIEW SIGNIFICANT CHANGE
        --------------------------------------
        */

        if (
            Math.abs(
                purviewPercentageChange
            ) >= 25
        ) {

            insights.push({

                type:
                    "source_change",

                priority:
                    purviewPercentageChange > 0
                        ? "medium"
                        : "low",

                metric:
                    purviewPercentageChange,

                message:
                    `Purview alert volume ${purviewPercentageChange > 0
                        ? "increased"
                        : "decreased"
                    } by ${Math.abs(purviewPercentageChange)}% compared with the previous report.`

            });

        }

    }

    /*
    ==========================================
    PHASE 2
    CYERA ALERT LIFECYCLE
    NEW VS CARRIED OVER
    ==========================================
    */

    const lifecycle =
        await getCyeraLifecycle(
            env,
            reportId
        );


    /*
    ==========================================
    LIFECYCLE INSIGHTS
    ==========================================
    */

    if (lifecycle.new > 0) {

        insights.push({

            type:
                "new_alert_volume",

            priority:
                lifecycle.newPercentage >= 50
                    ? "high"
                    : "medium",

            metric:
                lifecycle.newPercentage,

            message:
                `${lifecycle.new} alerts are newly observed in the latest Cyera report.`
        });

    }


    if (lifecycle.carriedOver > 0) {

        insights.push({

            type:
                "carried_over",

            priority:
                lifecycle.carriedOverPercentage >= 70
                    ? "high"
                    : "medium",

            metric:
                lifecycle.carriedOverPercentage,

            message:
                `${lifecycle.carriedOver} alerts (${lifecycle.carriedOverPercentage}%) were carried over from the previous Cyera report.`
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

        comparison,
        lifecycle,
        insights

    };

}