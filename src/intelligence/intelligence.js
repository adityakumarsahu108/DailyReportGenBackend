/*
==========================================
STABLE ALERT IDENTITY
==========================================

Cyera generates a different UUID for the
same logical alert across daily reports.

Therefore alert_id cannot be used to track
an alert across reports.

We generate a deterministic fingerprint
from fields that describe the actual event.
*/

function normalizeValue(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}


function getAlertFingerprint(alert) {

    const triggeringUser =
        normalizeValue(alert.triggering_user);

    const name =
        normalizeValue(alert.name);

    const policyId =
        normalizeValue(alert.policy_id);

    const sourceActivity =
        normalizeValue(alert.source_activity);

    const channel =
        normalizeValue(alert.channel);

    /*
    We intentionally do NOT use alert_id.

    These fields describe the underlying event
    rather than Cyera's generated record UUID.
    */

    return [
        triggeringUser,
        name,
        policyId,
        sourceActivity,
        channel
    ].join("|");
}



/*
==========================================
ALERT LIFECYCLE
==========================================
*/

async function calculateAlertLifecycle(
    env,
    currentReportId,
    previousReportId
) {

    if (!previousReportId) {

        return {
            currentReportId,
            previousReportId: null,
            currentAlerts: 0,
            new: 0,
            carriedOver: 0,
            newPercentage: 0,
            carriedOverPercentage: 0
        };
    }


    /*
    ==========================================
    LOAD CURRENT CYERA ALERTS
    ==========================================
    */

    const currentResult = await env.DB
        .prepare(`
            SELECT
                alert_id,
                name,
                triggering_user,
                policy_id,
                source_activity,
                channel,
                severity,
                status,
                assigned_user_email,
                timestamp,
                updated_at
            FROM cyera_alerts
            WHERE report_id = ?
        `)
        .bind(currentReportId)
        .all();


    /*
    ==========================================
    LOAD PREVIOUS CYERA ALERTS
    ==========================================
    */

    const previousResult = await env.DB
        .prepare(`
            SELECT
                alert_id,
                name,
                triggering_user,
                policy_id,
                source_activity,
                channel,
                severity,
                status,
                assigned_user_email,
                timestamp,
                updated_at
            FROM cyera_alerts
            WHERE report_id = ?
        `)
        .bind(previousReportId)
        .all();


    const currentAlerts =
        currentResult.results || [];

    const previousAlerts =
        previousResult.results || [];


    /*
    ==========================================
    CREATE PREVIOUS ALERT FINGERPRINT SET
    ==========================================
    */

    const previousFingerprints =
        new Set();

    for (const alert of previousAlerts) {

        const fingerprint =
            getAlertFingerprint(alert);

        if (fingerprint) {
            previousFingerprints.add(fingerprint);
        }
    }


    /*
    ==========================================
    CLASSIFY CURRENT ALERTS
    ==========================================
    */

    let newCount = 0;
    let carriedOverCount = 0;

    const newAlerts = [];
    const carriedOverAlerts = [];


    for (const alert of currentAlerts) {

        const fingerprint =
            getAlertFingerprint(alert);


        if (
            fingerprint &&
            previousFingerprints.has(fingerprint)
        ) {

            carriedOverCount++;

            carriedOverAlerts.push({
                alertId: alert.alert_id,
                fingerprint,
                name: alert.name,
                severity: alert.severity,
                status: alert.status,
                assignedUser:
                    alert.assigned_user_email || null
            });

        } else {

            newCount++;

            newAlerts.push({
                alertId: alert.alert_id,
                fingerprint,
                name: alert.name,
                severity: alert.severity,
                status: alert.status,
                assignedUser:
                    alert.assigned_user_email || null
            });
        }
    }


    /*
    ==========================================
    PERCENTAGES
    ==========================================
    */

    const total =
        currentAlerts.length;

    const newPercentage =
        total > 0
            ? Number(
                ((newCount / total) * 100).toFixed(1)
            )
            : 0;

    const carriedOverPercentage =
        total > 0
            ? Number(
                ((carriedOverCount / total) * 100).toFixed(1)
            )
            : 0;


    /*
    ==========================================
    RETURN
    ==========================================
    */

    return {

        currentReportId,

        previousReportId,

        currentAlerts:
            total,

        new:
            newCount,

        carriedOver:
            carriedOverCount,

        newPercentage,

        carriedOverPercentage,

        /*
        Keep the actual alerts available
        for future intelligence features.
        */

        newAlerts,

        carriedOverAlerts
    };
}
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
/*
==========================================
PHASE 4
CYERA SECURITY INTELLIGENCE
DETERMINISTIC ANALYSIS
==========================================
*/

async function calculateCyeraSecurityIntelligence(
    env,
    reportId
) {

    const result = await env.DB
        .prepare(`
            SELECT
                alert_id,
                name,
                triggering_user,
                policy_id,
                source_activity,
                channel,
                severity,
                status,
                assigned_user_email,
                timestamp,
                updated_at
            FROM cyera_alerts
            WHERE report_id = ?
        `)
        .bind(reportId)
        .all();

    const alerts = result.results || [];

    /*
    ==========================================
    HELPERS
    ==========================================
    */

    const countBy = (items, key) => {

        const counts = {};

        for (const item of items) {

            const value =
                item[key] ||
                "unknown";

            counts[value] =
                (counts[value] || 0) + 1;
        }

        return counts;
    };


    const sortCounts = (counts) => {

        return Object.entries(counts)
            .sort((a, b) => b[1] - a[1])
            .map(([value, count]) => ({
                value,
                count
            }));
    };


    /*
    ==========================================
    DISTRIBUTIONS
    ==========================================
    */

    const severityDistribution =
        sortCounts(
            countBy(alerts, "severity")
        );

    const statusDistribution =
        sortCounts(
            countBy(alerts, "status")
        );

    const channelDistribution =
        sortCounts(
            countBy(alerts, "channel")
        );

    const activityDistribution =
        sortCounts(
            countBy(alerts, "source_activity")
        );

    const policyDistribution =
        sortCounts(
            countBy(alerts, "policy_id")
        );

    const userDistribution =
        sortCounts(
            countBy(alerts, "triggering_user")
        );


    /*
    ==========================================
    EXTERNAL / ASSIGNED ACTIVITY
    ==========================================
    */

    const assignedAlerts =
        alerts.filter(
            alert =>
                alert.assigned_user_email
        );

    const unassignedAlerts =
        alerts.filter(
            alert =>
                !alert.assigned_user_email
        );


    /*
    ==========================================
    RISK ACCEPTED
    ==========================================
    */

    const riskAcceptedAlerts =
        alerts.filter(
            alert =>
                String(alert.status)
                    .toLowerCase()
                === "riskaccepted"
        );


    /*
    ==========================================
    HIGH / CRITICAL
    ==========================================
    */

    const highRiskAlerts =
        alerts.filter(alert => {

            const severity =
                String(alert.severity || "")
                    .toLowerCase();

            return (
                severity === "high" ||
                severity === "critical"
            );
        });


    /*
    ==========================================
    FINDINGS
    ==========================================
    */

    const findings = [];


    /*
    ------------------------------------------
    HIGH / CRITICAL ACTIVITY
    ------------------------------------------
    */

    if (highRiskAlerts.length > 0) {

        findings.push({

            type:
                "high_risk_activity",

            severity:
                "high",

            title:
                "High-risk alerts require attention",

            description:
                `${highRiskAlerts.length} high or critical severity alerts are present in the current Cyera report.`,

            evidence: {

                alertCount:
                    highRiskAlerts.length

            },

            recommendedAction:
                "Prioritize review of high and critical severity alerts before lower-risk activity."
        });
    }


    /*
    ------------------------------------------
    RISK ACCEPTED
    ------------------------------------------
    */

    if (riskAcceptedAlerts.length > 0) {

        findings.push({

            type:
                "risk_accepted_activity",

            severity:
                "medium",

            title:
                "Risk-accepted alerts detected",

            description:
                `${riskAcceptedAlerts.length} alerts are currently marked as risk accepted.`,

            evidence: {

                alertCount:
                    riskAcceptedAlerts.length,

                percentage:
                    alerts.length > 0
                        ? Number(
                            (
                                riskAcceptedAlerts.length /
                                alerts.length *
                                100
                            ).toFixed(1)
                        )
                        : 0
            },

            recommendedAction:
                "Periodically validate risk-accepted alerts to ensure the business justification remains valid."
        });
    }


    /*
    ------------------------------------------
    UNASSIGNED ALERTS
    ------------------------------------------
    */

    if (unassignedAlerts.length > 0) {

        findings.push({

            type:
                "unassigned_alerts",

            severity:
                unassignedAlerts.length >= 10
                    ? "medium"
                    : "low",

            title:
                "Alerts remain unassigned",

            description:
                `${unassignedAlerts.length} alerts currently have no assigned user.`,

            evidence: {

                alertCount:
                    unassignedAlerts.length

            },

            recommendedAction:
                "Review unassigned alerts and route actionable cases to the appropriate security owner."
        });
    }


    /*
    ------------------------------------------
    DOMINANT CHANNEL
    ------------------------------------------
    */

    if (channelDistribution.length > 0) {

        const topChannel =
            channelDistribution[0];

        const percentage =
            alerts.length > 0
                ? Number(
                    (
                        topChannel.count /
                        alerts.length *
                        100
                    ).toFixed(1)
                )
                : 0;

        if (percentage >= 50) {

            findings.push({

                type:
                    "channel_concentration",

                severity:
                    "medium",

                title:
                    "Security activity is concentrated in one channel",

                description:
                    `${percentage}% of current alerts originate from the ${topChannel.value} channel.`,

                evidence: {

                    channel:
                        topChannel.value,

                    alertCount:
                        topChannel.count,

                    percentage

                },

                recommendedAction:
                    "Review the dominant channel for recurring patterns and determine whether additional preventive controls are appropriate."
            });
        }
    }


    /*
    ------------------------------------------
    DOMINANT POLICY
    ------------------------------------------
    */

    if (policyDistribution.length > 0) {

        const topPolicy =
            policyDistribution[0];

        const percentage =
            alerts.length > 0
                ? Number(
                    (
                        topPolicy.count /
                        alerts.length *
                        100
                    ).toFixed(1)
                )
                : 0;

        if (percentage >= 25) {

            findings.push({

                type:
                    "policy_concentration",

                severity:
                    "medium",

                title:
                    "Alert volume is concentrated around a policy",

                description:
                    `${percentage}% of current alerts are associated with the same Cyera policy.`,

                evidence: {

                    policyId:
                        topPolicy.value,

                    alertCount:
                        topPolicy.count,

                    percentage

                },

                recommendedAction:
                    "Review the policy generating the highest alert volume to determine whether the activity reflects genuine risk or excessive detection noise."
            });
        }
    }


    /*
    ==========================================
    RETURN
    ==========================================
    */

    return {

        reportId,

        totalAlerts:
            alerts.length,

        distributions: {

            severity:
                severityDistribution,

            status:
                statusDistribution,

            channel:
                channelDistribution,

            activity:
                activityDistribution,

            policy:
                policyDistribution.slice(0, 10),

            users:
                userDistribution.slice(0, 10)

        },

        workload: {

            assigned:
                assignedAlerts.length,

            unassigned:
                unassignedAlerts.length,

            riskAccepted:
                riskAcceptedAlerts.length

        },

        risk: {

            highOrCritical:
                highRiskAlerts.length

        },

        findings

    };
}
/*
==========================================
CYERA ALERT AGING / PERSISTENCE
==========================================
*/

async function getCyeraAlertAging(
    env,
    reportId
) {

    /*
    ==========================================
    GET ALERT PERSISTENCE
    ==========================================
    */

    const result =
        await env.DB
            .prepare(`
                SELECT
                    ah.alert_id,

                    COUNT(
                        DISTINCT ah.report_id
                    ) AS reports_seen,

                    MIN(
                        ah.observed_at
                    ) AS first_seen_at,

                    MAX(
                        ah.observed_at
                    ) AS last_seen_at,

                    a.current_severity
                        AS severity,

                    a.current_status
                        AS status,

                    a.current_assigned_user
                        AS assigned_user

                FROM alert_history ah

                JOIN alerts a
                    ON a.id = ah.alert_id

                WHERE
                    a.source = 'cyera'

                GROUP BY
                    ah.alert_id

                ORDER BY
                    reports_seen DESC
            `)
            .all();


    const rows =
        result.results || [];


    /*
    ==========================================
    INITIALIZE METRICS
    ==========================================
    */

    let persistent2Plus = 0;

    let persistent3Plus = 0;

    let highOrCriticalPersistent = 0;

    let longestPersistence =
        0;

    let longestRunningAlerts = [];


    /*
    ==========================================
    PROCESS ALERTS
    ==========================================
    */

    for (const row of rows) {

        const reportsSeen =
            Number(
                row.reports_seen || 0
            );


        /*
        --------------------------------------
        2+ REPORTS
        --------------------------------------
        */

        if (reportsSeen >= 2) {

            persistent2Plus++;

        }


        /*
        --------------------------------------
        3+ REPORTS
        --------------------------------------
        */

        if (reportsSeen >= 3) {

            persistent3Plus++;

        }


        /*
        --------------------------------------
        HIGH / CRITICAL PERSISTENCE
        --------------------------------------
        */

        const severity =
            String(
                row.severity || ""
            ).toLowerCase();


        if (
            reportsSeen >= 2
            &&
            (
                severity === "high"
                ||
                severity === "critical"
            )
        ) {

            highOrCriticalPersistent++;

        }


        /*
        --------------------------------------
        LONGEST RUNNING
        --------------------------------------
        */

        if (
            reportsSeen >
            longestPersistence
        ) {

            longestPersistence =
                reportsSeen;

            longestRunningAlerts = [
                row
            ];

        }

        else if (
            reportsSeen ===
            longestPersistence
        ) {

            longestRunningAlerts.push(
                row
            );

        }

    }


    /*
    ==========================================
    CURRENT REPORT ALERTS
    ==========================================
    */

    const currentResult =
        await env.DB
            .prepare(`
                SELECT
                    ah.alert_id,

                    COUNT(
                        DISTINCT ah.report_id
                    ) AS reports_seen,

                    MIN(
                        ah.observed_at
                    ) AS first_seen_at,

                    MAX(
                        ah.observed_at
                    ) AS last_seen_at,

                    a.current_severity
                        AS severity,

                    a.current_status
                        AS status,

                    a.current_assigned_user
                        AS assigned_user,

                    a.name

                FROM alert_history ah

                JOIN alerts a
                    ON a.id = ah.alert_id

                WHERE
                    ah.report_id = ?

                    AND a.source = 'cyera'

                GROUP BY
                    ah.alert_id

                ORDER BY
                    reports_seen DESC
            `)
            .bind(reportId)
            .all();


    const currentAlerts =
        currentResult.results || [];


    /*
    ==========================================
    CURRENT REPORT PERSISTENT ALERTS
    ==========================================
    */

    const currentPersistentAlerts =
        currentAlerts.filter(
            alert =>
                Number(
                    alert.reports_seen || 0
                ) >= 2
        );


    const currentPersistent2Plus =
        currentPersistentAlerts.length;


    const currentPersistent3Plus =
        currentAlerts.filter(
            alert =>
                Number(
                    alert.reports_seen || 0
                ) >= 3
        ).length;


    const currentHighCriticalPersistent =
        currentPersistentAlerts.filter(
            alert => {

                const severity =
                    String(
                        alert.severity || ""
                    ).toLowerCase();

                return (
                    severity === "high"
                    ||
                    severity === "critical"
                );

            }
        ).length;


    /*
    ==========================================
    RETURN AGING METRICS
    ==========================================
    */

    return {

        reportId,

        totalTrackedAlerts:
            rows.length,

        currentReportAlerts:
            currentAlerts.length,

        persistent2Plus:
            currentPersistent2Plus,

        persistent3Plus:
            currentPersistent3Plus,

        highOrCriticalPersistent:
            currentHighCriticalPersistent,

        longestPersistence,

        longestRunningAlerts:
            longestRunningAlerts
                .slice(0, 10)
                .map(alert => ({

                    alertId:
                        alert.alert_id,

                    name:
                        alert.name || null,

                    reportsSeen:
                        Number(
                            alert.reports_seen || 0
                        ),

                    firstSeenAt:
                        alert.first_seen_at,

                    lastSeenAt:
                        alert.last_seen_at,

                    severity:
                        alert.severity,

                    status:
                        alert.status,

                    assignedUser:
                        alert.assigned_user

                }))

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

    const lifecycle = await calculateAlertLifecycle(
        env,
        reportId,
        previousReport.report_id
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
PHASE 3
CYERA ALERT AGING / PERSISTENCE
==========================================
*/

    const aging =
        await getCyeraAlertAging(
            env,
            reportId
        );


    /*
    ==========================================
    AGING INSIGHTS
    ==========================================
    */

    if (
        aging.persistent3Plus > 0
    ) {

        insights.push({

            type:
                "persistent_alerts",

            priority:
                aging.persistent3Plus >= 10
                    ? "high"
                    : "medium",

            metric:
                aging.persistent3Plus,

            message:
                `${aging.persistent3Plus} Cyera alerts have persisted across at least 3 reports.`
        });

    }


    if (
        aging.highOrCriticalPersistent > 0
    ) {

        insights.push({

            type:
                "persistent_high_risk",

            priority:
                "high",

            metric:
                aging.highOrCriticalPersistent,

            message:
                `${aging.highOrCriticalPersistent} high or critical Cyera alerts have persisted across multiple reports.`
        });

    }

    /*
==========================================
PHASE 4
CYERA SECURITY INTELLIGENCE
==========================================
*/

    const securityIntelligence =
        await calculateCyeraSecurityIntelligence(
            env,
            reportId
        );


    /*
    ==========================================
    SECURITY INTELLIGENCE INSIGHTS
    ==========================================
    */

    for (
        const finding of securityIntelligence.findings
    ) {

        insights.push({

            type:
                finding.type,

            priority:
                finding.severity,

            metric:
                finding.evidence?.alertCount || 0,

            message:
                finding.description

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
        aging,
        securityIntelligence,
        insights

    };

}