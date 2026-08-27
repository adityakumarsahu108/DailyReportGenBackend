/*
==========================================
SECURITY INTELLIGENCE ENGINE
==========================================

Current capabilities:

Phase 1
- Overall alert volume
- Severity analysis
- Status analysis
- Cyera / Purview comparison
- Basic explainable observations

Phase 2
- Alert lifecycle
- New vs carried-over alerts

Phase 3
- Alert aging
- Alert persistence

Phase 4
- Deterministic Cyera intelligence
- Alert prioritization

Phase 5
- Multi-report trends
- Behavioral analysis
- User patterns
- Policy patterns
- Channel patterns
- Correlations
- Severity escalation
- Status stagnation
- Repeated risk acceptance
- Emerging risks
- Anomaly detection
- Operational weaknesses
- Intelligence summary

IMPORTANT:
This engine is READ-ONLY.

It generates intelligence and observations.
It does NOT modify alerts, assign alerts,
change statuses, or perform security actions.
==========================================
*/


/*
==========================================
GENERAL HELPERS
==========================================
*/

function normalizeValue(value) {

    if (
        value === null ||
        value === undefined
    ) {

        return "";

    }

    return String(value)
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");

}


function safeNumber(value) {

    const number =
        Number(value);

    return Number.isFinite(number)
        ? number
        : 0;

}


function percentage(
    value,
    total
) {

    if (!total) {
        return 0;
    }

    return Number(
        (
            value /
            total *
            100
        ).toFixed(1)
    );

}


function percentageChange(
    current,
    previous
) {

    if (!previous) {
        return 0;
    }

    return Number(
        (
            (
                current -
                previous
            ) /
            previous *
            100
        ).toFixed(1)
    );

}


function sortCounts(counts) {

    return Object.entries(counts)
        .sort(
            (a, b) =>
                b[1] - a[1]
        )
        .map(
            ([value, count]) => ({
                value,
                count
            })
        );

}


function countBy(
    items,
    key
) {

    const counts = {};

    for (
        const item
        of items
    ) {

        const value =
            normalizeValue(
                item[key]
            ) ||
            "unknown";

        counts[value] =
            (
                counts[value] ||
                0
            ) + 1;

    }

    return counts;

}


/*
==========================================
STABLE ALERT IDENTITY
==========================================

Cyera may generate a different UUID for the
same logical alert across daily reports.

Therefore alert_id should not be relied upon
for cross-report behavioral analysis.

We generate a deterministic fingerprint.
==========================================
*/

function getAlertFingerprint(alert) {

    const triggeringUser =
        normalizeValue(
            alert.triggering_user
        );

    const name =
        normalizeValue(
            alert.name
        );

    const policyId =
        normalizeValue(
            alert.policy_id
        );

    const sourceActivity =
        normalizeValue(
            alert.source_activity
        );

    const channel =
        normalizeValue(
            alert.channel
        );

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
ALERT PRIORITIZATION
==========================================
*/

function prioritizeCyeraAlerts(
    alerts,
    lifecycle,
    aging
) {

    if (
        !Array.isArray(alerts)
    ) {

        return [];

    }

    const severityWeight = {

        critical: 100,
        high: 80,
        medium: 50,
        low: 20

    };

    return alerts
        .map(alert => {

            let score =
                severityWeight[
                    normalizeValue(
                        alert.severity
                    )
                ] || 50;

            const reasons = [];


            /*
            ----------------------------------
            SEVERITY
            ----------------------------------
            */

            if (
                normalizeValue(
                    alert.severity
                ) === "critical"
            ) {

                score += 30;

                reasons.push(
                    "Critical severity"
                );

            }
            else if (
                normalizeValue(
                    alert.severity
                ) === "high"
            ) {

                score += 20;

                reasons.push(
                    "High severity"
                );

            }


            /*
            ----------------------------------
            STATUS
            ----------------------------------
            */

            if (
                normalizeValue(
                    alert.status
                ) === "open"
            ) {

                score += 10;

                reasons.push(
                    "Alert remains open"
                );

            }


            /*
            ----------------------------------
            ASSIGNMENT
            ----------------------------------
            */

            if (
                !alert.assignedUser
            ) {

                score += 15;

                reasons.push(
                    "Alert is unassigned"
                );

            }


            /*
            ----------------------------------
            RISK ACCEPTED
            ----------------------------------
            */

            if (
                normalizeValue(
                    alert.status
                ) === "riskaccepted"
            ) {

                score -= 20;

                reasons.push(
                    "Risk already accepted"
                );

            }


            /*
            ----------------------------------
            LIFECYCLE
            ----------------------------------
            */

            const isCarriedOver =
                lifecycle
                    ?.carriedOverAlerts
                    ?.some(
                        previous =>
                            previous.fingerprint ===
                            alert.fingerprint
                    );

            if (
                isCarriedOver
            ) {

                score += 20;

                reasons.push(
                    "Carried over from previous report"
                );

            }


            /*
            ----------------------------------
            AGING
            ----------------------------------
            */

            const agingAlert =
                aging
                    ?.longestRunningAlerts
                    ?.find(
                        item =>
                            item.alertId ===
                            alert.alertId
                    );

            if (
                agingAlert &&
                agingAlert.reportsSeen >= 3
            ) {

                score += 30;

                reasons.push(
                    "Persisted across 3+ reports"
                );

            }
            else if (
                agingAlert &&
                agingAlert.reportsSeen >= 2
            ) {

                score += 15;

                reasons.push(
                    "Persisted across multiple reports"
                );

            }


            /*
            ----------------------------------
            PRIORITY
            ----------------------------------
            */

            let priority;

            if (
                score >= 120
            ) {

                priority =
                    "critical";

            }
            else if (
                score >= 90
            ) {

                priority =
                    "high";

            }
            else if (
                score >= 60
            ) {

                priority =
                    "medium";

            }
            else {

                priority =
                    "low";

            }


            return {

                alertId:
                    alert.alertId,

                name:
                    alert.name,

                severity:
                    alert.severity,

                status:
                    alert.status,

                assignedUser:
                    alert.assignedUser,

                priorityScore:
                    score,

                priority,

                reasons

            };

        })
        .sort(
            (a, b) =>
                b.priorityScore -
                a.priorityScore
        );

}


/*
==========================================
CYERA ALERT LIFECYCLE
==========================================
*/

async function calculateAlertLifecycle(
    env,
    currentReportId,
    previousReportId
) {

    if (
        !previousReportId
    ) {

        return {

            currentReportId,

            previousReportId:
                null,

            currentAlerts:
                0,

            new:
                0,

            carriedOver:
                0,

            newPercentage:
                0,

            carriedOverPercentage:
                0,

            newAlerts: [],

            carriedOverAlerts: []

        };

    }


    /*
    ======================================
    CURRENT ALERTS
    ======================================
    */

    const currentResult =
        await env.DB
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
            .bind(
                currentReportId
            )
            .all();


    /*
    ======================================
    PREVIOUS ALERTS
    ======================================
    */

    const previousResult =
        await env.DB
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
            .bind(
                previousReportId
            )
            .all();


    const currentAlerts =
        currentResult.results || [];

    const previousAlerts =
        previousResult.results || [];


    const previousFingerprints =
        new Set();


    for (
        const alert
        of previousAlerts
    ) {

        const fingerprint =
            getAlertFingerprint(
                alert
            );

        if (
            fingerprint
        ) {

            previousFingerprints.add(
                fingerprint
            );

        }

    }


    let newCount = 0;
    let carriedOverCount = 0;

    const newAlerts = [];
    const carriedOverAlerts = [];


    for (
        const alert
        of currentAlerts
    ) {

        const fingerprint =
            getAlertFingerprint(
                alert
            );


        if (
            fingerprint &&
            previousFingerprints.has(
                fingerprint
            )
        ) {

            carriedOverCount++;

            carriedOverAlerts.push({

                alertId:
                    alert.alert_id,

                fingerprint,

                name:
                    alert.name,

                severity:
                    alert.severity,

                status:
                    alert.status,

                triggeringUser:
                    alert.triggering_user,

                policyId:
                    alert.policy_id,

                channel:
                    alert.channel,

                sourceActivity:
                    alert.source_activity,

                assignedUser:
                    alert.assigned_user_email ||
                    null

            });

        }
        else {

            newCount++;

            newAlerts.push({

                alertId:
                    alert.alert_id,

                fingerprint,

                name:
                    alert.name,

                severity:
                    alert.severity,

                status:
                    alert.status,

                triggeringUser:
                    alert.triggering_user,

                policyId:
                    alert.policy_id,

                channel:
                    alert.channel,

                sourceActivity:
                    alert.source_activity,

                assignedUser:
                    alert.assigned_user_email ||
                    null

            });

        }

    }


    const total =
        currentAlerts.length;


    return {

        currentReportId,

        previousReportId,

        currentAlerts:
            total,

        new:
            newCount,

        carriedOver:
            carriedOverCount,

        newPercentage:
            percentage(
                newCount,
                total
            ),

        carriedOverPercentage:
            percentage(
                carriedOverCount,
                total
            ),

        newAlerts,

        carriedOverAlerts

    };

}


/*
==========================================
CYERA ALERT AGING
==========================================
*/

async function getCyeraAlertAging(
    env,
    reportId
) {

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


    let persistent2Plus = 0;
    let persistent3Plus = 0;
    let highOrCriticalPersistent = 0;
    let longestPersistence = 0;

    let longestRunningAlerts = [];


    for (
        const row
        of rows
    ) {

        const reportsSeen =
            safeNumber(
                row.reports_seen
            );


        if (
            reportsSeen >= 2
        ) {

            persistent2Plus++;

        }


        if (
            reportsSeen >= 3
        ) {

            persistent3Plus++;

        }


        const severity =
            normalizeValue(
                row.severity
            );


        if (
            reportsSeen >= 2 &&
            (
                severity === "high" ||
                severity === "critical"
            )
        ) {

            highOrCriticalPersistent++;

        }


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
            .bind(
                reportId
            )
            .all();


    const currentAlerts =
        currentResult.results || [];


    const currentPersistentAlerts =
        currentAlerts.filter(
            alert =>
                safeNumber(
                    alert.reports_seen
                ) >= 2
        );


    const currentPersistent3Plus =
        currentAlerts.filter(
            alert =>
                safeNumber(
                    alert.reports_seen
                ) >= 3
        );


    const currentHighCriticalPersistent =
        currentPersistentAlerts.filter(
            alert => {

                const severity =
                    normalizeValue(
                        alert.severity
                    );

                return (
                    severity === "high" ||
                    severity === "critical"
                );

            }
        );


    return {

        reportId,

        totalTrackedAlerts:
            rows.length,

        currentReportAlerts:
            currentAlerts.length,

        persistent2Plus:
            currentPersistentAlerts.length,

        persistent3Plus:
            currentPersistent3Plus.length,

        highOrCriticalPersistent:
            currentHighCriticalPersistent.length,

        longestPersistence,

        longestRunningAlerts:
            longestRunningAlerts
                .slice(0, 10)
                .map(
                    alert => ({

                        alertId:
                            alert.alert_id,

                        name:
                            alert.name ||
                            null,

                        reportsSeen:
                            safeNumber(
                                alert.reports_seen
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

                    })
                )

    };

}


/*
==========================================
CYERA SECURITY INTELLIGENCE
==========================================
*/

async function calculateCyeraSecurityIntelligence(
    env,
    reportId
) {

    const result =
        await env.DB
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
            .bind(
                reportId
            )
            .all();


    const alerts =
        result.results || [];


    const severityDistribution =
        sortCounts(
            countBy(
                alerts,
                "severity"
            )
        );


    const statusDistribution =
        sortCounts(
            countBy(
                alerts,
                "status"
            )
        );


    const channelDistribution =
        sortCounts(
            countBy(
                alerts,
                "channel"
            )
        );


    const activityDistribution =
        sortCounts(
            countBy(
                alerts,
                "source_activity"
            )
        );


    const policyDistribution =
        sortCounts(
            countBy(
                alerts,
                "policy_id"
            )
        );


    const userDistribution =
        sortCounts(
            countBy(
                alerts,
                "triggering_user"
            )
        );


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


    const riskAcceptedAlerts =
        alerts.filter(
            alert =>
                normalizeValue(
                    alert.status
                ) === "riskaccepted"
        );


    const highRiskAlerts =
        alerts.filter(
            alert => {

                const severity =
                    normalizeValue(
                        alert.severity
                    );

                return (
                    severity === "high" ||
                    severity === "critical"
                );

            }
        );


    const findings = [];


    if (
        highRiskAlerts.length > 0
    ) {

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


    if (
        riskAcceptedAlerts.length > 0
    ) {

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
                    percentage(
                        riskAcceptedAlerts.length,
                        alerts.length
                    )

            },

            recommendedAction:
                "Periodically validate risk-accepted alerts to ensure the business justification remains valid."

        });

    }


    if (
        unassignedAlerts.length > 0
    ) {

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


    if (
        channelDistribution.length > 0
    ) {

        const topChannel =
            channelDistribution[0];


        const channelPercentage =
            percentage(
                topChannel.count,
                alerts.length
            );


        if (
            channelPercentage >= 50
        ) {

            findings.push({

                type:
                    "channel_concentration",

                severity:
                    "medium",

                title:
                    "Security activity is concentrated in one channel",

                description:
                    `${channelPercentage}% of current alerts originate from the ${topChannel.value} channel.`,

                evidence: {

                    channel:
                        topChannel.value,

                    alertCount:
                        topChannel.count,

                    percentage:
                        channelPercentage

                },

                recommendedAction:
                    "Review the dominant channel for recurring patterns and determine whether additional preventive controls are appropriate."

            });

        }

    }


    if (
        policyDistribution.length > 0
    ) {

        const topPolicy =
            policyDistribution[0];


        const policyPercentage =
            percentage(
                topPolicy.count,
                alerts.length
            );


        if (
            policyPercentage >= 25
        ) {

            findings.push({

                type:
                    "policy_concentration",

                severity:
                    "medium",

                title:
                    "Alert volume is concentrated around a policy",

                description:
                    `${policyPercentage}% of current alerts are associated with the same Cyera policy.`,

                evidence: {

                    policyId:
                        topPolicy.value,

                    alertCount:
                        topPolicy.count,

                    percentage:
                        policyPercentage

                },

                recommendedAction:
                    "Review the policy generating the highest alert volume to determine whether the activity reflects genuine risk or excessive detection noise."

            });

        }

    }


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
                policyDistribution
                    .slice(0, 10),

            users:
                userDistribution
                    .slice(0, 10)

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
MULTI-REPORT TREND INTELLIGENCE
==========================================

Analyzes historical reports instead of only
comparing the latest two.
==========================================
*/

async function calculateTrendIntelligence(
    env,
    latestReport
) {

    const result =
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
                LIMIT 30
            `)
            .all();


    const rows =
        (
            result.results || []
        ).reverse();


    if (
        rows.length === 0
    ) {

        return {

            reportsAnalyzed: 0,

            window7: null,
            window10: null,
            window30: null,

            direction:
                "stable",

            insights: []

        };

    }


    function summarizeWindow(
        windowRows
    ) {

        if (
            windowRows.length === 0
        ) {

            return null;

        }


        const first =
            windowRows[0];

        const last =
            windowRows[
                windowRows.length - 1
            ];


        const firstTotal =
            safeNumber(
                first.total_alerts
            );

        const lastTotal =
            safeNumber(
                last.total_alerts
            );


        const firstCyera =
            safeNumber(
                first.cyera_count
            );

        const lastCyera =
            safeNumber(
                last.cyera_count
            );


        const firstPurview =
            safeNumber(
                first.purview_count
            );

        const lastPurview =
            safeNumber(
                last.purview_count
            );


        return {

            reports:
                windowRows.length,

            firstReport:
                first.report_id,

            lastReport:
                last.report_id,

            firstDate:
                first.report_date,

            lastDate:
                last.report_date,

            firstTotal,

            lastTotal,

            totalChange:
                lastTotal -
                firstTotal,

            totalPercentageChange:
                percentageChange(
                    lastTotal,
                    firstTotal
                ),

            cyeraChange:
                lastCyera -
                firstCyera,

            cyeraPercentageChange:
                percentageChange(
                    lastCyera,
                    firstCyera
                ),

            purviewChange:
                lastPurview -
                firstPurview,

            purviewPercentageChange:
                percentageChange(
                    lastPurview,
                    firstPurview
                )

        };

    }


    const window7 =
        summarizeWindow(
            rows.slice(-7)
        );


    const window10 =
        summarizeWindow(
            rows.slice(-10)
        );


    const window30 =
        summarizeWindow(
            rows.slice(-30)
        );


    const recent =
        rows.slice(-5);


    let increasing = 0;
    let decreasing = 0;


    for (
        let i = 1;
        i < recent.length;
        i++
    ) {

        const previous =
            safeNumber(
                recent[i - 1]
                    .total_alerts
            );

        const current =
            safeNumber(
                recent[i]
                    .total_alerts
            );


        if (
            current > previous
        ) {

            increasing++;

        }
        else if (
            current < previous
        ) {

            decreasing++;

        }

    }


    let direction =
        "stable";


    if (
        increasing >= 3 &&
        increasing > decreasing
    ) {

        direction =
            "increasing";

    }
    else if (
        decreasing >= 3 &&
        decreasing > increasing
    ) {

        direction =
            "decreasing";

    }


    const insights = [];


    if (
        window7 &&
        Math.abs(
            window7.totalPercentageChange
        ) >= 25
    ) {

        insights.push({

            type:
                "short_term_volume_trend",

            priority:
                window7.totalPercentageChange > 0
                    ? "high"
                    : "medium",

            metric:
                window7.totalPercentageChange,

            message:
                `Alert volume has ${window7.totalPercentageChange > 0 ? "increased" : "decreased"} by ${Math.abs(window7.totalPercentageChange)}% across the latest ${window7.reports} reports.`

        });

    }


    if (
        window10 &&
        Math.abs(
            window10.cyeraPercentageChange
        ) >= 30
    ) {

        insights.push({

            type:
                "cyera_trend",

            priority:
                window10.cyeraPercentageChange > 0
                    ? "medium"
                    : "low",

            metric:
                window10.cyeraPercentageChange,

            message:
                `Cyera alert volume has ${window10.cyeraPercentageChange > 0 ? "increased" : "decreased"} by ${Math.abs(window10.cyeraPercentageChange)}% across the latest ${window10.reports} reports.`

        });

    }


    if (
        window10 &&
        Math.abs(
            window10.purviewPercentageChange
        ) >= 30
    ) {

        insights.push({

            type:
                "purview_trend",

            priority:
                window10.purviewPercentageChange > 0
                    ? "medium"
                    : "low",

            metric:
                window10.purviewPercentageChange,

            message:
                `Purview alert volume has ${window10.purviewPercentageChange > 0 ? "increased" : "decreased"} by ${Math.abs(window10.purviewPercentageChange)}% across the latest ${window10.reports} reports.`

        });

    }


    if (
        direction ===
        "increasing"
    ) {

        insights.push({

            type:
                "sustained_growth",

            priority:
                "medium",

            metric:
                increasing,

            message:
                "Alert volume has increased across most of the recent reporting sequence, indicating a sustained upward trend rather than a single-report spike."

        });

    }


    if (
        direction ===
        "decreasing"
    ) {

        insights.push({

            type:
                "sustained_decline",

            priority:
                "low",

            metric:
                decreasing,

            message:
                "Alert volume has decreased across most of the recent reporting sequence."

        });

    }


    return {

        reportsAnalyzed:
            rows.length,

        window7,

        window10,

        window30,

        direction,

        insights

    };

}


/*
==========================================
LOAD CURRENT CYERA ALERTS
==========================================
*/

async function loadCurrentCyeraAlerts(
    env,
    reportId
) {

    const result =
        await env.DB
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
            .bind(
                reportId
            )
            .all();


    return result.results || [];

}


/*
==========================================
BEHAVIORAL INTELLIGENCE
==========================================

Looks for:

- Dominant users
- Dominant policies
- Dominant channels
- User + policy patterns
- User + channel patterns
- Policy + channel patterns
- High-risk concentration
==========================================
*/

function calculateBehavioralIntelligence(
    alerts
) {

    const insights = [];


    if (
        !alerts.length
    ) {

        return {

            notableUsers: [],
            notablePolicies: [],
            notableChannels: [],

            correlations: [],

            insights: []

        };

    }


    /*
    ======================================
    USER ANALYSIS
    ======================================
    */

    const userMap = {};


    for (
        const alert
        of alerts
    ) {

        const user =
            normalizeValue(
                alert.triggering_user
            ) ||
            "unknown";


        if (
            !userMap[user]
        ) {

            userMap[user] = {

                count: 0,

                highRisk: 0,

                critical: 0,

                policies: {},

                channels: {},

                activities: {}

            };

        }


        const entry =
            userMap[user];


        entry.count++;


        const severity =
            normalizeValue(
                alert.severity
            );


        if (
            severity === "high" ||
            severity === "critical"
        ) {

            entry.highRisk++;

        }


        if (
            severity === "critical"
        ) {

            entry.critical++;

        }


        const policy =
            normalizeValue(
                alert.policy_id
            ) ||
            "unknown";


        const channel =
            normalizeValue(
                alert.channel
            ) ||
            "unknown";


        const activity =
            normalizeValue(
                alert.source_activity
            ) ||
            "unknown";


        entry.policies[policy] =
            (
                entry.policies[policy] ||
                0
            ) + 1;


        entry.channels[channel] =
            (
                entry.channels[channel] ||
                0
            ) + 1;


        entry.activities[activity] =
            (
                entry.activities[activity] ||
                0
            ) + 1;

    }


    const notableUsers =
        Object.entries(
            userMap
        )
            .map(
                ([user, data]) => ({

                    user,

                    alertCount:
                        data.count,

                    percentage:
                        percentage(
                            data.count,
                            alerts.length
                        ),

                    highRisk:
                        data.highRisk,

                    critical:
                        data.critical,

                    topPolicy:
                        sortCounts(
                            data.policies
                        )[0]?.value ||
                        null,

                    topChannel:
                        sortCounts(
                            data.channels
                        )[0]?.value ||
                        null,

                    topActivity:
                        sortCounts(
                            data.activities
                        )[0]?.value ||
                        null

                })
            )
            .sort(
                (a, b) =>
                    b.alertCount -
                    a.alertCount
            )
            .slice(0, 10);


    /*
    ======================================
    POLICY ANALYSIS
    ======================================
    */

    const policyMap = {};


    for (
        const alert
        of alerts
    ) {

        const policy =
            normalizeValue(
                alert.policy_id
            ) ||
            "unknown";


        if (
            !policyMap[policy]
        ) {

            policyMap[policy] = {

                count: 0,

                highRisk: 0,

                users: {},

                channels: {}

            };

        }


        const entry =
            policyMap[policy];


        entry.count++;


        const severity =
            normalizeValue(
                alert.severity
            );


        if (
            severity === "high" ||
            severity === "critical"
        ) {

            entry.highRisk++;

        }


        const user =
            normalizeValue(
                alert.triggering_user
            ) ||
            "unknown";


        const channel =
            normalizeValue(
                alert.channel
            ) ||
            "unknown";


        entry.users[user] =
            (
                entry.users[user] ||
                0
            ) + 1;


        entry.channels[channel] =
            (
                entry.channels[channel] ||
                0
            ) + 1;

    }


    const notablePolicies =
        Object.entries(
            policyMap
        )
            .map(
                ([policy, data]) => ({

                    policy,

                    alertCount:
                        data.count,

                    percentage:
                        percentage(
                            data.count,
                            alerts.length
                        ),

                    highRisk:
                        data.highRisk,

                    topUser:
                        sortCounts(
                            data.users
                        )[0]?.value ||
                        null,

                    topChannel:
                        sortCounts(
                            data.channels
                        )[0]?.value ||
                        null

                })
            )
            .sort(
                (a, b) =>
                    b.alertCount -
                    a.alertCount
            )
            .slice(0, 10);


    /*
    ======================================
    CHANNEL ANALYSIS
    ======================================
    */

    const channelMap = {};


    for (
        const alert
        of alerts
    ) {

        const channel =
            normalizeValue(
                alert.channel
            ) ||
            "unknown";


        if (
            !channelMap[channel]
        ) {

            channelMap[channel] = {

                count: 0,

                highRisk: 0,

                users: {},

                policies: {}

            };

        }


        const entry =
            channelMap[channel];


        entry.count++;


        const severity =
            normalizeValue(
                alert.severity
            );


        if (
            severity === "high" ||
            severity === "critical"
        ) {

            entry.highRisk++;

        }


        const user =
            normalizeValue(
                alert.triggering_user
            ) ||
            "unknown";


        const policy =
            normalizeValue(
                alert.policy_id
            ) ||
            "unknown";


        entry.users[user] =
            (
                entry.users[user] ||
                0
            ) + 1;


        entry.policies[policy] =
            (
                entry.policies[policy] ||
                0
            ) + 1;

    }


    const notableChannels =
        Object.entries(
            channelMap
        )
            .map(
                ([channel, data]) => ({

                    channel,

                    alertCount:
                        data.count,

                    percentage:
                        percentage(
                            data.count,
                            alerts.length
                        ),

                    highRisk:
                        data.highRisk,

                    topUser:
                        sortCounts(
                            data.users
                        )[0]?.value ||
                        null,

                    topPolicy:
                        sortCounts(
                            data.policies
                        )[0]?.value ||
                        null

                })
            )
            .sort(
                (a, b) =>
                    b.alertCount -
                    a.alertCount
            )
            .slice(0, 10);


    /*
    ======================================
    CORRELATION ANALYSIS
    ======================================
    */

    const combinations = {};


    for (
        const alert
        of alerts
    ) {

        const user =
            normalizeValue(
                alert.triggering_user
            ) ||
            "unknown";


        const policy =
            normalizeValue(
                alert.policy_id
            ) ||
            "unknown";


        const channel =
            normalizeValue(
                alert.channel
            ) ||
            "unknown";


        const key =
            `${user}|${policy}|${channel}`;


        if (
            !combinations[key]
        ) {

            combinations[key] = {

                user,

                policy,

                channel,

                count: 0,

                highRisk: 0

            };

        }


        combinations[key].count++;


        const severity =
            normalizeValue(
                alert.severity
            );


        if (
            severity === "high" ||
            severity === "critical"
        ) {

            combinations[key].highRisk++;

        }

    }


    const correlations =
        Object.values(
            combinations
        )
            .filter(
                item =>
                    item.count >= 2
            )
            .sort(
                (a, b) => {

                    if (
                        b.highRisk !==
                        a.highRisk
                    ) {

                        return (
                            b.highRisk -
                            a.highRisk
                        );

                    }

                    return (
                        b.count -
                        a.count
                    );

                }
            )
            .slice(0, 10);


    /*
    ======================================
    GENERATE USER INSIGHTS
    ======================================
    */

    const topUser =
        notableUsers[0];


    if (
        topUser &&
        topUser.percentage >= 25
    ) {

        insights.push({

            type:
                "user_concentration",

            priority:
                topUser.highRisk > 0
                    ? "high"
                    : "medium",

            metric:
                topUser.percentage,

            message:
                `${topUser.user} is associated with ${topUser.alertCount} alerts (${topUser.percentage}% of current Cyera activity), making this user a notable concentration point.`

        });

    }


    const highRiskUser =
        notableUsers
            .filter(
                user =>
                    user.highRisk > 0
            )
            .sort(
                (a, b) =>
                    b.highRisk -
                    a.highRisk
            )[0];


    if (
        highRiskUser &&
        highRiskUser.highRisk >= 3
    ) {

        insights.push({

            type:
                "user_high_risk_concentration",

            priority:
                "high",

            metric:
                highRiskUser.highRisk,

            message:
                `${highRiskUser.user} is associated with ${highRiskUser.highRisk} high or critical alerts, indicating concentrated higher-risk activity.`

        });

    }


    const topPolicy =
        notablePolicies[0];


    if (
        topPolicy &&
        topPolicy.percentage >= 25
    ) {

        insights.push({

            type:
                "policy_behavioral_concentration",

            priority:
                "medium",

            metric:
                topPolicy.percentage,

            message:
                `Policy ${topPolicy.policy} accounts for ${topPolicy.percentage}% of current Cyera alerts and is the dominant detection pattern.`

        });

    }


    const topCorrelation =
        correlations[0];


    if (
        topCorrelation &&
        topCorrelation.count >= 3
    ) {

        insights.push({

            type:
                "behavioral_correlation",

            priority:
                topCorrelation.highRisk > 0
                    ? "high"
                    : "medium",

            metric:
                topCorrelation.count,

            message:
                `A recurring pattern links user ${topCorrelation.user}, policy ${topCorrelation.policy}, and channel ${topCorrelation.channel} across ${topCorrelation.count} alerts.`

        });

    }


    return {

        notableUsers,

        notablePolicies,

        notableChannels,

        correlations,

        insights

    };

}


/*
==========================================
STATUS STAGNATION
==========================================

Detects large numbers of alerts remaining in
the same non-resolved state.
==========================================
*/

function calculateStatusStagnation(
    alerts
) {

    const insights = [];


    if (
        !alerts.length
    ) {

        return {

            stagnantStatuses: [],

            insights

        };

    }


    const statusCounts =
        countBy(
            alerts,
            "status"
        );


    const stagnantStatuses =
        Object.entries(
            statusCounts
        )
            .map(
                ([status, count]) => ({

                    status,

                    count,

                    percentage:
                        percentage(
                            count,
                            alerts.length
                        )

                })
            )
            .filter(
                item =>
                    item.status !==
                    "resolved" &&
                    item.status !==
                    "closed" &&
                    item.percentage >= 30
            )
            .sort(
                (a, b) =>
                    b.count -
                    a.count
            );


    for (
        const status
        of stagnantStatuses
    ) {

        insights.push({

            type:
                "status_stagnation",

            priority:
                status.percentage >= 60
                    ? "high"
                    : "medium",

            metric:
                status.percentage,

            message:
                `${status.count} alerts (${status.percentage}%) remain in the ${status.status} state, indicating a significant concentration of unresolved workflow activity.`

        });

    }


    return {

        stagnantStatuses,

        insights

    };

}


/*
==========================================
SEVERITY ESCALATION
==========================================

Compares the same logical alert across the
current and previous report.
==========================================
*/

function calculateSeverityEscalation(
    currentAlerts,
    previousAlerts
) {

    const insights = [];


    const previousMap =
        new Map();


    for (
        const alert
        of previousAlerts
    ) {

        const fingerprint =
            getAlertFingerprint(
                alert
            );


        if (
            fingerprint
        ) {

            previousMap.set(
                fingerprint,
                alert
            );

        }

    }


    const severityRank = {

        low: 1,
        medium: 2,
        high: 3,
        critical: 4

    };


    const escalations = [];


    for (
        const alert
        of currentAlerts
    ) {

        const fingerprint =
            getAlertFingerprint(
                alert
            );


        const previous =
            previousMap.get(
                fingerprint
            );


        if (
            !previous
        ) {

            continue;

        }


        const previousSeverity =
            normalizeValue(
                previous.severity
            );


        const currentSeverity =
            normalizeValue(
                alert.severity
            );


        const previousRank =
            severityRank[
                previousSeverity
            ] || 0;


        const currentRank =
            severityRank[
                currentSeverity
            ] || 0;


        if (
            currentRank >
            previousRank
        ) {

            escalations.push({

                alertId:
                    alert.alert_id,

                name:
                    alert.name,

                previousSeverity,

                currentSeverity,

                triggeringUser:
                    alert.triggering_user,

                policyId:
                    alert.policy_id

            });

        }

    }


    if (
        escalations.length > 0
    ) {

        const criticalEscalations =
            escalations.filter(
                item =>
                    item.currentSeverity ===
                    "critical"
            );


        insights.push({

            type:
                "severity_escalation",

            priority:
                criticalEscalations.length > 0
                    ? "high"
                    : "medium",

            metric:
                escalations.length,

            message:
                `${escalations.length} recurring alerts increased in severity compared with the previous report${criticalEscalations.length > 0 ? `, including ${criticalEscalations.length} that escalated to critical` : ""}.`

        });

    }


    return {

        count:
            escalations.length,

        criticalEscalations:
            escalations.filter(
                item =>
                    item.currentSeverity ===
                    "critical"
            ).length,

        alerts:
            escalations
                .slice(0, 20),

        insights

    };

}


/*
==========================================
RISK ACCEPTANCE PATTERNS
==========================================

Analyzes risk-accepted Cyera alerts and
identifies concentration by severity,
policy, user and other useful dimensions.

IMPORTANT:
D1 `.all()` returns rows as OBJECTS.

Do NOT use:

rows.map(([key, value]) => ...)

unless the data has first been converted
with Object.entries().
==========================================
*/

async function calculateRiskAcceptancePatterns(
    env,
    reportId
) {

    /*
    ==========================================
    LOAD RISK-ACCEPTED ALERTS
    ==========================================
    */

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
            WHERE
                report_id = ?
                AND LOWER(
                    COALESCE(status, '')
                ) = 'riskaccepted'
        `)
        .bind(reportId)
        .all();


    const alerts =
        result.results || [];


    /*
    ==========================================
    EMPTY RESULT
    ==========================================
    */

    if (alerts.length === 0) {

        return {

            reportId,

            totalRiskAccepted: 0,

            percentages: {

                total: 0,

                bySeverity: [],

                byPolicy: [],

                byUser: [],

                byChannel: [],

                byActivity: []

            },

            patterns: []

        };

    }


    /*
    ==========================================
    GENERIC COUNTER
    ==========================================
    */

    function countBy(
        items,
        field
    ) {

        const counts = {};

        for (const item of items) {

            const value =
                String(
                    item?.[field] ||
                    "unknown"
                )
                    .trim()
                    .toLowerCase();

            counts[value] =
                (counts[value] || 0) + 1;

        }

        return Object.entries(counts)
            .sort(
                (a, b) =>
                    b[1] - a[1]
            )
            .map(
                ([value, count]) => ({

                    value,

                    count,

                    percentage:
                        Number(
                            (
                                count /
                                items.length *
                                100
                            ).toFixed(1)
                        )

                })
            );

    }


    /*
    ==========================================
    DISTRIBUTIONS
    ==========================================
    */

    const bySeverity =
        countBy(
            alerts,
            "severity"
        );


    const byPolicy =
        countBy(
            alerts,
            "policy_id"
        );


    const byUser =
        countBy(
            alerts,
            "triggering_user"
        );


    const byChannel =
        countBy(
            alerts,
            "channel"
        );


    const byActivity =
        countBy(
            alerts,
            "source_activity"
        );


    /*
    ==========================================
    PATTERN DETECTION
    ==========================================
    */

    const patterns = [];


    /*
    ------------------------------------------
    HIGH / CRITICAL RISK ACCEPTANCE
    ------------------------------------------
    */

    const highRiskAccepted =
        alerts.filter(
            alert => {

                const severity =
                    String(
                        alert.severity || ""
                    ).toLowerCase();

                return (
                    severity === "high" ||
                    severity === "critical"
                );

            }
        );


    if (
        highRiskAccepted.length > 0
    ) {

        const percentage =
            Number(
                (
                    highRiskAccepted.length /
                    alerts.length *
                    100
                ).toFixed(1)
            );


        patterns.push({

            type:
                "high_risk_acceptance",

            severity:
                highRiskAccepted.some(
                    alert =>
                        String(
                            alert.severity || ""
                        ).toLowerCase() ===
                        "critical"
                )
                    ? "high"
                    : "medium",

            metric:
                highRiskAccepted.length,

            percentage,

            message:
                `${highRiskAccepted.length} high or critical severity alerts are currently risk accepted (${percentage}% of risk-accepted activity).`,

            implication:
                "Risk acceptance is being applied to higher-severity activity and may warrant periodic validation of the business justification."

        });

    }


    /*
    ------------------------------------------
    DOMINANT POLICY
    ------------------------------------------
    */

    if (
        byPolicy.length > 0
    ) {

        const topPolicy =
            byPolicy[0];


        if (
            topPolicy.percentage >= 40
        ) {

            patterns.push({

                type:
                    "risk_acceptance_policy_concentration",

                severity:
                    "medium",

                metric:
                    topPolicy.count,

                percentage:
                    topPolicy.percentage,

                policy:
                    topPolicy.value,

                message:
                    `${topPolicy.percentage}% of risk-accepted alerts are associated with the same policy.`,

                implication:
                    "A single policy is responsible for a significant share of risk acceptance activity and may deserve closer review."

            });

        }

    }


    /*
    ------------------------------------------
    DOMINANT USER
    ------------------------------------------
    */

    if (
        byUser.length > 0
    ) {

        const topUser =
            byUser[0];


        if (
            topUser.percentage >= 40
        ) {

            patterns.push({

                type:
                    "risk_acceptance_user_concentration",

                severity:
                    "medium",

                metric:
                    topUser.count,

                percentage:
                    topUser.percentage,

                user:
                    topUser.value,

                message:
                    `${topUser.percentage}% of risk-accepted alerts involve the same triggering user.`,

                implication:
                    "Risk acceptance activity is concentrated around a single user and may indicate a recurring business workflow or repeated exception."

            });

        }

    }


    /*
    ------------------------------------------
    DOMINANT CHANNEL
    ------------------------------------------
    */

    if (
        byChannel.length > 0
    ) {

        const topChannel =
            byChannel[0];


        if (
            topChannel.percentage >= 50
        ) {

            patterns.push({

                type:
                    "risk_acceptance_channel_concentration",

                severity:
                    "low",

                metric:
                    topChannel.count,

                percentage:
                    topChannel.percentage,

                channel:
                    topChannel.value,

                message:
                    `${topChannel.percentage}% of risk-accepted alerts originate from the ${topChannel.value} channel.`,

                implication:
                    "Risk acceptance activity is concentrated in one communication or data movement channel."

            });

        }

    }


    /*
    ------------------------------------------
    DOMINANT ACTIVITY
    ------------------------------------------
    */

    if (
        byActivity.length > 0
    ) {

        const topActivity =
            byActivity[0];


        if (
            topActivity.percentage >= 40
        ) {

            patterns.push({

                type:
                    "risk_acceptance_activity_concentration",

                severity:
                    "medium",

                metric:
                    topActivity.count,

                percentage:
                    topActivity.percentage,

                activity:
                    topActivity.value,

                message:
                    `${topActivity.percentage}% of risk-accepted alerts involve the same source activity.`,

                implication:
                    "A recurring activity is responsible for a significant portion of accepted risk."

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

        totalRiskAccepted:
            alerts.length,

        percentages: {

            total:
                alerts.length,

            bySeverity,

            byPolicy,

            byUser,

            byChannel,

            byActivity

        },

        patterns

    };

}
/*
==========================================
EMERGING RISK DETECTION
==========================================

Detects categories that were absent or much
smaller in the previous report.
==========================================
*/

function calculateEmergingRisks(
    currentAlerts,
    previousAlerts
) {

    const insights = [];


    const dimensions = [

        {
            name:
                "policy",

            field:
                "policy_id"

        },

        {
            name:
                "channel",

            field:
                "channel"

        },

        {
            name:
                "activity",

            field:
                "source_activity"

        },

        {
            name:
                "user",

            field:
                "triggering_user"

        }

    ];


    const emerging = [];


    for (
        const dimension
        of dimensions
    ) {

        const currentCounts =
            countBy(
                currentAlerts,
                dimension.field
            );


        const previousCounts =
            countBy(
                previousAlerts,
                dimension.field
            );


        for (
            const [
                value,
                currentCount
            ]
            of Object.entries(
                currentCounts
            )
        ) {

            const previousCount =
                previousCounts[
                    value
                ] || 0;


            const currentPercentage =
                percentage(
                    currentCount,
                    currentAlerts.length
                );


            /*
            A category is considered emerging
            when:

            - It did not exist previously, OR
            - It increased substantially
            */

            if (
                (
                    previousCount === 0 &&
                    currentCount >= 2
                )
                ||
                (
                    previousCount > 0 &&
                    currentCount >= 3 &&
                    currentCount >=
                        previousCount * 2
                )
            ) {

                emerging.push({

                    dimension:
                        dimension.name,

                    value,

                    currentCount,

                    previousCount,

                    currentPercentage,

                    growth:
                        previousCount === 0
                            ? null
                            : percentageChange(
                                currentCount,
                                previousCount
                            )

                });

            }

        }

    }


    const topEmerging =
        emerging
            .sort(
                (a, b) =>
                    b.currentCount -
                    a.currentCount
            )
            .slice(0, 15);


    for (
        const item
        of topEmerging
            .slice(0, 5)
    ) {

        insights.push({

            type:
                "emerging_pattern",

            priority:
                item.currentPercentage >= 25
                    ? "high"
                    : "medium",

            metric:
                item.currentCount,

            message:
                `${item.dimension} pattern "${item.value}" is emerging, with ${item.currentCount} current alerts compared with ${item.previousCount} in the previous report.`

        });

    }


    return {

        patterns:
            topEmerging,

        insights

    };

}


/*
==========================================
OPERATIONAL WEAKNESSES
==========================================

Combines multiple signals to identify
workflow-level weaknesses.
==========================================
*/

function calculateOperationalWeaknesses(
    alerts,
    aging,
    statusStagnation
) {

    const insights = [];


    const unassigned =
        alerts.filter(
            alert =>
                !alert.assigned_user_email
        ).length;


    const riskAccepted =
        alerts.filter(
            alert =>
                normalizeValue(
                    alert.status
                ) ===
                "riskaccepted"
        ).length;


    const unresolved =
        alerts.filter(
            alert => {

                const status =
                    normalizeValue(
                        alert.status
                    );

                return (
                    status !== "resolved" &&
                    status !== "closed"
                );

            }
        ).length;


    /*
    ======================================
    HIGH UNASSIGNED + UNRESOLVED
    ======================================
    */

    if (
        unassigned > 0 &&
        unresolved > 0
    ) {

        const percentageUnassigned =
            percentage(
                unassigned,
                alerts.length
            );


        if (
            percentageUnassigned >= 20
        ) {

            insights.push({

                type:
                    "operational_assignment_weakness",

                priority:
                    "high",

                metric:
                    percentageUnassigned,

                message:
                    `${unassigned} alerts (${percentageUnassigned}%) are unassigned while ${unresolved} remain unresolved, indicating a potential analyst workload or routing weakness.`

            });

        }

    }


    /*
    ======================================
    PERSISTENT + UNASSIGNED
    ======================================
    */

    if (
        aging.highOrCriticalPersistent >
        0 &&
        unassigned >
        0
    ) {

        insights.push({

            type:
                "persistent_unassigned_risk",

            priority:
                "high",

            metric:
                aging.highOrCriticalPersistent,

            message:
                `${aging.highOrCriticalPersistent} high or critical alerts have persisted across multiple reports while alerts remain unassigned, increasing the likelihood of unresolved recurring risk.`

        });

    }


    /*
    ======================================
    RISK ACCEPTANCE + PERSISTENCE
    ======================================
    */

    if (
        riskAccepted > 0 &&
        aging.persistent3Plus > 0
    ) {

        insights.push({

            type:
                "accepted_persistent_risk",

            priority:
                "medium",

            metric:
                aging.persistent3Plus,

            message:
                `Persistent alert activity exists alongside risk-accepted alerts. This may warrant periodic validation that accepted risks remain appropriately justified.`

        });

    }


    /*
    ======================================
    STATUS CONCENTRATION
    ======================================
    */

    if (
        statusStagnation
            ?.stagnantStatuses
            ?.length > 0
    ) {

        const top =
            statusStagnation
                .stagnantStatuses[0];


        if (
            top.percentage >= 50
        ) {

            insights.push({

                type:
                    "workflow_stagnation",

                priority:
                    "medium",

                metric:
                    top.percentage,

                message:
                    `More than half of the current alert population is concentrated in the ${top.status} state, suggesting a significant workflow backlog or investigation bottleneck.`

            });

        }

    }


    return {

        unassigned,

        unresolved,

        riskAccepted,

        insights

    };

}


/*
==========================================
INTELLIGENCE SUMMARY
==========================================

Produces a concise human-readable assessment
from the underlying deterministic signals.
==========================================
*/

function buildIntelligenceSummary(
    context
) {

    const statements = [];


    const {

        totalAlerts,

        severity,

        comparison,

        trend,

        lifecycle,

        aging,

        behavioral,

        escalation,

        emerging,

        operational

    } = context;


    /*
    ======================================
    OVERALL STATE
    ======================================
    */

    if (
        totalAlerts === 0
    ) {

        statements.push(
            "No alerts are currently available for analysis."
        );

    }
    else {

        const highCritical =
            safeNumber(
                severity.high
            ) +
            safeNumber(
                severity.critical
            );


        statements.push(
            `The current reporting period contains ${totalAlerts} alerts, including ${highCritical} high or critical severity alerts.`
        );

    }


    /*
    ======================================
    TREND
    ======================================
    */

    if (
        trend?.direction ===
        "increasing"
    ) {

        statements.push(
            "Recent alert volume shows a sustained upward trend."
        );

    }
    else if (
        trend?.direction ===
        "decreasing"
    ) {

        statements.push(
            "Recent alert volume shows a sustained downward trend."
        );

    }
    else {

        statements.push(
            "Recent alert volume does not show a strong sustained directional trend."
        );

    }


    /*
    ======================================
    LIFECYCLE
    ======================================
    */

    if (
        lifecycle &&
        lifecycle.carriedOverPercentage >= 50
    ) {

        statements.push(
            `${lifecycle.carriedOverPercentage}% of current Cyera alerts were carried over from the previous report, indicating substantial recurring activity.`
        );

    }


    /*
    ======================================
    PERSISTENCE
    ======================================
    */

    if (
        aging &&
        aging.persistent3Plus > 0
    ) {

        statements.push(
            `${aging.persistent3Plus} Cyera alerts have persisted across at least three reports.`
        );

    }


    /*
    ======================================
    BEHAVIOR
    ======================================
    */

    if (
        behavioral
            ?.correlations
            ?.length > 0
    ) {

        const correlation =
            behavioral.correlations[0];


        statements.push(
            `A recurring user-policy-channel pattern was detected involving ${correlation.user}, ${correlation.policy}, and ${correlation.channel}.`
        );

    }


    /*
    ======================================
    ESCALATION
    ======================================
    */

    if (
        escalation?.count > 0
    ) {

        statements.push(
            `${escalation.count} recurring alerts increased in severity compared with the previous report.`
        );

    }


    /*
    ======================================
    EMERGING
    ======================================
    */

    if (
        emerging
            ?.patterns
            ?.length > 0
    ) {

        statements.push(
            `${emerging.patterns.length} potentially emerging behavioral patterns were detected.`
        );

    }


    /*
    ======================================
    OPERATIONAL
    ======================================
    */

    if (
        operational
            ?.insights
            ?.length > 0
    ) {

        statements.push(
            "The current data also indicates operational workflow pressure involving assignment, persistence, or unresolved alert handling."
        );

    }


    /*
    ======================================
    COMPARISON
    ======================================
    */

    if (
        comparison
    ) {

        if (
            comparison.change.totalPercentage >
            25
        ) {

            statements.push(
                `Total alert volume increased ${comparison.change.totalPercentage}% compared with the previous report.`
            );

        }
        else if (
            comparison.change.totalPercentage <
            -25
        ) {

            statements.push(
                `Total alert volume decreased ${Math.abs(comparison.change.totalPercentage)}% compared with the previous report.`
            );

        }

    }


    return {

        headline:
            statements[0] ||
            "Security activity is currently being analyzed.",

        statements:
            statements.slice(0, 8),

        signalCount:
            statements.length

    };

}


/*
==========================================
MAIN SECURITY INTELLIGENCE ENGINE
==========================================
*/

export async function generateSecurityIntelligence(
    env
) {

    /*
    ======================================
    FIND LATEST REPORTS
    ======================================
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
                LIMIT 30
            `)
            .all();


    const reports =
        reportsResult.results || [];


    const latestReport =
        reports[0] ||
        null;


    const previousReport =
        reports[1] ||
        null;


    /*
    ======================================
    NO REPORTS
    ======================================
    */

    if (
        !latestReport
    ) {

        return {

            generatedAt:
                new Date().toISOString(),

            report:
                null,

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

            comparison:
                null,

            lifecycle:
                null,

            aging:
                null,

            securityIntelligence:
                null,

            prioritization: {

                summary: {

                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0

                },

                alerts: []

            },

            trends:
                null,

            behavioralPatterns:
                null,

            severityEscalation:
                null,

            emergingRisks:
                null,

            operationalWeaknesses:
                null,

            intelligenceSummary: {

                headline:
                    "No security reports are currently available.",

                statements: [],

                signalCount:
                    0

            },

            insights: []

        };

    }


    const reportId =
        latestReport.report_id;


    /*
    ======================================
    CYERA SUMMARY
    ======================================
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
            .bind(
                reportId
            )
            .all();


    /*
    ======================================
    PURVIEW SUMMARY
    ======================================
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
            .bind(
                reportId
            )
            .all();


    /*
    ======================================
    INITIALIZE METRICS
    ======================================
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
    ======================================
    PROCESS CYERA
    ======================================
    */

    for (
        const row
        of cyeraRows.results || []
    ) {

        const count =
            safeNumber(
                row.count
            );


        cyeraTotal += count;


        const severityKey =
            normalizeValue(
                row.severity
            ) ||
            "unknown";


        const statusKey =
            normalizeValue(
                row.status
            ) ||
            "unknown";


        if (
            Object.prototype.hasOwnProperty
                .call(
                    severity,
                    severityKey
                )
        ) {

            severity[
                severityKey
            ] += count;

        }


        if (
            Object.prototype.hasOwnProperty
                .call(
                    status,
                    statusKey
                )
        ) {

            status[
                statusKey
            ] += count;

        }

    }


    /*
    ======================================
    PROCESS PURVIEW
    ======================================
    */

    for (
        const row
        of purviewRows.results || []
    ) {

        const count =
            safeNumber(
                row.count
            );


        purviewTotal += count;


        const severityKey =
            normalizeValue(
                row.severity
            ) ||
            "unknown";


        const statusKey =
            normalizeValue(
                row.status
            ) ||
            "unknown";


        if (
            Object.prototype.hasOwnProperty
                .call(
                    severity,
                    severityKey
                )
        ) {

            severity[
                severityKey
            ] += count;

        }


        if (
            Object.prototype.hasOwnProperty
                .call(
                    status,
                    statusKey
                )
        ) {

            status[
                statusKey
            ] += count;

        }

    }


    /*
    ======================================
    UNASSIGNED
    ======================================
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
            .bind(
                reportId
            )
            .first();


    const unassigned =
        safeNumber(
            unassignedResult?.count
        );


    /*
    ======================================
    TOTAL
    ======================================
    */

    const totalAlerts =
        cyeraTotal +
        purviewTotal;


    /*
    ======================================
    BASIC INSIGHTS
    ======================================
    */

    const insights = [];


    if (
        severity.critical > 0
    ) {

        insights.push({

            type:
                "critical",

            priority:
                "high",

            metric:
                severity.critical,

            message:
                `${severity.critical} critical ${severity.critical === 1 ? "alert requires" : "alerts require"} attention.`

        });

    }


    if (
        severity.high > 0
    ) {

        insights.push({

            type:
                "severity",

            priority:
                "high",

            metric:
                severity.high,

            message:
                `${severity.high} high-severity ${severity.high === 1 ? "alert is" : "alerts are"} currently present.`

        });

    }


    if (
        totalAlerts > 0
    ) {

        const mediumPercentage =
            percentage(
                severity.medium,
                totalAlerts
            );


        if (
            mediumPercentage >= 70
        ) {

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


    if (
        totalAlerts > 0
    ) {

        const resolved =
            status.resolved ||
            0;


        const resolutionPercentage =
            percentage(
                resolved,
                totalAlerts
            );


        if (
            resolutionPercentage < 25
        ) {

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


    if (
        unassigned > 0
    ) {

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
    ======================================
    PREVIOUS REPORT COMPARISON
    ======================================
    */

    let comparison = null;


    if (
        previousReport
    ) {

        const currentTotal =
            totalAlerts;


        const previousTotal =
            safeNumber(
                previousReport.total_alerts
            );


        const totalChange =
            currentTotal -
            previousTotal;


        const totalPercentage =
            percentageChange(
                currentTotal,
                previousTotal
            );


        const currentCyera =
            cyeraTotal;


        const previousCyera =
            safeNumber(
                previousReport.cyera_count
            );


        const cyeraChange =
            currentCyera -
            previousCyera;


        const cyeraPercentage =
            percentageChange(
                currentCyera,
                previousCyera
            );


        const currentPurview =
            purviewTotal;


        const previousPurview =
            safeNumber(
                previousReport.purview_count
            );


        const purviewChange =
            currentPurview -
            previousPurview;


        const purviewPercentage =
            percentageChange(
                currentPurview,
                previousPurview
            );


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
                    totalPercentage,

                cyera:
                    cyeraChange,

                cyeraPercentage:
                    cyeraPercentage,

                purview:
                    purviewChange,

                purviewPercentage:
                    purviewPercentage

            }

        };


        if (
            totalChange > 0
        ) {

            insights.push({

                type:
                    "volume_change",

                priority:
                    totalPercentage >= 50
                        ? "high"
                        : "medium",

                metric:
                    totalPercentage,

                message:
                    `The latest report contains ${currentTotal} alerts, an increase of ${totalChange} (${totalPercentage}%) compared with the previous report.`

            });

        }
        else if (
            totalChange < 0
        ) {

            insights.push({

                type:
                    "volume_change",

                priority:
                    "low",

                metric:
                    totalPercentage,

                message:
                    `The latest report contains ${currentTotal} alerts, a decrease of ${Math.abs(totalChange)} (${Math.abs(totalPercentage)}%) compared with the previous report.`

            });

        }
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


        if (
            Math.abs(
                cyeraPercentage
            ) >= 25
        ) {

            insights.push({

                type:
                    "source_change",

                priority:
                    cyeraPercentage > 0
                        ? "medium"
                        : "low",

                metric:
                    cyeraPercentage,

                message:
                    `Cyera alert volume ${cyeraPercentage > 0 ? "increased" : "decreased"} by ${Math.abs(cyeraPercentage)}% compared with the previous report.`

            });

        }


        if (
            Math.abs(
                purviewPercentage
            ) >= 25
        ) {

            insights.push({

                type:
                    "source_change",

                priority:
                    purviewPercentage > 0
                        ? "medium"
                        : "low",

                metric:
                    purviewPercentage,

                message:
                    `Purview alert volume ${purviewPercentage > 0 ? "increased" : "decreased"} by ${Math.abs(purviewPercentage)}% compared with the previous report.`

            });

        }

    }


    /*
    ======================================
    LIFECYCLE
    ======================================
    */

    const lifecycle =
        await calculateAlertLifecycle(
            env,
            reportId,
            previousReport?.report_id ||
            null
        );


    if (
        lifecycle.new > 0
    ) {

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


    if (
        lifecycle.carriedOver > 0
    ) {

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
    ======================================
    AGING
    ======================================
    */

    const aging =
        await getCyeraAlertAging(
            env,
            reportId
        );


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
    ======================================
    PRIORITIZATION
    ======================================
    */

    const prioritizedAlerts =
        prioritizeCyeraAlerts(
            lifecycle.newAlerts.concat(
                lifecycle.carriedOverAlerts
            ),
            lifecycle,
            aging
        );


    const prioritySummary = {

        critical:
            prioritizedAlerts.filter(
                alert =>
                    alert.priority ===
                    "critical"
            ).length,

        high:
            prioritizedAlerts.filter(
                alert =>
                    alert.priority ===
                    "high"
            ).length,

        medium:
            prioritizedAlerts.filter(
                alert =>
                    alert.priority ===
                    "medium"
            ).length,

        low:
            prioritizedAlerts.filter(
                alert =>
                    alert.priority ===
                    "low"
            ).length

    };


    /*
    ======================================
    CURRENT CYERA ALERTS
    ======================================
    */

    const currentCyeraAlerts =
        await loadCurrentCyeraAlerts(
            env,
            reportId
        );


    let previousCyeraAlerts = [];


    if (
        previousReport
    ) {

        previousCyeraAlerts =
            await loadCurrentCyeraAlerts(
                env,
                previousReport.report_id
            );

    }


    /*
    ======================================
    PHASE 5
    TREND INTELLIGENCE
    ======================================
    */

    const trends =
        await calculateTrendIntelligence(
            env,
            latestReport
        );


    for (
        const insight
        of trends.insights
    ) {

        insights.push(
            insight
        );

    }


    /*
    ======================================
    BEHAVIORAL INTELLIGENCE
    ======================================
    */

    const behavioralPatterns =
        calculateBehavioralIntelligence(
            currentCyeraAlerts
        );


    for (
        const insight
        of behavioralPatterns.insights
    ) {

        insights.push(
            insight
        );

    }


    /*
    ======================================
    STATUS STAGNATION
    ======================================
    */

    const statusStagnation =
        calculateStatusStagnation(
            currentCyeraAlerts
        );


    for (
        const insight
        of statusStagnation.insights
    ) {

        insights.push(
            insight
        );

    }


    /*
    ======================================
    SEVERITY ESCALATION
    ======================================
    */

    const severityEscalation =
        calculateSeverityEscalation(
            currentCyeraAlerts,
            previousCyeraAlerts
        );


    for (
        const insight
        of severityEscalation.insights
    ) {

        insights.push(
            insight
        );

    }


    /*
    ======================================
    RISK ACCEPTANCE
    ======================================
    */

    const riskAcceptance =
        calculateRiskAcceptancePatterns(
            currentCyeraAlerts
        );


    for (
        const insight
        of riskAcceptance.insights
    ) {

        insights.push(
            insight
        );

    }


    /*
    ======================================
    EMERGING RISKS
    ======================================
    */

    const emergingRisks =
        calculateEmergingRisks(
            currentCyeraAlerts,
            previousCyeraAlerts
        );


    for (
        const insight
        of emergingRisks.insights
    ) {

        insights.push(
            insight
        );

    }


    /*
    ======================================
    OPERATIONAL WEAKNESSES
    ======================================
    */

    const operationalWeaknesses =
        calculateOperationalWeaknesses(
            currentCyeraAlerts,
            aging,
            statusStagnation
        );


    for (
        const insight
        of operationalWeaknesses.insights
    ) {

        insights.push(
            insight
        );

    }


    /*
    ======================================
    EXISTING SECURITY INTELLIGENCE
    ======================================
    */

    const securityIntelligence =
        await calculateCyeraSecurityIntelligence(
            env,
            reportId
        );


    for (
        const finding
        of securityIntelligence.findings
    ) {

        insights.push({

            type:
                finding.type,

            priority:
                finding.severity,

            metric:
                finding.evidence?.alertCount ||
                0,

            message:
                finding.description

        });

    }


    /*
    ======================================
    HIGH-LEVEL SUMMARY
    ======================================
    */

    const intelligenceSummary =
        buildIntelligenceSummary({

            totalAlerts,

            severity,

            comparison,

            trend:
                trends,

            lifecycle,

            aging,

            behavioral:
                behavioralPatterns,

            escalation:
                severityEscalation,

            emerging:
                emergingRisks,

            operational:
                operationalWeaknesses

        });


    /*
    ======================================
    FINAL RESULT
    ======================================
    */

    return {

        generatedAt:
            new Date().toISOString(),


        /*
        ----------------------------------
        REPORT
        ----------------------------------
        */

        report: {

            reportId:
                latestReport.report_id,

            reportDate:
                latestReport.report_date,

            generatedAt:
                latestReport.generated_at

        },


        /*
        ----------------------------------
        ALERT SUMMARY
        ----------------------------------
        */

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


        /*
        ----------------------------------
        TWO-REPORT COMPARISON
        ----------------------------------
        */

        comparison,


        /*
        ----------------------------------
        ALERT LIFECYCLE
        ----------------------------------
        */

        lifecycle,


        /*
        ----------------------------------
        ALERT AGING
        ----------------------------------
        */

        aging,


        /*
        ----------------------------------
        DETERMINISTIC CYERA INTELLIGENCE
        ----------------------------------
        */

        securityIntelligence,


        /*
        ----------------------------------
        ALERT PRIORITIZATION
        ----------------------------------
        */

        prioritization: {

            summary:
                prioritySummary,

            alerts:
                prioritizedAlerts

        },


        /*
        ----------------------------------
        NEW PHASE 5 INTELLIGENCE
        ----------------------------------
        */

        trends,

        behavioralPatterns,

        severityEscalation,

        emergingRisks,

        operationalWeaknesses,

        riskAcceptancePatterns:
            riskAcceptance,

        statusStagnation,


        /*
        ----------------------------------
        HIGH-LEVEL HUMAN SUMMARY
        ----------------------------------
        */

        intelligenceSummary,


        /*
        ----------------------------------
        COMBINED INSIGHTS
        ----------------------------------
        */

        insights

    };

}