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
ALERT PRIORITIZATION
==========================================
*/

function prioritizeCyeraAlerts(alerts, lifecycle, aging) {

    if (!Array.isArray(alerts)) {
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

            let score = severityWeight[
                String(alert.severity || "medium").toLowerCase()
            ] || 50;

            const reasons = [];

            /*
            ------------------------------------------
            SEVERITY
            ------------------------------------------
            */

            if (alert.severity === "critical") {

                score += 30;

                reasons.push(
                    "Critical severity"
                );

            }
            else if (alert.severity === "high") {

                score += 20;

                reasons.push(
                    "High severity"
                );

            }


            /*
            ------------------------------------------
            STATUS
            ------------------------------------------
            */

            if (
                alert.status &&
                alert.status.toLowerCase() === "open"
            ) {

                score += 10;

                reasons.push(
                    "Alert remains open"
                );

            }


            /*
            ------------------------------------------
            ASSIGNMENT
            ------------------------------------------
            */

            if (!alert.assignedUser) {

                score += 15;

                reasons.push(
                    "Alert is unassigned"
                );

            }


            /*
            ------------------------------------------
            RISK ACCEPTED
            ------------------------------------------
            */

            if (
                alert.status &&
                alert.status.toLowerCase() === "riskaccepted"
            ) {

                score -= 20;

                reasons.push(
                    "Risk already accepted"
                );

            }


            /*
            ------------------------------------------
            LIFECYCLE
            ------------------------------------------
            */

            const isCarriedOver =
                lifecycle?.carriedOverAlerts?.some(
                    previous =>
                        previous.fingerprint ===
                        alert.fingerprint
                );

            if (isCarriedOver) {

                score += 20;

                reasons.push(
                    "Carried over from previous report"
                );

            }


            /*
            ------------------------------------------
            PERSISTENCE / AGING

            FIXED: previously this looked up the alert
            in aging.longestRunningAlerts by alertId.
            That was broken in two ways:

              1. alertId mismatch - aging used a numeric
                 surrogate key from alert_history/alerts,
                 while lifecycle alerts carry Cyera's
                 rotating UUID. They never matched, so
                 this bonus never fired.

              2. Even with matching keys, longestRunningAlerts
                 only contains the alert(s) tied for the
                 single longest persistence streak in the
                 WHOLE table - not every alert with
                 reportsSeen >= 2 or >= 3. An alert persisting
                 3 reports got no bonus unless it happened to
                 tie the overall longest streak.

            Fixed by looking up persistence directly by
            fingerprint (the same identity key lifecycle
            uses) against a full fingerprint -> reportsSeen
            map computed in getCyeraAlertAging.
            ------------------------------------------
            */

            const reportsSeen =
                aging?.persistenceByFingerprint?.[alert.fingerprint] || 0;

            if (reportsSeen >= 3) {

                score += 30;

                reasons.push(
                    "Persisted across 3+ reports"
                );

            }
            else if (reportsSeen >= 2) {

                score += 15;

                reasons.push(
                    "Persisted across multiple reports"
                );

            }


            /*
            ------------------------------------------
            PRIORITY CLASSIFICATION
            ------------------------------------------
            */

            let priority;

            if (score >= 120) {

                priority = "critical";

            }
            else if (score >= 90) {

                priority = "high";

            }
            else if (score >= 60) {

                priority = "medium";

            }
            else {

                priority = "low";

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
            carriedOverPercentage: 0,
            newAlerts: [],
            carriedOverAlerts: []
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
    BUILD PREVIOUS FINGERPRINT MULTISET

    FIXED: this was a Set, which can only answer
    "did this fingerprint exist at all yesterday?".

    If the same user/policy/channel combination fires
    twice in one day (a real, common case - e.g. one
    person emailing the same domain twice), a Set
    matches BOTH of today's alerts against the SAME
    single fingerprint entry, so both get marked
    carried-over/new based on one boolean instead of
    being matched one-for-one against how many times
    that fingerprint actually appeared yesterday.

    A multiset (fingerprint -> remaining count) lets
    each occurrence match at most one occurrence from
    the previous report, which is what "carried over"
    should mean.
    ==========================================
    */

    const previousFingerprintCounts =
        new Map();

    for (const alert of previousAlerts) {

        const fingerprint =
            getAlertFingerprint(alert);

        if (!fingerprint) {
            continue;
        }

        previousFingerprintCounts.set(
            fingerprint,
            (previousFingerprintCounts.get(fingerprint) || 0) + 1
        );
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

        const remaining =
            fingerprint
                ? (previousFingerprintCounts.get(fingerprint) || 0)
                : 0;


        if (
            fingerprint &&
            remaining > 0
        ) {

            carriedOverCount++;

            // Consume one occurrence so a second
            // alert with the same fingerprint today
            // must match a second occurrence yesterday,
            // not the same one twice.
            previousFingerprintCounts.set(
                fingerprint,
                remaining - 1
            );

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
CYERA ALERT LIFECYCLE (LEGACY / alert_history BASED)
NEW VS CARRIED OVER

NOTE: This function is NOT called by
generateSecurityIntelligence() below -
calculateAlertLifecycle() (fingerprint-based)
is used instead. This is kept only in case
another endpoint in index.js still calls it.

WARNING: this function has the same identity
mismatch that getCyeraAlertAging() used to have -
it joins on alert_history.alert_id, a numeric
surrogate key, which does not correspond to
Cyera's rotating alert_id UUID on cyera_alerts.
If this function is actually in use anywhere,
it should be rewritten the same way
getCyeraAlertAging() was below (fingerprint-based,
sourced from cyera_alerts directly) rather than
patched in place. Flagging rather than silently
changing it since its call sites are unknown from
this file alone.
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

REWRITTEN: previously this joined
alert_history -> alerts using a numeric
surrogate alert_id, which never lines up
with cyera_alerts.alert_id (Cyera's rotating
UUID). That mismatch meant
currentPersistentAlerts always filtered to
an empty list, so persistent2Plus /
persistent3Plus / highOrCriticalPersistent
were silently 0 in every report regardless
of actual persistence.

This version sources directly from
cyera_alerts (all reports) and groups rows
by the same fingerprint used in
calculateAlertLifecycle(), so aging and
lifecycle now share one identity system
instead of two disconnected ones.

Note: this scans the full cyera_alerts
table (not just two reports). That's fine
at current volumes; if the table grows very
large over many months, consider narrowing
the date range or persisting fingerprint ->
first-seen data incrementally instead of
recomputing from scratch each run.
==========================================
*/

async function getCyeraAlertAging(
    env,
    reportId
) {

    const result = await env.DB
        .prepare(`
            SELECT
                report_id,
                alert_id,
                name,
                triggering_user,
                policy_id,
                source_activity,
                channel,
                severity,
                status,
                assigned_user_email,
                timestamp
            FROM cyera_alerts
        `)
        .all();

    const rows = result.results || [];


    /*
    ==========================================
    GROUP ROWS BY STABLE FINGERPRINT
    ==========================================
    */

    const groups = new Map();

    for (const row of rows) {

        const fingerprint =
            getAlertFingerprint(row);

        if (!fingerprint) {
            continue;
        }

        if (!groups.has(fingerprint)) {

            groups.set(fingerprint, {
                fingerprint,
                reportIds: new Set(),
                rows: []
            });
        }

        const group =
            groups.get(fingerprint);

        group.reportIds.add(row.report_id);
        group.rows.push(row);
    }


    /*
    ==========================================
    RESOLVE "LATEST" ROW PER GROUP

    report_id is formatted REP-YYYYMMDD, so
    lexical sort order matches chronological
    order without needing to join `reports`.
    ==========================================
    */

    for (const group of groups.values()) {

        group.rows.sort(
            (a, b) =>
                String(a.report_id)
                    .localeCompare(String(b.report_id))
        );

        group.latest =
            group.rows[group.rows.length - 1];

        group.reportsSeen =
            group.reportIds.size;
    }

    const allGroups =
        Array.from(groups.values());


    /*
    ==========================================
    FINGERPRINT -> REPORTS-SEEN LOOKUP

    Used by prioritizeCyeraAlerts() so scoring
    can check persistence for ANY alert, not
    only the ones tied for the single longest
    streak (see longestRunningAlerts below).
    ==========================================
    */

    const persistenceByFingerprint = {};

    for (const group of allGroups) {
        persistenceByFingerprint[group.fingerprint] =
            group.reportsSeen;
    }


    /*
    ==========================================
    AGGREGATE METRICS (ACROSS ALL TRACKED ALERTS)
    ==========================================
    */

    let persistent2PlusAll = 0;
    let persistent3PlusAll = 0;

    let longestPersistence = 0;
    let longestRunningAlerts = [];

    for (const group of allGroups) {

        const reportsSeen =
            group.reportsSeen;

        if (reportsSeen >= 2) {
            persistent2PlusAll++;
        }

        if (reportsSeen >= 3) {
            persistent3PlusAll++;
        }

        if (reportsSeen > longestPersistence) {

            longestPersistence = reportsSeen;
            longestRunningAlerts = [group];

        } else if (reportsSeen === longestPersistence) {

            longestRunningAlerts.push(group);

        }
    }


    /*
    ==========================================
    CURRENT REPORT PERSISTENT ALERTS
    ==========================================
    */

    const currentGroups =
        allGroups.filter(
            group => group.reportIds.has(reportId)
        );

    const currentPersistentAlerts =
        currentGroups.filter(
            group => group.reportsSeen >= 2
        );

    const currentPersistent2Plus =
        currentPersistentAlerts.length;

    const currentPersistent3Plus =
        currentGroups.filter(
            group => group.reportsSeen >= 3
        ).length;

    const currentHighCriticalPersistent =
        currentPersistentAlerts.filter(
            group => {

                const severity =
                    String(
                        group.latest.severity || ""
                    ).toLowerCase();

                return (
                    severity === "high" ||
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
            allGroups.length,

        currentReportAlerts:
            currentGroups.length,

        persistent2Plus:
            currentPersistent2Plus,

        persistent3Plus:
            currentPersistent3Plus,

        highOrCriticalPersistent:
            currentHighCriticalPersistent,

        longestPersistence,

        // Full lookup for scoring - see prioritizeCyeraAlerts()
        persistenceByFingerprint,

        longestRunningAlerts:
            longestRunningAlerts
                .slice(0, 10)
                .map(group => ({

                    fingerprint:
                        group.fingerprint,

                    alertId:
                        group.latest.alert_id,

                    name:
                        group.latest.name || null,

                    reportsSeen:
                        group.reportsSeen,

                    firstSeenAt:
                        group.rows[0].timestamp,

                    lastSeenAt:
                        group.latest.timestamp,

                    severity:
                        group.latest.severity,

                    status:
                        group.latest.status,

                    assignedUser:
                        group.latest.assigned_user_email

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
        previousReport?.report_id
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
    PHASE 4
    CYERA ALERT PRIORITIZATION
    ==========================================
    */

    const prioritizedAlerts =
        prioritizeCyeraAlerts(
            lifecycle.newAlerts.concat(
                lifecycle.carriedOverAlerts
            ),
            lifecycle,
            aging
        );


    /*
    ==========================================
    PRIORITIZATION SUMMARY
    ==========================================
    */

    const prioritySummary = {

        critical:
            prioritizedAlerts.filter(
                alert => alert.priority === "critical"
            ).length,

        high:
            prioritizedAlerts.filter(
                alert => alert.priority === "high"
            ).length,

        medium:
            prioritizedAlerts.filter(
                alert => alert.priority === "medium"
            ).length,

        low:
            prioritizedAlerts.filter(
                alert => alert.priority === "low"
            ).length

    };
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
        prioritization: {

            summary:
                prioritySummary,

            alerts:
                prioritizedAlerts

        },
        insights

    };

}