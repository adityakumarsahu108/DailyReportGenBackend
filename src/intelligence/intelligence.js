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

/*
==========================================
CASE OUTCOME & DISPOSITION INTELLIGENCE
==========================================

Risk Accepted is treated as a valid security
outcome/disposition, not as an unresolved case.

Current supported outcomes:

- open
- active
- investigating
- riskAccepted
- falsePositive
- resolved
- closed

This first version intentionally uses only the
current report data.

Historical case-flow analysis will be added
separately after this is validated.
==========================================
*/

async function calculateCaseOutcomeIntelligence(
    env,
    reportId
) {

    /*
    ==========================================
    LOAD CURRENT CYERA CASES
    ==========================================
    */

    const result =
        await env.DB
            .prepare(`
            SELECT
                id,
                external_alert_id,
                name,
                current_severity,
                current_status,
                current_assigned_user,
                first_seen_at,
                last_seen_at,
                resolved_at
            FROM alerts
            WHERE source = 'cyera'
        `)
            .all();


    const alerts =
        result.results || [];


    /*
    ==========================================
    STATUS NORMALIZATION
    ==========================================
    */

    const normalizeStatus = (value) => {

        return String(value || "")
            .trim()
            .toLowerCase()
            .replace(/[\s_-]+/g, "");
    };


    /*
    ==========================================
    INITIALIZE OUTCOME COUNTS
    ==========================================
    */

    const outcomes = {

        open: 0,

        active: 0,

        investigating: 0,

        riskAccepted: 0,

        falsePositive: 0,

        resolved: 0,

        closed: 0,

        unknown: 0

    };


    /*
    ==========================================
    SEVERITY BREAKDOWN
    ==========================================
    */

    const dispositionedBySeverity = {

        critical: 0,

        high: 0,

        medium: 0,

        low: 0,

        unknown: 0

    };


    const activeBySeverity = {

        critical: 0,

        high: 0,

        medium: 0,

        low: 0,

        unknown: 0

    };


    /*
    ==========================================
    PROCESS CASES
    ==========================================
    */

    for (const alert of alerts) {

        const status =
            normalizeStatus(
                alert.current_status
            );


        const severity =
            String(
                alert.current_severity || "unknown"
            )
                .trim()
                .toLowerCase();


        const severityKey =
            Object.prototype.hasOwnProperty.call(
                dispositionedBySeverity,
                severity
            )
                ? severity
                : "unknown";


        /*
        --------------------------------------
        CLASSIFY OUTCOME
        --------------------------------------
        */

        let outcomeKey = "unknown";


        if (status === "open") {

            outcomeKey = "open";

        }

        else if (status === "active") {

            outcomeKey = "active";

        }

        else if (
            status === "investigating"
        ) {

            outcomeKey = "investigating";

        }

        else if (
            status === "riskaccepted"
        ) {

            outcomeKey = "riskAccepted";

        }

        else if (
            status === "falsepositive"
        ) {

            outcomeKey = "falsePositive";

        }

        else if (
            status === "resolved"
        ) {

            outcomeKey = "resolved";

        }

        else if (
            status === "closed"
        ) {

            outcomeKey = "closed";

        }


        outcomes[outcomeKey]++;


        /*
        --------------------------------------
        DISPOSITIONED CASE
        --------------------------------------
        */

        const isDispositioned =
            (
                outcomeKey === "riskAccepted" ||
                outcomeKey === "falsePositive" ||
                outcomeKey === "resolved" ||
                outcomeKey === "closed"
            );


        /*
        --------------------------------------
        ACTIVE CASE
        --------------------------------------
        */

        const isActive =
            (
                outcomeKey === "open" ||
                outcomeKey === "active" ||
                outcomeKey === "investigating"
            );


        if (isDispositioned) {

            dispositionedBySeverity[
                severityKey
            ]++;

        }


        if (isActive) {

            activeBySeverity[
                severityKey
            ]++;

        }

    }


    /*
    ==========================================
    CORE METRICS
    ==========================================
    */

    const totalCases =
        alerts.length;


    const dispositionedCases =
        outcomes.riskAccepted +
        outcomes.falsePositive +
        outcomes.resolved +
        outcomes.closed;


    const activeCases =
        outcomes.open +
        outcomes.active +
        outcomes.investigating;


    const dispositionRate =
        totalCases > 0
            ? Number(
                (
                    dispositionedCases /
                    totalCases *
                    100
                ).toFixed(1)
            )
            : 0;


    const activeRate =
        totalCases > 0
            ? Number(
                (
                    activeCases /
                    totalCases *
                    100
                ).toFixed(1)
            )
            : 0;


    const riskAcceptanceRate =
        totalCases > 0
            ? Number(
                (
                    outcomes.riskAccepted /
                    totalCases *
                    100
                ).toFixed(1)
            )
            : 0;


    /*
    ==========================================
    ACCEPTED VS FORMALLY CLOSED
    ==========================================

    This distinction is important for management.

    Risk Accepted is a valid outcome in your
    operating model, but it is different from
    a formally resolved/closed case.
    ==========================================
    */

    const formallyClosedCases =
        outcomes.resolved +
        outcomes.closed;


    const formalClosureRate =
        totalCases > 0
            ? Number(
                (
                    formallyClosedCases /
                    totalCases *
                    100
                ).toFixed(1)
            )
            : 0;


    /*
    ==========================================
    RISK ACCEPTANCE SEVERITY
    ==========================================
    */

    const riskAcceptedSeverity = {

        critical: 0,

        high: 0,

        medium: 0,

        low: 0,

        unknown: 0

    };


    for (const alert of alerts) {

        const status =
            normalizeStatus(
                alert.current_status
            );


        if (status !== "riskaccepted") {
            continue;
        }


        const severity =
            String(
                alert.current_severity || "unknown"
            )
                .trim()
                .toLowerCase();


        const severityKey =
            Object.prototype.hasOwnProperty.call(
                riskAcceptedSeverity,
                severity
            )
                ? severity
                : "unknown";


        riskAcceptedSeverity[
            severityKey
        ]++;

    }


    /*
    ==========================================
    MANAGEMENT FINDINGS
    ==========================================
    */

    const findings = [];


    /*
    ------------------------------------------
    OVERALL DISPOSITION
    ------------------------------------------
    */

    if (totalCases > 0) {

        findings.push({

            type:
                "case_disposition",

            severity:
                dispositionRate >= 50
                    ? "low"
                    : "medium",

            title:
                "Case disposition overview",

            description:
                `${dispositionedCases} of ${totalCases} Cyera cases (${dispositionRate}%) have reached an accepted or closed disposition.`,

            evidence: {

                totalCases,

                dispositionedCases,

                dispositionRate

            },

            recommendedAction:
                "Review the distribution of active and dispositioned cases to understand overall case-handling effectiveness."

        });

    }


    /*
    ------------------------------------------
    ACTIVE CASE LOAD
    ------------------------------------------
    */

    if (activeCases > 0) {

        findings.push({

            type:
                "active_case_load",

            severity:
                activeRate >= 75
                    ? "high"
                    : "medium",

            title:
                "Active case workload",

            description:
                `${activeCases} of ${totalCases} Cyera cases (${activeRate}%) remain in an active, open, or investigating state.`,

            evidence: {

                activeCases,

                activeRate,

                open:
                    outcomes.open,

                active:
                    outcomes.active,

                investigating:
                    outcomes.investigating

            },

            recommendedAction:
                "Review the active case population and determine whether cases are progressing toward an appropriate disposition."

        });

    }


    /*
    ------------------------------------------
    RISK ACCEPTANCE
    ------------------------------------------
    */

    if (outcomes.riskAccepted > 0) {

        findings.push({

            type:
                "risk_acceptance",

            severity:
                "low",

            title:
                "Risk acceptance is an established case outcome",

            description:
                `${outcomes.riskAccepted} cases (${riskAcceptanceRate}%) have reached a risk-accepted disposition.`,

            evidence: {

                riskAccepted:
                    outcomes.riskAccepted,

                riskAcceptanceRate,

                severity:
                    riskAcceptedSeverity

            },

            recommendedAction:
                "Periodically review accepted-risk cases to confirm that the underlying business justification remains valid."

        });

    }


    /*
    ------------------------------------------
    HIGH / CRITICAL RISK ACCEPTED
    ------------------------------------------
    */

    const highCriticalRiskAccepted =
        riskAcceptedSeverity.high +
        riskAcceptedSeverity.critical;


    if (highCriticalRiskAccepted > 0) {

        findings.push({

            type:
                "high_risk_accepted",

            severity:
                "medium",

            title:
                "High-severity cases reached risk acceptance",

            description:
                `${highCriticalRiskAccepted} high or critical severity cases have reached a risk-accepted disposition.`,

            evidence: {

                high:
                    riskAcceptedSeverity.high,

                critical:
                    riskAcceptedSeverity.critical,

                total:
                    highCriticalRiskAccepted

            },

            recommendedAction:
                "Validate that high and critical severity risk acceptances have appropriate business justification and ownership."

        });

    }


    /*
    ------------------------------------------
    FORMAL CLOSURE
    ------------------------------------------
    */

    if (
        formallyClosedCases > 0
    ) {

        findings.push({

            type:
                "formal_closure",

            severity:
                "low",

            title:
                "Cases formally resolved or closed",

            description:
                `${formallyClosedCases} cases have reached a formally resolved or closed state.`,

            evidence: {

                formallyClosedCases,

                formalClosureRate

            },

            recommendedAction:
                "Continue monitoring formal closure alongside accepted-risk outcomes to understand how cases are being dispositioned."

        });

    }


    /*
    ==========================================
    RETURN
    ==========================================
    */

    return {

        reportId,

        totalCases,

        outcomes,

        disposition: {

            total:
                dispositionedCases,

            rate:
                dispositionRate

        },

        active: {

            total:
                activeCases,

            rate:
                activeRate

        },

        riskAcceptance: {

            total:
                outcomes.riskAccepted,

            rate:
                riskAcceptanceRate,

            bySeverity:
                riskAcceptedSeverity

        },

        formalClosure: {

            total:
                formallyClosedCases,

            rate:
                formalClosureRate

        },

        severity: {

            dispositioned:
                dispositionedBySeverity,

            active:
                activeBySeverity

        },

        findings

    };

}

async function calculateRiskAcceptanceIntelligence(env) {
    const result = await env.DB.prepare(`
    SELECT
      id,
      source,
      external_alert_id,
      name,
      current_severity,
      current_status,
      first_seen_at,
      last_seen_at,
      resolved_at,
      current_assigned_user,
      created_at,
      updated_at
    FROM alerts
    WHERE LOWER(COALESCE(current_status, '')) = 'riskaccepted'
    ORDER BY first_seen_at ASC
  `).all();

    const cases = result.results || [];

    const now = Date.now();

    const severity = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0
    };

    const userCounts = {};
    const nameCounts = {};

    let totalAgeDays = 0;
    let oldestAgeDays = 0;

    const agingBuckets = {
        "0-7": 0,
        "8-30": 0,
        "31-90": 0,
        "90+": 0
    };

    for (const item of cases) {
        const sev = String(item.current_severity || "unknown").toLowerCase();

        if (Object.prototype.hasOwnProperty.call(severity, sev)) {
            severity[sev]++;
        } else {
            severity.unknown++;
        }

        const user = item.current_assigned_user || "Unassigned";
        userCounts[user] = (userCounts[user] || 0) + 1;

        const name = item.name || "Unknown alert";
        nameCounts[name] = (nameCounts[name] || 0) + 1;

        const start =
            item.first_seen_at ||
            item.created_at ||
            item.updated_at;

        if (start) {
            const timestamp = new Date(start).getTime();

            if (!Number.isNaN(timestamp)) {
                const ageDays = Math.max(
                    0,
                    (now - timestamp) / (1000 * 60 * 60 * 24)
                );

                totalAgeDays += ageDays;
                oldestAgeDays = Math.max(oldestAgeDays, ageDays);

                if (ageDays <= 7) {
                    agingBuckets["0-7"]++;
                } else if (ageDays <= 30) {
                    agingBuckets["8-30"]++;
                } else if (ageDays <= 90) {
                    agingBuckets["31-90"]++;
                } else {
                    agingBuckets["90+"]++;
                }
            }
        }
    }

    const total = cases.length;

    const averageAgeDays =
        total > 0
            ? Number((totalAgeDays / total).toFixed(1))
            : 0;

    const highRiskAccepted =
        severity.high + severity.critical;

    const highRiskAcceptanceRate =
        total > 0
            ? Number(((highRiskAccepted / total) * 100).toFixed(1))
            : 0;

    function topEntries(map, limit = 5) {
        return Object.entries(map)
            .sort((a, b) => b[1] - a[1])
            .slice(0, limit)
            .map(([name, count]) => ({
                name,
                count,
                rate: total > 0
                    ? Number(((count / total) * 100).toFixed(1))
                    : 0
            }));
    }

    const topUsers = topEntries(userCounts);
    const topAlertTypes = topEntries(nameCounts);

    const longStandingAccepted =
        agingBuckets["31-90"] + agingBuckets["90+"];

    const veryOldAccepted = agingBuckets["90+"];

    const findings = [];

    // ---------------------------------------------------------
    // 1. High-risk acceptance
    // ---------------------------------------------------------

    if (highRiskAccepted > 0) {
        findings.push({
            type: "high_risk_acceptance",
            severity: highRiskAccepted >= 10 ? "high" : "medium",
            title: "High-severity risks are being accepted",
            description:
                `${highRiskAccepted} of ${total} risk-accepted cases ` +
                `(${highRiskAcceptanceRate}%) are high or critical severity.`,
            evidence: {
                totalRiskAccepted: total,
                high: severity.high,
                critical: severity.critical,
                highRiskAccepted,
                highRiskAcceptanceRate
            },
            recommendedAction:
                "Review high and critical risk acceptances to confirm documented business justification, ownership, and appropriate review cadence."
        });
    }

    // ---------------------------------------------------------
    // 2. Aging
    // ---------------------------------------------------------

    if (longStandingAccepted > 0) {
        const rate =
            total > 0
                ? Number(((longStandingAccepted / total) * 100).toFixed(1))
                : 0;

        findings.push({
            type: "risk_acceptance_aging",
            severity: veryOldAccepted > 0 ? "high" : "medium",
            title: "Accepted risks are remaining active over time",
            description:
                `${longStandingAccepted} risk-accepted cases (${rate}%) ` +
                `have remained accepted for more than 30 days.`,
            evidence: {
                totalRiskAccepted: total,
                over30Days: longStandingAccepted,
                over90Days: veryOldAccepted,
                rateOver30Days: rate,
                averageAgeDays,
                oldestAgeDays: Number(oldestAgeDays.toFixed(1)),
                agingBuckets
            },
            recommendedAction:
                "Review long-standing accepted risks periodically to confirm that the original business justification and risk posture remain valid."
        });
    }

    // ---------------------------------------------------------
    // 3. Concentration
    // ---------------------------------------------------------

    if (topAlertTypes.length > 0) {
        const top = topAlertTypes[0];

        if (top.count >= 3) {
            findings.push({
                type: "risk_acceptance_concentration",
                severity: top.count >= 10 ? "high" : "medium",
                title: "Risk acceptance is concentrated in recurring alert patterns",
                description:
                    `${top.count} risk-accepted cases (${top.rate}%) ` +
                    `share the same alert pattern: "${top.name}".`,
                evidence: {
                    totalRiskAccepted: total,
                    topAlertPattern: top.name,
                    topAlertPatternCount: top.count,
                    topAlertPatternRate: top.rate,
                    topAlertPatterns: topAlertTypes
                },
                recommendedAction:
                    "Review recurring accepted-risk patterns to determine whether they represent an understood business process, an opportunity for policy tuning, or a repeated control exception."
            });
        }
    }

    // ---------------------------------------------------------
    // 4. User concentration
    // ---------------------------------------------------------

    if (topUsers.length > 0) {
        const top = topUsers[0];

        if (
            top.name !== "Unassigned" &&
            top.count >= 3
        ) {
            findings.push({
                type: "risk_acceptance_user_concentration",
                severity: top.count >= 10 ? "medium" : "low",
                title: "Risk acceptances are concentrated among specific owners",
                description:
                    `${top.count} risk-accepted cases (${top.rate}%) ` +
                    `are assigned to ${top.name}.`,
                evidence: {
                    totalRiskAccepted: total,
                    topOwner: top.name,
                    topOwnerCount: top.count,
                    topOwnerRate: top.rate,
                    topOwners: topUsers
                },
                recommendedAction:
                    "Review whether concentrated risk acceptance reflects legitimate ownership or indicates a recurring exception pattern requiring broader policy or process review."
            });
        }
    }

    // ---------------------------------------------------------
    // 5. Overall observation
    // ---------------------------------------------------------

    if (total > 0) {
        findings.push({
            type: "risk_acceptance_profile",
            severity: "low",
            title: "Risk acceptance profile",
            description:
                `${total} cases have reached a risk-accepted disposition. ` +
                `Their average age is ${averageAgeDays} days, with ` +
                `${longStandingAccepted} remaining accepted for more than 30 days.`,
            evidence: {
                totalRiskAccepted: total,
                severity,
                averageAgeDays,
                oldestAgeDays: Number(oldestAgeDays.toFixed(1)),
                agingBuckets,
                highRiskAccepted,
                highRiskAcceptanceRate
            },
            recommendedAction:
                "Use the risk acceptance profile to distinguish deliberate, governed exceptions from risks that may require renewed review."
        });
    }

    return {
        totalRiskAccepted: total,

        severity,

        highRisk: {
            total: highRiskAccepted,
            rate: highRiskAcceptanceRate
        },

        aging: {
            averageDays: averageAgeDays,
            oldestDays: Number(oldestAgeDays.toFixed(1)),
            buckets: agingBuckets,
            over30Days: longStandingAccepted,
            over90Days: veryOldAccepted
        },

        concentration: {
            topAlertPatterns: topAlertTypes,
            topOwners: topUsers
        },

        findings
    };
}

/*
==========================================
CYERA WORK & ANALYST INTELLIGENCE
==========================================

Purpose:

Understand how Cyera alerts are actually
being worked by analysts.

Important:

- Uses canonical `alerts` for current state
- Uses `alert_history` for analyst activity
- Does NOT change Purview logic
- Risk Accepted is treated as handled
- False Positive is treated as handled
- Open/Active/Investigating are active work
==========================================
*/

async function calculateCyeraWorkIntelligence(env, reportId) {

    /*
    ==========================================
    CURRENT CYERA WORKLOAD
    ==========================================
    */

    const currentResult =
        await env.DB
            .prepare(`
                SELECT
                    id,
                    external_alert_id,
                    name,
                    current_severity,
                    current_status,
                    current_assigned_user,
                    first_seen_at,
                    last_seen_at
                FROM alerts
                WHERE source = 'cyera'
            `)
            .all();

    const alerts =
        currentResult.results || [];


    /*
    ==========================================
    STATUS NORMALIZATION
    ==========================================
    */

    const normalizeStatus = (value) => {

        return String(value || "")
            .trim()
            .toLowerCase()
            .replace(/[\s_-]+/g, "");
    };


    /*
    ==========================================
    WORK STATE COUNTS
    ==========================================
    */

    const workState = {

        highRiskUnassigned: 0,

        highRiskAssigned: 0,

        inProgress: 0,

        openAssigned: 0,

        openUnassigned: 0,

        handled: 0,

        other: 0

    };


    const severity = {

        critical: 0,

        high: 0,

        medium: 0,

        low: 0,

        unknown: 0

    };


    /*
    ==========================================
    PROCESS CURRENT ALERTS
    ==========================================
    */

    for (const alert of alerts) {

        const status =
            normalizeStatus(
                alert.current_status
            );

        const sev =
            String(
                alert.current_severity || "unknown"
            )
                .trim()
                .toLowerCase();

        const assigned =
            Boolean(
                alert.current_assigned_user &&
                String(
                    alert.current_assigned_user
                ).trim()
            );


        /*
        --------------------------------------
        SEVERITY
        --------------------------------------
        */

        if (
            Object.prototype.hasOwnProperty.call(
                severity,
                sev
            )
        ) {

            severity[sev]++;

        } else {

            severity.unknown++;

        }


        /*
        --------------------------------------
        HANDLED
        --------------------------------------
        */

        if (
            [
                "riskaccepted",
                "falsepositive",
                "resolved",
                "closed"
            ].includes(status)
        ) {

            workState.handled++;

            continue;
        }


        /*
        --------------------------------------
        IN PROGRESS
        --------------------------------------
        */

        if (
            [
                "inprogress",
                "investigating",
                "active"
            ].includes(status)
        ) {

            workState.inProgress++;

            continue;
        }


        /*
        --------------------------------------
        OPEN
        --------------------------------------
        */

        if (status === "open") {

            const highRisk =
                sev === "critical" ||
                sev === "high";


            if (highRisk && !assigned) {

                workState.highRiskUnassigned++;

            }
            else if (highRisk && assigned) {

                workState.highRiskAssigned++;

            }
            else if (assigned) {

                workState.openAssigned++;

            }
            else {

                workState.openUnassigned++;

            }

            continue;
        }


        /*
        --------------------------------------
        UNKNOWN / OTHER
        --------------------------------------
        */

        workState.other++;

    }


    /*
    ==========================================
    ANALYST ACTIVITY
    ==========================================

    We use alert_history because the canonical
    alerts table only tells us the current state.

    History lets us identify actual transitions.
    ==========================================
    */

    const historyResult =
        await env.DB
            .prepare(`
                WITH ordered_history AS (

                    SELECT
                        h.alert_id,
                        h.report_id,
                        h.observed_at,
                        h.status,
                        h.severity,
                        h.assigned_user,

                        LAG(h.status) OVER (
                            PARTITION BY h.alert_id
                            ORDER BY
                                h.observed_at,
                                h.report_id
                        ) AS previous_status,

                        LAG(h.assigned_user) OVER (
                            PARTITION BY h.alert_id
                            ORDER BY
                                h.observed_at,
                                h.report_id
                        ) AS previous_assigned_user

                    FROM alert_history h

                    JOIN alerts a
                        ON a.id = h.alert_id

                    WHERE
                        a.source = 'cyera'
                )

                SELECT

                    assigned_user AS analyst,

                    COUNT(*) FILTER (
                        WHERE
                            LOWER(status) = 'riskaccepted'
                            AND LOWER(
                                COALESCE(
                                    previous_status,
                                    ''
                                )
                            ) <> 'riskaccepted'
                    ) AS risk_accepted_actions,

                    COUNT(*) FILTER (
                        WHERE
                            LOWER(status) = 'falsepositive'
                            AND LOWER(
                                COALESCE(
                                    previous_status,
                                    ''
                                )
                            ) <> 'falsepositive'
                    ) AS false_positive_actions,

                    COUNT(*) FILTER (
                        WHERE
                            LOWER(status) = 'inprogress'
                            AND LOWER(
                                COALESCE(
                                    previous_status,
                                    ''
                                )
                            ) <> 'inprogress'
                    ) AS started_investigations,

                    COUNT(*) FILTER (
                        WHERE
                            assigned_user IS NOT NULL
                            AND (
                                previous_assigned_user IS NULL
                                OR previous_assigned_user <> assigned_user
                            )
                    ) AS assignment_actions,

                    COUNT(*) FILTER (
                        WHERE
                            LOWER(status) IN (
                                'riskaccepted',
                                'falsepositive',
                                'resolved',
                                'closed'
                            )
                            AND LOWER(
                                COALESCE(
                                    previous_status,
                                    ''
                                )
                            ) NOT IN (
                                'riskaccepted',
                                'falsepositive',
                                'resolved',
                                'closed'
                            )
                    ) AS handled_actions

                FROM ordered_history

                WHERE assigned_user IS NOT NULL

                GROUP BY assigned_user

                ORDER BY
                    handled_actions DESC,
                    analyst
            `)
            .all();


    const analystActivity =
        (historyResult.results || []).map(
            row => ({

                analyst:
                    row.analyst,

                riskAcceptedActions:
                    Number(
                        row.risk_accepted_actions || 0
                    ),

                falsePositiveActions:
                    Number(
                        row.false_positive_actions || 0
                    ),

                startedInvestigations:
                    Number(
                        row.started_investigations || 0
                    ),

                assignmentActions:
                    Number(
                        row.assignment_actions || 0
                    ),

                handledActions:
                    Number(
                        row.handled_actions || 0
                    )

            })
        );


    /*
    ==========================================
    CORE METRICS
    ==========================================
    */

    const total =
        alerts.length;


    const highRiskOpen =
        workState.highRiskUnassigned +
        workState.highRiskAssigned;


    const activeWork =
        workState.highRiskUnassigned +
        workState.highRiskAssigned +
        workState.inProgress +
        workState.openAssigned +
        workState.openUnassigned;


    const unassigned =
        workState.highRiskUnassigned +
        workState.openUnassigned;


    const handled =
        workState.handled;


    const handledRate =
        total > 0
            ? Number(
                (
                    handled /
                    total *
                    100
                ).toFixed(1)
            )
            : 0;


    const unassignedRate =
        total > 0
            ? Number(
                (
                    unassigned /
                    total *
                    100
                ).toFixed(1)
            )
            : 0;


    /*
    ==========================================
    HIGH-RISK UNASSIGNED
    ==========================================
    */

    const findings = [];


    if (
        workState.highRiskUnassigned > 0
    ) {

        findings.push({

            type:
                "high_risk_unassigned",

            severity:
                workState.highRiskUnassigned >= 5
                    ? "high"
                    : "medium",

            title:
                "High-risk Cyera alerts remain unassigned",

            description:
                `${workState.highRiskUnassigned} high or critical Cyera alerts are open without an assigned analyst.`,

            evidence: {

                count:
                    workState.highRiskUnassigned,

                critical:
                    alerts.filter(alert =>
                        normalizeStatus(
                            alert.current_status
                        ) === "open" &&
                        ["critical"].includes(
                            String(
                                alert.current_severity || ""
                            ).toLowerCase()
                        ) &&
                        !alert.current_assigned_user
                    ).length,

                high:
                    alerts.filter(alert =>
                        normalizeStatus(
                            alert.current_status
                        ) === "open" &&
                        ["high"].includes(
                            String(
                                alert.current_severity || ""
                            ).toLowerCase()
                        ) &&
                        !alert.current_assigned_user
                    ).length

            },

            recommendedAction:
                "Prioritize assignment of open high and critical Cyera alerts to an appropriate security analyst."

        });

    }


    /*
    ==========================================
    HIGH-RISK ASSIGNED
    ==========================================
    */

    if (
        workState.highRiskAssigned > 0
    ) {

        findings.push({

            type:
                "high_risk_assigned",

            severity:
                "medium",

            title:
                "High-risk Cyera alerts are assigned",

            description:
                `${workState.highRiskAssigned} high or critical Cyera alerts are open and assigned to analysts.`,

            evidence: {

                count:
                    workState.highRiskAssigned

            },

            recommendedAction:
                "Review assigned high-risk alerts for timely investigation and appropriate disposition."

        });

    }


    /*
    ==========================================
    ACTIVE INVESTIGATIONS
    ==========================================
    */

    if (
        workState.inProgress > 0
    ) {

        findings.push({

            type:
                "active_investigations",

            severity:
                "medium",

            title:
                "Cyera investigations are actively being worked",

            description:
                `${workState.inProgress} Cyera alerts are currently in an investigation or active-work state.`,

            evidence: {

                count:
                    workState.inProgress

            },

            recommendedAction:
                "Review active investigations to ensure they are progressing toward an appropriate disposition."

        });

    }


    /*
    ==========================================
    OPEN BACKLOG
    ==========================================
    */

    if (
        workState.openUnassigned > 0
    ) {

        findings.push({

            type:
                "open_backlog",

            severity:
                workState.openUnassigned >= 50
                    ? "medium"
                    : "low",

            title:
                "Open Cyera backlog remains",

            description:
                `${workState.openUnassigned} open Cyera alerts currently have no analyst assignment.`,

            evidence: {

                count:
                    workState.openUnassigned

            },

            recommendedAction:
                "Review the open backlog and determine which alerts require analyst assignment or disposition."

        });

    }


    /*
    ==========================================
    HANDLED CASES
    ==========================================
    */

    if (
        handled > 0
    ) {

        findings.push({

            type:
                "handled_cases",

            severity:
                "low",

            title:
                "Cyera alerts have reached a handled disposition",

            description:
                `${handled} of ${total} Cyera alerts (${handledRate}%) have reached risk acceptance, false positive, resolution, or closure.`,

            evidence: {

                handled,

                handledRate,

                total

            },

            recommendedAction:
                "Continue reviewing handled cases periodically to ensure dispositions remain appropriate."

        });

    }


    /*
    ==========================================
    ANALYST ACTIVITY SUMMARY
    ==========================================
    */

    const totalHandledActions =
        analystActivity.reduce(
            (sum, analyst) =>
                sum +
                analyst.handledActions,
            0
        );


    const totalAssignments =
        analystActivity.reduce(
            (sum, analyst) =>
                sum +
                analyst.assignmentActions,
            0
        );


    const totalInvestigations =
        analystActivity.reduce(
            (sum, analyst) =>
                sum +
                analyst.startedInvestigations,
            0
        );


    /*
    ==========================================
    RETURN
    ==========================================
    */

    return {

        reportId,

        totalAlerts:
            total,

        workState,

        severity,

        workload: {

            active:
                activeWork,

            handled,

            handledRate,

            unassigned,

            unassignedRate,

            highRiskOpen

        },

        analystActivity,

        analystActivitySummary: {

            analysts:
                analystActivity.length,

            totalHandledActions,

            totalAssignments,

            totalInvestigations

        },

        findings

    };
}

/*
====================================================
CYERA DISPOSITION INTELLIGENCE
====================================================
*/

async function buildCyeraDispositionIntelligence(env, reportId) {

    /*
    ------------------------------------------
    CURRENT DISPOSITION SUMMARY
    ------------------------------------------
    */

    const dispositionSummary = await env.DB
        .prepare(`
            SELECT

                COUNT(*) AS total,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'riskaccepted'
                ) AS risk_accepted,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'falsepositive'
                ) AS false_positive,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'resolved',
                        'closed'
                    )
                ) AS resolved_or_closed,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'inprogress',
                        'investigating',
                        'active'
                    )
                ) AS in_progress,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'open'
                ) AS open_count

            FROM alerts

            WHERE source = 'cyera'
        `)
        .first();


    /*
    ------------------------------------------
    HIGH / CRITICAL OUTCOMES
    ------------------------------------------
    */

    const highRiskOutcome = await env.DB
        .prepare(`
            SELECT

                COUNT(*) AS total,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'riskaccepted'
                ) AS risk_accepted,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'falsepositive'
                ) AS false_positive,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'resolved',
                        'closed'
                    )
                ) AS resolved_or_closed,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'inprogress',
                        'investigating',
                        'active'
                    )
                ) AS in_progress,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'open'
                ) AS open_count,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'open'
                    AND current_assigned_user IS NULL
                ) AS open_unassigned

            FROM alerts

            WHERE
                source = 'cyera'
                AND LOWER(current_severity) IN (
                    'critical',
                    'high'
                )
        `)
        .first();


    /*
    ------------------------------------------
    ANALYST DISPOSITION
    ------------------------------------------
    */

    const analystResult = await env.DB
        .prepare(`
            SELECT

                current_assigned_user AS analyst,

                COUNT(*) AS total_handled,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'riskaccepted'
                ) AS risk_accepted,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'falsepositive'
                ) AS false_positive,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'resolved',
                        'closed'
                    )
                ) AS resolved_or_closed,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'critical'
                ) AS critical_handled,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'high'
                ) AS high_handled,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'medium'
                ) AS medium_handled

            FROM alerts

            WHERE
                source = 'cyera'
                AND current_assigned_user IS NOT NULL
                AND LOWER(current_status) IN (
                    'riskaccepted',
                    'falsepositive',
                    'resolved',
                    'closed'
                )

            GROUP BY current_assigned_user

            ORDER BY total_handled DESC
        `)
        .all();


    /*
    ------------------------------------------
    IMPORTANT ALERT OUTCOMES BY ANALYST
    ------------------------------------------
    */

    const highRiskAnalystResult = await env.DB
        .prepare(`
            SELECT

                current_assigned_user AS analyst,

                COUNT(*) AS total_handled,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'critical'
                ) AS critical_handled,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'high'
                ) AS high_handled,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'riskaccepted'
                ) AS risk_accepted,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'falsepositive'
                ) AS false_positive,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'resolved',
                        'closed'
                    )
                ) AS resolved_or_closed

            FROM alerts

            WHERE
                source = 'cyera'
                AND current_assigned_user IS NOT NULL
                AND LOWER(current_severity) IN (
                    'critical',
                    'high'
                )
                AND LOWER(current_status) IN (
                    'riskaccepted',
                    'falsepositive',
                    'resolved',
                    'closed'
                )

            GROUP BY current_assigned_user

            ORDER BY
                critical_handled DESC,
                high_handled DESC,
                total_handled DESC
        `)
        .all();


    /*
    ------------------------------------------
    CURRENT IMPORTANT ALERTS
    ------------------------------------------
    */

    const importantAlertsResult = await env.DB
        .prepare(`
            SELECT

                external_alert_id AS alertId,

                name,

                current_severity AS severity,

                current_status AS status,

                current_assigned_user AS analyst,

                first_seen_at AS firstSeenAt,

                last_seen_at AS lastSeenAt,

                resolved_at AS resolvedAt

            FROM alerts

            WHERE
                source = 'cyera'
                AND LOWER(current_severity) IN (
                    'critical',
                    'high'
                )

            ORDER BY

                CASE LOWER(current_severity)
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    ELSE 3
                END,

                CASE LOWER(current_status)
                    WHEN 'open' THEN 1
                    WHEN 'inprogress' THEN 2
                    WHEN 'investigating' THEN 3
                    WHEN 'riskaccepted' THEN 4
                    WHEN 'falsepositive' THEN 5
                    WHEN 'resolved' THEN 6
                    WHEN 'closed' THEN 7
                    ELSE 8
                END,

                last_seen_at DESC

            LIMIT 20
        `)
        .all();


    const summary = dispositionSummary || {};
    const highRisk = highRiskOutcome || {};

    const analystActivity =
        analystResult?.results || [];

    const highRiskAnalysts =
        highRiskAnalystResult?.results || [];

    const importantAlerts =
        importantAlertsResult?.results || [];


    /*
    ------------------------------------------
    FINDINGS
    ------------------------------------------
    */

    const findings = [];


    /*
    HIGH / CRITICAL HANDLED
    */

    if (Number(highRisk.risk_accepted || 0) > 0) {

        findings.push({

            type: "high_risk_handled",

            severity: "info",

            title:
                "High and critical alerts have been reviewed",

            description:
                `${Number(highRisk.risk_accepted)} high or critical Cyera alerts were risk accepted after analyst review.`,

            evidence: {
                total: Number(highRisk.total || 0),
                riskAccepted:
                    Number(highRisk.risk_accepted || 0)
            },

            recommendedAction:
                "Review the recorded risk acceptance decisions periodically to ensure the accepted business risk remains valid."

        });
    }


    /*
    FALSE POSITIVE
    */

    if (Number(highRisk.false_positive || 0) > 0) {

        findings.push({

            type: "high_risk_false_positive",

            severity: "low",

            title:
                "High or critical alerts were determined to be false positives",

            description:
                `${Number(highRisk.false_positive)} high or critical Cyera alerts were closed as false positives.`,

            evidence: {
                count:
                    Number(highRisk.false_positive)
            },

            recommendedAction:
                "Review false-positive decisions periodically for detection tuning opportunities."

        });
    }


    /*
    ACTIVE HIGH / CRITICAL
    */

    const activeHighRisk =
        Number(highRisk.in_progress || 0) +
        Number(highRisk.open_count || 0);


    if (activeHighRisk > 0) {

        const unassigned =
            Number(highRisk.open_unassigned || 0);

        findings.push({

            type: "high_risk_active",

            severity:
                unassigned > 0
                    ? "high"
                    : "medium",

            title:
                unassigned > 0
                    ? "High-risk Cyera alerts require attention"
                    : "High-risk Cyera alerts are actively being worked",

            description:
                unassigned > 0
                    ? `${unassigned} high or critical Cyera alerts are open and unassigned.`
                    : `${activeHighRisk} high or critical Cyera alerts are currently active or under investigation.`,

            evidence: {
                active: activeHighRisk,
                unassigned
            },

            recommendedAction:
                unassigned > 0
                    ? "Assign the outstanding high or critical alerts for analyst review."
                    : "Continue monitoring the active high-risk investigations until an appropriate disposition is recorded."

        });
    }


    /*
    NOTHING ACTIVE
    */

    if (
        Number(highRisk.total || 0) > 0 &&
        activeHighRisk === 0
    ) {

        findings.push({

            type: "high_risk_backlog_clear",

            severity: "low",

            title:
                "No high or critical Cyera alerts remain active",

            description:
                `All ${Number(highRisk.total)} high or critical Cyera alerts currently have a recorded disposition.`,

            evidence: {
                total:
                    Number(highRisk.total),
                riskAccepted:
                    Number(highRisk.risk_accepted || 0),
                falsePositive:
                    Number(highRisk.false_positive || 0),
                resolvedOrClosed:
                    Number(highRisk.resolved_or_closed || 0)
            },

            recommendedAction:
                "No immediate high-risk backlog action is required. Continue monitoring new high and critical alerts."

        });
    }


    return {

        reportId,

        disposition: {

            total:
                Number(summary.total || 0),

            riskAccepted:
                Number(summary.risk_accepted || 0),

            falsePositive:
                Number(summary.false_positive || 0),

            resolvedOrClosed:
                Number(summary.resolved_or_closed || 0),

            inProgress:
                Number(summary.in_progress || 0),

            open:
                Number(summary.open_count || 0)

        },

        highRiskOutcome: {

            total:
                Number(highRisk.total || 0),

            riskAccepted:
                Number(highRisk.risk_accepted || 0),

            falsePositive:
                Number(highRisk.false_positive || 0),

            resolvedOrClosed:
                Number(highRisk.resolved_or_closed || 0),

            inProgress:
                Number(highRisk.in_progress || 0),

            open:
                Number(highRisk.open_count || 0),

            openUnassigned:
                Number(highRisk.open_unassigned || 0)

        },

        analystOutcomes:
            analystActivity.map(row => ({

                analyst:
                    row.analyst,

                totalHandled:
                    Number(row.total_handled || 0),

                riskAccepted:
                    Number(row.risk_accepted || 0),

                falsePositive:
                    Number(row.false_positive || 0),

                resolvedOrClosed:
                    Number(row.resolved_or_closed || 0),

                criticalHandled:
                    Number(row.critical_handled || 0),

                highHandled:
                    Number(row.high_handled || 0),

                mediumHandled:
                    Number(row.medium_handled || 0)

            })),

        highRiskAnalystOutcomes:
            highRiskAnalysts.map(row => ({

                analyst:
                    row.analyst,

                totalHandled:
                    Number(row.total_handled || 0),

                criticalHandled:
                    Number(row.critical_handled || 0),

                highHandled:
                    Number(row.high_handled || 0),

                riskAccepted:
                    Number(row.risk_accepted || 0),

                falsePositive:
                    Number(row.false_positive || 0),

                resolvedOrClosed:
                    Number(row.resolved_or_closed || 0)

            })),

        importantAlerts:
            importantAlerts.map(row => ({

                alertId:
                    row.alertId,

                name:
                    row.name,

                severity:
                    row.severity,

                status:
                    row.status,

                analyst:
                    row.analyst,

                firstSeenAt:
                    row.firstSeenAt,

                lastSeenAt:
                    row.lastSeenAt,

                resolvedAt:
                    row.resolvedAt

            })),

        findings

    };

}

async function getCyeraCurrentOperationalState(env) {

    const result = await env.DB
        .prepare(`
            SELECT
                COUNT(*) AS total,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'open'
                ) AS open,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'inprogress',
                        'investigating',
                        'active'
                    )
                ) AS in_progress,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'riskaccepted',
                        'falsepositive',
                        'resolved',
                        'closed'
                    )
                ) AS handled,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'open'
                    AND current_assigned_user IS NULL
                ) AS unassigned,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) IN (
                        'critical',
                        'high'
                    )
                    AND LOWER(current_status) IN (
                        'open',
                        'inprogress',
                        'investigating',
                        'active'
                    )
                ) AS high_risk_active,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) IN (
                        'critical',
                        'high'
                    )
                    AND LOWER(current_status) = 'open'
                    AND current_assigned_user IS NULL
                ) AS high_risk_unassigned

            FROM alerts

            WHERE source = 'cyera'
        `)
        .first();

    return {
        total: Number(result?.total || 0),
        open: Number(result?.open || 0),
        inProgress: Number(result?.in_progress || 0),
        handled: Number(result?.handled || 0),
        unassigned: Number(result?.unassigned || 0),
        highRiskActive: Number(result?.high_risk_active || 0),
        highRiskUnassigned: Number(result?.high_risk_unassigned || 0)
    };
}

async function getCyeraAnalystActions(env) {

    const result = await env.DB
        .prepare(`
            WITH ordered_history AS (

                SELECT
                    h.alert_id,
                    h.observed_at,
                    LOWER(h.status) AS status,
                    h.assigned_user,

                    LAG(LOWER(h.status)) OVER (
                        PARTITION BY h.alert_id
                        ORDER BY h.observed_at, h.report_id
                    ) AS previous_status,

                    LAG(h.assigned_user) OVER (
                        PARTITION BY h.alert_id
                        ORDER BY h.observed_at, h.report_id
                    ) AS previous_assigned_user

                FROM alert_history h

                JOIN alerts a
                    ON a.id = h.alert_id

                WHERE a.source = 'cyera'
            )

            SELECT

                assigned_user AS analyst,

                COUNT(*) FILTER (
                    WHERE status = 'riskaccepted'
                    AND COALESCE(previous_status, '') <> 'riskaccepted'
                ) AS risk_accepted_actions,

                COUNT(*) FILTER (
                    WHERE status = 'falsepositive'
                    AND COALESCE(previous_status, '') <> 'falsepositive'
                ) AS false_positive_actions,

                COUNT(*) FILTER (
                    WHERE status IN (
                        'inprogress',
                        'investigating',
                        'active'
                    )
                    AND COALESCE(previous_status, '') NOT IN (
                        'inprogress',
                        'investigating',
                        'active'
                    )
                ) AS investigation_started,

                COUNT(*) FILTER (
                    WHERE assigned_user IS NOT NULL
                    AND (
                        previous_assigned_user IS NULL
                        OR previous_assigned_user <> assigned_user
                    )
                ) AS assignment_actions,

                COUNT(*) FILTER (
                    WHERE status IN (
                        'riskaccepted',
                        'falsepositive',
                        'resolved',
                        'closed'
                    )
                    AND COALESCE(previous_status, '') NOT IN (
                        'riskaccepted',
                        'falsepositive',
                        'resolved',
                        'closed'
                    )
                ) AS handled_actions

            FROM ordered_history

            WHERE assigned_user IS NOT NULL

            GROUP BY assigned_user

            ORDER BY handled_actions DESC, analyst
        `)
        .all();

    return (result?.results || []).map(row => ({
        analyst: row.analyst,

        riskAcceptedActions:
            Number(row.risk_accepted_actions || 0),

        falsePositiveActions:
            Number(row.false_positive_actions || 0),

        startedInvestigations:
            Number(row.investigation_started || 0),

        assignmentActions:
            Number(row.assignment_actions || 0),

        handledActions:
            Number(row.handled_actions || 0)
    }));
}
async function getCyeraHighRiskOutcomes(env) {

    const result = await env.DB
        .prepare(`
            SELECT

                COUNT(*) AS total,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'riskaccepted'
                ) AS risk_accepted,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'falsepositive'
                ) AS false_positive,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'resolved',
                        'closed'
                    )
                ) AS resolved_or_closed,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) IN (
                        'inprogress',
                        'investigating',
                        'active'
                    )
                ) AS in_progress,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'open'
                ) AS open,

                COUNT(*) FILTER (
                    WHERE LOWER(current_status) = 'open'
                    AND current_assigned_user IS NULL
                ) AS open_unassigned,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'critical'
                ) AS critical,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'high'
                ) AS high,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'critical'
                    AND LOWER(current_status) = 'riskaccepted'
                ) AS critical_risk_accepted,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) = 'high'
                    AND LOWER(current_status) = 'riskaccepted'
                ) AS high_risk_accepted,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) IN (
                        'critical',
                        'high'
                    )
                    AND LOWER(current_status) IN (
                        'inprogress',
                        'investigating',
                        'active'
                    )
                ) AS high_risk_in_progress,

                COUNT(*) FILTER (
                    WHERE LOWER(current_severity) IN (
                        'critical',
                        'high'
                    )
                    AND LOWER(current_status) = 'open'
                    AND current_assigned_user IS NULL
                ) AS high_risk_open_unassigned

            FROM alerts

            WHERE source = 'cyera'

            AND LOWER(current_severity) IN (
                'critical',
                'high'
            )
        `)
        .first();

    return {
        total: Number(result?.total || 0),

        riskAccepted:
            Number(result?.risk_accepted || 0),

        falsePositive:
            Number(result?.false_positive || 0),

        resolvedOrClosed:
            Number(result?.resolved_or_closed || 0),

        inProgress:
            Number(result?.in_progress || 0),

        open:
            Number(result?.open || 0),

        openUnassigned:
            Number(result?.open_unassigned || 0),

        critical:
            Number(result?.critical || 0),

        high:
            Number(result?.high || 0),

        criticalRiskAccepted:
            Number(result?.critical_risk_accepted || 0),

        highRiskAccepted:
            Number(result?.high_risk_accepted || 0),

        highRiskInProgress:
            Number(result?.high_risk_in_progress || 0),

        highRiskOpenUnassigned:
            Number(result?.high_risk_open_unassigned || 0)
    };
}
async function getCyeraImportantAlerts(env) {

    const result = await env.DB
        .prepare(`
            SELECT

                external_alert_id AS alert_id,

                name,

                LOWER(current_severity) AS severity,

                LOWER(current_status) AS status,

                current_assigned_user AS analyst,

                first_seen_at,

                last_seen_at,

                resolved_at

            FROM alerts

            WHERE source = 'cyera'

            AND LOWER(current_severity) IN (
                'critical',
                'high'
            )

            ORDER BY

                CASE LOWER(current_severity)
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    ELSE 3
                END,

                CASE LOWER(current_status)
                    WHEN 'open' THEN 1
                    WHEN 'inprogress' THEN 2
                    WHEN 'investigating' THEN 3
                    WHEN 'active' THEN 4
                    WHEN 'riskaccepted' THEN 5
                    WHEN 'falsepositive' THEN 6
                    WHEN 'resolved' THEN 7
                    WHEN 'closed' THEN 8
                    ELSE 9
                END,

                first_seen_at ASC
        `)
        .all();

    return (result?.results || []).map(row => ({
        alertId: row.alert_id,
        name: row.name,
        severity: row.severity,
        status: row.status,
        analyst: row.analyst,
        firstSeenAt: row.first_seen_at,
        lastSeenAt: row.last_seen_at,
        resolvedAt: row.resolved_at
    }));
}
function buildCyeraOperationalFindings(
    current,
    highRisk
) {

    const findings = [];

    /*
    ==========================================
    HIGH / CRITICAL UNASSIGNED
    ==========================================
    */

    if (highRisk.highRiskOpenUnassigned > 0) {

        findings.push({
            type: "high_risk_unassigned",
            severity: "critical",

            title:
                "High-risk alerts require analyst assignment",

            description:
                `${highRisk.highRiskOpenUnassigned} high or critical Cyera alerts are open and unassigned.`,

            evidence: {
                count: highRisk.highRiskOpenUnassigned
            },

            recommendedAction:
                "Assign these alerts for immediate analyst review."
        });
    }


    /*
    ==========================================
    HIGH / CRITICAL IN PROGRESS
    ==========================================
    */

    if (highRisk.highRiskInProgress > 0) {

        findings.push({
            type: "high_risk_active",
            severity: "medium",

            title:
                "High-risk alerts are actively being worked",

            description:
                `${highRisk.highRiskInProgress} high or critical Cyera alerts are currently in progress or under investigation.`,

            evidence: {
                active: highRisk.highRiskInProgress
            },

            recommendedAction:
                "Continue monitoring these investigations until an appropriate disposition is recorded."
        });
    }


    /*
    ==========================================
    HIGH / CRITICAL HANDLED
    ==========================================
    */

    const handledHighRisk =
        highRisk.riskAccepted +
        highRisk.falsePositive +
        highRisk.resolvedOrClosed;

    if (handledHighRisk > 0) {

        findings.push({
            type: "high_risk_handled",
            severity: "info",

            title:
                "High and critical alerts have been reviewed",

            description:
                `${handledHighRisk} of ${highRisk.total} high or critical Cyera alerts have reached a handled disposition.`,

            evidence: {
                total: highRisk.total,
                riskAccepted: highRisk.riskAccepted,
                falsePositive: highRisk.falsePositive,
                resolvedOrClosed: highRisk.resolvedOrClosed
            },

            recommendedAction:
                "Review recorded dispositions periodically to ensure the accepted or resolved business risk remains appropriate."
        });
    }


    /*
    ==========================================
    CRITICAL SPECIFICALLY
    ==========================================
    */

    if (
        highRisk.critical > 0 &&
        highRisk.criticalRiskAccepted === highRisk.critical
    ) {

        findings.push({
            type: "critical_all_handled",
            severity: "info",

            title:
                "All critical Cyera alerts have been reviewed",

            description:
                `All ${highRisk.critical} critical Cyera alerts have been risk accepted by analysts. No critical alerts remain open.`,

            evidence: {
                critical: highRisk.critical,
                riskAccepted: highRisk.criticalRiskAccepted
            },

            recommendedAction:
                "Periodically validate that the recorded risk acceptance decisions remain appropriate."
        });
    }


    /*
    ==========================================
    GENERAL OPEN BACKLOG
    ==========================================
    */

    if (current.unassigned > 0) {

        findings.push({
            type: "open_backlog",
            severity: "medium",

            title:
                "Cyera open backlog remains",

            description:
                `${current.unassigned} open Cyera alerts currently have no analyst assignment.`,

            evidence: {
                count: current.unassigned
            },

            recommendedAction:
                "Review the backlog and determine which alerts require assignment or disposition."
        });
    }


    /*
    ==========================================
    NOTHING CRITICAL
    ==========================================
    */

    if (
        highRisk.highRiskOpenUnassigned === 0 &&
        highRisk.highRiskInProgress === 0 &&
        highRisk.critical > 0
    ) {

        findings.push({
            type: "high_risk_under_control",
            severity: "info",

            title:
                "No high-risk Cyera alerts require immediate assignment",

            description:
                "All currently identified high and critical Cyera alerts are assigned and have reached an appropriate disposition.",

            evidence: {
                highRisk: highRisk.total,
                openUnassigned: highRisk.highRiskOpenUnassigned,
                inProgress: highRisk.highRiskInProgress
            },

            recommendedAction:
                "Continue periodic review of high-risk dispositions."
        });
    }


    return findings;
}

async function getCyeraOperationalIntelligence(
    env,
    reportId
) {

    const current =
        await getCyeraCurrentOperationalState(env);

    const analystActivity =
        await getCyeraAnalystActions(env);

    const highRisk =
        await getCyeraHighRiskOutcomes(env);

    const importantAlerts =
        await getCyeraImportantAlerts(env);

    const findings =
        buildCyeraOperationalFindings(
            current,
            highRisk
        );

    const handledRate =
        current.total > 0
            ? Number(
                (
                    current.handled /
                    current.total *
                    100
                ).toFixed(1)
            )
            : 0;

    const unassignedRate =
        current.total > 0
            ? Number(
                (
                    current.unassigned /
                    current.total *
                    100
                ).toFixed(1)
            )
            : 0;

    return {

        reportId,

        currentState: {

            totalAlerts:
                current.total,

            open:
                current.open,

            inProgress:
                current.inProgress,

            handled:
                current.handled,

            unassigned:
                current.unassigned,

            handledRate,

            unassignedRate,

            highRiskActive:
                current.highRiskActive,

            highRiskUnassigned:
                current.highRiskUnassigned
        },

        highRiskOutcome: {

            total:
                highRisk.total,

            critical:
                highRisk.critical,

            high:
                highRisk.high,

            riskAccepted:
                highRisk.riskAccepted,

            falsePositive:
                highRisk.falsePositive,

            resolvedOrClosed:
                highRisk.resolvedOrClosed,

            inProgress:
                highRisk.inProgress,

            open:
                highRisk.open,

            openUnassigned:
                highRisk.openUnassigned
        },

        analystActivity,

        analystActivitySummary: {

            analysts:
                analystActivity.length,

            totalHandledActions:
                analystActivity.reduce(
                    (sum, analyst) =>
                        sum + analyst.handledActions,
                    0
                ),

            totalAssignments:
                analystActivity.reduce(
                    (sum, analyst) =>
                        sum + analyst.assignmentActions,
                    0
                ),

            totalInvestigations:
                analystActivity.reduce(
                    (sum, analyst) =>
                        sum + analyst.startedInvestigations,
                    0
                )
        },

        importantAlerts,

        findings
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
CASE OUTCOME & DISPOSITION INTELLIGENCE
==========================================
*/

    const caseOutcome =
        await calculateCaseOutcomeIntelligence(
            env,
            reportId
        );

    const riskAcceptance = await calculateRiskAcceptanceIntelligence(env);

    const cyeraWorkIntelligence =
        await calculateCyeraWorkIntelligence(
            env,
            reportId
        );

    const cyeraDispositionIntelligence =
    await buildCyeraDispositionIntelligence(
        env,
        reportId
    );
    const cyeraOperationalIntelligence =
    await getCyeraOperationalIntelligence(
        env,
        reportId
    );

    /*
==========================================
CASE OUTCOME INSIGHTS
==========================================
*/

    for (
        const finding of caseOutcome.findings
    ) {

        insights.push({

            type:
                finding.type,

            priority:
                finding.severity,

            metric:
                finding.evidence?.total ||
                finding.evidence?.activeCases ||
                finding.evidence?.riskAccepted ||
                0,

            message:
                finding.description

        });

    }

    /*
    ==========================================
    CYERA WORK INTELLIGENCE INSIGHTS
    ==========================================
    */

    for (
        const finding of cyeraWorkIntelligence.findings
    ) {

        insights.push({

            type:
                finding.type,

            priority:
                finding.severity,

            metric:
                finding.evidence?.count ||
                finding.evidence?.handled ||
                0,

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
        caseOutcome,
        riskAcceptance,
        cyeraWorkIntelligence,
        cyeraDispositionIntelligence,
        cyeraOperationalIntelligence,
        prioritization: {

            summary:
                prioritySummary,

            alerts:
                prioritizedAlerts

        },
        insights

    };

}