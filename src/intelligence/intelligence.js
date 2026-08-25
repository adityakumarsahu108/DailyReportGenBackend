/*
==========================================
SECURITY INTELLIGENCE ENGINE
==========================================

Phase 1:
Basic Security Intelligence Summary

Purpose:
Convert existing D1 alert data into a
structured security summary.

No AI.
No scoring.
No anomaly detection.
No recommendations yet.
==========================================
*/


/*
==========================================
GENERATE SECURITY INTELLIGENCE
==========================================
*/

export async function generateSecurityIntelligence(env) {

    /*
    --------------------------------------
    TOTAL ALERTS
    --------------------------------------
    */

    const totals =
        await env.DB
            .prepare(`
                SELECT
                    COUNT(*) AS total
                FROM alerts
            `)
            .first();


    /*
    --------------------------------------
    SEVERITY
    --------------------------------------
    */

    const severityRows =
        await env.DB
            .prepare(`
                SELECT
                    LOWER(
                        COALESCE(
                            current_severity,
                            'unknown'
                        )
                    ) AS severity,
                    COUNT(*) AS count
                FROM alerts
                GROUP BY
                    LOWER(
                        COALESCE(
                            current_severity,
                            'unknown'
                        )
                    )
            `)
            .all();


    /*
    --------------------------------------
    STATUS
    --------------------------------------
    */

    const statusRows =
        await env.DB
            .prepare(`
                SELECT
                    LOWER(
                        COALESCE(
                            current_status,
                            'unknown'
                        )
                    ) AS status,
                    COUNT(*) AS count
                FROM alerts
                GROUP BY
                    LOWER(
                        COALESCE(
                            current_status,
                            'unknown'
                        )
                    )
            `)
            .all();


    /*
    --------------------------------------
    UNASSIGNED
    --------------------------------------

    Important:
    This refers to the analyst assigned
    to the alert.

    It does NOT refer to the user involved
    in the security event.
    --------------------------------------
    */

    const unassigned =
        await env.DB
            .prepare(`
                SELECT
                    COUNT(*) AS count
                FROM alerts
                WHERE
                    current_assigned_user IS NULL
                    OR
                    TRIM(current_assigned_user) = ''
            `)
            .first();


    /*
    --------------------------------------
    BUILD SEVERITY OBJECT
    --------------------------------------
    */

    const severity = {

        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0

    };


    for (
        const row
        of severityRows.results || []
    ) {

        const key =
            String(
                row.severity
            ).toLowerCase();


        if (
            Object.prototype.hasOwnProperty
                .call(
                    severity,
                    key
                )
        ) {

            severity[key] =
                Number(
                    row.count
                );

        }

    }


    /*
    --------------------------------------
    BUILD STATUS OBJECT
    --------------------------------------
    */

    const status = {

        open: 0,
        active: 0,
        investigating: 0,
        resolved: 0,
        closed: 0,
        unknown: 0

    };


    for (
        const row
        of statusRows.results || []
    ) {

        const key =
            String(
                row.status
            ).toLowerCase();


        if (
            Object.prototype.hasOwnProperty
                .call(
                    status,
                    key
                )
        ) {

            status[key] =
                Number(
                    row.count
                );

        }

    }


    /*
    --------------------------------------
    RETURN INTELLIGENCE
    --------------------------------------
    */

    return {

        generatedAt:
            new Date().toISOString(),

        alerts: {

            total:
                Number(
                    totals?.total || 0
                ),

            unassigned:
                Number(
                    unassigned?.count || 0
                ),

            severity,

            status

        }

    };

}