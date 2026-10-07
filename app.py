from __future__ import annotations

from pathlib import Path

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from app.core.assessment import assess_scan
from app.core.intelligence import (
    build_certificate_story,
    compare_scans,
)
from app.core.pki_intelligence import (
    build_pki_intelligence,
)
from app.core.scanner import scan_certificate
from app.core.compare import compare_snapshots
from app.core.timeline import (
    build_ca_timeline,
    build_lifecycle,
)
from app.services.history import (
    get_previous_scan,
    list_scans,
    load_scan,
    save_scan,
)
from app.services.scan_service import execute_scan
from app.services.watchlist import (
    add_target,
    load_watchlist,
    remove_target,
)
from app.core.dashboard import (
    build_asset,
    build_dashboard,
)
from app.core.event_feed import (
    build_event_feed,
    event_counts,
)
from app.services.pdf_report import generate_pdf
from app.services.evidence import (
    write_evidence_package,
)


app = Flask(
    __name__,
    template_folder="app/templates",
    static_folder="app/static",
)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/scan")
def scan():
    target = request.form.get(
        "target",
        "",
    ).strip()

    try:
        result, scan_path = execute_scan(
            target
        )

        return render_template(
            "index.html",
            result=result,
            report_id=scan_path.stem,
        )

    except Exception as exc:
        return render_template(
            "index.html",
            error=(
                "Unable to analyze target: "
                f"{exc}"
            ),
        ), 400




@app.get("/dashboard")
def dashboard():
    watchlist = load_watchlist()
    scans = list_scans()

    data = build_dashboard(
        watchlist,
        scans,
    )

    feed = build_event_feed(
        scans,
        limit=20,
    )

    return render_template(
        "dashboard.html",
        dashboard=data,
        event_feed=feed,
        event_counts=event_counts(
            feed
        ),
        message=request.args.get(
            "message"
        ),
    )


@app.post("/watchlist/add")
def watchlist_add():
    target = request.form.get(
        "target",
        "",
    ).strip()

    try:
        item = add_target(
            target
        )

        message = (
            f"{item['target']} added "
            "to the watchlist."
        )

    except Exception as exc:
        message = (
            f"Unable to add target: {exc}"
        )

    return redirect(
        url_for(
            "dashboard",
            message=message,
        )
    )


@app.post("/watchlist/remove")
def watchlist_remove():
    target = request.form.get(
        "target",
        "",
    ).strip()

    try:
        remove_target(
            target
        )

        message = (
            f"{target} removed "
            "from the watchlist."
        )

    except Exception as exc:
        message = (
            f"Unable to remove target: {exc}"
        )

    return redirect(
        url_for(
            "dashboard",
            message=message,
        )
    )


@app.post("/watchlist/scan/<target>")
def watchlist_scan(target: str):
    try:
        add_target(
            target
        )

        execute_scan(
            target
        )

        message = (
            f"{target} scanned successfully."
        )

    except Exception as exc:
        message = (
            f"Scan failed for "
            f"{target}: {exc}"
        )

    return redirect(
        url_for(
            "dashboard",
            message=message,
        )
    )


@app.post("/watchlist/scan-all")
def watchlist_scan_all():
    watchlist = load_watchlist()

    success = 0
    failures = []

    for item in watchlist:
        target = item.get(
            "target"
        )

        if not target:
            continue

        try:
            execute_scan(
                target
            )

            success += 1

        except Exception as exc:
            failures.append(
                f"{target}: {exc}"
            )

    message = (
        f"Scan All completed: "
        f"{success} successful, "
        f"{len(failures)} failed."
    )

    if failures:
        message += (
            " Failed: "
            + " | ".join(
                failures
            )
        )

    return redirect(
        url_for(
            "dashboard",
            message=message,
        )
    )


@app.get("/target/<target>")
def target_detail(target: str):
    watchlist = load_watchlist()
    scans = list_scans(
        target
    )

    asset = build_asset(
        target,
        list_scans(),
    )

    return render_template(
        "target.html",
        target=target,
        asset=asset,
        records=scans,
        watched=any(
            item.get("target")
            == target
            for item in watchlist
        ),
    )


@app.get("/history")
def history():
    records = list_scans()

    return render_template(
        "history.html",
        records=records,
    )


@app.get("/history/<scan_id>")
def history_detail(scan_id: str):
    result = load_scan(scan_id)

    if not result:
        abort(404)

    return render_template(
        "index.html",
        result=result,
        report_id=scan_id,
        historical=True,
    )



@app.get("/compare")
def compare():
    records = list_scans()

    before_id = request.args.get(
        "before",
        "",
    )

    after_id = request.args.get(
        "after",
        "",
    )

    comparison = None
    before = None
    after = None

    if before_id and after_id:
        before = load_scan(
            before_id
        )

        after = load_scan(
            after_id
        )

        if not before or not after:
            abort(404)

        comparison = compare_snapshots(
            before,
            after,
        )

    return render_template(
        "compare.html",
        records=records,
        before_id=before_id,
        after_id=after_id,
        before=before,
        after=after,
        comparison=comparison,
    )



@app.get("/evidence/<report_id>")
def evidence(report_id: str):
    result = load_scan(
        report_id
    )

    if not result:
        abort(404)

    evidence_path = write_evidence_package(
        result,
        report_id,
    )

    return send_file(
        evidence_path,
        as_attachment=True,
        download_name=evidence_path.name,
        mimetype="application/json",
    )


@app.get("/report/<report_id>")
def report(report_id: str):
    result = load_scan(report_id)

    if not result:
        abort(404)

    pdf_path = generate_pdf(
        result,
        report_id=report_id,
    )

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=pdf_path.name,
        mimetype="application/pdf",
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5050,
        debug=False,
    )
