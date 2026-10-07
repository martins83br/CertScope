from __future__ import annotations

from app.core.assessment import (
    assess_scan,
)
from app.core.intelligence import (
    build_certificate_story,
    compare_scans,
)
from app.core.pki_intelligence import (
    build_pki_intelligence,
)
from app.core.scanner import (
    scan_certificate,
)
from app.core.timeline import (
    build_ca_timeline,
    build_lifecycle,
)
from app.core.risk_intelligence import (
    build_risk_intelligence,
)
from app.services.history import (
    get_previous_scan,
    save_scan,
)


def execute_scan(
    target: str,
) -> tuple[dict, object]:
    result = scan_certificate(
        target
    )

    result["assessment"] = (
        assess_scan(
            result
        )
    )

    previous = get_previous_scan(
        result["target"]
    )

    comparison = compare_scans(
        previous,
        result,
    )

    result["comparison"] = (
        comparison
    )

    result["story"] = (
        build_certificate_story(
            previous,
            result,
            comparison,
        )
    )

    result["risk_intelligence"] = (
        build_risk_intelligence(
            previous,
            result,
        )
    )

    result["pki"] = (
        build_pki_intelligence(
            result["target"],
            result["port"],
        )
    )

    result["lifecycle"] = (
        build_lifecycle(
            result
        )
    )

    result["ca_timeline"] = (
        build_ca_timeline(
            result["pki"]["ct"]
        )
    )

    scan_path = save_scan(
        result
    )

    return (
        result,
        scan_path,
    )
