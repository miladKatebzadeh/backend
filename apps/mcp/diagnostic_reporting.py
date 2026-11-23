"""User-facing Incident reports and safe Ollama diagnostics.

Monitoring evidence is authoritative about observed failures, while model
hypotheses are only suggestions. A missing LLM must never erase an Incident.
"""
import json

from apps.mcp.trace_presentation import safe_text


ACTIVE_STATUSES = {
    "open", "acknowledged", "investigating", "exited", "dead", "firing",
    "critical", "warning", "failure", "failed", "unstable", "aborted",
}


def observed_incident(context):
    alert = (context or {}).get("alert") or {}
    return (
        bool(alert.get("source") and alert.get("resource"))
        and str(alert.get("status") or "").lower() in ACTIVE_STATUSES
    )


def ollama_error_details(exc, model):
    """Keep useful provider diagnostics without exposing raw request/stack/keys."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        status = None

    error_type = exc.__class__.__name__
    if status == 404:
        category = "not_found"
        hint = "نام مدل نصب‌شده و آدرس API سرویس Ollama را بررسی کنید."
    elif status in (401, 403):
        category = "unauthorized"
        hint = "مجوز و تنظیمات اتصال به Ollama را بررسی کنید."
    elif status == 400:
        category = "invalid_request"
        hint = "مدل انتخابی، قالب JSON و پارامترهای درخواست را بررسی کنید."
    elif status == 429:
        category = "capacity"
        hint = "ظرفیت سرویس و محدودیت هم‌زمانی درخواست‌ها را بررسی کنید."
    elif status in (408, 504) or "timeout" in error_type.lower():
        category = "timeout"
        hint = "مدت پاسخ‌گویی مدل، بار سرویس و تنظیمات Timeout را بررسی کنید."
    elif status is not None and status >= 500:
        category = "server_error"
        hint = "لاگ سرویس Ollama، منابع RAM/GPU و وضعیت بارگذاری مدل را بررسی کنید."
    elif "connection" in error_type.lower() or "connect" in error_type.lower():
        category = "connection"
        hint = "دسترسی شبکه از داخل کانتینر Backend به آدرس Ollama را بررسی کنید."
    else:
        category = "unknown"
        hint = "وضعیت سرویس، مدل انتخاب‌شده و لاگ Ollama را بررسی کنید."

    # The SDK may include a provider response body. Truncate and redact it;
    # never include raw exception repr, credentials, traceback or whole prompt.
    raw = getattr(exc, "error", None)
    if raw is None and status is not None:
        raw = str(exc)
    if raw is None:
        raw = error_type
    return {
        "error_type": safe_text(error_type, 80),
        "http_status": status,
        "category": category,
        "message": safe_text(raw, 280),
        "model": safe_text(model, 110),
        "hint": hint,
    }


def offline_diagnosis(context, error):
    """Backward-compatible JSON reply with monitoring truth, not a false negative."""
    alert = (context or {}).get("alert") or {}
    confirmed = observed_incident(context)
    resource = safe_text(alert.get("resource") or "سیستم", 100)
    source = safe_text(alert.get("source") or "پایش", 80)
    report = (
        f"خرابی {resource} در {source} توسط سامانه پایش ثبت شده است. "
        "مدل هوش مصنوعی در حال حاضر پاسخ نداده و علت ریشه‌ای هنوز تأیید نشده است. "
        "برای ادامه بررسی، شواهد ثبت‌شده و لاگ مربوط به همان منبع را بررسی کنید."
        if confirmed
        else "پاسخ هوش مصنوعی دریافت نشد. بدون شواهد مستقل نمی‌توان وضعیت سیستم یا علت مشکل را تأیید کرد."
    )
    return json.dumps({
        "incident_detected": confirmed,
        "error_scope": safe_text(alert.get("family") or "engine", 100),
        "engine_status": "offline",
        "diagnostic_report": report,
        "evidence_refs": [
            safe_text(item.get("source"), 80)
            for item in ((context or {}).get("errors") or [])[:4]
            if isinstance(item, dict) and item.get("source")
        ],
        "ollama_error": error,
        "tool_name": "",
        "tool_target": "",
    }, ensure_ascii=False)


def _list_of_text(value, limit=4, max_chars=230):
    if not isinstance(value, list):
        return []
    return [
        safe_text(item, max_chars) for item in value[:limit]
        if isinstance(item, str) and item.strip()
    ]


def _default_steps(source, status):
    if source == "jenkins":
        return (
            [
                "لاگ کامل همان Build را از Jenkins باز کنید و دستور شکست‌خورده و خطوط قبل از Exit Code را بررسی کنید.",
                "مرحله Pipeline، وابستگی‌ها و تنظیمات محیط اجرای دستور ناموفق را کنترل کنید.",
            ],
            ["پس از رفع علت، یک Build جدید اجرا کنید و نتیجه SUCCESS را در Jenkins تأیید کنید."],
        )
    if source == "docker":
        return (
            [
                "لاگ‌ها و وضعیت Docker inspect همان کانتینر را بررسی کنید.",
                "کد خروج، OOMKilled و محدودیت حافظه را با شواهد واقعی مقایسه کنید.",
            ],
            ["پس از رفع علت، وضعیت running و پایداری کانتینر را دوباره تأیید کنید."],
        )
    if source in ("prometheus", "alertmanager"):
        return (
            [
                "Metric یا Alert مربوط به همان منبع را در بازه زمانی رخداد بررسی کنید.",
                "مقدارهای قبل و بعد از هشدار و تغییرات مرتبط سرویس را مقایسه کنید.",
            ],
            ["بازگشت Metric به محدوده طبیعی و پایان هشدار را از منبع پایش تأیید کنید."],
        )
    return (
        ["لاگ‌ها و شواهد منبع در بازه زمانی Incident را بررسی کنید."],
        ["پس از اصلاح، سلامت سرویس را با داده پایش مستقل تأیید کنید."],
    )


def readable_report(incident_context, reply_text, engine_status, agent=None, retrieval=None, error=None):
    """Create a Persian, evidence-first report for every diagnostic outcome.

    AI text is marked as a model assessment. For offline/invalid responses the
    report relies only on verified monitoring observations.
    """
    context = incident_context or {}
    alert = context.get("alert") or {}
    errors = context.get("errors") or []
    source = str(alert.get("source") or "").lower()
    resource = safe_text(alert.get("resource") or "منبع نامشخص", 100)
    alert_text = safe_text(alert.get("message"), 360)
    status = str(alert.get("status") or "").lower()
    confirmed = observed_incident(context)
    model_ok = engine_status == "ok"
    try:
        parsed = json.loads(reply_text)
        if not isinstance(parsed, dict):
            parsed = {}
    except (TypeError, ValueError):
        parsed = {}
    model_report = parsed.get("user_report") if isinstance(parsed.get("user_report"), dict) else {}
    steps, verification = _default_steps(source, status)
    evidence = []
    for item in errors[:4]:
        if isinstance(item, dict) and item.get("message"):
            evidence.append({
                "text": safe_text(item["message"], 230),
                "source": safe_text(item.get("source") or "monitoring", 65),
                "type": "observed",
            })

    if confirmed:
        title = f"گزارش خرابی {source.upper()}: {resource}"
        summary = (
            f"سامانه پایش خرابی {resource} را ثبت کرده است."
            + (f" هشدار: {alert_text}" if alert_text else "")
        )
    elif alert_text:
        title = f"گزارش بررسی: {resource}"
        summary = f"درخواست یا هشدار دریافت شد: {alert_text}"
    else:
        title = "گزارش بررسی زیرساخت"
        summary = "درخواست برای تحلیل وضعیت سیستم دریافت شد."

    root_cause = "علت اصلی هنوز با شواهد موجود تأیید نشده است."
    if model_ok:
        model_summary = model_report.get("summary") or parsed.get("diagnostic_report")
        if isinstance(model_summary, str) and model_summary.strip():
            summary = safe_text(model_summary, 1050)
        suggested_cause = model_report.get("likely_cause")
        if isinstance(suggested_cause, str) and suggested_cause.strip() and suggested_cause.strip().lower() not in ("unknown", "n/a", "none", "نامشخص"):
            root_cause = "ارزیابی پیشنهادی AI (هنوز نیازمند تأیید): " + safe_text(suggested_cause, 430)
        proposed_steps = _list_of_text(model_report.get("recommended_steps"), limit=5)
        proposed_checks = _list_of_text(model_report.get("verification_steps"), limit=4)
        if proposed_steps:
            steps = proposed_steps
        if proposed_checks:
            verification = proposed_checks
        report_status = "ai_assessment"
        ai_note = "تحلیل AI موجود است، اما علت ریشه‌ای و رفع مشکل بدون بررسی شواهد تأییدشده نیست."
    else:
        report_status = "ai_unavailable" if engine_status == "offline" else "ai_unusable"
        ai_note = (
            "موتور هوش مصنوعی پاسخ نداد؛ گزارش فقط بر پایه شواهد Monitoring تهیه شده است."
            if engine_status == "offline"
            else "پاسخ مدل قابل اعتبارسنجی نبود؛ نتیجه تشخیص AI در این گزارش استفاده نشده است."
        )
        steps = list(steps) + [
            "اتصال، نام مدل و لاگ‌های سرویس Ollama را بررسی کنید."
        ]
    if not evidence:
        ai_note += " شواهد خطای مستقلی علاوه بر Alert در دسترس نیست."

    agent = agent or {}
    executed = bool(agent.get("agent_triggered"))
    verified = executed and bool(agent.get("resolved"))
    if verified:
        action = "ابزار اجرا شد و بازیابی منبع به‌طور مستقل تأیید شده است."
    elif executed:
        action = "ابزار اجرا شده است؛ رفع کامل مشکل تأیید نشده است."
    else:
        action = "هیچ ابزار اصلاحی اجرا نشده است."

    matched = (retrieval or {}).get("results") or []
    return {
        "language": "fa",
        "status": report_status,
        "title": title,
        "incident_confirmed": confirmed,
        "summary": summary,
        "root_cause": root_cause,
        "evidence": evidence,
        "recommended_steps": steps,
        "verification_steps": verification,
        "ai_status": engine_status,
        "ai_note": ai_note,
        "runbook_count": len(matched),
        "action": action,
        "recovery_verified": verified,
        "source": "ai_and_monitoring" if model_ok else "monitoring_only",
    }
