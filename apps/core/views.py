import json

from django.db.utils import OperationalError, ProgrammingError
from django.http import JsonResponse

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.mcp.models import get_setting, set_setting


def health(request):
    from django.db import connection
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        database = 'ok'
    except Exception:
        database = 'degraded'
    return JsonResponse({'status': 'ok', 'database': database, 'service': 'opshub-api'})


def process_metric_smart(metric_name, raw_value):
    try:
        val = float(raw_value)
    except (ValueError, TypeError):
        return str(raw_value), 20, 'Metric / Trace'

    if 'bytes' in metric_name or 'size' in metric_name:
        if val > (1024 ** 4):
            display_val = f'{val / (1024 ** 4):.2f} TB'
        elif val > (1024 ** 3):
            display_val = f'{val / (1024 ** 3):.2f} GB'
        else:
            display_val = f'{val / (1024 ** 2):.1f} MB'
        if 'MemAvailable' in metric_name:
            percent = int((val / (8 * 1024 ** 3)) * 100)
            description = 'MEMORY / available'
        elif 'free' in metric_name or 'avail' in metric_name:
            percent = int((val / (256 * 1024 ** 3)) * 100)
            description = 'STORAGE / available'
        else:
            percent = 50
            description = 'CAPACITY / raw bytes'
        return display_val, max(10, min(100, percent)), description

    if 'seconds' in metric_name or 'time' in metric_name:
        if 'cpu' in metric_name:
            percent = int(val) % 100 if val > 0 else 0
            return f'{val:.1f}s', max(15, percent), 'CPU / aggregate active time'
        return f'{val:.2f} s', 40, 'TIME / duration'

    if 'network' in metric_name or 'bytes_total' in metric_name:
        if val > (1024 ** 4):
            display_val = f'{val / (1024 ** 4):.2f} TB'
        else:
            display_val = f'{val / (1024 ** 3):.2f} GB'
        description = 'NETWORK / total received' if 'receive' in metric_name else 'NETWORK / traffic'
        return display_val, 35, description

    if val > 1_000_000:
        display_val = f'{val / 1_000_000:.1f}M'
    elif val > 1_000:
        display_val = f'{val / 1_000:.1f}K'
    else:
        display_val = str(int(val))
    return display_val, 60, 'SYSTEM / counter total'


def _selected_metrics(request):
    raw = request.GET.get('filtered_metrics')
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, str) and item][:50]


def _remember_watched(selected):
    if not selected:
        return
    try:
        current = json.loads(get_setting('watched_metrics', '[]') or '[]')
    except json.JSONDecodeError:
        current = []
    if not isinstance(current, list):
        current = []
    merged = []
    for name in [*selected, *current]:
        if isinstance(name, str) and name not in merged:
            merged.append(name)
    set_setting('watched_metrics', json.dumps(merged[:50]))


def infrastructure_telemetry(request):
    try:
        return JsonResponse(_telemetry_payload(request))
    except (OperationalError, ProgrammingError):
        return JsonResponse({'detail': 'Telemetry tables are missing. Run migrations in backend/.'}, status=500)


def _telemetry_payload(request):
    selected = _selected_metrics(request)
    _remember_watched(selected)

    latest_containers = {}
    for row in DockerMetric.objects.order_by('-id')[:500]:
        latest_containers.setdefault(row.container_name, row)
    containers = list(latest_containers.values())
    builds = list(JenkinsBuild.objects.order_by('-id')[:4])

    try:
        catalog = json.loads(get_setting('prometheus_catalog', '[]') or '[]')
    except json.JSONDecodeError:
        catalog = []
    if not isinstance(catalog, list) or not catalog:
        catalog = list(PrometheusAlert.objects.order_by('metric_name').values_list('metric_name', flat=True).distinct())

    metric_rows = []
    if selected:
        for name in selected:
            row = PrometheusAlert.objects.filter(metric_name=name).order_by('-id').first()
            if row is not None:
                metric_rows.append(row)
    else:
        metric_rows = list(PrometheusAlert.objects.order_by('-id')[:4])

    containers_list = [
        [row.container_name, row.status, f'{row.cpu_percent or 0:.1f}%', f'{row.mem_usage_mb or 0:.1f} MB']
        for row in containers
    ]
    builds_list = []
    for build in builds:
        duration = int((build.duration_ms or 0) / 1000)
        duration_text = f'{duration // 60}m {duration % 60}s' if duration > 60 else f'{duration}s'
        builds_list.append([build.job_name, f'#{build.build_number}', build.result or 'PENDING', duration_text])

    core_metrics = []
    for row in metric_rows:
        display_value, bar_percent, description = process_metric_smart(row.metric_name, row.value)
        core_metrics.append([row.metric_name, display_value, description, str(bar_percent)])

    total = len(containers_list)
    running = sum(1 for row in containers if row.status == 'running')
    return {
        'metrics': {
            'system_health': f'{(running / total) * 100:.1f}%' if total else '0%',
            'active_containers': str(running),
            'pipelines_today': str(JenkinsBuild.objects.count()),
            'telemetry_events': f'{total + len(builds_list)} active nodes',
        },
        'containers': containers_list,
        'builds': builds_list,
        'core_metrics': core_metrics,
        'all_available_metrics': [name for name in catalog if isinstance(name, str)],
    }
