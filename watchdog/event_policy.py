"""Semantic filter. It supplements, but cannot narrow, an upstream webhook."""
REPOSITORY = 'tpuzz/mckay-watchdog'
PREFIXES = {
    'MCKAY_FINE_RECOVERY_TEST': 'test',
    'MCKAY_FINE_WORKFLOW_STALE': 'recovery',
    'MCKAY_FINE_WORKFLOW_TERMINAL': 'delivery',
    'MCKAY_FINE_INFRA_FAILURE': 'diagnostic',
}

def classify_event(event):
    if not isinstance(event, dict) or event.get('action') != 'opened':
        return 'ignore'
    repository = event.get('repository', {})
    pr = event.get('pull_request', {})
    if not isinstance(repository, dict) or not isinstance(pr, dict):
        return 'ignore'
    if repository.get('full_name') != REPOSITORY:
        return 'ignore'
    if pr.get('base', {}).get('repo', {}).get('full_name') != REPOSITORY:
        return 'ignore'
    title = pr.get('title')
    if not isinstance(title, str):
        return 'ignore'
    return next((kind for prefix, kind in PREFIXES.items() if title.startswith(prefix)), 'ignore')

