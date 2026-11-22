from django.db import models


class MCPTool(models.Model):
    STATUS_CHOICES = [('draft', 'Draft'), ('active', 'Active'), ('disabled', 'Disabled'), ('archived', 'Archived')]
    name = models.SlugField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    code = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='draft')
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class MCPToolVersion(models.Model):
    tool = models.ForeignKey(MCPTool, related_name='versions', on_delete=models.CASCADE)
    version = models.PositiveIntegerField()
    description = models.TextField(blank=True)
    code = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['tool', 'version'], name='unique_tool_version')]


class SystemSetting(models.Model):
    key = models.CharField(max_length=255, unique=True)
    value = models.TextField()

    class Meta:
        db_table = 'mcp_systemsetting'


def get_setting(key, default=''):
    try:
        value = SystemSetting.objects.filter(key=key).values_list('value', flat=True).first()
    except Exception:
        return default
    if value is None or value == '':
        return default
    if key in ('jenkins_token', 'langfuse_secret_key'):
        from apps.mcp.secrets import decrypt_secret
        return decrypt_secret(value) or default
    return value


def set_setting(key, value):
    stored = str(value)
    if key in ('jenkins_token', 'langfuse_secret_key') and stored:
        from apps.mcp.secrets import encrypt_secret
        stored = encrypt_secret(stored)
    SystemSetting.objects.update_or_create(key=key, defaults={'value': stored})
