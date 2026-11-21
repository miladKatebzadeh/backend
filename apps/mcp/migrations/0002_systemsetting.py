from django.db import migrations, models


def forwards(apps, schema_editor):
    from apps.mcp.models import SystemSetting

    connection = schema_editor.connection
    table = SystemSetting._meta.db_table
    existing = set(connection.introspection.table_names())
    if table not in existing:
        schema_editor.create_model(SystemSetting)
        return
    with connection.cursor() as cursor:
        columns = {col.name for col in connection.introspection.get_table_description(cursor, table)}
    for field in SystemSetting._meta.local_fields:
        if field.column not in columns:
            schema_editor.add_field(SystemSetting, field)


class Migration(migrations.Migration):

    dependencies = [
        ('mcp', '0001_initial'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.CreateModel(
                    name='SystemSetting',
                    fields=[
                        ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                        ('key', models.CharField(max_length=255, unique=True)),
                        ('value', models.TextField()),
                    ],
                    options={'db_table': 'mcp_systemsetting'},
                ),
            ],
            database_operations=[
                migrations.RunPython(forwards, migrations.RunPython.noop),
            ],
        ),
    ]
