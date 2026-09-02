"""
服务器监控 / 配置备份 / 防火墙策略三张新表,外加两处对既有表的改动:

1. **Event 多一个 server 外键**,那条"同一来源同一类型只允许一条未恢复事件"
   的部分唯一索引要跟着重建。

2. 重建时给它加上 `nulls_distinct=False`。**原来那条约束一行都没挡住** ——
   四个来源外键里永远只有一个非空,而 PostgreSQL 默认认为 NULL != NULL,
   所以任何一行只要有 NULL 列就永远不会和别的行冲突(和 CLAUDE.md 第 2 条
   讲的 ProbeTarget 端点约束是同一个坑)。

   因为它一直没生效,**老库里可能已经存在重复的未恢复事件**,那样
   AddConstraint 会直接失败。所以加约束之前先跑一遍
   `resolve_duplicate_open_events`:同一来源同一类型留最早的那条
   (它的 started_at 才是真实的故障开始时间),其余的关掉并在备注里写明原因。
"""
import core.crypto
import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


def resolve_duplicate_open_events(apps, schema_editor):
    """
    加唯一索引之前先把重复的未恢复事件收拾掉。

    留**最早**的那条:它的 started_at 是这次故障真正开始的时间,
    而重复出来的那些是并发采集或旧约束失效时多开的。被关掉的那些在
    note 里写明原因 —— 不写的话事后看到一条持续时长很短的"恢复"
    会被当成误报去查。
    """

    from django.utils import timezone

    Event = apps.get_model("netcheck", "Event")
    seen: dict[tuple, int] = {}
    now = timezone.now()
    closed = 0

    # 按 started_at 升序扫,第一次见到的那个组合就是要保留的那条
    for event in Event.objects.filter(resolved_at__isnull=True).order_by("started_at", "id").iterator():
        key = (
            event.source_type, event.target_id, event.device_id,
            event.interface_id, getattr(event, "server_id", None), event.kind,
        )
        if key not in seen:
            seen[key] = event.pk
            continue
        event.resolved_at = now
        event.duration_s = max(0, int((now - event.started_at).total_seconds()))
        event.note = (event.note + "\n" if event.note else "") + (
            f"[系统关闭] 与事件 #{seen[key]} 重复(同一来源同一类型只允许一条未恢复事件);"
            "旧的部分唯一索引因为 NULL 语义一直没生效,这次加索引时一并收拾"
        )
        # 不推恢复通知 —— 没人在等一条"这条是重复的所以它好了"的消息
        event.notified_recover = True
        event.save(update_fields=["resolved_at", "duration_s", "note", "notified_recover"])
        closed += 1

    if closed:
        print(f"  关闭了 {closed} 条重复的未恢复事件")


class Migration(migrations.Migration):

    dependencies = [
        ('netcheck', '0003_retentionpolicy'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceBackup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.DateTimeField(db_index=True, help_text='这个版本第一次被备份到的时间', verbose_name='首次出现时间')),
                ('last_seen_at', models.DateTimeField(help_text='最近一次备份确认配置仍是这个版本的时间', verbose_name='最后确认时间')),
                ('seen_count', models.IntegerField(default=1, verbose_name='确认次数')),
                ('method', models.CharField(help_text='ssh / api', max_length=8, verbose_name='备份通道')),
                ('content', models.TextField(blank=True, verbose_name='配置文本')),
                ('size_bytes', models.IntegerField(default=0, verbose_name='字节数')),
                ('line_count', models.IntegerField(default=0, verbose_name='行数')),
                ('content_hash', models.CharField(db_index=True, max_length=64, verbose_name='内容哈希')),
                ('lines_added', models.IntegerField(blank=True, null=True, verbose_name='新增行数')),
                ('lines_removed', models.IntegerField(blank=True, null=True, verbose_name='删除行数')),
                ('is_first', models.BooleanField(default=False, verbose_name='首个版本')),
            ],
            options={
                'verbose_name': '配置备份',
                'verbose_name_plural': '配置备份',
                'ordering': ['-ts', '-id'],
            },
        ),
        migrations.CreateModel(
            name='FirewallPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vdom', models.CharField(blank=True, default='root', max_length=64, verbose_name='VDOM')),
                ('policy_id', models.IntegerField(help_text='设备上的 policyid,不是这张表的主键', verbose_name='策略 ID')),
                ('seq', models.IntegerField(default=0, help_text='策略表里的先后。**防火墙是先匹配先生效的**,顺序本身是语义', verbose_name='顺序')),
                ('name', models.CharField(blank=True, max_length=128, verbose_name='名称')),
                ('src_intf', models.JSONField(blank=True, default=list, verbose_name='源接口')),
                ('dst_intf', models.JSONField(blank=True, default=list, verbose_name='目的接口')),
                ('src_addr', models.JSONField(blank=True, default=list, verbose_name='源地址')),
                ('dst_addr', models.JSONField(blank=True, default=list, verbose_name='目的地址')),
                ('service', models.JSONField(blank=True, default=list, verbose_name='服务')),
                ('schedule', models.CharField(blank=True, max_length=64, verbose_name='生效时间')),
                ('action', models.CharField(choices=[('accept', '允许'), ('deny', '拒绝'), ('ipsec', 'IPsec'), ('other', '其它')], default='other', max_length=10, verbose_name='动作')),
                ('enabled', models.BooleanField(default=True, verbose_name='已启用')),
                ('nat', models.BooleanField(default=False, verbose_name='NAT')),
                ('log_traffic', models.CharField(blank=True, max_length=16, verbose_name='日志')),
                ('comments', models.CharField(blank=True, max_length=255, verbose_name='备注')),
                ('uuid', models.CharField(blank=True, max_length=64, verbose_name='UUID')),
                ('hit_count', models.BigIntegerField(blank=True, null=True, verbose_name='命中次数')),
                ('bytes_count', models.BigIntegerField(blank=True, null=True, verbose_name='字节数')),
                ('packets', models.BigIntegerField(blank=True, null=True, verbose_name='包数')),
                ('sessions', models.IntegerField(blank=True, null=True, verbose_name='活动会话')),
                ('first_hit_at', models.DateTimeField(blank=True, null=True, verbose_name='首次命中')),
                ('last_hit_at', models.DateTimeField(blank=True, null=True, verbose_name='最后命中')),
                ('raw', models.JSONField(blank=True, default=dict, verbose_name='原始记录')),
                ('synced_at', models.DateTimeField(db_index=True, verbose_name='同步时间')),
                ('method', models.CharField(blank=True, help_text='api / ssh', max_length=8, verbose_name='同步通道')),
            ],
            options={
                'verbose_name': '防火墙策略',
                'verbose_name_plural': '防火墙策略',
                'ordering': ['device_id', 'vdom', 'seq', 'policy_id'],
            },
        ),
        migrations.CreateModel(
            name='Server',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('meta', models.JSONField(blank=True, default=dict, verbose_name='META 扩展')),
                ('name', models.CharField(max_length=128, unique=True, verbose_name='服务器名称')),
                ('host', models.CharField(help_text='IP 或域名', max_length=255, verbose_name='地址')),
                ('ssh_port', models.IntegerField(default=22, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(65535)], verbose_name='SSH 端口')),
                ('ssh_username', models.CharField(max_length=64, verbose_name='SSH 用户名')),
                ('ssh_password', core.crypto.EncryptedTextField(blank=True, default='', verbose_name='SSH 密码')),
                ('ssh_private_key', core.crypto.EncryptedTextField(blank=True, default='', help_text='和密码填一个即可;私钥更适合无人值守', verbose_name='SSH 私钥')),
                ('ssh_key_passphrase', core.crypto.EncryptedTextField(blank=True, default='', help_text='私钥带口令时填', verbose_name='私钥口令')),
                ('site', models.CharField(blank=True, max_length=64, verbose_name='机房/位置')),
                ('role', models.CharField(blank=True, help_text='如 应用 / 数据库 / 网关。只用于展示分组', max_length=64, verbose_name='用途')),
                ('interval_seconds', models.IntegerField(default=60, help_text='每次采集是一次完整的 SSH 握手 + 一批 /proc 读取,最小 15 秒', validators=[django.core.validators.MinValueValidator(15), django.core.validators.MaxValueValidator(86400)], verbose_name='采集频率(秒)')),
                ('timeout_ms', models.IntegerField(default=8000, validators=[django.core.validators.MinValueValidator(1000), django.core.validators.MaxValueValidator(60000)], verbose_name='超时(毫秒)')),
                ('net_interface', models.CharField(blank=True, help_text='留空 = 自动取默认路由那块网卡。**不要把所有网卡加起来** —— docker0 / veth / br- 这些虚拟口会把同一份流量数两三遍', max_length=32, verbose_name='流量统计网卡')),
                ('cpu_warn_pct', models.IntegerField(default=80, verbose_name='CPU 警告线(%)')),
                ('cpu_crit_pct', models.IntegerField(default=92, verbose_name='CPU 严重线(%)')),
                ('mem_warn_pct', models.IntegerField(default=85, verbose_name='内存警告线(%)')),
                ('mem_crit_pct', models.IntegerField(default=95, verbose_name='内存严重线(%)')),
                ('disk_warn_pct', models.IntegerField(default=80, help_text='按**占用率最高的那个挂载点**判,不是根分区', verbose_name='磁盘警告线(%)')),
                ('disk_crit_pct', models.IntegerField(default=90, verbose_name='磁盘严重线(%)')),
                ('load_warn', models.FloatField(default=1.5, help_text='判的是 load1 ÷ 核数。1.0 = 刚好跑满', verbose_name='负载警告线(每核)')),
                ('load_crit', models.FloatField(default=3.0, verbose_name='负载严重线(每核)')),
                ('fail_threshold', models.IntegerField(default=2, validators=[django.core.validators.MinValueValidator(1)], verbose_name='连续失败次数开事件')),
                ('recover_threshold', models.IntegerField(default=2, validators=[django.core.validators.MinValueValidator(1)], verbose_name='连续正常次数关事件')),
                ('collect_processes', models.BooleanField(default=True, help_text='多一条 ps 命令,换来「是谁在吃 CPU」这个答案', verbose_name='采集进程 Top')),
                ('enabled', models.BooleanField(db_index=True, default=True, verbose_name='启用')),
                ('order', models.IntegerField(default=0, verbose_name='排序')),
                ('state', models.CharField(choices=[('unknown', '未知'), ('up', '正常'), ('degraded', '劣化'), ('down', '中断')], db_index=True, default='unknown', max_length=12, verbose_name='当前状态')),
                ('last_collected_at', models.DateTimeField(blank=True, null=True, verbose_name='最后采集时间')),
                ('last_error', models.CharField(blank=True, max_length=255, verbose_name='最后错误')),
                ('consecutive_fail', models.IntegerField(default=0, verbose_name='连续失败次数')),
                ('consecutive_ok', models.IntegerField(default=0, verbose_name='连续正常次数')),
                ('hostname', models.CharField(blank=True, max_length=128, verbose_name='主机名')),
                ('os_name', models.CharField(blank=True, max_length=128, verbose_name='操作系统')),
                ('kernel', models.CharField(blank=True, max_length=64, verbose_name='内核版本')),
                ('cpu_cores', models.IntegerField(blank=True, null=True, verbose_name='CPU 核数')),
                ('mem_total_bytes', models.BigIntegerField(blank=True, null=True, verbose_name='内存总量(字节)')),
            ],
            options={
                'verbose_name': '服务器',
                'verbose_name_plural': '服务器',
                'ordering': ['order', 'id'],
            },
        ),
        migrations.CreateModel(
            name='ServerInterface',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('meta', models.JSONField(blank=True, default=dict, verbose_name='META 扩展')),
                ('if_name', models.CharField(max_length=32, verbose_name='网卡名')),
                ('is_primary', models.BooleanField(default=False, help_text='默认路由走的那块,ServerSample 的流量统计用它', verbose_name='主网卡')),
                ('is_virtual', models.BooleanField(default=False, help_text='docker0 / veth* / br-* / lo 之类。**不计入总流量**,否则同一份流量被数几遍', verbose_name='虚拟口')),
                ('in_bps', models.FloatField(blank=True, null=True, verbose_name='入向速率(bps)')),
                ('out_bps', models.FloatField(blank=True, null=True, verbose_name='出向速率(bps)')),
                ('in_err_delta', models.BigIntegerField(blank=True, null=True, verbose_name='入向错包增量')),
                ('out_err_delta', models.BigIntegerField(blank=True, null=True, verbose_name='出向错包增量')),
                ('in_octets', models.BigIntegerField(blank=True, null=True, verbose_name='入向字节计数')),
                ('out_octets', models.BigIntegerField(blank=True, null=True, verbose_name='出向字节计数')),
            ],
            options={
                'verbose_name': '服务器网卡',
                'verbose_name_plural': '服务器网卡',
                'ordering': ['server_id', '-is_primary', 'if_name'],
            },
        ),
        migrations.CreateModel(
            name='ServerSample',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.DateTimeField(db_index=True, verbose_name='采样时间')),
                ('reachable', models.BooleanField(default=True, verbose_name='可达')),
                ('latency_ms', models.FloatField(blank=True, null=True, verbose_name='采集耗时(ms)')),
                ('cpu_pct', models.FloatField(blank=True, null=True, verbose_name='CPU 使用率(%)')),
                ('cpu_iowait_pct', models.FloatField(blank=True, help_text='CPU 不高但系统很卡时看它 —— 那是在等磁盘,不是在算', null=True, verbose_name='iowait(%)')),
                ('mem_pct', models.FloatField(blank=True, null=True, verbose_name='内存使用率(%)')),
                ('swap_pct', models.FloatField(blank=True, null=True, verbose_name='Swap 使用率(%)')),
                ('disk_pct', models.FloatField(blank=True, help_text='占用率最高的那个挂载点', null=True, verbose_name='磁盘使用率(%)')),
                ('load1', models.FloatField(blank=True, null=True, verbose_name='1 分钟负载')),
                ('load5', models.FloatField(blank=True, null=True, verbose_name='5 分钟负载')),
                ('load15', models.FloatField(blank=True, null=True, verbose_name='15 分钟负载')),
                ('uptime_s', models.BigIntegerField(blank=True, null=True, verbose_name='运行时长(秒)')),
                ('process_count', models.IntegerField(blank=True, null=True, verbose_name='进程数')),
                ('tcp_established', models.IntegerField(blank=True, null=True, verbose_name='ESTABLISHED 连接数')),
                ('net_in_bps', models.FloatField(blank=True, null=True, verbose_name='入向速率(bps)')),
                ('net_out_bps', models.FloatField(blank=True, null=True, verbose_name='出向速率(bps)')),
                ('extra', models.JSONField(blank=True, default=dict, verbose_name='其它指标')),
                ('error', models.CharField(blank=True, max_length=255, verbose_name='错误信息')),
            ],
            options={
                'verbose_name': '服务器样本',
                'verbose_name_plural': '服务器样本',
                'ordering': ['-ts'],
            },
        ),
        migrations.RemoveConstraint(
            model_name='event',
            name='uniq_open_event_per_source_kind',
        ),
        migrations.AddField(
            model_name='device',
            name='backup_enabled',
            field=models.BooleanField(default=False, help_text='需要 SSH 凭据(FortiGate 也可用 API Token)。型号画像里没定义备份命令的型号开了也备不了', verbose_name='启用配置备份'),
        ),
        migrations.AddField(
            model_name='device',
            name='backup_interval_hours',
            field=models.IntegerField(default=24, help_text='配置不是时序数据,一天一次足够。改配置后想立刻留档用页面上的「立即备份」', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(8760)], verbose_name='备份间隔(小时)'),
        ),
        migrations.AddField(
            model_name='device',
            name='backup_keep',
            field=models.IntegerField(default=20, help_text='**只数「变更过的版本」**:配置没变不会新增版本,所以 20 个版本通常够回溯很久', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(500)], verbose_name='保留版本数'),
        ),
        migrations.AddField(
            model_name='device',
            name='last_backup_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='最后备份时间'),
        ),
        migrations.AddField(
            model_name='device',
            name='last_backup_error',
            field=models.CharField(blank=True, max_length=255, verbose_name='最后备份错误'),
        ),
        migrations.AddField(
            model_name='device',
            name='last_backup_status',
            field=models.CharField(choices=[('never', '从未备份'), ('ok', '成功'), ('failed', '失败')], default='never', max_length=8, verbose_name='最后备份结果'),
        ),
        migrations.AddField(
            model_name='device',
            name='last_policy_error',
            field=models.CharField(blank=True, max_length=255, verbose_name='最后策略同步错误'),
        ),
        migrations.AddField(
            model_name='device',
            name='last_policy_sync_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='最后策略同步时间'),
        ),
        migrations.AddField(
            model_name='device',
            name='policy_count',
            field=models.IntegerField(default=0, verbose_name='策略条数'),
        ),
        migrations.AddField(
            model_name='device',
            name='policy_sync_enabled',
            field=models.BooleanField(default=False, help_text='仅防火墙。FortiGate 走 API(带命中计数)或 SSH(只有配置,没有命中数)', verbose_name='同步防火墙策略'),
        ),
        migrations.AddField(
            model_name='device',
            name='policy_sync_interval_minutes',
            field=models.IntegerField(default=30, help_text='策略表几百条起,一次同步要拉两个端点;5 分钟以下没有意义', validators=[django.core.validators.MinValueValidator(5), django.core.validators.MaxValueValidator(1440)], verbose_name='策略同步间隔(分钟)'),
        ),
        migrations.AlterField(
            model_name='event',
            name='kind',
            field=models.CharField(choices=[('down', '断线'), ('loss', '丢包'), ('latency', '延迟'), ('jitter', '抖动'), ('anomaly', '异常'), ('device_down', '设备失联'), ('cpu_high', 'CPU 过高'), ('mem_high', '内存过高'), ('temp_high', '温度过高'), ('if_down', '接口 Down'), ('if_error', '接口错包'), ('if_saturated', '接口带宽饱和'), ('ha_change', 'HA 状态切换'), ('session_high', '会话数过高'), ('psu_fault', '电源异常'), ('server_down', '服务器失联'), ('disk_high', '磁盘空间不足'), ('load_high', '负载过高'), ('backup_failed', '配置备份失败'), ('config_changed', '配置发生变更')], db_index=True, max_length=16, verbose_name='事件类型'),
        ),
        migrations.AlterField(
            model_name='event',
            name='source_type',
            field=models.CharField(choices=[('probe', '线路拨测'), ('device', '设备'), ('interface', '设备接口'), ('server', '服务器')], db_index=True, max_length=12, verbose_name='来源类型'),
        ),
        migrations.AddField(
            model_name='devicebackup',
            name='device',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='backups', to='netcheck.device', verbose_name='设备'),
        ),
        migrations.AddField(
            model_name='firewallpolicy',
            name='device',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='policies', to='netcheck.device', verbose_name='设备'),
        ),
        migrations.AddIndex(
            model_name='server',
            index=models.Index(fields=['enabled', 'state'], name='netcheck_se_enabled_2bb3d7_idx'),
        ),
        migrations.AddConstraint(
            model_name='server',
            constraint=models.UniqueConstraint(fields=('host', 'ssh_port'), name='uniq_server_endpoint'),
        ),
        migrations.AddField(
            model_name='event',
            name='server',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='events', to='netcheck.server', verbose_name='服务器'),
        ),
        # **必须在 AddConstraint 之前。**老库里可能已经有重复的未恢复事件
        # (旧约束因为 NULL 语义从来没生效过),不先收拾掉的话下面这一步
        # 会以 UniqueViolation 失败,而那时候迁移已经跑了一半
        migrations.RunPython(
            resolve_duplicate_open_events,
            # 回滚不需要做任何事:被关掉的事件留着不影响旧约束
            migrations.RunPython.noop,
        ),
        migrations.AddConstraint(
            model_name='event',
            constraint=models.UniqueConstraint(condition=models.Q(('resolved_at__isnull', True)), fields=('source_type', 'target', 'device', 'interface', 'server', 'kind'), name='uniq_open_event_per_source_kind', nulls_distinct=False),
        ),
        migrations.AddField(
            model_name='serverinterface',
            name='server',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='interfaces', to='netcheck.server', verbose_name='服务器'),
        ),
        migrations.AddField(
            model_name='serversample',
            name='server',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='samples', to='netcheck.server', verbose_name='服务器'),
        ),
        migrations.AddIndex(
            model_name='devicebackup',
            index=models.Index(fields=['device', '-ts'], name='idx_backup_device_ts'),
        ),
        migrations.AddIndex(
            model_name='firewallpolicy',
            index=models.Index(fields=['device', 'seq'], name='idx_policy_device_seq'),
        ),
        migrations.AddIndex(
            model_name='firewallpolicy',
            index=models.Index(fields=['device', 'action'], name='idx_policy_device_action'),
        ),
        migrations.AddConstraint(
            model_name='firewallpolicy',
            constraint=models.UniqueConstraint(fields=('device', 'vdom', 'policy_id'), name='uniq_policy_per_device_vdom'),
        ),
        migrations.AddConstraint(
            model_name='serverinterface',
            constraint=models.UniqueConstraint(fields=('server', 'if_name'), name='uniq_server_ifname'),
        ),
        migrations.AddIndex(
            model_name='serversample',
            index=models.Index(fields=['server', '-ts'], name='idx_srvsample_ts'),
        ),
    ]
