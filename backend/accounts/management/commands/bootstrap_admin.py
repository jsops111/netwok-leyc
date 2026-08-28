"""
首次部署时建出第一个管理员。

**没有这个命令,一个全新部署是打不开的** —— 全站要登录,而库里一个用户都没有,
页面停在登录框、`createsuperuser` 又需要有人先 exec 进容器。所以 backend 容器
的启动命令里串了这一条(见 backend/Dockerfile)。

两条规矩:

- **只在一个用户都没有的时候动手。**否则每次容器重启都会把管理员密码重置回
  环境变量里那个值,而运维在页面上改过的密码会莫名其妙失效。
- **没给密码就随机生成并打印到日志。**打印是有意的:它只出现这一次,
  `docker compose logs backend` 能捞到,而写死一个默认密码是更糟的选择。
"""

from __future__ import annotations

import secrets
import string

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

ALPHABET = string.ascii_letters + string.digits + "!@#%^&*-_=+"


class Command(BaseCommand):
    help = "库里没有任何用户时,创建第一个管理员账号"

    def add_arguments(self, parser):
        parser.add_argument("--username", default=None, help="默认取 NETCHECK_ADMIN_USERNAME 或 admin")
        parser.add_argument("--password", default=None, help="默认取 NETCHECK_ADMIN_PASSWORD 或随机生成")
        parser.add_argument("--force", action="store_true",
                            help="已经有用户时也创建/重置这个账号(救急用)")

    def handle(self, *args, **options):
        import os

        if User.objects.exists() and not options["force"]:
            self.stdout.write("已有用户,跳过管理员初始化")
            return

        username = (options["username"] or os.environ.get("NETCHECK_ADMIN_USERNAME") or "admin").strip()
        password = options["password"] or os.environ.get("NETCHECK_ADMIN_PASSWORD") or ""
        generated = not password
        if generated:
            password = "".join(secrets.choice(ALPHABET) for _ in range(16))

        user, created = User.objects.get_or_create(
            username=username,
            defaults={"is_staff": True, "is_superuser": True, "first_name": "管理员"},
        )
        user.is_staff = user.is_superuser = user.is_active = True
        user.set_password(password)
        user.save()

        banner = "=" * 66
        self.stdout.write(banner)
        self.stdout.write(f"  管理员账号已{'创建' if created else '重置'}:{username}")
        if generated:
            self.stdout.write(f"  初始密码(只显示这一次):{password}")
            self.stdout.write("  登录后请立刻在「管理后台 → 我的安全」里改掉。")
        else:
            self.stdout.write("  密码取自 NETCHECK_ADMIN_PASSWORD。")
        self.stdout.write("  两步验证是自愿的,在同一页里绑定。")
        self.stdout.write(banner)
