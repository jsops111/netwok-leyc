"""
Redfish 客户端 —— **只发 HTTP,不解析业务语义**(解析在 `parse.py`,纯函数)。

## 为什么走 Redfish 而不是 SNMP / racadm

- SNMP 的 IDRAC-MIB 拿得到同样的东西,但要维护一大堆 OID,而且
  DisplayString 型 OID 在很多 exporter 里输出成 `0x435055312054656D70`
  这种十六进制,还得自己解码
- `racadm` 要 SSH 上去跑命令,输出是给人看的表格,格式随固件版本变
- Redfish 是 JSON,DMTF 标准,iDRAC 7/8/9 都有,而且**只读**

## 打 BMC 要克制

iDRAC 的 BMC 是一颗很弱的处理器。打太勤会把它自己拖慢,严重时管理界面
登不进去 —— **而那正是出事时要用的东西**。所以:

- 采集间隔最小 60 秒(模型上的 validator 挡着)
- 一次采集复用同一个 `requests.Session`(TLS 握手是这里最贵的一步,
  五个端点各握一次手会让一次采集从 1 秒变成 3 秒)
- 每个端点**独立 try**:一个端点 404 / 超时不该让整次采集失败。
  iDRAC 7 上没有的端点是常态,那种情况下对应的部件留空,不是错误

## 自签证书

iDRAC 出厂是自签证书,所以 `verify_tls` 默认关。关掉 verify 时 urllib3 会
每次打一条 InsecureRequestWarning,几十台机器每分钟一次会把日志淹掉 ——
所以在这里显式关掉那个警告(只在 verify=False 时)。
"""

from __future__ import annotations

import logging

import requests
import urllib3

log = logging.getLogger("netcheck.idrac")


class RedfishError(Exception):
    """带外采不到。iDRAC 只有一条通道,所以这个异常等价于"这台带外没通"。"""


# Dell 的 Redfish 路径。**写死 System.Embedded.1 是有意的**:标准做法是先
# GET /redfish/v1/Systems 拿到成员列表再取第一个,那要多一个来回;而 Dell
# 的单机系统这个 id 是固定的。真机上如果 404 了,再改成先列集合 —— 但别
# 为了"更标准"平白给每台机器每拍加一次请求。
_SYSTEM = "/redfish/v1/Systems/System.Embedded.1"
_CHASSIS = "/redfish/v1/Chassis/System.Embedded.1"
_MANAGER = "/redfish/v1/Managers/iDRAC.Embedded.1"

#: (段名, 路径, 这一段拿不到算不算致命)。**只有 system 是致命的** ——
#: 它拿不到说明地址/凭据/型号有问题,那时候报错要指向那个原因;
#: 其余每一段拿不到只让对应的部件留空
ENDPOINTS: list[tuple[str, str, bool]] = [
    ("system", _SYSTEM, True),
    ("thermal", f"{_CHASSIS}/Thermal", False),
    ("power", f"{_CHASSIS}/Power", False),
    # $expand 把成员一次展开,否则 24 条内存就是 24 个请求 —— 对 BMC 是灾难。
    # iDRAC 7/8 上 $expand 可能不支持,那时这一段拿不到,内存只剩
    # system.MemorySummary 那个汇总状态(见 parse.py)
    ("memory", f"{_SYSTEM}/Memory?$expand=*($levels=1)", False),
    ("storage", f"{_SYSTEM}/Storage?$expand=*($levels=3)", False),
]

#: 硬件事件日志。单独列出来是因为它由 `collect_events` 开关控制
SEL_ENDPOINT = ("sel", f"{_MANAGER}/LogServices/Sel/Entries?$top=50", False)

#: 管理器信息(iDRAC 固件版本)。便宜,顺手取
MANAGER_ENDPOINT = ("manager", _MANAGER, False)


def _session(host, port, username, password, verify_tls: bool) -> requests.Session:
    session = requests.Session()
    session.auth = (username, password)
    session.verify = verify_tls
    session.headers.update({"Accept": "application/json"})
    if not verify_tls:
        # 几十台机器每分钟一条 InsecureRequestWarning 会把日志淹掉,
        # 而"我们知道这是自签证书"这件事已经由 verify_tls 这个开关表达过了
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def fetch_all(
    host: str, port: int, username: str, password: str,
    verify_tls: bool, timeout: float, with_events: bool = True,
) -> dict:
    """
    一次采集要的全部 JSON,按段名返回。

    **一个 Session 打完所有端点** —— TLS 握手是这里最贵的一步,
    五个端点各握一次手会让一次采集从 1 秒变成 3 秒,而这是每台每拍都要付的。

    返回的 dict 里,**取不到的段直接不出现**(不是 None,也不是 {}),
    调用方用 `.get(name)` 判断。诊断信息在 `_errors` 里 —— 页面上
    "为什么内存那一栏是空的"这个问题只有它答得了。
    """

    base = f"https://{host}:{port}"
    out: dict = {"_errors": {}}
    session = _session(host, port, username, password, verify_tls)

    endpoints = list(ENDPOINTS) + [MANAGER_ENDPOINT]
    if with_events:
        endpoints.append(SEL_ENDPOINT)

    try:
        for name, path, fatal in endpoints:
            try:
                response = session.get(f"{base}{path}", timeout=timeout)
            except requests.exceptions.SSLError as exc:
                raise RedfishError(
                    f"TLS 握手失败:{str(exc)[:120]} —— "
                    "iDRAC 出厂是自签证书,把「校验 TLS 证书」关掉"
                ) from exc
            except requests.exceptions.ConnectTimeout as exc:
                raise RedfishError(f"连接超时(>{timeout:.0f}s):{host}:{port}") from exc
            except requests.exceptions.ReadTimeout as exc:
                # 只有致命段的超时才中断:BMC 慢是常态,某个端点慢不该
                # 把已经拿到的部件一起丢掉
                if fatal:
                    raise RedfishError(f"读取超时(>{timeout:.0f}s),BMC 响应太慢") from exc
                out["_errors"][name] = f"超时(>{timeout:.0f}s)"
                continue
            except requests.exceptions.ConnectionError as exc:
                raise RedfishError(f"连不上 {host}:{port}:{str(exc)[:120]}") from exc

            if response.status_code == 401:
                raise RedfishError("认证失败(401),检查用户名 / 密码")
            if response.status_code == 403:
                # **403 和"没有这个东西"是两件事。**权限不够时那一段是空的,
                # 但页面上不能说成"这台机器没有硬盘"
                out["_errors"][name] = "403 权限不足 —— 这个账号读不到这一段"
                if fatal:
                    raise RedfishError(
                        "账号没有读取系统信息的权限(403)—— "
                        "iDRAC 里给它 Read Only 及以上的角色"
                    )
                continue
            if response.status_code == 404:
                out["_errors"][name] = "404 这个固件版本没有这个端点"
                if fatal:
                    raise RedfishError(
                        f"{path} 返回 404 —— 这台可能不是 Dell,"
                        "或者 iDRAC 固件太老(Redfish 要 iDRAC 7 以上)"
                    )
                continue
            if response.status_code >= 400:
                out["_errors"][name] = f"HTTP {response.status_code}"
                if fatal:
                    raise RedfishError(f"{path} 返回 HTTP {response.status_code}")
                continue

            try:
                out[name] = response.json()
            except ValueError:
                # 返回了 200 但不是 JSON —— 多半是被某个反代/门户拦了。
                # 把开头几十个字符带出来,否则这个错完全没法查
                head = response.text.strip().replace("\n", " ")[:100]
                message = f"返回的不是 JSON:{head}"
                out["_errors"][name] = message
                if fatal:
                    raise RedfishError(
                        f"{message} —— 这个地址后面是 iDRAC 吗?"
                    ) from None
    finally:
        session.close()

    return out


def test_login(host: str, port: int, username: str, password: str,
               verify_tls: bool, timeout: float) -> dict:
    """
    「测试」按钮:只打一个端点,验证地址 + 凭据 + 是不是真的 iDRAC。

    **不取部件明细** —— 测试要快,而且它要回答的是"能不能连上",
    不是"这台机器健不健康"。
    """

    data = fetch_all(host, port, username, password, verify_tls, timeout, with_events=False)
    return data
