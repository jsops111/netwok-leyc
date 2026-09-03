from django.urls import include, path
from rest_framework.routers import DefaultRouter

from netcheck import views

router = DefaultRouter()
router.register("probe-groups", views.ProbeGroupViewSet, basename="probe-group")
router.register("probes", views.ProbeTargetViewSet, basename="probe")
router.register("devices", views.DeviceViewSet, basename="device")
router.register("interfaces", views.DeviceInterfaceViewSet, basename="interface")
router.register("neighbors", views.DeviceNeighborViewSet, basename="neighbor")
router.register("servers", views.ServerViewSet, basename="server")
# 配置备份和防火墙策略都是**只读**的:它们是采集产物,
# 写入只有一条路(定时任务 / 页面上的「立即执行」按钮)
router.register("backups", views.DeviceBackupViewSet, basename="backup")
router.register("firewall-policies", views.FirewallPolicyViewSet, basename="firewall-policy")
router.register("firewall-vips", views.FirewallVipViewSet, basename="firewall-vip")
router.register("firewall-addresses", views.FirewallAddressViewSet, basename="firewall-address")
router.register("firewall-services", views.FirewallServiceViewSet, basename="firewall-service")
router.register("sdwan", views.SdwanLinkViewSet, basename="sdwan")
router.register("cisco-acl", views.CiscoAclViewSet, basename="cisco-acl")
router.register("idrac", views.IdracHostViewSet, basename="idrac")
router.register("events", views.EventViewSet, basename="event")
router.register("notifiers", views.NotifierViewSet, basename="notifier")
router.register("notify-logs", views.NotifyLogViewSet, basename="notify-log")

urlpatterns = [
    path("", include(router.urls)),
    # 大屏聚合 —— 大屏一次刷新只打这三个
    path("dashboard/overview/", views.dashboard_overview, name="dashboard-overview"),
    path("dashboard/charts/", views.dashboard_charts, name="dashboard-charts"),
    path("dashboard/devices/", views.dashboard_devices, name="dashboard-devices"),
    path("dashboard/servers/", views.dashboard_servers, name="dashboard-servers"),
    path("meta/choices/", views.meta_choices, name="meta-choices"),
    path("health/", views.health, name="health"),
]
