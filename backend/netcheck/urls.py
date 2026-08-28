from django.urls import include, path
from rest_framework.routers import DefaultRouter

from netcheck import views

router = DefaultRouter()
router.register("probe-groups", views.ProbeGroupViewSet, basename="probe-group")
router.register("probes", views.ProbeTargetViewSet, basename="probe")
router.register("devices", views.DeviceViewSet, basename="device")
router.register("interfaces", views.DeviceInterfaceViewSet, basename="interface")
router.register("events", views.EventViewSet, basename="event")
router.register("notifiers", views.NotifierViewSet, basename="notifier")
router.register("notify-logs", views.NotifyLogViewSet, basename="notify-log")

urlpatterns = [
    path("", include(router.urls)),
    # 大屏聚合 —— 大屏一次刷新只打这三个
    path("dashboard/overview/", views.dashboard_overview, name="dashboard-overview"),
    path("dashboard/charts/", views.dashboard_charts, name="dashboard-charts"),
    path("dashboard/devices/", views.dashboard_devices, name="dashboard-devices"),
    path("meta/choices/", views.meta_choices, name="meta-choices"),
    path("health/", views.health, name="health"),
]
