from rest_framework.pagination import PageNumberPagination


class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 500


class SampleCursorPagination(PageNumberPagination):
    """
    时序样本用的大页 —— 图表一次要拉几百上千个点,20 条一页画不出线。
    上限压在 5000:再大就该改用降采样表,而不是把原始点全捞出来。
    """

    page_size = 1000
    page_size_query_param = "page_size"
    max_page_size = 5000
