from django.db import models


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField("创建时间", auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField("更新时间", auto_now=True)

    class Meta:
        abstract = True


class MetaModel(models.Model):
    """
    统一的 META 扩展位 —— 放暂时没有独立字段的记录项。

    加字段不用改表,但该建索引、该被过滤的东西不要塞进来。
    """

    meta = models.JSONField("META 扩展", default=dict, blank=True)

    class Meta:
        abstract = True


class BaseModel(TimeStampedModel, MetaModel):
    class Meta:
        abstract = True
