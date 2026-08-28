#!/usr/bin/env python3
"""
检查模板里用到的组件都 import 了。

**vue-tsc 查不出这个。**它没法确定一个 PascalCase 组件是不是全局注册的,
所以未 import 的组件既不报类型错、也不让构建失败 —— Vue 在运行时把它当成
未知元素渲染成一个裸标签:没有样式、不响应交互,看起来就是"一片灰"。
实测踩过:NInputNumber 漏了 import,保留策略那七个输入框全成了死的灰块。

    python3 frontend/scripts/check_components.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, "..", "src"))

# Vue / vue-router 内置,不需要 import
BUILTIN = {
    "Transition", "TransitionGroup", "KeepAlive", "Teleport", "Suspense",
    "Component", "Slot", "RouterView", "RouterLink",
}


def main() -> int:
    bad = 0
    for root, _, files in os.walk(SRC):
        if "node_modules" in root:
            continue
        for f in sorted(files):
            if not f.endswith(".vue"):
                continue
            path = os.path.join(root, f)
            text = open(path, encoding="utf-8").read()
            m = re.search(r"<template>(.*)</template>", text, re.S)
            if not m:
                continue
            template = re.sub(r"<!--.*?-->", "", m.group(1), flags=re.S)
            used = set(re.findall(r"<([A-Z][A-Za-z0-9]*)", template))
            script = text[: text.index("<template>")]
            for name in sorted(used - BUILTIN):
                # import { NButton, ... } 或 import Foo from '...'
                if re.search(r"\b" + re.escape(name) + r"\b", script):
                    continue
                print(f"✗ {os.path.relpath(path, SRC)}: <{name}> 用了但没 import")
                bad += 1
    if bad:
        print(f"\n{bad} 个组件没 import —— 它们在页面上会渲染成不能用的灰块")
        return 1
    print("✓ 模板里用到的组件都 import 了")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
