#!/usr/bin/env python3
"""
配色与主题校验器。**改了 styles/cyber.css 里任何一个颜色令牌就要跑一遍。**

    python3 frontend/scripts/theme_check.py

只用标准库,不需要装任何东西。做四件事:

  1. 两套令牌必须对称 —— 只在一套里定义的令牌,在另一套下会静默失效
     (CSS 变量取不到值时整条声明作废,不报错、不回退)
  2. 组件里不许有裸的十六进制/rgb 颜色 —— 那是"换了主题这一处没跟着变"的来源
  3. 文字与状态色对**面板底和页面底**都 ≥4.5:1(WCAG AA 正文)
  4. 图表八色对两个底都 ≥3:1,并且在正常/红色盲/绿色盲三种视觉下
     两两 ΔE2000 分离 —— 一张图上并排十条线,分不开等于没画

已知不达标项(会打 ✗,是有意留着的):**深色那套图表色的色盲分离度**。
protan 下 cat4/cat7 只有 0.7,deutan 下 cat3/cat6 只有 1.4。改它会改变
所有人已经熟悉的大屏观感,所以留作一次单独的决定 —— 见 theme.ts 顶部。

色盲模拟用 Viénot 1999 单平面投影。它只对 protan/deutan 有效;
**tritan 那一项本来就不准,所以这里不检查** —— 报一个不可信的数字
比不报更糟。
"""
import math
from itertools import combinations

# ---------------- sRGB <-> 线性 <-> XYZ <-> Lab / OKLab ----------------

def hex2rgb(h):
    h = h.lstrip('#')
    return tuple(int(h[i:i+2], 16) / 255 for i in (0, 2, 4))

def lin(c):
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

def rel_lum(h):
    r, g, b = (lin(c) for c in hex2rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b

def contrast(a, b):
    l1, l2 = sorted((rel_lum(a), rel_lum(b)), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)

def oklab(h):
    r, g, b = (lin(c) for c in hex2rgb(h))
    l = 0.4122214708*r + 0.5363325363*g + 0.0514459929*b
    m = 0.2119034982*r + 0.6806995451*g + 0.1073969566*b
    s = 0.0883024619*r + 0.2817188376*g + 0.6299787005*b
    l_, m_, s_ = l ** (1/3), m ** (1/3), s ** (1/3)
    return (0.2104542553*l_ + 0.7936177850*m_ - 0.0040720468*s_,
            1.9779984951*l_ - 2.4285922050*m_ + 0.4505937099*s_,
            0.0259040371*l_ + 0.7827717662*m_ - 0.8086757660*s_)

def oklch(h):
    L, a, b = oklab(h)
    return L, math.hypot(a, b), math.degrees(math.atan2(b, a)) % 360

def xyz(h):
    r, g, b = (lin(c) for c in hex2rgb(h))
    return (0.4124*r + 0.3576*g + 0.1805*b,
            0.2126*r + 0.7152*g + 0.0722*b,
            0.0193*r + 0.1192*g + 0.9505*b)

def lab(h):
    X, Y, Z = xyz(h)
    Xn, Yn, Zn = 0.95047, 1.0, 1.08883
    f = lambda t: t ** (1/3) if t > 216/24389 else (841/108) * t + 4/29
    fx, fy, fz = f(X/Xn), f(Y/Yn), f(Z/Zn)
    return 116*fy - 16, 500*(fx-fy), 200*(fy-fz)

def de2000(h1, h2):
    L1, a1, b1 = lab(h1); L2, a2, b2 = lab(h2)
    C1, C2 = math.hypot(a1, b1), math.hypot(a2, b2)
    Cb = (C1 + C2) / 2
    G = 0.5 * (1 - math.sqrt(Cb**7 / (Cb**7 + 25**7))) if Cb else 0.5
    a1p, a2p = (1+G)*a1, (1+G)*a2
    C1p, C2p = math.hypot(a1p, b1), math.hypot(a2p, b2)
    h1p = math.degrees(math.atan2(b1, a1p)) % 360 if (a1p or b1) else 0
    h2p = math.degrees(math.atan2(b2, a2p)) % 360 if (a2p or b2) else 0
    dLp, dCp = L2 - L1, C2p - C1p
    if C1p * C2p == 0: dhp = 0
    elif abs(h2p - h1p) <= 180: dhp = h2p - h1p
    elif h2p - h1p > 180: dhp = h2p - h1p - 360
    else: dhp = h2p - h1p + 360
    dHp = 2 * math.sqrt(C1p * C2p) * math.sin(math.radians(dhp) / 2)
    Lbp, Cbp = (L1 + L2) / 2, (C1p + C2p) / 2
    if C1p * C2p == 0: hbp = h1p + h2p
    elif abs(h1p - h2p) <= 180: hbp = (h1p + h2p) / 2
    elif h1p + h2p < 360: hbp = (h1p + h2p + 360) / 2
    else: hbp = (h1p + h2p - 360) / 2
    T = (1 - 0.17*math.cos(math.radians(hbp-30)) + 0.24*math.cos(math.radians(2*hbp))
         + 0.32*math.cos(math.radians(3*hbp+6)) - 0.20*math.cos(math.radians(4*hbp-63)))
    dTh = 30 * math.exp(-(((hbp-275)/25)**2))
    Rc = 2 * math.sqrt(Cbp**7 / (Cbp**7 + 25**7)) if Cbp else 0
    Sl = 1 + (0.015*(Lbp-50)**2) / math.sqrt(20 + (Lbp-50)**2)
    Sc, Sh = 1 + 0.045*Cbp, 1 + 0.015*Cbp*T
    Rt = -math.sin(math.radians(2*dTh)) * Rc
    return math.sqrt((dLp/Sl)**2 + (dCp/Sc)**2 + (dHp/Sh)**2 + Rt*(dCp/Sc)*(dHp/Sh))

# ---------------- 色盲模拟(Viénot 1999 线性投影) ----------------

_CVD = {
    "protan": ((0.0, 2.02344, -2.52581), 0),
    "deutan": ((0.494207, 0.0, 1.24827), 1),
    "tritan": ((-0.395913, 0.801109, 0.0), 2),
}

def simulate(h, kind):
    r, g, b = (lin(c) for c in hex2rgb(h))
    L = 17.8824*r + 43.5161*g + 4.11935*b
    M = 3.45565*r + 27.1554*g + 3.86714*b
    S = 0.0299566*r + 0.184309*g + 1.46709*b
    coef, idx = _CVD[kind]
    lms = [L, M, S]
    lms[idx] = coef[0]*L + coef[1]*M + coef[2]*S
    L2, M2, S2 = lms
    r2 = 0.0809444479*L2 - 0.130504409*M2 + 0.116721066*S2
    g2 = -0.0102485335*L2 + 0.0540193266*M2 - 0.113614708*S2
    b2 = -0.000365296938*L2 - 0.00412161469*M2 + 0.693511405*S2
    def enc(c):
        c = max(0.0, min(1.0, c))
        c = 12.92*c if c <= 0.0031308 else 1.055*c**(1/2.4) - 0.055
        return f"{round(c*255):02x}"
    return "#" + enc(r2) + enc(g2) + enc(b2)

# ---------------- 报告 ----------------

def check(name, colors, ground, *, min_contrast, band=None, min_chroma=None, min_de=None):
    print(f"\n{'='*72}\n{name}  (底色 {ground})\n{'='*72}")
    ok = True
    for label, hexv in colors.items():
        c = contrast(hexv, ground)
        L, C, H = oklch(hexv)
        flags = []
        if c < min_contrast: flags.append(f"对比度 {c:.2f} < {min_contrast}"); ok = False
        if band and not (band[0] <= L <= band[1]): flags.append(f"明度 {L:.3f} 不在 {band}"); ok = False
        if min_chroma and C < min_chroma: flags.append(f"色度 {C:.3f} < {min_chroma}"); ok = False
        mark = "✗" if flags else "✓"
        print(f"  {mark} {label:14s} {hexv}  对比 {c:5.2f}:1  L={L:.3f} C={C:.3f} H={H:5.1f}"
              + ("   ← " + "; ".join(flags) if flags else ""))
    if min_de:
        worst = (1e9, None, None, None)
        for (n1, c1), (n2, c2) in combinations(colors.items(), 2):
            for kind in ("normal", "protan", "deutan", "tritan"):
                a = c1 if kind == "normal" else simulate(c1, kind)
                b = c2 if kind == "normal" else simulate(c2, kind)
                d = de2000(a, b)
                if d < worst[0]: worst = (d, n1, n2, kind)
        d, n1, n2, kind = worst
        mark = "✓" if d >= min_de else "✗"
        if d < min_de: ok = False
        print(f"\n  {mark} 最差分离度 ΔE2000 = {d:.1f}  ({n1} vs {n2},{kind})  要求 ≥{min_de}")
    return ok


# ---------------- OKLCH -> sRGB(用于按明度微调) ----------------

def _enc(c):
    c = max(0.0, min(1.0, c))
    c = 12.92*c if c <= 0.0031308 else 1.055*c**(1/2.4) - 0.055
    return round(c*255)

def oklch2hex(L, C, H):
    a = C * math.cos(math.radians(H)); b = C * math.sin(math.radians(H))
    l_ = L + 0.3963377774*a + 0.2158037573*b
    m_ = L - 0.1055613458*a - 0.0638541728*b
    s_ = L - 0.0894841775*a - 1.2914855480*b
    l, m, s = l_**3, m_**3, s_**3
    r = +4.0767416621*l - 3.3077115913*m + 0.2309699292*s
    g = -1.2684380046*l + 2.6097574011*m - 0.3413193965*s
    bb = -0.0041960863*l - 0.7034186147*m + 1.7076147010*s
    return "#%02x%02x%02x" % (_enc(r), _enc(g), _enc(bb))

def darken_to_contrast(hexv, ground, target):
    """保持色相/色度,只降明度,直到对底色的对比度达标。"""
    L, C, H = oklch(hexv)
    for step in range(0, 260):
        cand = oklch2hex(max(0.0, L - step * 0.002), C, H)
        if contrast(cand, ground) >= target:
            return cand
    return "#000000"


# ============================================================================
# 主流程
# ============================================================================

import os, re, sys
from itertools import combinations

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, "..", "src"))
CSS_PATH = os.path.join(SRC, "styles", "cyber.css")


def token_block(css, selector):
    i = css.index(selector)
    j = css.index("}", i)
    return dict(re.findall(r"(--cy-[\w-]+)\s*:\s*([^;]+);", css[i:j]))


def hex_tokens(css, selector):
    i = css.index(selector)
    j = css.index("}", i)
    return dict(re.findall(r"(--cy-[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;", css[i:j]))


DARK_SEL = ':root,\n:root[data-theme="dark"] {'
LIGHT_SEL = ':root[data-theme="light"] {'

# 与主题无关、有意写死的颜色
ALLOW = {
    "components/cyber/SeverityTag.vue": {"#0c1016", "#ffffff"},  # 按底色亮度算出的字色
    "views/Manage.vue": {"#fff"},                                # 二维码底必须是白的
}

# 深色图表色的色盲分离度是**已知不达标**的,单独列出来,不让它把整个检查判红
KNOWN_FAILURES = {("深色", "protan"), ("深色", "deutan")}


def main() -> int:
    css = open(CSS_PATH, encoding="utf-8").read()
    dark, light = token_block(css, DARK_SEL), token_block(css, LIGHT_SEL)
    problems = []

    # ---- 1. 两套令牌对称 ----
    only_d, only_l = set(dark) - set(light), set(light) - set(dark)
    if only_d or only_l:
        problems.append(f"令牌不对称:只有深色 {sorted(only_d)},只有亮色 {sorted(only_l)}")
        print(f"✗ 两套令牌不对称  只有深色 {sorted(only_d)}  只有亮色 {sorted(only_l)}")
    else:
        print(f"✓ 两套令牌对称,各 {len(dark)} 个")

    # ---- 2. 组件里没有裸颜色 ----
    hexre, rgbre = re.compile(r"#[0-9a-fA-F]{3,8}\b"), re.compile(r"rgba?\(\s*\d")
    raw = 0
    for root, _, files in os.walk(SRC):
        if "node_modules" in root:
            continue
        for f in sorted(files):
            if not f.endswith((".vue", ".css", ".ts")):
                continue
            rel = os.path.relpath(os.path.join(root, f), SRC)
            if rel in ("styles/cyber.css", "theme.ts"):
                continue                       # 令牌与 naive-ui 覆盖的定义处
            text = open(os.path.join(root, f), encoding="utf-8").read()
            allowed = {a.lower() for a in ALLOW.get(rel.replace(os.sep, "/"), set())}
            hits = [h for h in hexre.findall(text) if h.lower() not in allowed]
            hits += rgbre.findall(text)
            if hits:
                raw += len(hits)
                print(f"✗ {rel}: 裸颜色 {hits[:6]}")
    if raw:
        problems.append(f"{raw} 处裸颜色")
    else:
        print("✓ 组件里没有裸颜色")

    # ---- 3. 引用的令牌都有定义 ----
    used = set()
    for root, _, files in os.walk(SRC):
        if "node_modules" in root:
            continue
        for f in files:
            if not f.endswith((".vue", ".css", ".ts")):
                continue
            body = open(os.path.join(root, f), encoding="utf-8").read()
            body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)     # 注释里的是文档示例
            body = re.sub(r"^\s*(//|\s\*).*$", "", body, flags=re.M)
            used |= set(re.findall(r"var\((--cy-[\w-]+)", body))
    missing = sorted(used - set(dark))
    if missing:
        problems.append(f"引用了未定义的令牌 {missing}")
        print(f"✗ 用到但没定义:{missing}")
    else:
        print(f"✓ 引用的 {len(used)} 个令牌都有定义")
    unused = sorted(set(dark) - used)
    if unused:
        print(f"  提示:定义了但没用到 —— {unused}")

    # ---- 4. 对比度与色盲分离度 ----
    TEXT_TOKENS = ["--cy-ink", "--cy-ink-2", "--cy-ink-3", "--cy-cyan", "--cy-up",
                   "--cy-degraded", "--cy-down", "--cy-unknown", "--cy-info",
                   "--cy-magenta", "--cy-violet"]
    for name, sel in (("深色", DARK_SEL), ("亮色", LIGHT_SEL)):
        t = hex_tokens(css, sel)
        card, body_bg = t["--cy-card"], t["--cy-body"]
        print(f"\n--- {name}  面板底 {card} / 页面底 {body_bg} ---")
        for k in TEXT_TOKENS:
            if k not in t:
                continue
            c = min(contrast(t[k], card), contrast(t[k], body_bg))
            if c < 4.5:
                problems.append(f"{name} {k} 对比度 {c:.2f}:1 < 4.5")
                print(f"  ✗ {k:16s} {t[k]}  最差 {c:5.2f}:1  ← 正文要 ≥4.5:1")
        cat = {f"cat{i}": t[f"--cy-cat-{i}"] for i in range(1, 9)}
        for k, v in cat.items():
            c = min(contrast(v, card), contrast(v, body_bg))
            if c < 3.0:
                problems.append(f"{name} {k} 对比度 {c:.2f}:1 < 3.0")
                print(f"  ✗ {k} {v}  最差 {c:5.2f}:1  ← 图表要 ≥3:1")
            L, C, _ = oklch(v)
            if C < 0.10:
                print(f"  ! {k} {v} 色度 {C:.3f} 偏低,在别的线旁边会显灰")
        for kind in ("normal", "protan", "deutan"):
            w = min(((de2000(a if kind == "normal" else simulate(a, kind),
                             b if kind == "normal" else simulate(b, kind)), n1, n2)
                     for (n1, a), (n2, b) in combinations(cat.items(), 2)))
            known = (name, kind) in KNOWN_FAILURES
            if w[0] >= 8.0:
                print(f"  ✓ {kind:7s} 最差 ΔE2000 {w[0]:5.1f}")
            elif known:
                print(f"  ✗ {kind:7s} 最差 ΔE2000 {w[0]:5.1f}  ({w[1]}/{w[2]}) ← 已知缺陷,见 theme.ts")
            else:
                problems.append(f"{name} {kind} 分离度 {w[0]:.1f} < 8")
                print(f"  ✗ {kind:7s} 最差 ΔE2000 {w[0]:5.1f}  ({w[1]}/{w[2]})")
        print(f"  文字类最差对比度 {min(min(contrast(t[k],card),contrast(t[k],body_bg)) for k in TEXT_TOKENS if k in t):.2f}:1")

    print()
    if problems:
        print(f"✗ {len(problems)} 项不通过:")
        for p in problems:
            print(f"    - {p}")
        return 1
    print("✓ 全部通过(已知缺陷除外)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
