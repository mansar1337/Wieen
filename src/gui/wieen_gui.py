#!/usr/bin/env python3
"""Wieen — the interface of the injector.

Soft, dark, and split in tabs:

    01 install   build the agent and register it in the flatpak runtime
    02 launch    start Sober (optionally straight into a place)
    03 attach    talk to the agent and show the greeting in the game

The workspace is three tabs — the script, the console, and the agent — and
switching between them is animated with a short blur, so a page arrives out
of focus and settles.

    python3 src/gui/wieen_gui.py
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import time
import traceback
from pathlib import Path

from PyQt6.QtCore import (QAbstractAnimation, QEasingCurve, QPoint, QPointF,
                          QProcess, QProcessEnvironment, QRectF,
                          QPropertyAnimation, QSize, Qt, QTimer, pyqtProperty,
                          pyqtSignal)
from PyQt6.QtGui import (QColor, QFont, QFontDatabase, QIcon, QKeySequence,
                         QLinearGradient, QPainter, QPainterPath, QPalette,
                         QPen, QRadialGradient, QShortcut, QTextCharFormat,
                         QSyntaxHighlighter)
from PyQt6.QtWidgets import (QApplication, QFileDialog, QFrame,
                             QGraphicsBlurEffect, QGraphicsOpacityEffect,
                             QHBoxLayout, QLabel, QMainWindow,
                             QPlainTextEdit, QPushButton, QStackedWidget,
                             QVBoxLayout, QWidget)

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "src" / "cli" / "wieen.py"
TOAST = REPO / "tools" / "toast.luau"
PY = sys.executable or "python3"

# ------------------------------------------------------------------ theme

BG        = "#070708"
TEXT      = "#e7e7ec"
DIM       = "#9a9aa4"
FAINT     = "#5d5d68"
WHITE     = "#fbfbfd"
ERR       = "#e0928f"
OK        = "#a8d3b6"

GLASS     = 9      # alpha of a panel's fill, out of 255
GLASS_HI  = 15     # alpha of its hairline
RADIUS    = 16

MONO = "JetBrainsMono Nerd Font Mono"

FADE_MS = 300
BLUR_FROM = 13.0


def mono(size: int, weight: QFont.Weight = QFont.Weight.Normal) -> QFont:
    families = QFontDatabase.families()
    for name in (MONO, "JetBrains Mono", "DejaVu Sans Mono", "monospace"):
        if name in families or name == "monospace":
            f = QFont(name, size)
            break
    else:  # pragma: no cover
        f = QFont("monospace", size)
    f.setWeight(weight)
    f.setStyleHint(QFont.StyleHint.Monospace)
    return f


def soft(color: str, alpha: int) -> QColor:
    c = QColor(color)
    c.setAlpha(alpha)
    return c


QSS = f"""
QWidget {{
    background: transparent;
    color: {TEXT};
}}
QLabel {{
    background: transparent;
}}
QLineEdit {{
    background: rgba(0, 0, 0, 22%);
    border: 1px solid rgba(255, 255, 255, 6%);
    border-radius: 9px;
    padding: 7px 10px;
    selection-background-color: rgba(255, 255, 255, 12%);
    selection-color: {WHITE};
}}
QLineEdit:focus {{
    border: 1px solid rgba(255, 255, 255, 16%);
}}
QPlainTextEdit {{
    background: rgba(0, 0, 0, 20%);
    border: 1px solid rgba(255, 255, 255, 5%);
    border-radius: 12px;
    padding: 10px;
    selection-background-color: rgba(255, 255, 255, 13%);
    selection-color: {WHITE};
}}
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: rgba(255, 255, 255, 9%);
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: rgba(255, 255, 255, 16%);
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: rgba(255, 255, 255, 9%);
    border-radius: 3px;
    min-width: 30px;
}}
QToolTip {{
    background: #14141a;
    color: {TEXT};
    border: 1px solid rgba(255, 255, 255, 10%);
    padding: 5px 8px;
}}
"""


# ------------------------------------------------------------------ painting


class SoftButton(QPushButton):
    """A rounded button that is painted, not styled: a sheet of glass."""

    def __init__(self, text: str, primary: bool = False, parent=None,
                 icon: str | None = None):
        super().__init__(text, parent)
        self.primary = primary
        self.icon = icon
        self._hover = 0.0
        self.setFont(mono(10))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFlat(True)
        self.setMinimumHeight(32)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self._anim = QPropertyAnimation(self, b"glow", self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def sizeHint(self) -> QSize:
        w = self.fontMetrics().horizontalAdvance(self.text()) + 34
        if self.icon:
            w += 21
        return QSize(max(w, 64), 32)

    @pyqtProperty(float)
    def glow(self) -> float:
        return self._hover

    @glow.setter
    def glow(self, value: float) -> None:
        self._hover = value
        self.update()

    def animate_to(self, value: float) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._hover)
        self._anim.setEndValue(value)
        self._anim.start()

    def enterEvent(self, event) -> None:
        if self.isEnabled():
            self.animate_to(1.0)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self.animate_to(0.0)
        super().leaveEvent(event)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        enabled = self.isEnabled()
        h = self._hover if enabled else 0.0

        if self.primary and enabled:
            fill = QColor(WHITE)
            fill.setAlpha(int(232 - 14 * h))
        else:
            fill = QColor(255, 255, 255, int(6 + 10 * h) if enabled else 3)
        p.setBrush(fill)
        p.setPen(QColor(255, 255, 255, int(18 + 26 * h) if enabled else 8))
        p.drawRoundedRect(r, 9, 9)

        if enabled and h > 0:
            p.setPen(QColor(255, 255, 255, int(30 * h)))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), 8.5, 8.5)

        if self.primary and enabled:
            p.setPen(QColor("#08080a"))
        elif enabled:
            p.setPen(QColor(DIM).lighter(int(100 + 40 * h)))
        else:
            p.setPen(QColor(FAINT))
        p.setFont(self.font())
        color = p.pen().color()
        text_w = self.fontMetrics().horizontalAdvance(self.text())
        icon_w = 14 if self.icon else 0
        gap = 7 if self.icon else 0
        total = icon_w + gap + text_w
        left = (self.width() - total) / 2
        if self.icon:
            self._paint_icon(p, left, self.height() / 2, color)
            text_rect = QRectF(left + icon_w + gap, 0,
                               text_w + 2, self.height())
            p.drawText(text_rect,
                       int(Qt.AlignmentFlag.AlignVCenter |
                           Qt.AlignmentFlag.AlignLeft), self.text())
        else:
            p.drawText(self.rect(), int(Qt.AlignmentFlag.AlignCenter),
                       self.text())

    def _paint_icon(self, p: QPainter, x: float, cy: float,
                    color: QColor) -> None:
        """A small line icon, drawn where the text would start."""
        kind = self.icon
        if not kind:
            return
        s = 14.0
        top = cy - s / 2
        p.save()
        pen = QPen(color, 1.5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        if kind == "run":
            path = QPainterPath()
            path.moveTo(x + 2.5, top + 1.8)
            path.lineTo(x + 12.0, cy)
            path.lineTo(x + 2.5, top + s - 1.8)
            path.closeSubpath()
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(color)
            p.drawPath(path)
        elif kind == "open":
            p.drawRoundedRect(QRectF(x + 1.0, top + 4.0, 12.0, 8.5), 1.6,
                              1.6)
            path = QPainterPath()
            path.moveTo(x + 1.0, top + 4.5)
            path.lineTo(x + 1.0, top + 2.2)
            path.quadTo(x + 1.0, top + 1.4, x + 2.0, top + 1.4)
            path.lineTo(x + 5.4, top + 1.4)
            path.lineTo(x + 6.8, top + 3.2)
            path.lineTo(x + 11.0, top + 3.2)
            path.quadTo(x + 12.0, top + 3.2, x + 12.0, top + 4.0)
            p.drawPath(path)
        elif kind == "save":
            p.drawRoundedRect(QRectF(x + 1.5, top + 1.5, 11.0, 11.0), 1.8,
                              1.8)
            p.drawRoundedRect(QRectF(x + 4.2, top + 1.5, 5.6, 4.0), 0.8,
                              0.8)
            p.drawRoundedRect(QRectF(x + 4.0, top + 8.0, 6.0, 4.5), 0.8,
                              0.8)
        elif kind == "clear":
            p.drawLine(QPointF(x + 2.0, top + 3.2),
                       QPointF(x + 12.0, top + 3.2))
            p.drawLine(QPointF(x + 5.0, top + 3.2),
                       QPointF(x + 5.0, top + 1.6))
            p.drawLine(QPointF(x + 9.0, top + 3.2),
                       QPointF(x + 9.0, top + 1.6))
            p.drawLine(QPointF(x + 5.0, top + 1.6),
                       QPointF(x + 9.0, top + 1.6))
            path = QPainterPath()
            path.moveTo(x + 3.2, top + 4.0)
            path.lineTo(x + 4.2, top + 12.4)
            path.quadTo(x + 4.3, top + 13.2, x + 5.1, top + 13.2)
            path.lineTo(x + 8.9, top + 13.2)
            path.quadTo(x + 9.7, top + 13.2, x + 9.8, top + 12.4)
            path.lineTo(x + 10.8, top + 4.0)
            p.drawPath(path)
        elif kind == "attach":
            p.drawEllipse(QRectF(x + 1.0, top + 3.4, 6.0, 7.2))
            p.drawEllipse(QRectF(x + 7.0, top + 3.4, 6.0, 7.2))
            p.drawLine(QPointF(x + 4.0, cy), QPointF(x + 10.0, cy))
        elif kind == "bolt":
            path = QPainterPath()
            path.moveTo(x + 7.8, top + 0.8)
            path.lineTo(x + 2.6, top + 8.0)
            path.lineTo(x + 6.6, top + 8.0)
            path.lineTo(x + 5.4, top + 13.2)
            path.lineTo(x + 11.4, top + 5.6)
            path.lineTo(x + 7.2, top + 5.6)
            path.closeSubpath()
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(color)
            p.drawPath(path)
        p.restore()


class GlassCard(QWidget):
    """A rounded sheet of frosted glass over the backdrop."""

    def __init__(self, radius: int = RADIUS, parent=None):
        super().__init__(parent)
        self.radius = radius
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)

        # the sheet itself
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(255, 255, 255, GLASS))
        p.drawRoundedRect(r, self.radius, self.radius)

        # A thin highlight along the top, the way glass catches light.
        # The gradient goes through a brush: Qt 6.12 in PyQt aborts on
        # QPainter.fillRect(QRectF, QGradient).
        top = QLinearGradient(0, 0, 0, 42)
        top.setColorAt(0.0, QColor(255, 255, 255, 16))
        top.setColorAt(1.0, QColor(255, 255, 255, 0))
        path = QPainterPath()
        path.addRoundedRect(r, self.radius, self.radius)
        p.setClipPath(path)
        p.setBrush(top)
        p.drawRect(QRectF(0, 0, self.width(), 42))
        p.setClipping(False)

        # the hairline
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QColor(255, 255, 255, GLASS_HI))
        p.drawRoundedRect(r, self.radius, self.radius)


class Veil(QWidget):
    """A sheet that covers the workspace while a page settles."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG))


class Backdrop(QWidget):
    """The wallpaper of the window: a dark gradient and two soft blooms."""

    def __init__(self):
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        base = QLinearGradient(0, 0, 0, h)
        base.setColorAt(0.0, QColor("#0c0c10"))
        base.setColorAt(0.55, QColor("#08080a"))
        base.setColorAt(1.0, QColor("#050506"))
        p.fillRect(self.rect(), base)

        bloom = QRadialGradient(w * 0.22, h * 0.10, w * 0.55)
        bloom.setColorAt(0.0, QColor(120, 130, 165, 26))
        bloom.setColorAt(0.55, QColor(90, 95, 120, 10))
        bloom.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.fillRect(self.rect(), bloom)

        bloom2 = QRadialGradient(w * 0.92, h * 0.92, w * 0.5)
        bloom2.setColorAt(0.0, QColor(60, 70, 90, 20))
        bloom2.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.fillRect(self.rect(), bloom2)


# ------------------------------------------------------------------ tabs


class TabBar(QWidget):
    """Pills with an indicator that glides between them."""

    changed = pyqtSignal(int)

    def __init__(self, labels: list[str], parent=None):
        super().__init__(parent)
        self.labels = labels
        self.index = 0
        self._hover = -1
        self.setFont(mono(10, QFont.Weight.DemiBold))
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(40)
        self._pill = QRectF()
        self._anim = QPropertyAnimation(self, b"pill", self)
        self._anim.setDuration(320)
        self._anim.setEasingCurve(QEasingCurve.Type.OutBack)
        QTimer.singleShot(0, self.place_pill)

    def sizeHint(self) -> QSize:
        width = sum(self.label_width(i) + 6 for i in range(len(self.labels)))
        return QSize(width, 40)

    def minimumSizeHint(self) -> QSize:
        return self.sizeHint()

    def label_width(self, i: int) -> int:
        return self.fontMetrics().horizontalAdvance(self.labels[i]) + 30

    def tab_rect(self, i: int) -> QRectF:
        x = 0.0
        for k in range(i):
            x += self.label_width(k) + 6
        return QRectF(x, 4, self.label_width(i), self.height() - 8)

    def place_pill(self) -> None:
        self._pill = self.tab_rect(self.index)
        self.update()

    def select(self, i: int) -> None:
        if i == self.index:
            return
        start = self._pill
        end = self.tab_rect(i)
        self.index = i
        self._anim.stop()
        self._anim.setStartValue(start)
        self._anim.setEndValue(end)
        self._anim.start()
        self.changed.emit(i)
        self.update()

    def hit(self, pos: QPoint) -> int:
        for i in range(len(self.labels)):
            if self.tab_rect(i).contains(pos):
                return i
        return -1

    def mousePressEvent(self, event) -> None:
        i = self.hit(event.position())
        if i >= 0:
            self.select(i)

    def mouseMoveEvent(self, event) -> None:
        i = self.hit(event.position())
        if i != self._hover:
            self._hover = i
            self.update()

    def leaveEvent(self, event) -> None:
        self._hover = -1
        self.update()

    def resizeEvent(self, event) -> None:
        self._pill = self.tab_rect(self.index)

    @pyqtProperty(QRectF)
    def pill(self) -> QRectF:
        return self._pill

    @pill.setter
    def pill(self, value: QRectF) -> None:
        self._pill = value
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        if not self._pill.isNull():
            p.setPen(QColor(255, 255, 255, 14))
            p.setBrush(QColor(255, 255, 255, 11))
            p.drawRoundedRect(self._pill, 9, 9)

        for i, label in enumerate(self.labels):
            r = self.tab_rect(i)
            if i == self.index:
                p.setPen(QColor(WHITE))
            elif i == self._hover:
                p.setPen(QColor(DIM).lighter(115))
            else:
                p.setPen(QColor(FAINT).lighter(115))
            p.setFont(self.font())
            p.drawText(r, int(Qt.AlignmentFlag.AlignCenter), label)


# ------------------------------------------------------------------ editor


class LuauHighlighter(QSyntaxHighlighter):
    KEYWORDS = ("and break do else elseif end false for function if in "
                "local nil not or repeat return then true until while "
                "continue export type").split()
    BUILTINS = ("game workspace script print warn error pcall xpcall "
                "Instance Enum task wait typeof tostring tonumber pairs "
                "ipairs next select string table math os coroutine").split()

    def __init__(self, document):
        super().__init__(document)
        def fmt(color: str, italic: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            f.setFontItalic(italic)
            return f
        self.keyword = fmt("#cdcdd4")
        self.builtin = fmt("#9ea0aa")
        self.string = fmt("#9dab9f")
        self.comment = fmt("#565660", True)
        self.number = fmt("#bdbeac")

    def highlightBlock(self, text: str) -> None:
        comment_at = text.find("--")
        code = text if comment_at < 0 else text[:comment_at]
        if comment_at >= 0:
            self.setFormat(comment_at, len(text) - comment_at, self.comment)

        for m in re.finditer(r'"[^"]*"|\'[^\']*\'', code):
            self.setFormat(m.start(), len(m.group(0)), self.string)
        for m in re.finditer(r"\b\d+(\.\d+)?\b", code):
            self.setFormat(m.start(), len(m.group(0)), self.number)
        for m in re.finditer(r"[A-Za-z_]\w*", code):
            word = m.group(0)
            if word in self.KEYWORDS:
                self.setFormat(m.start(), len(word), self.keyword)
            elif word in self.BUILTINS:
                self.setFormat(m.start(), len(word), self.builtin)


class LineNumbers(QWidget):
    def __init__(self, editor: "ScriptEditor"):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self.editor.gutter_width(), 0)

    def paintEvent(self, event) -> None:
        self.editor.paint_gutter(event)


class ScriptEditor(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setFont(mono(13))
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.gutter = LineNumbers(self)
        self.blockCountChanged.connect(lambda _: self.update_gutter_width())
        self.updateRequest.connect(self.on_update_request)
        self.update_gutter_width()
        self.highlighter = LuauHighlighter(self.document())

    def gutter_width(self) -> int:
        digits = max(2, len(str(max(1, self.blockCount()))))
        return 22 + self.fontMetrics().horizontalAdvance("0") * digits

    def update_gutter_width(self) -> None:
        self.setViewportMargins(self.gutter_width(), 0, 0, 0)

    def on_update_request(self, rect, dy) -> None:
        if dy:
            self.gutter.scroll(0, dy)
        else:
            self.gutter.update(0, rect.y(), self.gutter.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_gutter_width()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.gutter.setGeometry(cr.left() + 10, cr.top(), self.gutter_width(),
                                cr.height())

    def paint_gutter(self, event) -> None:
        painter = QPainter(self.gutter)
        painter.fillRect(event.rect(), QColor(0, 0, 0, 0))
        painter.setFont(self.font())
        block = self.firstVisibleBlock()
        number = block.blockNumber() + 1
        top = int(self.blockBoundingGeometry(block).translated(
            self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.setPen(QColor("#40404a"))
                painter.drawText(0, top, self.gutter.width() - 10,
                                 self.fontMetrics().height(),
                                 int(Qt.AlignmentFlag.AlignRight), str(number))
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            number += 1


class Console(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(mono(12))
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setMaximumBlockCount(4000)
        self.setPlaceholderText("the output of the game will be here")

    def _append(self, html: str) -> None:
        self.appendHtml(html)
        bar = self.verticalScrollBar()
        bar.setValue(bar.maximum())

    def log(self, text: str, color: str = DIM, prefix: str = "·") -> None:
        stamp = time.strftime("%H:%M:%S")
        self._append(f'<span style="color:{FAINT}">{stamp}</span> '
                     f'<span style="color:{color}">{prefix} '
                     f'{self.escape(text)}</span>')

    def out(self, text: str) -> None:
        self._append(f'<span style="color:{TEXT}">{self.escape(text)}</span>')

    @staticmethod
    def escape(text: str) -> str:
        return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\n", "<br>")
                .replace(" ", "&nbsp;"))


class Task:
    """A function on a thread of its own.

    The result is not delivered with a signal: a queued signal can reach a
    window that its receiver has already lost, and PyQt then walks a dead
    wrapper and segfaults.  The worker only drops its answer into a queue,
    and the window picks it up from the event loop.
    """

    def __init__(self):
        self.queue: queue.SimpleQueue = queue.SimpleQueue()

    def run(self, fn) -> None:
        def body():
            try:
                self.queue.put((True, fn()))
            except Exception as exc:  # noqa: BLE001 — shown to the user
                self.queue.put((False, str(exc) or exc.__class__.__name__))
        threading.Thread(target=body, daemon=True).start()


# ------------------------------------------------------------------ window


class App(QApplication):
    """An exception in a slot is printed, not fatal.

    PyQt turns an unhandled exception of a slot into qFatal, and the whole
    interface disappears without a word.
    """

    def notify(self, obj, event) -> bool:
        try:
            return super().notify(obj, event)
        except Exception:  # noqa: BLE001 — reported, not raised
            traceback.print_exc()
            return False


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("wieen")
        logo = REPO / "docs" / "logo.png"
        if logo.exists():
            self.setWindowIcon(QIcon(str(logo)))
        self.resize(1200, 800)
        self.setMinimumSize(980, 640)
        self.setStyleSheet(QSS)

        self.installed = False
        self.attached = False
        self.place = ""
        self.busy = False
        self.launch_proc: QProcess | None = None
        self.momentum_proc: QProcess | None = None
        self.momentum_step = 0
        self.jobs: list[tuple[Task, object]] = []
        self._anims: list[QPropertyAnimation] = []
        self._pulse_value = 1.0
        self._fade_token = 0

        central = Backdrop()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 14, 18, 14)
        root.setSpacing(12)

        root.addWidget(self.build_header())

        body = QHBoxLayout()
        body.setSpacing(14)
        body.addWidget(self.build_workspace(), 1)
        root.addLayout(body, 1)

        self.beat_anim = QPropertyAnimation(self, b"beat", self)
        self.beat_anim.setStartValue(0.35)
        self.beat_anim.setEndValue(1.0)
        self.beat_anim.setDuration(750)
        self.beat_anim.setLoopCount(-1)
        self.beat_anim.setEasingCurve(QEasingCurve.Type.InOutSine)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(2500)

        self.jobs_timer = QTimer(self)
        self.jobs_timer.timeout.connect(self.drain_jobs)
        self.jobs_timer.start(90)

        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(
            lambda: self.clock.setText(time.strftime("%H:%M")))
        self.clock_timer.start(1000)

        QTimer.singleShot(120, self.probe)

    # -- motion

    @pyqtProperty(float)
    def beat(self) -> float:
        return self._pulse_value

    @beat.setter
    def beat(self, value: float) -> None:
        self._pulse_value = value
        if not hasattr(self, "state_dot"):
            return
        c = QColor(self.state_color)
        alpha = int(255 * max(0.0, min(1.0, value)))
        self.state_dot.setStyleSheet(
            f"color: rgba({c.red()}, {c.green()}, {c.blue()}, {alpha});")

    def start_pulse(self, on: bool) -> None:
        if on:
            if self.beat_anim.state() != QAbstractAnimation.State.Running:
                self.beat_anim.start()
        else:
            self.beat_anim.stop()
            self._pulse_value = 1.0
            self.state_dot.setStyleSheet(f"color: {self.state_color};")

    # -- header

    def build_header(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(46)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(6, 0, 6, 0)
        lay.setSpacing(14)

        logo = QLabel()
        pic = QPixmap_icon(REPO / "docs" / "logo.png", 26)
        if pic is not None:
            logo.setPixmap(pic)
        lay.addWidget(logo)

        mark = QLabel("WIEEN")
        mark.setFont(mono(13, QFont.Weight.DemiBold))
        mark.setStyleSheet(f"color: {WHITE}; letter-spacing: 7px;")
        lay.addWidget(mark)

        lay.addSpacing(6)

        self.state_dot = QLabel("●")
        self.state_dot.setFont(mono(9))
        self.state_color = FAINT
        self.state_dot.setStyleSheet(f"color: {FAINT};")
        self.state_label = QLabel("DETACHED")
        self.state_label.setFont(mono(9))
        self.state_label.setStyleSheet(f"color: {FAINT}; letter-spacing: 2px;")
        lay.addWidget(self.state_dot)
        lay.addWidget(self.state_label)

        self.place_sep = QLabel("·")
        self.place_sep.setFont(mono(10))
        self.place_sep.setStyleSheet(f"color: {FAINT};")
        self.place_sep.hide()
        lay.addWidget(self.place_sep)

        self.place_label = QLabel("")
        self.place_label.setFont(mono(10))
        self.place_label.setStyleSheet(f"color: {DIM};")
        lay.addWidget(self.place_label)
        lay.addStretch(1)

        self.clock = QLabel(time.strftime("%H:%M"))
        self.clock.setFont(mono(10))
        self.clock.setStyleSheet(f"color: {FAINT};")
        lay.addWidget(self.clock)
        return bar

    # -- momentum run

    def on_momentum(self) -> None:
        """Build, register, launch — straight from the page, no dialog."""
        if self.busy:
            return
        if self.momentum_proc and self.momentum_proc.state() != \
                QProcess.ProcessState.NotRunning:
            self.log("momentum run is already going", DIM, "01")
            return
        self.set_busy(True, "momentum")
        self.momentum_step = 0
        self.tabs.select(0)
        self.log("momentum run: build the agent and the compiler", DIM, "01")
        self.start_momentum(["make", "agent", "compile"], 0)

    def start_momentum(self, argv: list[str], step: int) -> None:
        proc = QProcess(self)
        self.momentum_proc = proc
        self.momentum_step = step
        proc.setWorkingDirectory(str(REPO))
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        proc.readyReadStandardOutput.connect(self.read_momentum)
        proc.finished.connect(self.momentum_done)
        proc.start(argv[0], argv[1:])
        if not proc.waitForStarted(5000):
            self.momentum_fail("the process did not start")

    def read_momentum(self) -> None:
        if not self.momentum_proc:
            return
        text = bytes(self.momentum_proc.readAllStandardOutput()).decode(
            errors="replace")
        prefix = ("01", "02", "03")[min(self.momentum_step, 2)]
        for line in text.splitlines():
            if not line.strip():
                continue
            low = line.lower()
            if any(word in low for word in ("error", "fatal", "failed")):
                self.log(line, ERR, prefix)
            else:
                self.log(line, DIM, prefix)

    def momentum_done(self, code: int, _status) -> None:
        if code != 0:
            self.momentum_fail(f"step {self.momentum_step + 1} failed "
                               f"(exit {code})")
            return
        if self.momentum_step == 0:
            self.log("preload: register it in the runtime", DIM, "02")
            script = REPO / "tools" / "install_preload.sh"
            self.start_momentum(
                ["sh", "-c", f'sudo -n bash "{script}" || '
                             f'pkexec env SUDO_HOME="$HOME" bash "{script}"'],
                1)
        elif self.momentum_step == 1:
            self.log("launch: starting Sober", DIM, "03")
            if not self.start_sober():
                self.momentum_fail("Sober did not start")
                return
            self.set_busy(False)
            self.log("momentum run: enter a place, then press ATTACH",
                     OK, "03")
        else:
            self.set_busy(False)

    def momentum_fail(self, message: str) -> None:
        self.log(f"momentum run: {message}", ERR, "!")
        self.set_busy(False)

    # -- workspace

    def build_workspace(self) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        head = QHBoxLayout()
        head.setContentsMargins(4, 0, 4, 0)
        self.tabs = TabBar(["SCRIPT", "AGENT"])
        self.tabs.changed.connect(self.on_tab)
        head.addWidget(self.tabs)
        head.addStretch(1)
        lay.addLayout(head)

        self.stack = QStackedWidget()
        self.stack.addWidget(self.build_script_page())
        self.stack.addWidget(self.build_agent_page())
        lay.addWidget(self.stack, 1)

        self.veil = Veil(self.stack)
        self.veil.hide()
        self.veil_effect = QGraphicsOpacityEffect(self.veil)
        self.veil_effect.setOpacity(0.0)
        self.veil.setGraphicsEffect(self.veil_effect)
        return wrap

    def build_script_page(self) -> QWidget:
        card = GlassCard()
        lay = QVBoxLayout(card)
        lay.setContentsMargins(18, 14, 18, 16)
        lay.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(8)
        self.file_label = QLabel("untitled.luau")
        self.file_label.setFont(mono(10))
        self.file_label.setStyleSheet(f"color: {DIM};")
        head.addWidget(self.file_label)
        head.addStretch(1)

        self.attach_button = SoftButton("ATTACH", icon="attach")
        self.attach_button.setToolTip(
            "connect to the game and post the notification")
        self.attach_button.clicked.connect(self.on_attach)
        head.addWidget(self.attach_button)

        self.momentum_button = SoftButton("MOMENTUM RUN", icon="bolt")
        self.momentum_button.setToolTip(
            "build the agent, register the preload, start Sober")
        self.momentum_button.clicked.connect(self.on_momentum)
        head.addWidget(self.momentum_button)

        self.run_button = SoftButton("RUN", primary=True, icon="run")
        self.run_button.setToolTip("run the script in the game (ctrl+enter)")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self.on_run)
        head.addWidget(self.run_button)
        for label, slot, tip, icon in (
                ("OPEN", self.on_open, "ctrl+o", "open"),
                ("SAVE", self.on_save, "ctrl+s", "save"),
                ("CLEAR", self.clear_script, "erase the text", "clear")):
            b = SoftButton(label, icon=icon)
            b.setToolTip(tip)
            b.clicked.connect(slot)
            head.addWidget(b)
        lay.addLayout(head)

        self.editor = ScriptEditor()
        self.editor.setPlaceholderText(
            '-- wieen\nprint("hello from", game.PlaceId)')
        lay.addWidget(self.editor, 3)

        # The console is not a place you go to, it is the floor of the page:
        # the script above, whatever it printed below, both in sight at once.
        line = QFrame()
        line.setFixedHeight(1)
        line.setStyleSheet("background: rgba(255, 255, 255, 8%);")
        lay.addWidget(line)

        head = QHBoxLayout()
        head.setSpacing(8)
        title = QLabel("CONSOLE")
        title.setFont(mono(9))
        title.setStyleSheet(f"color: {FAINT}; letter-spacing: 2px;")
        head.addWidget(title)
        head.addStretch(1)
        clear = SoftButton("CLEAR", icon="clear")
        clear.setToolTip("wipe the console")
        clear.clicked.connect(lambda: self.console.clear())
        head.addWidget(clear)
        lay.addLayout(head)

        self.console = Console()
        lay.addWidget(self.console, 2)
        return card

    def build_agent_page(self) -> QWidget:
        card = GlassCard()
        lay = QVBoxLayout(card)
        lay.setContentsMargins(18, 16, 18, 18)
        lay.setSpacing(14)

        title = QLabel("STATE")
        title.setFont(mono(9))
        title.setStyleSheet(f"color: {FAINT};")
        lay.addWidget(title)

        self.info_rows: dict[str, QLabel] = {}
        for key, what in (("socket", "socket"),
                          ("preload", "preload"),
                          ("agent", "agent"),
                          ("place", "place"),
                          ("build", "build")):
            row = QHBoxLayout()
            row.setSpacing(12)
            label = QLabel(what)
            label.setFont(mono(9))
            label.setFixedWidth(70)
            label.setStyleSheet(f"color: {FAINT};")
            value = QLabel("—")
            value.setFont(mono(10))
            value.setStyleSheet(f"color: {DIM};")
            value.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(label)
            row.addWidget(value, 1)
            self.info_rows[key] = value
            lay.addLayout(row)

        lay.addSpacing(8)
        note = QLabel("the agent lives inside the client process:\n"
                      "restart the game after make deploy")
        note.setFont(mono(9))
        note.setStyleSheet(f"color: {FAINT};")
        lay.addWidget(note)
        lay.addStretch(1)
        return card

    # -- teardown

    def closeEvent(self, event) -> None:
        self.timer.stop()
        self.jobs_timer.stop()
        self.jobs.clear()
        self.clock_timer.stop()
        self.beat_anim.stop()
        if self.momentum_proc and self.momentum_proc.state() != \
                QProcess.ProcessState.NotRunning:
            self.momentum_proc.terminate()
            self.momentum_proc.waitForFinished(1500)
        for a in self._anims:
            a.stop()
            a.setTargetObject(None)
        self._anims = []
        for i in range(self.stack.count()):
            self.stack.widget(i).setGraphicsEffect(None)
        self.veil.hide()
        super().closeEvent(event)

    # -- state

    def on_tab(self, index: int) -> None:
        prev = self.stack.currentIndex()
        if index == prev:
            return
        direction = 1 if index > prev else -1
        page = self.stack.widget(index)
        self.stack.setCurrentIndex(index)
        page.setGeometry(self.stack.rect())
        self.glide(page, direction)

    def glide(self, page: QWidget, direction: int) -> None:
        """The page slides in from the side it came from, out of focus.

        The old page is gone before the new one arrives, so nothing has to be
        blended: the page is born blurred and a little off its place, and the
        veil over the stack burns off while it travels.
        """
        for old in self._anims:
            old.stop()
            # the target may be an effect of a page that is about to lose it
            old.setTargetObject(None)
            old.deleteLater()
        self._anims = []
        for i in range(self.stack.count()):
            other = self.stack.widget(i)
            if other is page:
                continue
            other.move(0, 0)
            other.setGraphicsEffect(None)

        self._fade_token += 1
        token = self._fade_token

        origin = QPoint(direction * 30, 14)
        page.move(origin)

        effect = QGraphicsBlurEffect(page)
        effect.setBlurRadius(BLUR_FROM)
        effect.setBlurHints(QGraphicsBlurEffect.BlurHint.PerformanceHint)
        page.setGraphicsEffect(effect)

        self.veil.setGeometry(self.stack.rect())
        self.veil.raise_()
        self.veil_effect.setOpacity(0.45)
        self.veil.show()

        slide = QPropertyAnimation(page, b"pos", self)
        slide.setDuration(FADE_MS + 60)
        slide.setStartValue(origin)
        slide.setEndValue(QPoint(0, 0))
        slide.setEasingCurve(QEasingCurve.Type.OutCubic)

        blur = QPropertyAnimation(effect, b"blurRadius", self)
        blur.setDuration(FADE_MS + 40)
        blur.setStartValue(BLUR_FROM)
        blur.setEndValue(0.0)
        blur.setEasingCurve(QEasingCurve.Type.OutCubic)

        fade = QPropertyAnimation(self.veil_effect, b"opacity", self)
        fade.setDuration(FADE_MS)
        fade.setStartValue(0.45)
        fade.setEndValue(0.0)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)

        def finish() -> None:
            if token != self._fade_token:
                return
            for a in self._anims:
                a.stop()
                a.setTargetObject(None)
                a.deleteLater()
            self._anims = []
            page.move(0, 0)
            page.setGraphicsEffect(None)
            self.veil.hide()

        blur.finished.connect(finish)
        self._anims = [slide, blur, fade]
        for a in self._anims:
            a.start()

    def set_state(self) -> None:
        if self.attached:
            label, color = "ATTACHED", OK
        elif self.installed:
            label, color = "READY", DIM
        else:
            label, color = "DETACHED", FAINT
        self.state_color = color
        self.beat = self._pulse_value
        if self.beat_anim.state() != QAbstractAnimation.State.Running:
            self.state_dot.setStyleSheet(f"color: {color};")
        self.state_label.setText(label)
        self.state_label.setStyleSheet(f"color: {color}; letter-spacing: 2px;")
        self.place_label.setText(self.place)
        self.place_sep.setVisible(bool(self.place))

        self.run_button.setEnabled(self.attached and not self.busy)
        self.momentum_button.setEnabled(not self.busy)
        self.attach_button.primary = False
        self.attach_button.setEnabled(not self.busy)
        self.attach_button.setText("ATTACHED" if self.attached else "ATTACH")
        self.attach_button.setToolTip(
            "press again to repeat the notification" if self.attached
            else "connect to the game and post the notification")
        self.attach_button.update()
        self.info_rows["place"].setText(self.place or "—")

    def say(self, text: str) -> None:
        """Nothing to say: the console and the header already carry it."""
        del text

    def set_busy(self, busy: bool, text: str = "") -> None:
        del text
        self.busy = busy
        self.start_pulse(busy)
        self.set_state()

    # -- jobs

    def spawn(self, fn, callback) -> None:
        task = Task()
        self.jobs.append((task, callback))
        task.run(fn)

    def drain_jobs(self) -> None:
        if not self.jobs:
            return
        for entry in list(self.jobs):
            task, callback = entry
            try:
                ok, payload = task.queue.get_nowait()
            except queue.Empty:
                continue
            self.jobs.remove(entry)
            try:
                callback(ok, payload)
            except Exception:  # noqa: BLE001 — a slot must not kill the window
                traceback.print_exc()

    # -- probing

    def probe(self) -> None:
        def work():
            sys.path.insert(0, str(CLI.parent))
            import wieen
            return {
                "preload": wieen.preload_ok(),
                "socket": str(wieen.socket_path()),
                "alive": wieen.socket_path().exists(),
                "installed": wieen.agent_path().exists(),
                "build": f"{wieen.AGENT_BUILD.stat().st_size // 1024} KiB"
                if wieen.AGENT_BUILD.exists() else "not built",
            }

        self.spawn(work, self.on_probe)

    def on_probe(self, ok: bool, payload) -> None:
        if not ok:
            self.log(str(payload), DIM, "·")
            return
        info = payload
        self.info_rows["socket"].setText(Path(info["socket"]).name)
        state = {True: ("ok", OK), False: ("missing", ERR),
                 None: ("?", FAINT)}[info["preload"]]
        self.info_rows["preload"].setText(state[0])
        self.info_rows["preload"].setStyleSheet(f"color: {state[1]};")
        self.info_rows["agent"].setText("installed" if info["installed"]
                                        else "not installed")
        self.info_rows["build"].setText(info["build"])
        self.installed = bool(info["installed"] and info["preload"])
        self.set_state()

    def poll(self) -> None:
        if self.busy:
            return
        sock = Path(os.environ.get("WIEEN_SOCKET")) if \
            os.environ.get("WIEEN_SOCKET") else (
                Path.home() / ".var" / "app" / "org.vinegarhq.Sober" /
                "data" / "wieen" / "wieen.sock")
        if self.attached and not sock.exists():
            self.attached = False
            self.place = ""
            self.log("agent is gone: the game closed or restarted", ERR)
            self.set_state()

    # -- console helper

    def log(self, text: str, color: str = DIM, prefix: str = "·") -> None:
        self.console.log(text, color, prefix)

    def out(self, text: str) -> None:
        self.console.out(text)

    def clear_script(self) -> None:
        self.editor.clear()

    # -- launch: only the dialog calls this

    def start_sober(self) -> bool:
        """Start Sober and keep it as the window's child process.

        The CLI prints its log until the game exits, so the process lives as
        long as the game; the console of the window follows it.
        """
        if self.launch_proc and self.launch_proc.state() != \
                QProcess.ProcessState.NotRunning:
            self.log("Sober is already starting", DIM, "02")
            return True
        self.log("starting Sober", DIM, "02")
        proc = QProcess(self)
        self.launch_proc = proc
        proc.setWorkingDirectory(str(REPO))
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        # The greeting needs the game thread: without this the agent builds
        # a low-capability thread where game:GetService("Players") is nil.
        env = QProcessEnvironment.systemEnvironment()
        env.insert("WIEEN_INTHREAD", "1")
        proc.setProcessEnvironment(env)
        proc.readyReadStandardOutput.connect(self.read_launch)
        proc.finished.connect(self.launch_done)
        proc.start(PY, [str(CLI), "launch"])
        proc.waitForStarted(5000)
        started = proc.state() != QProcess.ProcessState.NotRunning
        if not started:
            self.log("Sober did not start", ERR, "02")
        return started

    def read_launch(self) -> None:
        if not self.launch_proc:
            return
        text = bytes(self.launch_proc.readAllStandardOutput()).decode(
            errors="replace").strip()
        for line in text.splitlines():
            low = line.lower()
            if any(word in low for word in ("error", "fatal", "crash")):
                self.log(line, ERR, "02")
            elif line.strip():
                self.out(line)

    def launch_done(self, code: int, _status) -> None:
        if code == 0:
            self.log("Sober closed", DIM, "02")
        else:
            self.log(f"Sober exited with code {code}", ERR, "02")

    # -- step 03: attach

    def on_attach(self) -> None:
        if self.busy:
            return
        if self.attached:
            self.log("already attached; posting the notification again",
                     DIM, "03")
        self.set_busy(True, "attach")

        def work() -> str:
            sys.path.insert(0, str(CLI.parent))
            import wieen
            agent = wieen.Agent(timeout=90.0)
            if not agent.connect():
                raise RuntimeError("the agent does not answer: the game is "
                                   "not running or the preload is missing")
            try:
                name = agent.exec("return tostring(game.Name)").strip()
                if name in ("", "LuaApp"):
                    raise RuntimeError(
                        f"the client is still in the menu ({name or '?'}): "
                        "enter a place and press ATTACH again")
                source = TOAST.read_text()
                result = ""
                for _ in range(15):
                    result = agent.exec(source).strip()
                    if not result.startswith("wait"):
                        break
                    time.sleep(1.0)
                # A "wait" is not a success, and neither is an error of the
                # chunk: the toast either says "ok" or the attach is a lie.
                if result != "ok":
                    raise RuntimeError(
                        f"the greeting did not go through ({result or '?'})")
                return name
            finally:
                agent.close()

        self.spawn(work, self.on_attach_done)

    def on_attach_done(self, ok: bool, payload) -> None:
        self.set_busy(False)
        if not ok:
            self.log(str(payload), ERR, "03")
            return
        self.attached = True
        self.place = str(payload)
        self.log(f"attached to {self.place}", OK, "03")
        self.log("notification and F9 line sent", OK, "03")
        self.set_state()
        self.tabs.select(0)
        self.editor.setFocus()

    # -- run

    def on_run(self) -> None:
        if not self.attached or self.busy:
            return
        source = self.editor.toPlainText()
        if not source.strip():
            self.log("the script is empty", ERR, "!")
            return
        self.set_busy(True, "run")
        self.log("running the script", DIM, "»")

        def work() -> str:
            sys.path.insert(0, str(CLI.parent))
            import wieen
            agent = wieen.Agent(timeout=150.0)
            if not agent.connect():
                raise RuntimeError("the agent does not answer")
            try:
                return agent.exec(source)
            finally:
                agent.close()

        self.spawn(work, self.on_run_done)

    def on_run_done(self, ok: bool, payload) -> None:
        self.set_busy(False)
        if not ok:
            self.log(str(payload), ERR, "!")
            return
        if payload:
            self.out(str(payload))

    # -- files

    def on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "open script", str(REPO / "examples"), "Luau (*.luau *.lua)")
        if not path:
            return
        self.editor.setPlainText(Path(path).read_text(errors="replace"))
        self.file_label.setText(Path(path).name)
        self.tabs.select(0)
        self.log(f"opened {Path(path).name}", DIM, "+")

    def on_save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "save script", str(REPO / "examples" / "script.luau"),
            "Luau (*.luau)")
        if not path:
            return
        Path(path).write_text(self.editor.toPlainText())
        self.file_label.setText(Path(path).name)
        self.log(f"saved: {path}", OK, "+")


def QPixmap_icon(path: Path, size: int):
    """The logo, scaled down with a smooth filter."""
    from PyQt6.QtGui import QPixmap
    if not path.exists():
        return None
    pm = QPixmap(str(path))
    if pm.isNull():
        return None
    return pm.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio,
                     Qt.TransformationMode.SmoothTransformation)


def main() -> int:
    app = App(sys.argv)
    app.setApplicationName("wieen")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(BG))
    palette.setColor(QPalette.ColorRole.Base, QColor("#0b0b0e"))
    palette.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    app.setPalette(palette)
    window = Window()
    window.show()
    code = app.exec()
    # The teardown of QApplication in PyQt 6.12 walks a wrapper of an object
    # that is already gone and segfaults.  The loop is over, nothing is left
    # to write, so the process ends here instead of inside the destructor.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    # The interpreter teardown of PyQt 6.12 occasionally walks a dead wrapper
    # and segfaults after the window is already gone.  Nothing is left to
    # flush by then, so the process ends without it.
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        os._exit(0)
    except Exception:  # pragma: no cover
        traceback.print_exc()
        os._exit(1)
