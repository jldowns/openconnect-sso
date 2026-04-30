import asyncio
import json
import multiprocessing
import signal
import sys
from urllib.parse import urlparse

import attr
import pkg_resources
import structlog

from PyQt6.QtCore import QUrl, QTimer, pyqtSlot, Qt
from PyQt6.QtNetwork import QNetworkCookie, QNetworkProxy, QSslCertificate
from PyQt6.QtWebEngineCore import QWebEngineScript, QWebEngineProfile, QWebEnginePage
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QApplication, QWidget, QSizePolicy, QVBoxLayout

from openconnect_sso import config


app = None
profile = None
logger = structlog.get_logger("webengine")


@attr.s
class Url:
    url = attr.ib()


@attr.s
class Credentials:
    credentials = attr.ib()


@attr.s
class StartupInfo:
    url = attr.ib()
    credentials = attr.ib()


@attr.s
class SetCookie:
    name = attr.ib()
    value = attr.ib()


class Process(multiprocessing.Process):
    def __init__(self, proxy, display_mode):
        super().__init__()

        self._commands = multiprocessing.Queue()
        self._states = multiprocessing.Queue()
        self.proxy = proxy
        self.display_mode = display_mode

    def authenticate_at(self, url, credentials):
        self._commands.put(StartupInfo(url, credentials))

    async def get_state_async(self):
        while self.is_alive():
            try:
                return self._states.get_nowait()
            except multiprocessing.queues.Empty:
                await asyncio.sleep(0.01)
        if not self.is_alive():
            raise EOFError()

    def run(self):
        # To work around funky GC conflicts with C++ code by ensuring QApplication terminates last
        global app
        global profile

        signal.signal(signal.SIGTERM, on_sigterm)
        signal.signal(signal.SIGINT, signal.SIG_DFL)

        cfg = config.load()

        argv = sys.argv.copy()
        if self.display_mode == config.DisplayMode.HIDDEN:
            argv += ["-platform", "minimal"]
        app = QApplication(argv)
        profile = QWebEngineProfile("openconnect-sso")

        if self.proxy:
            parsed = urlparse(self.proxy)
            if parsed.scheme.startswith("socks5"):
                proxy_type = QNetworkProxy.Socks5Proxy
            elif parsed.scheme.startswith("http"):
                proxy_type = QNetworkProxy.HttpProxy
            else:
                raise ValueError("Unsupported proxy type", parsed.scheme)
            proxy = QNetworkProxy(proxy_type, parsed.hostname, parsed.port)

            QNetworkProxy.setApplicationProxy(proxy)

        # In order to make Python able to handle signals
        force_python_execution = QTimer()
        force_python_execution.start(200)

        def ignore():
            pass

        force_python_execution.timeout.connect(ignore)
        web = WebBrowser(cfg.auto_fill_rules, self._states.put, profile)

        startup_info = self._commands.get()
        logger.info("Browser started", startup_info=startup_info)

        logger.info("Loading page", url=startup_info.url)

        web.authenticate_at(QUrl(startup_info.url), startup_info.credentials)

        web.show()
        rc = app.exec()

        logger.info("Exiting browser")
        return rc

    async def wait(self):
        while self.is_alive():
            await asyncio.sleep(0.01)
        self.join()


def on_sigterm(signum, frame):
    global profile
    logger.info("Terminate requested.")
    # Force flush cookieStore to disk. Without this hack the cookieStore may
    # not be synced at all if the browser lives only for a short amount of
    # time. Something is off with the call order of destructors as there is no
    # such issue in C++.

    # See: https://github.com/qutebrowser/qutebrowser/commit/8d55d093f29008b268569cdec28b700a8c42d761
    cookie = QNetworkCookie()
    profile.cookieStore().deleteCookie(cookie)

    # Give some time to actually save cookies
    exit_timer = QTimer(app)
    exit_timer.timeout.connect(QApplication.quit)
    exit_timer.start(1000)  # ms


class WebBrowser(QWebEngineView):
    def __init__(self, auto_fill_rules, on_update, profile):
        super().__init__()
        self._on_update = on_update
        self._auto_fill_rules = auto_fill_rules
        page = QWebEnginePage(profile, self)
        self.setPage(page)
        cookie_store = self.page().profile().cookieStore()
        cookie_store.cookieAdded.connect(self._on_cookie_added)
        self.page().loadFinished.connect(self._on_load_finished)
        # Handle TLS client-cert challenges (e.g. Azure CBA / DOD CAC). Without
        # this signal hook QtWebEngine silently rejects every cert request.
        self.page().selectClientCertificate.connect(self._on_select_client_cert)

    def createWindow(self, type):
        if type == QWebEnginePage.WebDialog:
            self._popupWindow = WebPopupWindow(self.page().profile())
            return self._popupWindow.view()

    def authenticate_at(self, url, credentials):
        script_source = pkg_resources.resource_string(__name__, "user.js").decode()
        script = QWebEngineScript()
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.ApplicationWorld)
        script.setSourceCode(script_source)
        self.page().scripts().insert(script)

        if credentials:
            logger.info("Initiating autologin", cred=credentials)
            for url_pattern, rules in self._auto_fill_rules.items():
                script = QWebEngineScript()
                script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
                script.setWorldId(QWebEngineScript.ScriptWorldId.ApplicationWorld)
                script.setSourceCode(
                    f"""
// ==UserScript==
// @include {url_pattern}
// ==/UserScript==

function autoFill() {{
    {get_selectors(rules, credentials)}
    setTimeout(autoFill, 1000);
}}
autoFill();
"""
                )
                self.page().scripts().insert(script)

        self.load(QUrl(url))

    def _on_cookie_added(self, cookie):
        logger.debug("Cookie set", name=to_str(cookie.name()))
        self._on_update(SetCookie(to_str(cookie.name()), to_str(cookie.value())))

    def _on_load_finished(self, success):
        url = self.page().url().toString()
        logger.debug("Page loaded", url=url)

        self._on_update(Url(url))

    def _on_select_client_cert(self, selection):
        # Picks a TLS client cert when the IdP (e.g. Azure CBA) requests one.
        # On macOS the candidate list comes from the Keychain (via
        # CryptoTokenKit), which exposes CAC/PIV identities; on Linux it comes
        # from the NSS DB / PKCS#11 modules visible to Chromium.
        #
        # DOD CAC heuristic: of the 4 certs on the card, only the
        # "PIV Authentication" one is valid for TLS client auth. It is issued
        # by "DOD ID CA-*" and its subject CN is the user's name (contains
        # '.', no '-'). The Card Authentication cert has the same issuer but
        # a UUID-style CN; the Digital Signature / Encryption certs are
        # issued by "DOD EMAIL CA-*". Falls back to the first candidate for
        # non-CAC scenarios where there's typically only one cert anyway.
        certs = selection.certificates()
        logger.info("Client certificate requested", count=len(certs))
        if not certs:
            logger.warning("No client certificates available to QtWebEngine")
            return
        chosen = None
        for c in certs:
            subj_cn = " ".join(c.subjectInfo(QSslCertificate.SubjectInfo.CommonName) or [])
            iss_cn = " ".join(c.issuerInfo(QSslCertificate.SubjectInfo.CommonName) or [])
            logger.info("Candidate cert", subject=subj_cn, issuer=iss_cn)
            if "ID CA" in iss_cn.upper() and "." in subj_cn and "-" not in subj_cn:
                chosen = c
                break
        chosen = chosen or certs[0]
        subj_cn = " ".join(chosen.subjectInfo(QSslCertificate.SubjectInfo.CommonName) or [])
        iss_cn = " ".join(chosen.issuerInfo(QSslCertificate.SubjectInfo.CommonName) or [])
        logger.info("Selecting client cert", subject=subj_cn, issuer=iss_cn)
        selection.select(chosen)


class WebPopupWindow(QWidget):
    def __init__(self, profile):
        super().__init__()
        self._view = QWebEngineView(self)

        super().setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        super().setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)

        layout = QVBoxLayout()
        super().setLayout(layout)
        layout.addWidget(self._view)

        self._view.setPage(QWebEnginePage(profile, self._view))

        self._view.titleChanged.connect(super().setWindowTitle)
        self._view.page().geometryChangeRequested.connect(
            self.handleGeometryChangeRequested
        )
        self._view.page().windowCloseRequested.connect(super().close)

    def view(self):
        return self._view

    @pyqtSlot("const QRect")
    def handleGeometryChangeRequested(self, newGeometry):
        self._view.setMinimumSize(newGeometry.width(), newGeometry.height())
        super().move(newGeometry.topLeft() - self._view.pos())
        super().resize(0, 0)
        super().show()


def to_str(qval):
    return bytes(qval).decode()


def get_selectors(rules, credentials):
    statements = []
    for rule in rules:
        selector = json.dumps(rule.selector)
        if rule.action == "stop":
            statements.append(
                f"""var elem = document.querySelector({selector}); if (elem) {{ return; }}"""
            )
        elif rule.fill:
            value = json.dumps(getattr(credentials, rule.fill, None))
            if value:
                statements.append(
                    f"""var elem = document.querySelector({selector}); if (elem) {{ elem.dispatchEvent(new Event("focus")); elem.value = {value}; elem.dispatchEvent(new Event("blur")); }}"""
                )
            else:
                logger.warning(
                    "Credential info not available",
                    type=rule.fill,
                    possibilities=dir(credentials),
                )
        elif rule.action == "click":
            statements.append(
                f"""var elem = document.querySelector({selector}); if (elem) {{ elem.dispatchEvent(new Event("focus")); elem.click(); }}"""
            )
    return "\n".join(statements)
