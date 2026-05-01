import UIKit
import Capacitor
import WebKit

// Breaks the WKWebView → userContentController → messageHandler retain cycle
private class WeakMsgHandler: NSObject, WKScriptMessageHandler {
    weak var target: WKScriptMessageHandler?
    init(_ target: WKScriptMessageHandler) { self.target = target }
    func userContentController(_ c: WKUserContentController, didReceive msg: WKScriptMessage) {
        target?.userContentController(c, didReceive: msg)
    }
}

class ViewController: CAPBridgeViewController {

    override func capacitorDidLoad() {
        super.capacitorDidLoad()
        guard let controller = webView?.configuration.userContentController else { return }
        let script = WKUserScript(
            source: consoleBridgeJS,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false
        )
        controller.addUserScript(script)
        controller.add(WeakMsgHandler(self), name: "logging")
    }

    // Overrides console.log/warn/error and window.onerror so they appear in Xcode output
    private var consoleBridgeJS: String { """
        (function() {
            function send(level, args) {
                var msg = Array.prototype.slice.call(args).map(function(a) {
                    try { return typeof a === 'object' ? JSON.stringify(a) : String(a); }
                    catch(e) { return String(a); }
                }).join(' ');
                if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.logging) {
                    window.webkit.messageHandlers.logging.postMessage({ level: level, message: msg });
                }
            }
            var _log   = console.log.bind(console);
            var _warn  = console.warn.bind(console);
            var _error = console.error.bind(console);
            console.log   = function() { send('LOG',   arguments); _log.apply(console, arguments);   };
            console.warn  = function() { send('WARN',  arguments); _warn.apply(console, arguments);  };
            console.error = function() { send('ERROR', arguments); _error.apply(console, arguments); };
            window.onerror = function(msg, src, line, col) {
                send('ERROR', ['UNCAUGHT: ' + msg + ' @ ' + src + ':' + line + ':' + col]);
            };
            window.addEventListener('unhandledrejection', function(e) {
                var reason = e.reason ? (e.reason.message || String(e.reason)) : 'unknown';
                send('ERROR', ['UNHANDLED PROMISE REJECTION: ' + reason]);
            });
            document.addEventListener('DOMContentLoaded', function() {
                send('LOG', [
                    'DOMContentLoaded — body.children: ' + document.body.children.length +
                    ', body.innerHTML length: ' + document.body.innerHTML.length +
                    ', head styleSheets: ' + document.styleSheets.length
                ]);
            });
        })();
        """
    }
}

extension ViewController: WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let level = body["level"] as? String,
              let msg = body["message"] as? String else { return }
        print("🌐 JS [\(level)]: \(msg)")
    }
}
