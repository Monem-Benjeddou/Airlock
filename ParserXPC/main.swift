// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockInspection
import Foundation

/// The AirlockParser XPC service: sandboxed, no network entitlement, parses untrusted archives.
final class ServiceDelegate: NSObject, NSXPCListenerDelegate {
    private let service: ParserXPCService = {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return ParserXPCService(container: caches)
    }()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = ParserXPCInterface.make()
        connection.exportedObject = service
        connection.resume()
        return true
    }
}

let delegate = ServiceDelegate()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
