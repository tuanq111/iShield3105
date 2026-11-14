//
//  iShield3105App.swift
//  iShield3105
//

import SwiftUI

@main
struct iShield3105App: App {
    @StateObject private var coordinator = SecurityDashboardCoordinator()

    var body: some Scene {
        WindowGroup {
            MainTabView()
                .environmentObject(coordinator)
                .preferredColorScheme(.dark)
        }
    }
}
