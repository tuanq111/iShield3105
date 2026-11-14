//
//  iShieldProApp.swift
//  iShieldPro
//
//  Commercial Mobile Threat Defense, Anti-Spyware & Privacy Shield
//

import SwiftUI

@main
struct iShieldProApp: App {
    @StateObject private var coordinator = SecurityDashboardCoordinator()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            MainTabView()
                .environmentObject(coordinator)
                .preferredColorScheme(.dark)
                .onChange(of: scenePhase) { newPhase in
                    if newPhase == .active {
                        Task {
                            await coordinator.handleSceneDidBecomeActive()
                        }
                    }
                }
        }
    }
}
