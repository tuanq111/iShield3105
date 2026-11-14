//
//  MainTabView.swift
//  iShieldPro
//
//  5-Tab Commercial Security Console
//

import SwiftUI
import UIKit

struct MainTabView: View {
    @EnvironmentObject var coordinator: SecurityDashboardCoordinator

    init() {
        let appearance = UITabBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = UIColor(red: 0.039, green: 0.059, blue: 0.098, alpha: 1.0)
        appearance.shadowColor = UIColor.white.withAlphaComponent(0.08)

        UITabBar.appearance().standardAppearance = appearance
        UITabBar.appearance().scrollEdgeAppearance = appearance

        let navAppearance = UINavigationBarAppearance()
        navAppearance.configureWithOpaqueBackground()
        navAppearance.backgroundColor = UIColor(red: 0.027, green: 0.043, blue: 0.071, alpha: 1.0)
        navAppearance.titleTextAttributes = [.foregroundColor: UIColor.white]
        navAppearance.largeTitleTextAttributes = [.foregroundColor: UIColor.white]
        UINavigationBar.appearance().standardAppearance = navAppearance
        UINavigationBar.appearance().scrollEdgeAppearance = navAppearance
    }

    var body: some View {
        TabView(selection: $coordinator.selectedTab) {
            DashboardView(
                coordinator: coordinator,
                containerManager: coordinator.containerManager,
                auditEngine: coordinator.auditEngine,
                networkScanner: coordinator.networkScanner,
                activeDefense: coordinator.activeDefense
            )
            .tabItem {
                Label("Tổng quan", systemImage: "shield.lefthalf.filled")
            }
            .tag(0)

            ActiveDefenseView(
                coordinator: coordinator,
                defense: coordinator.activeDefense
            )
            .tabItem {
                Label("Chống gián điệp", systemImage: "waveform.and.magnifyingglass")
            }
            .tag(1)

            ContainerInspectorView(
                coordinator: coordinator,
                containerManager: coordinator.containerManager
            )
            .tabItem {
                Label("Dọn App", systemImage: "shippingbox.fill")
            }
            .tag(2)

            NetworkShieldView(
                coordinator: coordinator,
                networkScanner: coordinator.networkScanner,
                dohManager: coordinator.dohManager
            )
            .tabItem {
                Label("Mạng & DNS", systemImage: "network.badge.shield.half.filled")
            }
            .tag(3)

            DeviceControlCheckView(
                coordinator: coordinator,
                auditEngine: coordinator.auditEngine,
                defense: coordinator.activeDefense
            )
            .tabItem {
                Label("Hệ thống", systemImage: "lock.shield.fill")
            }
            .tag(4)
        }
        .tint(CyberTheme.neonCyan)
        .task {
            if coordinator.lastDeepScanDate == nil {
                await coordinator.runDeepScan()
            }
        }
    }
}
