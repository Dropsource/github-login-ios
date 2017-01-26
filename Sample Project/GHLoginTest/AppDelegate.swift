//
//  AppDelegate.swift
//  GHLoginTest
//
//  Created by James McKowen on 1/17/17.
//  Copyright © 2017 James McKowen. All rights reserved.
//

import UIKit
import GHLogin

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ app: UIApplication, open url: URL, options: [UIApplicationOpenURLOptionsKey : Any] = [:]) -> Bool {
        GHLoginManager.shared.handle(applicationURL: url)
        return true
    }
    
}
