//
//  ViewController.swift
//  GHLoginTest
//
//  Created by James McKowen on 1/17/17.
//  Copyright © 2017 James McKowen. All rights reserved.
//

import UIKit
import GHLogin

class ViewController: UIViewController {
    @IBAction func loginButtonActivated(_ sender: Any) {
        GHLoginManager.shared.login(withScopes: [], allowSignups: true, presenter: self) { (accessToken, scopes, tokenType, error, details) in
            if let accessToken = accessToken, let scopes = scopes, let tokenType = tokenType {
                print("Access Token: \(accessToken), scopes: \(scopes.map { $0.rawValue }.joined(separator: ", ")), token type: \(tokenType)")
            }
            if let error = error as? GHLoginError {
                switch error {
                    case .UserCancelledLogin:
                        print("Cancelled login")
                    case .MissingQueryItemsInRedirect:
                        print("Missing query items")
                    default:
                        print(error)
                        print(details as Any)
                }
            }
        }
    }
}
