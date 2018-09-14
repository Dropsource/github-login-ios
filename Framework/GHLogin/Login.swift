//
//  Login.swift
//  GHLogin
//
//  Created by Nate Frechette on 1/17/17.
//  Copyright © 2017 Nate Frechette. All rights reserved.
//

import Foundation
import SafariServices

public enum GHLoginScopes : String {
    case User = "user"
    case UserEmail = "user:email"
    case UserFollow = "user:follow"
    case PublicRepo = "public_repo"
    case Repo = "repo"
    case RepoDeployment = "repo_deployment"
    case RepoStatus = "repo:status"
    case DeleteRepo = "delete_repo"
    case Notifications = "notifications"
    case Gist = "gist"
    case ReadRepoHook = "read:repo_hook"
    case WriteRepoHook = "write:repo_hook"
    case AdminRepoHook = "admin:repo_hook"
    case AdminOrgHook = "admin:org_hook"
    case ReadOrg = "read:org"
    case WriteOrg = "write:org"
    case AdminOrg = "admin:org"
    case ReadPublicKey = "read:public_key"
    case WritePublicKey = "write:public_key"
    case AdminPublicKey = "admin:public_key"
    case ReadGPGKey = "read:gpg_key"
    case WriteGPGKey = "write:gpg_key"
    case AdminGPGKey = "admin:gpg_key"
}

public enum GHLoginError : Error {
    case MissingQueryItemsInRedirect
    case AuthorizationRequestError
    case AccessTokenRequestError
    case UserCancelledLogin
}

public struct GHErrorDetails {
    var errorName = ""
    var errorDescription = ""
    var errorURI = ""
}

public class GHLoginManager : NSObject, SFSafariViewControllerDelegate {
    
    public static let shared = GHLoginManager()
    private var completionBlock : ((String?, [GHLoginScopes]?, String?, Error?, GHErrorDetails?) -> Void)!
    private var urlSchemeName : String
    private var clientSecret : String
    private let clientID : String
    private var safariViewController : SFSafariViewController?
    
    public func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        self.completionBlock(nil, nil, nil, GHLoginError.UserCancelledLogin, nil)
    }
    
    override init() {
        if let settingsDictionary = Bundle.main.object(forInfoDictionaryKey: "GHLogin") as? [String : Any], let clientID = settingsDictionary["client_id"] as? String, let urlScheme = settingsDictionary["url_scheme"] as? String, let clientSecret = settingsDictionary["client_secret"] as? String {
            self.clientID = clientID
            self.urlSchemeName = urlScheme
            self.clientSecret = clientSecret
        } else {
            self.clientID = ""
            self.urlSchemeName = ""
            self.clientSecret = ""
            fatalError()
        }
    }
    
    public func handle(applicationURL url : URL) {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        print(url)
        if (components.scheme! + "://") == urlSchemeName {
            self.safariViewController?.dismiss(animated: true, completion: nil)
            guard let queryItems = components.queryItems else {
                self.completionBlock(nil, nil, nil, GHLoginError.MissingQueryItemsInRedirect, nil)
                return
            }
            guard let baseURL = URL(string : "https://github.com/login/oauth/access_token") else {
                return
            }
            let session = URLSession(configuration: .default)
            var request = URLRequest(url: baseURL)
            var queryDictionary = [String : Any]()
            for item in queryItems { queryDictionary[item.name] = item.value }
            if let errorName = queryDictionary["error"] as? String, let errorDescription = queryDictionary["error_description"] as? String, let errorURI = queryDictionary["error_uri"] as? String {
                self.completionBlock(nil, nil, nil, GHLoginError.AuthorizationRequestError, GHErrorDetails(errorName: errorName, errorDescription: errorDescription, errorURI: errorURI))
                return
            }
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            let code = queryDictionary["code"] as! String
            request.httpBody = "client_id=\(self.clientID)&client_secret=\(self.clientSecret)&code=\(code)&redirect_uri=\(self.urlSchemeName)".data(using: .ascii)
            let task = session.dataTask(with: request) { [unowned self] (data, response, error) in
                if error != nil {
                    self.completionBlock(nil, nil, nil, error, nil)
                } else if let data = data {
                    let responseDictionary = (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String : Any]
                    guard responseDictionary != nil, let accessToken = responseDictionary?["access_token"] as? String, let scopes = responseDictionary?["scope"] as? String, let tokenType = responseDictionary?["token_type"] as? String else {
                        if let errorName = responseDictionary?["error"] as? String, let errorDescription = responseDictionary?["error_description"] as? String, let errorURI = responseDictionary?["error_uri"] as? String {
                            self.completionBlock(nil, nil, nil, GHLoginError.AccessTokenRequestError, GHErrorDetails(errorName: errorName, errorDescription: errorDescription, errorURI: errorURI))
                        }
                        return
                    }
                    var nativeScopes = [GHLoginScopes]()
                    if scopes.characters.count > 0 {
                        nativeScopes = scopes.components(separatedBy: ",").map{ GHLoginScopes(rawValue: $0)! }
                    }
                    self.completionBlock(accessToken, nativeScopes, tokenType, nil, nil)
                }
            }
            task.resume()
        }
    }
    
    private class func buildURL(withScopes scopes : [GHLoginScopes], andURLSchemeName urlSchemeName : String, allowingSignups allowsSignups : Bool, clientID : String) -> URL {
        var urlComponents = URLComponents()
        urlComponents.scheme = "https"
        urlComponents.host = "github.com"
        urlComponents.path = "/login/oauth/authorize"
        let scopeStrings = scopes.map { $0.rawValue }
        let scopesQueryItem = URLQueryItem(name: "scope", value: scopeStrings.joined(separator: " "))
        let redirectURIQueryItem = URLQueryItem(name: "redirect_uri", value: "\(urlSchemeName)")
        let allowSignupQueryItem = URLQueryItem(name: "allow_signup", value: "\(allowsSignups ? "true" : "false")")
        let clientIDQueryItem = URLQueryItem(name: "client_id", value: clientID)
        urlComponents.queryItems = [scopesQueryItem, redirectURIQueryItem, allowSignupQueryItem, clientIDQueryItem]
        return urlComponents.url!
    }
    
    public func login(withScopes scopes : [GHLoginScopes], allowSignups : Bool, presenter : UIViewController, completion : @escaping (String?, [GHLoginScopes]?, String?, Error?, GHErrorDetails?) -> Void) {
        self.completionBlock = completion
        let url = GHLoginManager.buildURL(withScopes: scopes, andURLSchemeName: urlSchemeName, allowingSignups: allowSignups, clientID: self.clientID)
        self.safariViewController = SFSafariViewController(url: url)
        self.safariViewController?.delegate = self
        presenter.present(self.safariViewController!, animated: true, completion: nil)
    }
    
}
