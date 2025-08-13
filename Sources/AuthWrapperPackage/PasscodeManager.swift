// SPDX-License-Identifier: EUPL-1.2

//
//  PasscodeManager.swift
//  AuthWrapperPackage
//
//  Created by Matīss Mamedovs on 15/11/2024.
//

import Security
import Foundation
import LocalAuthentication
import KeychainWrapperPackage
import UtilitiesPackage

final public class PasscodeManager: Sendable {
    
    public enum FailedPinState: Sendable {
        case canContinue, justSuspended, willSuspend, deleted
    }
    
    fileprivate let KEY_SERVICE: String = "KEY_SERVICE"
    fileprivate let KEY_SERVICE_TOKEN: String = "KEY_SERVICE_TOKEN"
    fileprivate let KEY_SERVICE_BIOMETRY: String = "KEY_SERVICE_BIOMETRY"
    fileprivate let PASSCODE_SET_KEY = "PASSCODE_SET_KEY"
    fileprivate let PASSCODE_FAIL_COUNTER = "PASSCODE_FAIL_COUNTER"
    fileprivate let PASSCODE_SUSPENSION_TIME = "PASSCODE_SUSPENSION_TIME"
    
    public static let ALLOWED_PIN_COUNT: Int = 5
    public static let SUSPENSION_TIME: Int = 10 * 60

    public static let shared = PasscodeManager()
    
    public func isPasscodeSet() -> Bool {
        let result: Bool = UserDefaultsManager.shared.get(key: PASSCODE_SET_KEY) ?? false
        
        return result
    }
    
    fileprivate func setPasscodeSetKey(isOn: Bool) {
        UserDefaultsManager.shared.set(value: isOn, key: PASSCODE_SET_KEY)
    }
    
    public func storeSessionToken(token: String, completion: @escaping (Bool) -> Void) {
        if let tokenData = KeychainManager.shared.convertToData(item: token) {
            let query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: self.KEY_SERVICE_TOKEN,
                kSecValueData as String: tokenData,
            ] as CFDictionary
            
            KeychainManager.shared.addItemToKeychain(query: query, completion: completion)
        }
    }
    
    public func getSessionToken() throws -> String? {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: KEY_SERVICE_TOKEN,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as CFDictionary
        
        if let token = try? KeychainManager.shared.throwRetrieve(query: query) {
            return KeychainManager.shared.convertToString(item: token)
        } else {
            return nil
        }
    }
    
    public func deleteSessionToken() {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount:self.KEY_SERVICE_TOKEN
        ] as CFDictionary
                
        KeychainManager.shared.delete(query: query, completion: { _ in })
    }
    
    public func storePasscode(passcode: String, completion: @escaping (Bool) -> Void) {
        if let passcodeData = KeychainManager.shared.convertToData(item: passcode) {
            let query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: self.KEY_SERVICE,
                kSecValueData as String: passcodeData,
            ] as CFDictionary
            
            KeychainManager.shared.addItemToKeychain(query: query, completion: { success in
                if success {
                    self.setPasscodeSetKey(isOn: success)
                }
                
                completion(success)
            })
        }
    }
    
    public func updatePasscode(passcode: String, completion: @escaping (Bool) -> Void) {
        if let passcodeData = KeychainManager.shared.convertToData(item: passcode) {
            let query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: self.KEY_SERVICE,
            ] as CFDictionary
            
            let updateFields = [
                kSecValueData as String: passcodeData,
            ] as CFDictionary
            
            KeychainManager.shared.updateKeychainItem(query: query, updateField: updateFields, completion: { success in
                if success {
                    // Drop biometry
                    self.deleteBiometricAuthentication()
                }
                
                completion(success)
            })
        }
    }
    
    public func storePasscodeWithBiometry(passcode: String) async throws -> Bool {
        if let accessControl = SecAccessControlCreateWithFlags(nil,  kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, nil),
           let passcodeData = KeychainManager.shared.convertToData(item: passcode) {
            let context = LAContext()
            context.localizedReason = "Biometry"
            do {
                var val = try await context.evaluateAccessControl(accessControl, operation: .useItem, localizedReason: "Biometrijas pieslēgšana")
                let query = [
                    kSecClass: kSecClassGenericPassword,
                    kSecAttrAccount:self.KEY_SERVICE_BIOMETRY,
                    kSecValueData: passcodeData,
                    kSecAttrAccessControl: accessControl,
                    kSecUseAuthenticationContext: context,
                    kSecReturnData: true
                ] as CFDictionary
                
                let result = try await KeychainManager.shared.addItemToKeychainAsync(query: query)
                if result {
                    BiometricsManager.shared.addBiometricsSwitchState()
                }
                return result
            } catch {
                return false
            }
        } else {
            return false
        }
    }
    public func validateUserPasscode(passcode: String, completion: @escaping (Bool) -> Void) {
        if let data = KeychainManager.shared.convertToData(item: passcode) {
            validateUserPasscode(passcode: data, completion: completion)
        }
    }
    
    public func validateUserPasscode(passcode: Data, completion: @escaping (Bool) -> Void) {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: KEY_SERVICE,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as CFDictionary
        
        KeychainManager.shared.retrieve(query: query, completion: { passcodeKeychain in
            guard let passcodeKeychain = passcodeKeychain else {
                completion(false)
                return
            }
            
            completion(passcodeKeychain == passcode)
        })
    }
    
    public func fireBiometryAuthentication(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        context.localizedReason = "Access your password on the keychain"
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount:self.KEY_SERVICE_BIOMETRY,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnAttributes: true,
            kSecUseAuthenticationContext: context,
            kSecReturnData: true
        ] as CFDictionary
        
        KeychainManager.shared.retrieve(query: query, completion: { biometricData in
            guard let biometricData = biometricData else {
                completion(false)
                return
            }
            self.validateUserPasscode(passcode: biometricData, completion: completion)
        })
    }
    
    public func deleteBiometricAuthentication() {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount:self.KEY_SERVICE_BIOMETRY
        ] as CFDictionary
        
        let status = SecItemDelete(query)
        if status == errSecSuccess {
            BiometricsManager.shared.removeBiometricsSwitchState()
            print("Biometry login dropped")
        } else {
            print("Cannot drop biometry login")
        }
        
        KeychainManager.shared.delete(query: query, completion: { success in
            if success {
                BiometricsManager.shared.removeBiometricsSwitchState()
                print("Biometry login dropped")
            }
        })
    }
    
    @MainActor public func clearAllData(completion: @escaping (Bool) -> Void) async {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrSynchronizable: kSecAttrSynchronizableAny
        ] as CFDictionary
        
        KeychainManager.shared.delete(query: query, completion: { success in
            if success {
                self.setPasscodeSetKey(isOn: false)
                BiometricsManager.shared.removeBiometricsSwitchState()
                print("All login information dropped")
            }
            
            completion(success)
        })
    }
    
    public func addUnsuccessfulAttempt(completion: @escaping (FailedPinState) -> Void) {
        var failedCount = 0
        self.getPinFailCount(completion: { count in
            failedCount = count
            failedCount += 1
            if failedCount == PasscodeManager.ALLOWED_PIN_COUNT {
                self.getIsSuspended(completion: { suspensionTime in
                    if suspensionTime == nil {
                        self.storeSuspensionTime(time: Int(Date().timeIntervalSince1970), completion: { success in
                            self.deletePinFailCount()
                            completion(.justSuspended)
                        })
                    } else {
                        // force delete
                        self.deletePinFailCount()
                        self.deleteSuspensionTime()
                        completion(.deleted)
                    }
                })
            } else {
                self.storePinFailCount(count: failedCount, completion: { success in
                    self.getIsSuspended(completion: { suspensionTime in
                        if suspensionTime == nil {
                            completion(.canContinue)
                        } else {
                            completion(.willSuspend)
                        }
                    })
                    
                })
            }
        })
    }
    
    public func getPinFailCount(completion: @escaping (Int) -> Void) {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: PASSCODE_FAIL_COUNTER,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as CFDictionary
        
        KeychainManager.shared.retrieve(query: query, completion: { failedCount in
            guard let failedCount else {
                completion(0)
                return
            }
            if let count = KeychainManager.shared.convertToInt(item: failedCount) {
                completion(Int(count))
            }
        })
    }
    
    public func getIsSuspended(completion: @escaping (Int?) -> Void) {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: PASSCODE_SUSPENSION_TIME,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as CFDictionary
        
        KeychainManager.shared.retrieve(query: query, completion: { suspensionTime in
            guard let suspensionTime else {
                completion(nil)
                return
            }
            if let time = KeychainManager.shared.convertToInt(item: suspensionTime) {
                completion(Int(time))
            }
        })
    }
    
    public func storeSuspensionTime(time: Int, completion: @escaping (Bool) -> Void) {
        if let passcodeData = KeychainManager.shared.convertToData(item: time) {
            let query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: self.PASSCODE_SUSPENSION_TIME,
                kSecValueData as String: passcodeData,
            ] as CFDictionary
            
            KeychainManager.shared.addItemToKeychain(query: query, completion: { success in
                completion(success)
            })
        }
    }
    
    public func storePinFailCount(count: Int, completion: @escaping (Bool) -> Void) {
        if let passcodeData = KeychainManager.shared.convertToData(item: count) {
            let query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: self.PASSCODE_FAIL_COUNTER,
                kSecValueData as String: passcodeData,
            ] as CFDictionary
            
            KeychainManager.shared.addItemToKeychain(query: query, completion: { success in
                completion(success)
            })
        }
    }
    
    fileprivate func deletePinFailCount() {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount:self.PASSCODE_FAIL_COUNTER
        ] as CFDictionary
                
        KeychainManager.shared.delete(query: query, completion: { _ in })
    }
    
    fileprivate func deleteSuspensionTime() {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount:self.PASSCODE_SUSPENSION_TIME
        ] as CFDictionary
                
        KeychainManager.shared.delete(query: query, completion: { _ in })
    }

    public func resetPinAfterSuccess() {
        self.deleteSuspensionTime()
        self.deletePinFailCount()
    }
    
    public func getSuspendedMinutes(completion: @escaping (Int) -> Void) {
        self.getIsSuspended(completion: { suspensionTime in
            guard let suspensionTime else {
                completion(0)
                return
            }
            
            let diff = ((suspensionTime ?? 0) + PasscodeManager.SUSPENSION_TIME) - Int(Date().timeIntervalSince1970)
            
            let mins = diff / 60
            
            completion(mins)
        })
    }
}
