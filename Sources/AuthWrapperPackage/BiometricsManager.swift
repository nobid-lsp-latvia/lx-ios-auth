// SPDX-License-Identifier: EUPL-1.2

//
//  BiometricsManager.swift
//  AuthWrapperPackage
//
//  Created by Matīss Mamedovs on 15/11/2024.
//

import Foundation
import LocalAuthentication
import UtilitiesPackage

final public class BiometricsManager: Sendable  {
    
    fileprivate let BIOMETRIC_SWITCH_KEY = "BIOMETRIC_SWITCH_KEY"
    
    public static let shared = BiometricsManager()
    
    enum BiometryState {
        case available, locked, notAvailable
    }
    
    public func isBiometryEnabled() -> Bool {
        return self.biometryState == .available
    }
    
    public func isBiometricSwitchOn() -> Bool {
        let result: Bool = UserDefaultsManager.shared.get(key: BIOMETRIC_SWITCH_KEY) ?? false
        
        return result
    }
    
    func removeBiometricsSwitchState() {
        self.setBiometricSwitchState(isOn: false)
    }
    
    func addBiometricsSwitchState() {
        self.setBiometricSwitchState(isOn: true)
    }
    
    public func getBiometricTypeImageName() -> String {
        switch self.getBiometricType() {
        case .faceID:
            return "ic_face_id"
        case .touchID:
            return "ic_touch_id"
        default:
            return "ic_touch_id"
        }
    }
    
    public func getBiometricType() -> LABiometryType {
        let context = LAContext()
        return context.biometryType
    }
   
    public func evaluatePolicyWithPasscode() async throws -> Bool {
        try await withCheckedThrowingContinuation { cont in
            LAContext().evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate using Face ID or Touch ID") { result, error in
                if let error = error {
                    return cont.resume(throwing: error)
                }
                cont.resume(returning: result)
            }
        }
    }
}

extension BiometricsManager {
    fileprivate var biometryState: BiometryState {
        let authContext = LAContext()
        var error: NSError?
        
        let biometryAvailable = authContext.canEvaluatePolicy(
            LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if let laError = error as? LAError, laError.code == LAError.Code.biometryLockout {
            return .locked
        }
        return biometryAvailable ? .available : .notAvailable
    }
    
    fileprivate func setBiometricSwitchState(isOn: Bool) {
        UserDefaultsManager.shared.set(value: isOn, key: BIOMETRIC_SWITCH_KEY)
    }
    
    
}
