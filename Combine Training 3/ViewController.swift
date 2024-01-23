//
//  ViewController.swift
//  Combine Training 3
//
//  Created by Pooyan J on 10/26/1402 AP.
//

import UIKit
import CommonCrypto

class ViewController: UIViewController {
    
    enum CryptoError: Error {
        case encryptionFailed(status: CCCryptorStatus)
        case decryptionFailed(status: CCCryptorStatus)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        encrypt(originalData: "ADASDSADASDSA")
        
        decryptAndPrint(encryptedBase64String: "2UjJzfwRtm7YAfLAM77r8w==")
    }
}

extension ViewController {
    
    func encrypt(originalData: String) {
        let data = originalData.data(using: .utf8)!
        let key = "0123456789012345".data(using: .utf8)!
        let iv = "0123456789012345".data(using: .utf8)!   
        let encryptedData = try? encrypt(data: data, key: key, iv: iv)
        print("ENCRYPTED DATA ===> ", encryptedData?.base64EncodedString() as Any)
    }
    
    func decryptAndPrint(encryptedBase64String: String) {
        do {
            let key = "0123456789012345".data(using: .utf8)!
            let iv = "0123456789012345".data(using: .utf8)!

            // Convert the base64-encoded string to Data
            guard let encryptedData = Data(base64Encoded: encryptedBase64String) else {
                print("Invalid base64-encoded string")
                return
            }

            let decryptedData = try decrypt(data: encryptedData, key: key, iv: iv)
            
            // Print the hexadecimal representation of the decrypted data
            let hexString = decryptedData.map { String(format: "%02hhx", $0) }.joined()
            print("Decrypted Data (Hex): \(hexString)")
            
            // Print the base64-encoded representation of the decrypted data
            let base64String = decryptedData.base64EncodedString()
            print("Decrypted Data (Base64): \(base64String)")
        } catch CryptoError.decryptionFailed(let status) {
            print("Decryption error: \(status)")
        } catch {
            print("An unexpected decryption error occurred: \(error)")
        }
    }
}

extension ViewController {
    
    func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        var encryptedData = Data(count: data.count + kCCBlockSizeAES128)
        var encryptedLength: Int = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress, key.count,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        encryptedData.withUnsafeMutableBytes { $0.baseAddress }, encryptedData.count,
                        &encryptedLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.encryptionFailed(status: status)
        }

        encryptedData.removeSubrange(encryptedLength..<encryptedData.count)
        return encryptedData
    }
    
    func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        var decryptedData = Data(count: data.count + kCCBlockSizeAES128)
        var decryptedLength: Int = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress, key.count,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        decryptedData.withUnsafeMutableBytes { $0.baseAddress }, decryptedData.count,
                        &decryptedLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.decryptionFailed(status: status)
        }

        decryptedData.removeSubrange(decryptedLength..<decryptedData.count)
        return decryptedData
    }
}
