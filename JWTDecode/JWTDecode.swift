// JWTDecode.swift
//
// Copyright (c) 2015 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Foundation

/**
Decodes a JWT token into an object that holds the decoded body (along with token header and signature parts).
If the token cannot be decoded a `NSError` will be thrown.

:param: jwt string value to decode

:returns: a decoded token as an instance of JWT
*/
public func decode(_ jwt: String) throws -> JWT {
    return try DecodedJWT(jwt: jwt)
}

struct DecodedJWT: JWT {

    let header: [String: AnyObject]
    let body: [String: AnyObject]
    let signature: String?
    let stringValue: String

    init(jwt: String) throws {
        let parts = jwt.components(separatedBy: ".")
        guard parts.count == 3 else {
            throw invalidPartCountInJWT(jwt, parts: parts.count)
        }

        self.header = try decodeJWTPart(parts[0])
        self.body = try decodeJWTPart(parts[1])
        self.signature = parts[2]
        self.stringValue = jwt
    }

    var expiresAt: Date? { return claim("exp") }
    var issuer: String? { return claim("iss") }
    var subject: String? { return claim("sub") }
    var audience: [String]? {
        guard let aud: String = claim("aud") else {
            return claim("aud")
        }
        return [aud]
    }
    var issuedAt: Date? { return claim("iat") }
    var notBefore: Date? { return claim("nbf") }
    var identifier: String? { return claim("jti") }

    fileprivate func claim(_ name: String) -> Date? {
        guard let timestamp:Double = claim(name) else {
            return nil
        }
        return Date(timeIntervalSince1970: timestamp)
    }

    var expired: Bool {
        guard let date = self.expiresAt else {
            return false
        }
        return date.compare(Date()) != ComparisonResult.orderedDescending
    }
}

private func base64UrlDecode(_ value: String) -> Data? {
    var base64 = value
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let length = Double(base64.lengthOfBytes(using: String.Encoding.utf8))
    let requiredLength = 4 * ceil(length / 4.0)
    let paddingLength = requiredLength - length
    if paddingLength > 0 {
        let padding = "".padding(toLength: Int(paddingLength), withPad: "=", startingAt: 0)
        base64 = base64 + padding
    }
    return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
}

private func decodeJWTPart(_ value: String) throws -> [String: AnyObject] {
    guard let bodyData = base64UrlDecode(value) else {
        throw invalidBase64UrlValue(value)
    }

    do {
        guard let json = try JSONSerialization.jsonObject(with: bodyData, options: JSONSerialization.ReadingOptions()) as? [String: AnyObject] else {
            throw invalidJSONValue(value)
        }
        return json
    } catch {
        throw invalidJSONValue(value)
    }
}
