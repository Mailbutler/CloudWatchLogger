//
//  CloudWatchLogger.swift
//  Mailbutler
//
//  Created by Fabian Jäger on 17.05.17.
//  Copyright © 2017 Mailbutler. All rights reserved.
//

import CocoaLumberjack

fileprivate extension URLRequest {

    mutating func signWithAWSSignatureV4(awsAccessKey: String, awsAccessSecret: String, awsRegion: String, awsService: String) {

        let payloadDigest = (self.httpBody ?? Data()).sha256.hexDigest

        let iso8601DateFormatter = DateFormatter()
        iso8601DateFormatter.dateFormat = "yyyyMMdd'T'HHmmssZZZZZ"
        iso8601DateFormatter.timeZone =  TimeZone(abbreviation: "GMT")

        let shortDateFormatter = DateFormatter()
        shortDateFormatter.dateFormat = "yyyyMMdd"

        let now = Date()
        let shortDateString = shortDateFormatter.string(from: now)
        let iso8601DateString = iso8601DateFormatter.string(from: now)

        // Step 0: Set some other Amazon headers
        self.setValue(payloadDigest, forHTTPHeaderField: "x-amz-content-sha256")
        self.setValue(iso8601DateString, forHTTPHeaderField: "x-amz-date")
        self.setValue(nil, forHTTPHeaderField: "Authorization")

        guard let url = self.url else {
            print("Request requires a URL for AWS signing")
            return
        }
        guard let headers = self.allHTTPHeaderFields else {
            print("Request requires at least one header value for AWS signing")
            return
        }

        // step 1: canonical request
        let requestMethod = self.httpMethod ?? "GET"
        let canonicalURI = url.path.count > 0 ? url.path : "/"
        var canonicalQueryString = String()
        if let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems {
            canonicalQueryString = queryItems
                .sorted { $0.name < $1.name }
                .map { "\($0.name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)=\($0.value?.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
                .joined(separator: "&")
        }
        var canonicalHeaders = String()
        let signedHeaders = headers.keys
            .map { $0.lowercased() }
            .sorted { $0 < $1 }
            .joined(separator: ";")
        let sortedHeaders = headers
            .map { ($0.0.lowercased(), $0.1) }
            .sorted { $0.0 < $1.0 }
        for (key, value) in sortedHeaders {
            canonicalHeaders.append("\(key):\(value.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines))\n")
        }

        let canonicalRequest = "\(requestMethod)\n\(canonicalURI)\n\(canonicalQueryString)\n\(canonicalHeaders)\n\(signedHeaders)\n\(payloadDigest)"

        guard let hashedCanonicalRequest = canonicalRequest.data(using: String.Encoding.utf8)?.sha256.hexDigest else {
            return
        }

        // step 2: string to sign
        let stringToSign = "AWS4-HMAC-SHA256\n\(iso8601DateString)\n\(shortDateString)/\(awsRegion)/\(awsService)/aws4_request\n\(hashedCanonicalRequest)"

        // step 3: Calculate signature
        let dateKey = shortDateString.hmac(algorithm: .SHA256, key: "AWS4\(awsAccessSecret)".data(using: String.Encoding.utf8)!)
        let dateRegionKey = awsRegion.hmac(algorithm: .SHA256, key: dateKey)
        let dateRegionServiceKey = awsService.hmac(algorithm: .SHA256, key: dateRegionKey)
        let signingKey = "aws4_request".hmac(algorithm: .SHA256, key: dateRegionServiceKey)

        // step 4: Generate Authorization header
        let credential = "\(awsAccessKey)/\(shortDateString)/\(awsRegion)/\(awsService)/aws4_request"
        let signature = stringToSign.hmac(algorithm: .SHA256, key: signingKey).hexDigest

        let authorizationHeader = "AWS4-HMAC-SHA256 Credential=\(credential),SignedHeaders=\(signedHeaders),Signature=\(signature)"

        self.setValue(authorizationHeader, forHTTPHeaderField: "Authorization")
    }

}

@objc public class CloudWatchLogger: DDAbstractLogger {

    private var nextSequenceToken: String?

    let logGroupName: String   // must exist in CloudWatch!

    let requestedStreamName: String
    var logStreamName: String?

    let awsAccessKey: String
    let awsAccessSecret: String
    let awsRegion: String

    let url: URL

    @objc(initWithLogGroupName:logStreamName:awsAccessKey:awsAccessSecret:awsRegion:)
    public init(logGroupName: String, logStreamName: String, awsAccessKey: String, awsAccessSecret: String, awsRegion: String) {
        self.logGroupName = logGroupName
        self.requestedStreamName = logStreamName

        self.awsAccessKey = awsAccessKey
        self.awsAccessSecret = awsAccessSecret
        self.awsRegion = awsRegion

        self.url = URL(string: "https://logs.\(awsRegion).amazonaws.com")!

        super.init()
    }

    private func createStream(for message: DDLogMessage?) {
        guard let host = url.host else {
            return
        }

        let logDict = [
            "logGroupName": logGroupName,
            "logStreamName": requestedStreamName
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: logDict, options: []) else {
            return
        }

        // create request
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(host, forHTTPHeaderField: "Host")
        request.setValue("application/x-amz-json-1.1", forHTTPHeaderField: "Content-Type")
        request.setValue("Logs_20140328.CreateLogStream", forHTTPHeaderField: "X-Amz-Target")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("\(jsonData.count)", forHTTPHeaderField: "Content-Length")

        request.httpBody = jsonData

        request.signWithAWSSignatureV4(awsAccessKey: self.awsAccessKey, awsAccessSecret: self.awsAccessSecret, awsRegion: self.awsRegion, awsService: "logs")

        let dataTask = URLSession.shared.dataTask(with: request) { _, response, error in
            // store session identifier upon success
            if error == nil && (response as? HTTPURLResponse)?.statusCode == 200 {
                self.logStreamName = self.requestedStreamName

                // try again with message
                if let message = message {
                    self.log(message: message)
                }
            }
        }

        dataTask.resume()
    }

    override public func log(message logMessage: DDLogMessage) {

        guard logMessage.message.count > 0 else {
            return
        }
        guard let host = url.host else {
            return
        }
        guard let logStreamName = logStreamName else {
            // create session identifier first
            createStream(for: logMessage)
            return
        }

        var logDict: [String: Any] = [
            "logGroupName": logGroupName,
            "logStreamName": logStreamName
        ]

        if nextSequenceToken != nil {
            logDict["sequenceToken"] = nextSequenceToken
        }

        let logEvents = [["message": logMessage.message, "timestamp": Int(logMessage.timestamp.timeIntervalSince1970*1000)] as [String: Any]]
        logDict["logEvents"] = logEvents

        guard let jsonData = try? JSONSerialization.data(withJSONObject: logDict, options: []) else {
            return
        }

        // create request
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(host, forHTTPHeaderField: "Host")
        request.setValue("application/x-amz-json-1.1", forHTTPHeaderField: "Content-Type")
        request.setValue("Logs_20140328.PutLogEvents", forHTTPHeaderField: "X-Amz-Target")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("\(jsonData.count)", forHTTPHeaderField: "Content-Length")

        request.httpBody = jsonData

        request.signWithAWSSignatureV4(awsAccessKey: self.awsAccessKey, awsAccessSecret: self.awsAccessSecret, awsRegion: self.awsRegion, awsService: "logs")

        let dataTask = URLSession.shared.dataTask(with: request) { data, _, _ in
            if let data = data, let json = try? JSONSerialization.jsonObject(with: data, options: .allowFragments) as? [String: Any] {
                if let expectedSequenceToken = json?["expectedSequenceToken"] as? String {
                    self.nextSequenceToken = expectedSequenceToken
                    // try again
                    self.log(message: logMessage)
                } else if let nextSequenceToken = json?["nextSequenceToken"] as? String {
                    self.nextSequenceToken = nextSequenceToken
                }
            }
        }

        dataTask.resume()
    }
}
