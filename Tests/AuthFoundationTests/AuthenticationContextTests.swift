//
// Copyright (c) 2024-Present, Okta, Inc. and/or its affiliates. All rights reserved.
// The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
//
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and limitations under the License.
//

import XCTest
@testable import AuthFoundation

final class AuthenticationContextTests: XCTestCase {
    func testStandardContext() throws {
        var context = StandardAuthenticationContext()
        XCTAssertNil(context.nonce)
        XCTAssertNil(context.maxAge)
        XCTAssertNil(context.audience)
        XCTAssertNil(context.resource)
        XCTAssertNil(context.acrValues)
        XCTAssertNil(context.additionalParameters)
        XCTAssertNil(context.persistValues)
        for category in OAuth2APIRequestCategory.allCases {
            XCTAssertNil(context.parameters(for: category))
        }
        
        context.acrValues = ["urn:foo:bar", "urn:ietf:foo:bar"]
        XCTAssertEqual(context.persistValues, [
            "acr_values": "urn:foo:bar urn:ietf:foo:bar"
        ])
        XCTAssertEqual(context.parameters(for: .authorization)?.mapValues(\.stringValue), [
            "acr_values": "urn:foo:bar urn:ietf:foo:bar"
        ])

        context = .init(additionalParameters: [
            "acr_values": "urn:foo:bar urn:ietf:foo:bar",
            "prompt": "none",
        ])
        XCTAssertEqual(context.acrValues, [
            "urn:foo:bar",
            "urn:ietf:foo:bar",
        ])
        XCTAssertEqual(context.additionalParameters?.mapValues(\.stringValue), [
            "prompt": "none"
        ])
        XCTAssertEqual(context.persistValues, [
            "acr_values": "urn:foo:bar urn:ietf:foo:bar",
        ])
        XCTAssertEqual(context.parameters(for: .authorization)?.mapValues(\.stringValue), [
            "prompt": "none",
            "acr_values": "urn:foo:bar urn:ietf:foo:bar",
        ])
        
        for category in OAuth2APIRequestCategory.allCases {
            let parameters = context.parameters(for: category)
            XCTAssertEqual(parameters?["prompt"]?.stringValue, "none")

            if category == .authorization {
                XCTAssertEqual(parameters?["acr_values"]?.stringValue, "urn:foo:bar urn:ietf:foo:bar")
            }
        }
        
        context = .init(additionalParameters: ["acr_values": "foo"])
        XCTAssertEqual(context.acrValues, ["foo"])
        XCTAssertNil(context.additionalParameters)

        context = .init()
        XCTAssertNil(context.acrValues)
        XCTAssertNil(context.additionalParameters)
    }
    
    func testAudienceAndResource() throws {
        let context = StandardAuthenticationContext(
            audience: "api://my-resource-server",
            resource: ["https://api.example.com/v1"]
        )
        XCTAssertEqual(context.audience, "api://my-resource-server")
        XCTAssertEqual(context.resource, ["https://api.example.com/v1"])
        
        let tokenParams = context.parameters(for: .token)?.mapValues(\.stringValue)
        XCTAssertEqual(tokenParams?["audience"], "api://my-resource-server")
        XCTAssertEqual(tokenParams?["resource"], "https://api.example.com/v1")
        
        // audience and resource should not appear in authorization parameters
        let authParams = context.parameters(for: .authorization)
        XCTAssertNil(authParams?["audience"])
        XCTAssertNil(authParams?["resource"])
    }
    
    func testResourceAsStringLiteral() throws {
        let context = StandardAuthenticationContext(
            resource: "https://api.example.com/v1 https://api.example.com/v2"
        )
        XCTAssertEqual(context.resource, [
            "https://api.example.com/v1",
            "https://api.example.com/v2",
        ])
        
        let tokenParams = context.parameters(for: .token)?.mapValues(\.stringValue)
        XCTAssertEqual(tokenParams?["resource"], "https://api.example.com/v1 https://api.example.com/v2")
    }
    
    func testNonceAndMaxAge() throws {
        let context = StandardAuthenticationContext(
            nonce: "custom-nonce",
            maxAge: 3600
        )
        XCTAssertEqual(context.nonce, "custom-nonce")
        XCTAssertEqual(context.maxAge, 3600)
    }
}
