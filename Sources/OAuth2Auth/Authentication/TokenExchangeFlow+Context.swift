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

import Foundation

extension TokenExchangeFlow {
    /// A model representing the context and current state for an authorization session.
    public struct Context: Sendable, AuthenticationContext {
        /// The `nonce` value used when beginning the authentication process.
        public var nonce: String?
        
        /// The maximum age the token should support when authenticating.
        public var maxAge: TimeInterval?

        /// The logical name of the target API or resource server
        /// ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)).
        public var audience: String?

        /// Target resource URI(s) ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)).
        @ClaimCollection
        public var resource: [String]?

        /// The ACR values, if any, which should be requested by the client.
        @ClaimCollection
        public var acrValues: [String]?

        /// Any additional query string parameters you would like to supply to the authorization server.
        public var additionalParameters: [String: any APIRequestArgument]?
        
        /// Initializer for creating a context.
        /// - Parameters:
        ///   - nonce: Custom nonce for ID token replay protection.
        ///   - maxAge: Maximum authentication age (seconds).
        ///   - audience: The audience of the authorization server. Defaults to ``TokenExchangeFlow/defaultAudience``.
        ///   - resource: Target resource URI(s) ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)).
        ///   - acrValues: Optional ACR values to use.
        ///   - additionalParameters: Optional parameters to include in all requests to the Authorization Server.
        public init(nonce: String? = nil,
                    maxAge: TimeInterval? = nil,
                    audience: String? = TokenExchangeFlow.defaultAudience,
                    resource: ClaimCollection<[String]?> = nil,
                    acrValues: ClaimCollection<[String]?> = nil,
                    additionalParameters: [String: any APIRequestArgument]? = nil)
        {
            self.nonce = nonce
            self.maxAge = maxAge
            self.audience = audience
            self._resource = resource
            self._acrValues = acrValues
            self.additionalParameters = additionalParameters?.omitting("acr_values")

            if let additionalAcrValues = additionalParameters?.spaceSeparatedValues(for: "acr_values") {
                if self.acrValues.isNil {
                    self.acrValues = additionalAcrValues
                } else {
                    self.acrValues?.append(contentsOf: additionalAcrValues)
                }
            }
        }

        /// Initializer accepting the deprecated ``TokenExchangeFlow/Audience`` enum.
        @available(*, deprecated, message: "Use the String-based audience initializer instead.")
        public init(nonce: String? = nil,
                    maxAge: TimeInterval? = nil,
                    audience: Audience,
                    resource: ClaimCollection<[String]?> = nil,
                    acrValues: ClaimCollection<[String]?> = nil,
                    additionalParameters: [String: any APIRequestArgument]? = nil)
        {
            self.init(nonce: nonce,
                      maxAge: maxAge,
                      audience: audience.stringValue,
                      resource: resource,
                      acrValues: acrValues,
                      additionalParameters: additionalParameters)
        }

        @_documentation(visibility: internal)
        public func parameters(for category: OAuth2APIRequestCategory) -> [String: any APIRequestArgument]? {
            var result = additionalParameters ?? [:]

            switch category {
            case .authorization, .token:
                if let values = $acrValues.rawValue {
                    result["acr_values"] = values
                }

                if let audience = audience {
                    result["audience"] = audience
                }
                result["grant_type"] = GrantType.tokenExchange
                
                if let values = $resource.rawValue {
                    result["resource"] = values
                }
                
            case .configuration, .resource, .other: break
            }
            
            return result
        }
    }
}
