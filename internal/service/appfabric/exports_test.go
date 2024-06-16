// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package appfabric

// Exports for use in tests only.
var (
	ResourceAppAuthorization = newAppAuthorizationResource
	ResourceAppBundle        = newAppBundleResource

	FindAppAuthorizationByTwoPartKey = findAppAuthorizationByTwoPartKey
	FindAppBundleByID                = findAppBundleByID
)
