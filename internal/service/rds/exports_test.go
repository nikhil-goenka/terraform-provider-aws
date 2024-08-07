// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rds

// Exports for use in tests only.
var (
	ResourceCertificate                         = resourceCertificate
	ResourceCluster                             = resourceCluster
	ResourceClusterEndpoint                     = resourceClusterEndpoint
	ResourceClusterParameterGroup               = resourceClusterParameterGroup
	ResourceClusterRoleAssociation              = resourceClusterRoleAssociation
	ResourceClusterSnapshot                     = resourceClusterSnapshot
	ResourceCustomDBEngineVersion               = resourceCustomDBEngineVersion
	ResourceEventSubscription                   = resourceEventSubscription
	ResourceInstanceAutomatedBackupsReplication = resourceInstanceAutomatedBackupsReplication
	ResourceInstanceRoleAssociation             = resourceInstanceRoleAssociation
	ResourceOptionGroup                         = resourceOptionGroup
	ResourceParameterGroup                      = resourceParameterGroup
	ResourceProxy                               = resourceProxy
	ResourceProxyDefaultTargetGroup             = resourceProxyDefaultTargetGroup
	ResourceProxyEndpoint                       = resourceProxyEndpoint
	ResourceProxyTarget                         = resourceProxyTarget
	ResourceSnapshot                            = resourceSnapshot
	ResourceSnapshotCopy                        = resourceSnapshotCopy
	ResourceSubnetGroup                         = resourceSubnetGroup

	FindCustomDBEngineVersionByTwoPartKey      = findCustomDBEngineVersionByTwoPartKey
	FindDBClusterEndpointByID                  = findDBClusterEndpointByID
	FindDBClusterParameterGroupByName          = findDBClusterParameterGroupByName
	FindDBClusterRoleByTwoPartKey              = findDBClusterRoleByTwoPartKey
	FindDBClusterSnapshotByID                  = findDBClusterSnapshotByID
	FindDBInstanceAutomatedBackupByARN         = findDBInstanceAutomatedBackupByARN
	FindDBInstanceByID                         = findDBInstanceByIDSDKv1
	FindDBInstanceRoleByTwoPartKey             = findDBInstanceRoleByTwoPartKey
	FindDBParameterGroupByName                 = findDBParameterGroupByName
	FindDBProxyByName                          = findDBProxyByName
	FindDBProxyEndpointByTwoPartKey            = findDBProxyEndpointByTwoPartKey
	FindDBProxyTargetByFourPartKey             = findDBProxyTargetByFourPartKey
	FindDBSnapshotByID                         = findDBSnapshotByID
	FindDBSubnetGroupByName                    = findDBSubnetGroupByName
	FindDefaultCertificate                     = findDefaultCertificate
	FindDefaultDBProxyTargetGroupByDBProxyName = findDefaultDBProxyTargetGroupByDBProxyName
	FindEventSubscriptionByID                  = findEventSubscriptionByID
	FindOptionGroupByName                      = findOptionGroupByName
	ListTags                                   = listTags
	NewBlueGreenOrchestrator                   = newBlueGreenOrchestrator
	ParameterGroupModifyChunk                  = parameterGroupModifyChunk
	ParseDBInstanceARN                         = parseDBInstanceARN
	ProxyTargetParseResourceID                 = proxyTargetParseResourceID
	WaitBlueGreenDeploymentDeleted             = waitBlueGreenDeploymentDeleted
	WaitBlueGreenDeploymentAvailable           = waitBlueGreenDeploymentAvailable
	WaitDBInstanceAvailable                    = waitDBInstanceAvailableSDKv2
	WaitDBInstanceDeleted                      = waitDBInstanceDeleted

	ErrCodeInvalidAction               = errCodeInvalidAction
	ErrCodeInvalidParameterCombination = errCodeInvalidParameterCombination
	ErrCodeInvalidParameterValue       = errCodeInvalidParameterValue
)
