// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iot

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iot"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_iot_topic_rule_destination")
func ResourceTopicRuleDestination() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceTopicRuleDestinationCreate,
		ReadWithoutTimeout:   resourceTopicRuleDestinationRead,
		UpdateWithoutTimeout: resourceTopicRuleDestinationUpdate,
		DeleteWithoutTimeout: resourceTopicRuleDestinationDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Minute),
			Update: schema.DefaultTimeout(30 * time.Minute),
			Delete: schema.DefaultTimeout(30 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrEnabled: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			names.AttrVPCConfiguration: {
				Type:     schema.TypeList,
				Required: true,
				ForceNew: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrRoleARN: {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							ValidateFunc: verify.ValidARN,
						},
						names.AttrSecurityGroups: {
							Type:     schema.TypeSet,
							Optional: true,
							ForceNew: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						names.AttrSubnetIDs: {
							Type:     schema.TypeSet,
							Required: true,
							ForceNew: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						names.AttrVPCID: {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},
					},
				},
			},
		},
	}
}

func resourceTopicRuleDestinationCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	input := &iot.CreateTopicRuleDestinationInput{
		DestinationConfiguration: &iot.TopicRuleDestinationConfiguration{},
	}

	if v, ok := d.GetOk(names.AttrVPCConfiguration); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		input.DestinationConfiguration.VpcConfiguration = expandVPCDestinationConfiguration(v.([]interface{})[0].(map[string]interface{}))
	}

	log.Printf("[INFO] Creating IoT Topic Rule Destination: %s", input)
	outputRaw, err := tfresource.RetryWhen(ctx, propagationTimeout,
		func() (interface{}, error) {
			return conn.CreateTopicRuleDestinationWithContext(ctx, input)
		},
		func(err error) (bool, error) {
			if tfawserr.ErrMessageContains(err, iot.ErrCodeInvalidRequestException, "sts:AssumeRole") ||
				tfawserr.ErrMessageContains(err, iot.ErrCodeInvalidRequestException, "Missing permission") {
				return true, err
			}

			return false, err
		},
	)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating IoT Topic Rule Destination: %s", err)
	}

	d.SetId(aws.StringValue(outputRaw.(*iot.CreateTopicRuleDestinationOutput).TopicRuleDestination.Arn))

	if _, err := waitTopicRuleDestinationCreated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for IoT Topic Rule Destination (%s) create: %s", d.Id(), err)
	}

	if _, ok := d.GetOk(names.AttrEnabled); !ok {
		_, err := conn.UpdateTopicRuleDestinationWithContext(ctx, &iot.UpdateTopicRuleDestinationInput{
			Arn:    aws.String(d.Id()),
			Status: aws.String(iot.TopicRuleDestinationStatusDisabled),
		})

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "disabling IoT Topic Rule Destination (%s): %s", d.Id(), err)
		}

		if _, err := waitTopicRuleDestinationDisabled(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
			return sdkdiag.AppendErrorf(diags, "waiting for IoT Topic Rule Destination (%s) disable: %s", d.Id(), err)
		}
	}

	return append(diags, resourceTopicRuleDestinationRead(ctx, d, meta)...)
}

func resourceTopicRuleDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	output, err := FindTopicRuleDestinationByARN(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] IoT Topic Rule Destination %s not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading IoT Topic Rule Destination (%s): %s", d.Id(), err)
	}

	d.Set(names.AttrARN, output.Arn)
	d.Set(names.AttrEnabled, aws.StringValue(output.Status) == iot.TopicRuleDestinationStatusEnabled)
	if output.VpcProperties != nil {
		if err := d.Set(names.AttrVPCConfiguration, []interface{}{flattenVPCDestinationProperties(output.VpcProperties)}); err != nil {
			return sdkdiag.AppendErrorf(diags, "setting vpc_configuration: %s", err)
		}
	} else {
		d.Set(names.AttrVPCConfiguration, nil)
	}

	return diags
}

func resourceTopicRuleDestinationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	if d.HasChange(names.AttrEnabled) {
		input := &iot.UpdateTopicRuleDestinationInput{
			Arn:    aws.String(d.Id()),
			Status: aws.String(iot.TopicRuleDestinationStatusEnabled),
		}
		waiter := waitTopicRuleDestinationEnabled

		if _, ok := d.GetOk(names.AttrEnabled); !ok {
			input.Status = aws.String(iot.TopicRuleDestinationStatusDisabled)
			waiter = waitTopicRuleDestinationDisabled
		}

		_, err := conn.UpdateTopicRuleDestinationWithContext(ctx, input)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating IoT Topic Rule Destination (%s): %s", d.Id(), err)
		}

		if _, err := waiter(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
			return sdkdiag.AppendErrorf(diags, "waiting for IoT Topic Rule Destination (%s) update: %s", d.Id(), err)
		}
	}

	return append(diags, resourceTopicRuleDestinationRead(ctx, d, meta)...)
}

func resourceTopicRuleDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	log.Printf("[INFO] Deleting IoT Topic Rule Destination: %s", d.Id())
	_, err := conn.DeleteTopicRuleDestinationWithContext(ctx, &iot.DeleteTopicRuleDestinationInput{
		Arn: aws.String(d.Id()),
	})

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting IoT Topic Rule Destination: %s", err)
	}

	if _, err := waitTopicRuleDestinationDeleted(ctx, conn, d.Id(), d.Timeout(schema.TimeoutDelete)); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for IoT Topic Rule Destination (%s) delete: %s", d.Id(), err)
	}

	return diags
}

func expandVPCDestinationConfiguration(tfMap map[string]interface{}) *iot.VpcDestinationConfiguration {
	if tfMap == nil {
		return nil
	}

	apiObject := &iot.VpcDestinationConfiguration{}

	if v, ok := tfMap[names.AttrRoleARN].(string); ok && v != "" {
		apiObject.RoleArn = aws.String(v)
	}

	if v, ok := tfMap[names.AttrSecurityGroups].(*schema.Set); ok && v.Len() > 0 {
		apiObject.SecurityGroups = flex.ExpandStringSet(v)
	}

	if v, ok := tfMap[names.AttrSubnetIDs].(*schema.Set); ok && v.Len() > 0 {
		apiObject.SubnetIds = flex.ExpandStringSet(v)
	}

	if v, ok := tfMap[names.AttrVPCID].(string); ok && v != "" {
		apiObject.VpcId = aws.String(v)
	}

	return apiObject
}

func flattenVPCDestinationProperties(apiObject *iot.VpcDestinationProperties) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.RoleArn; v != nil {
		tfMap[names.AttrRoleARN] = aws.StringValue(v)
	}

	if v := apiObject.SecurityGroups; v != nil {
		tfMap[names.AttrSecurityGroups] = aws.StringValueSlice(v)
	}

	if v := apiObject.SubnetIds; v != nil {
		tfMap[names.AttrSubnetIDs] = aws.StringValueSlice(v)
	}

	if v := apiObject.VpcId; v != nil {
		tfMap[names.AttrVPCID] = aws.StringValue(v)
	}

	return tfMap
}

func statusTopicRuleDestination(ctx context.Context, conn *iot.IoT, arn string) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		output, err := FindTopicRuleDestinationByARN(ctx, conn, arn)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, aws.StringValue(output.Status), nil
	}
}

func waitTopicRuleDestinationCreated(ctx context.Context, conn *iot.IoT, arn string, timeout time.Duration) (*iot.TopicRuleDestination, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{iot.TopicRuleDestinationStatusInProgress},
		Target:  []string{iot.TopicRuleDestinationStatusEnabled},
		Refresh: statusTopicRuleDestination(ctx, conn, arn),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*iot.TopicRuleDestination); ok {
		tfresource.SetLastError(err, errors.New(aws.StringValue(output.StatusReason)))

		return output, err
	}

	return nil, err
}

func waitTopicRuleDestinationDeleted(ctx context.Context, conn *iot.IoT, arn string, timeout time.Duration) (*iot.TopicRuleDestination, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{iot.TopicRuleDestinationStatusDeleting},
		Target:  []string{},
		Refresh: statusTopicRuleDestination(ctx, conn, arn),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*iot.TopicRuleDestination); ok {
		tfresource.SetLastError(err, errors.New(aws.StringValue(output.StatusReason)))

		return output, err
	}

	return nil, err
}

func waitTopicRuleDestinationDisabled(ctx context.Context, conn *iot.IoT, arn string, timeout time.Duration) (*iot.TopicRuleDestination, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{iot.TopicRuleDestinationStatusInProgress},
		Target:  []string{iot.TopicRuleDestinationStatusDisabled},
		Refresh: statusTopicRuleDestination(ctx, conn, arn),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*iot.TopicRuleDestination); ok {
		tfresource.SetLastError(err, errors.New(aws.StringValue(output.StatusReason)))

		return output, err
	}

	return nil, err
}

func waitTopicRuleDestinationEnabled(ctx context.Context, conn *iot.IoT, arn string, timeout time.Duration) (*iot.TopicRuleDestination, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{iot.TopicRuleDestinationStatusInProgress},
		Target:  []string{iot.TopicRuleDestinationStatusEnabled},
		Refresh: statusTopicRuleDestination(ctx, conn, arn),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*iot.TopicRuleDestination); ok {
		tfresource.SetLastError(err, errors.New(aws.StringValue(output.StatusReason)))

		return output, err
	}

	return nil, err
}
