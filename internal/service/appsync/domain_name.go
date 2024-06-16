// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsync

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/appsync"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_appsync_domain_name")
func ResourceDomainName() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceDomainNameCreate,
		ReadWithoutTimeout:   resourceDomainNameRead,
		UpdateWithoutTimeout: resourceDomainNameUpdate,
		DeleteWithoutTimeout: resourceDomainNameDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"appsync_domain_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrCertificateARN: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: verify.ValidARN,
			},
			names.AttrDescription: {
				Type:     schema.TypeString,
				Optional: true,
			},
			names.AttrDomainName: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			names.AttrHostedZoneID: {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceDomainNameCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).AppSyncConn(ctx)

	params := &appsync.CreateDomainNameInput{
		CertificateArn: aws.String(d.Get(names.AttrCertificateARN).(string)),
		Description:    aws.String(d.Get(names.AttrDescription).(string)),
		DomainName:     aws.String(d.Get(names.AttrDomainName).(string)),
	}

	resp, err := conn.CreateDomainNameWithContext(ctx, params)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Appsync Domain Name: %s", err)
	}

	d.SetId(aws.StringValue(resp.DomainNameConfig.DomainName))

	return append(diags, resourceDomainNameRead(ctx, d, meta)...)
}

func resourceDomainNameRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).AppSyncConn(ctx)

	domainName, err := FindDomainNameByID(ctx, conn, d.Id())
	if domainName == nil && !d.IsNewResource() {
		log.Printf("[WARN] AppSync Domain Name (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "getting Appsync Domain Name %q: %s", d.Id(), err)
	}

	d.Set(names.AttrDomainName, domainName.DomainName)
	d.Set(names.AttrDescription, domainName.Description)
	d.Set(names.AttrCertificateARN, domainName.CertificateArn)
	d.Set(names.AttrHostedZoneID, domainName.HostedZoneId)
	d.Set("appsync_domain_name", domainName.AppsyncDomainName)

	return diags
}

func resourceDomainNameUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).AppSyncConn(ctx)

	params := &appsync.UpdateDomainNameInput{
		DomainName: aws.String(d.Id()),
	}

	if d.HasChange(names.AttrDescription) {
		params.Description = aws.String(d.Get(names.AttrDescription).(string))
	}

	_, err := conn.UpdateDomainNameWithContext(ctx, params)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "updating Appsync Domain Name %q: %s", d.Id(), err)
	}

	return append(diags, resourceDomainNameRead(ctx, d, meta)...)
}

func resourceDomainNameDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).AppSyncConn(ctx)

	input := &appsync.DeleteDomainNameInput{
		DomainName: aws.String(d.Id()),
	}

	err := retry.RetryContext(ctx, 5*time.Minute, func() *retry.RetryError {
		_, err := conn.DeleteDomainNameWithContext(ctx, input)
		if tfawserr.ErrCodeEquals(err, appsync.ErrCodeConcurrentModificationException) {
			return retry.RetryableError(fmt.Errorf("deleting Appsync Domain Name %q: %w", d.Id(), err))
		}
		if err != nil {
			return retry.NonRetryableError(err)
		}

		return nil
	})
	if tfresource.TimedOut(err) {
		_, err = conn.DeleteDomainNameWithContext(ctx, input)
	}
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Appsync Domain Name %q: %s", d.Id(), err)
	}

	return diags
}
