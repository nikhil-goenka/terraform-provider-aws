// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kafkaconnect

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kafkaconnect"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKDataSource("aws_mskconnect_custom_plugin")
func DataSourceCustomPlugin() *schema.Resource {
	return &schema.Resource{
		ReadWithoutTimeout: dataSourceCustomPluginRead,

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDescription: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"latest_revision": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			names.AttrName: {
				Type:     schema.TypeString,
				Required: true,
			},
			names.AttrState: {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceCustomPluginRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).KafkaConnectConn(ctx)

	name := d.Get(names.AttrName)
	var output []*kafkaconnect.CustomPluginSummary

	err := conn.ListCustomPluginsPagesWithContext(ctx, &kafkaconnect.ListCustomPluginsInput{}, func(page *kafkaconnect.ListCustomPluginsOutput, lastPage bool) bool {
		if page == nil {
			return !lastPage
		}

		for _, v := range page.CustomPlugins {
			if aws.StringValue(v.Name) == name {
				output = append(output, v)
			}
		}

		return !lastPage
	})

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "listing MSK Connect Custom Plugins: %s", err)
	}

	if len(output) == 0 || output[0] == nil {
		err = tfresource.NewEmptyResultError(name)
	} else if count := len(output); count > 1 {
		err = tfresource.NewTooManyResultsError(count, name)
	}

	if err != nil {
		return sdkdiag.AppendFromErr(diags, tfresource.SingularDataSourceFindError("MSK Connect Custom Plugin", err))
	}

	plugin := output[0]

	d.SetId(aws.StringValue(plugin.CustomPluginArn))

	d.Set(names.AttrARN, plugin.CustomPluginArn)
	d.Set(names.AttrDescription, plugin.Description)
	d.Set(names.AttrName, plugin.Name)
	d.Set(names.AttrState, plugin.CustomPluginState)

	if plugin.LatestRevision != nil {
		d.Set("latest_revision", plugin.LatestRevision.Revision)
	} else {
		d.Set("latest_revision", nil)
	}

	return diags
}
