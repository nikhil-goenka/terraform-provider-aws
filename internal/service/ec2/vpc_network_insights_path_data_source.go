// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ec2

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKDataSource("aws_ec2_network_insights_path")
func DataSourceNetworkInsightsPath() *schema.Resource {
	return &schema.Resource{
		ReadWithoutTimeout: dataSourceNetworkInsightsPathRead,

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDestination: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDestinationARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"destination_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"destination_port": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			names.AttrFilter: customFiltersSchema(),
			"network_insights_path_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			names.AttrProtocol: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrSource: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"source_arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"source_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrTags: tftags.TagsSchemaComputed(),
		},
	}
}

func dataSourceNetworkInsightsPathRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).EC2Conn(ctx)
	ignoreTagsConfig := meta.(*conns.AWSClient).IgnoreTagsConfig

	input := &ec2.DescribeNetworkInsightsPathsInput{}

	if v, ok := d.GetOk("network_insights_path_id"); ok {
		input.NetworkInsightsPathIds = aws.StringSlice([]string{v.(string)})
	}

	input.Filters = append(input.Filters, newCustomFilterList(
		d.Get(names.AttrFilter).(*schema.Set),
	)...)

	if len(input.Filters) == 0 {
		// Don't send an empty filters list; the EC2 API won't accept it.
		input.Filters = nil
	}

	nip, err := FindNetworkInsightsPath(ctx, conn, input)

	if err != nil {
		return sdkdiag.AppendFromErr(diags, tfresource.SingularDataSourceFindError("EC2 Network Insights Path", err))
	}

	networkInsightsPathID := aws.StringValue(nip.NetworkInsightsPathId)
	d.SetId(networkInsightsPathID)
	d.Set(names.AttrARN, nip.NetworkInsightsPathArn)
	d.Set(names.AttrDestination, nip.Destination)
	d.Set(names.AttrDestinationARN, nip.DestinationArn)
	d.Set("destination_ip", nip.DestinationIp)
	d.Set("destination_port", nip.DestinationPort)
	d.Set("network_insights_path_id", networkInsightsPathID)
	d.Set(names.AttrProtocol, nip.Protocol)
	d.Set(names.AttrSource, nip.Source)
	d.Set("source_arn", nip.SourceArn)
	d.Set("source_ip", nip.SourceIp)

	if err := d.Set(names.AttrTags, KeyValueTags(ctx, nip.Tags).IgnoreAWS().IgnoreConfig(ignoreTagsConfig).Map()); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting tags: %s", err)
	}

	return diags
}
