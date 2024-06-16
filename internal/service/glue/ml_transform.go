// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package glue

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_glue_ml_transform", name="ML Transform")
// @Tags(identifierAttribute="arn")
func ResourceMLTransform() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceMLTransformCreate,
		ReadWithoutTimeout:   resourceMLTransformRead,
		UpdateWithoutTimeout: resourceMLTransformUpdate,
		DeleteWithoutTimeout: resourceMLTransformDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		CustomizeDiff: verify.SetTagsDiff,

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"input_record_tables": {
				Type:     schema.TypeList,
				Required: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrDatabaseName: {
							Type:     schema.TypeString,
							Required: true,
						},
						names.AttrTableName: {
							Type:     schema.TypeString,
							Required: true,
						},
						names.AttrCatalogID: {
							Type:     schema.TypeString,
							Optional: true,
						},
						"connection_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			names.AttrParameters: {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"find_matches_parameters": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"accuracy_cost_trade_off": {
										Type:         schema.TypeFloat,
										Optional:     true,
										ValidateFunc: validation.FloatAtMost(1.0),
									},
									"enforce_provided_labels": {
										Type:     schema.TypeBool,
										Optional: true,
									},
									"precision_recall_trade_off": {
										Type:         schema.TypeFloat,
										Optional:     true,
										ValidateFunc: validation.FloatAtMost(1.0),
									},
									"primary_key_column_name": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"transform_type": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringInSlice(glue.TransformType_Values(), false),
						},
					},
				},
			},
			names.AttrDescription: {
				Type:     schema.TypeString,
				Optional: true,
			},
			"glue_version": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			names.AttrMaxCapacity: {
				Type:          schema.TypeFloat,
				Optional:      true,
				Computed:      true,
				ConflictsWith: []string{"number_of_workers", "worker_type"},
				ValidateFunc:  validation.FloatBetween(2, 100),
			},
			"max_retries": {
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 10),
			},
			names.AttrName: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},
			names.AttrRoleARN: {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: verify.ValidARN,
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
			names.AttrTimeout: {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  2880,
			},
			"worker_type": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{names.AttrMaxCapacity},
				ValidateFunc:  validation.StringInSlice(glue.WorkerType_Values(), false),
				RequiredWith:  []string{"number_of_workers"},
			},
			"number_of_workers": {
				Type:          schema.TypeInt,
				Optional:      true,
				ConflictsWith: []string{names.AttrMaxCapacity},
				ValidateFunc:  validation.IntAtLeast(1),
				RequiredWith:  []string{"worker_type"},
			},
			"label_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			names.AttrSchema: {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrName: {
							Type:     schema.TypeString,
							Computed: true,
						},
						"data_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func resourceMLTransformCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)

	input := &glue.CreateMLTransformInput{
		Name:              aws.String(d.Get(names.AttrName).(string)),
		Role:              aws.String(d.Get(names.AttrRoleARN).(string)),
		Tags:              getTagsIn(ctx),
		Timeout:           aws.Int64(int64(d.Get(names.AttrTimeout).(int))),
		InputRecordTables: expandMLTransformInputRecordTables(d.Get("input_record_tables").([]interface{})),
		Parameters:        expandMLTransformParameters(d.Get(names.AttrParameters).([]interface{})),
	}

	if v, ok := d.GetOk(names.AttrMaxCapacity); ok {
		input.MaxCapacity = aws.Float64(v.(float64))
	}

	if v, ok := d.GetOk(names.AttrDescription); ok {
		input.Description = aws.String(v.(string))
	}

	if v, ok := d.GetOk("glue_version"); ok {
		input.GlueVersion = aws.String(v.(string))
	}

	if v, ok := d.GetOk("max_retries"); ok {
		input.MaxRetries = aws.Int64(int64(v.(int)))
	}

	if v, ok := d.GetOk("worker_type"); ok {
		input.WorkerType = aws.String(v.(string))
	}

	if v, ok := d.GetOk("number_of_workers"); ok {
		input.NumberOfWorkers = aws.Int64(int64(v.(int)))
	}

	log.Printf("[DEBUG] Creating Glue ML Transform: %s", input)
	output, err := conn.CreateMLTransformWithContext(ctx, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Glue ML Transform: %s", err)
	}

	d.SetId(aws.StringValue(output.TransformId))

	return append(diags, resourceMLTransformRead(ctx, d, meta)...)
}

func resourceMLTransformRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)

	input := &glue.GetMLTransformInput{
		TransformId: aws.String(d.Id()),
	}

	log.Printf("[DEBUG] Reading Glue ML Transform: %s", input)
	output, err := conn.GetMLTransformWithContext(ctx, input)
	if err != nil {
		if tfawserr.ErrCodeEquals(err, glue.ErrCodeEntityNotFoundException) {
			log.Printf("[WARN] Glue ML Transform (%s) not found, removing from state", d.Id())
			d.SetId("")
			return diags
		}
		return sdkdiag.AppendErrorf(diags, "reading Glue ML Transform (%s): %s", d.Id(), err)
	}

	if output == nil {
		log.Printf("[WARN] Glue ML Transform (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	log.Printf("[DEBUG] setting Glue ML Transform: %#v", output)

	mlTransformArn := arn.ARN{
		Partition: meta.(*conns.AWSClient).Partition,
		Service:   "glue",
		Region:    meta.(*conns.AWSClient).Region,
		AccountID: meta.(*conns.AWSClient).AccountID,
		Resource:  fmt.Sprintf("mlTransform/%s", d.Id()),
	}.String()
	d.Set(names.AttrARN, mlTransformArn)

	d.Set(names.AttrDescription, output.Description)
	d.Set("glue_version", output.GlueVersion)
	d.Set(names.AttrMaxCapacity, output.MaxCapacity)
	d.Set("max_retries", output.MaxRetries)
	d.Set(names.AttrName, output.Name)
	d.Set(names.AttrRoleARN, output.Role)
	d.Set(names.AttrTimeout, output.Timeout)
	d.Set("worker_type", output.WorkerType)
	d.Set("number_of_workers", output.NumberOfWorkers)
	d.Set("label_count", output.LabelCount)

	if err := d.Set("input_record_tables", flattenMLTransformInputRecordTables(output.InputRecordTables)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting input_record_tables: %s", err)
	}

	if err := d.Set(names.AttrParameters, flattenMLTransformParameters(output.Parameters)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting parameters: %s", err)
	}

	if err := d.Set(names.AttrSchema, flattenMLTransformSchemaColumns(output.Schema)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting schema: %s", err)
	}

	return diags
}

func resourceMLTransformUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)

	if d.HasChanges(names.AttrDescription, "glue_version", names.AttrMaxCapacity, "max_retries", "number_of_workers",
		names.AttrRoleARN, names.AttrTimeout, "worker_type", names.AttrParameters) {
		input := &glue.UpdateMLTransformInput{
			TransformId: aws.String(d.Id()),
			Role:        aws.String(d.Get(names.AttrRoleARN).(string)),
			Timeout:     aws.Int64(int64(d.Get(names.AttrTimeout).(int))),
		}

		if v, ok := d.GetOk(names.AttrDescription); ok {
			input.Description = aws.String(v.(string))
		}

		if v, ok := d.GetOk("worker_type"); ok {
			input.WorkerType = aws.String(v.(string))
		}

		if v, ok := d.GetOk("max_retries"); ok {
			input.MaxRetries = aws.Int64(int64(v.(int)))
		}

		if v, ok := d.GetOk("number_of_workers"); ok {
			input.NumberOfWorkers = aws.Int64(int64(v.(int)))
		} else {
			if v, ok := d.GetOk(names.AttrMaxCapacity); ok {
				input.MaxCapacity = aws.Float64(v.(float64))
			}
		}

		if v, ok := d.GetOk("glue_version"); ok {
			input.GlueVersion = aws.String(v.(string))
		}

		if v, ok := d.GetOk(names.AttrParameters); ok {
			input.Parameters = expandMLTransformParameters(v.([]interface{}))
		}

		log.Printf("[DEBUG] Updating Glue ML Transform: %s", input)
		_, err := conn.UpdateMLTransformWithContext(ctx, input)
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating Glue ML Transform (%s): %s", d.Id(), err)
		}
	}

	return append(diags, resourceMLTransformRead(ctx, d, meta)...)
}

func resourceMLTransformDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)

	log.Printf("[DEBUG] Deleting Glue ML Trasform: %s", d.Id())

	input := &glue.DeleteMLTransformInput{
		TransformId: aws.String(d.Id()),
	}

	_, err := conn.DeleteMLTransformWithContext(ctx, input)
	if err != nil {
		if tfawserr.ErrCodeEquals(err, glue.ErrCodeEntityNotFoundException) {
			return diags
		}
		return sdkdiag.AppendErrorf(diags, "deleting Glue ML Transform (%s): %s", d.Id(), err)
	}

	if _, err := waitMLTransformDeleted(ctx, conn, d.Id()); err != nil {
		if tfawserr.ErrCodeEquals(err, glue.ErrCodeEntityNotFoundException) {
			return diags
		}
		return sdkdiag.AppendErrorf(diags, "waiting for Glue ML Transform (%s) to be Deleted: %s", d.Id(), err)
	}

	return diags
}

func expandMLTransformInputRecordTables(l []interface{}) []*glue.Table {
	var tables []*glue.Table

	for _, mRaw := range l {
		m := mRaw.(map[string]interface{})

		table := &glue.Table{}

		if v, ok := m[names.AttrTableName].(string); ok {
			table.TableName = aws.String(v)
		}

		if v, ok := m[names.AttrDatabaseName].(string); ok {
			table.DatabaseName = aws.String(v)
		}

		if v, ok := m["connection_name"].(string); ok && v != "" {
			table.ConnectionName = aws.String(v)
		}

		if v, ok := m[names.AttrCatalogID].(string); ok && v != "" {
			table.CatalogId = aws.String(v)
		}

		tables = append(tables, table)
	}

	return tables
}

func flattenMLTransformInputRecordTables(tables []*glue.Table) []interface{} {
	l := []interface{}{}

	for _, table := range tables {
		m := map[string]interface{}{
			names.AttrTableName:    aws.StringValue(table.TableName),
			names.AttrDatabaseName: aws.StringValue(table.DatabaseName),
		}

		if table.ConnectionName != nil {
			m["connection_name"] = aws.StringValue(table.ConnectionName)
		}

		if table.CatalogId != nil {
			m[names.AttrCatalogID] = aws.StringValue(table.CatalogId)
		}

		l = append(l, m)
	}

	return l
}

func expandMLTransformParameters(l []interface{}) *glue.TransformParameters {
	m := l[0].(map[string]interface{})

	param := &glue.TransformParameters{
		TransformType: aws.String(m["transform_type"].(string)),
	}

	if v, ok := m["find_matches_parameters"]; ok && len(v.([]interface{})) > 0 {
		param.FindMatchesParameters = expandMLTransformFindMatchesParameters(v.([]interface{}))
	}

	return param
}

func flattenMLTransformParameters(parameters *glue.TransformParameters) []map[string]interface{} {
	if parameters == nil {
		return []map[string]interface{}{}
	}

	m := map[string]interface{}{
		"transform_type": aws.StringValue(parameters.TransformType),
	}

	if parameters.FindMatchesParameters != nil {
		m["find_matches_parameters"] = flattenMLTransformFindMatchesParameters(parameters.FindMatchesParameters)
	}

	return []map[string]interface{}{m}
}

func expandMLTransformFindMatchesParameters(l []interface{}) *glue.FindMatchesParameters {
	m := l[0].(map[string]interface{})

	param := &glue.FindMatchesParameters{}

	if v, ok := m["accuracy_cost_trade_off"]; ok {
		param.AccuracyCostTradeoff = aws.Float64(v.(float64))
	}

	if v, ok := m["precision_recall_trade_off"]; ok {
		param.PrecisionRecallTradeoff = aws.Float64(v.(float64))
	}

	if v, ok := m["enforce_provided_labels"]; ok {
		param.EnforceProvidedLabels = aws.Bool(v.(bool))
	}

	if v, ok := m["primary_key_column_name"]; ok && v != "" {
		param.PrimaryKeyColumnName = aws.String(v.(string))
	}

	return param
}

func flattenMLTransformFindMatchesParameters(parameters *glue.FindMatchesParameters) []map[string]interface{} {
	if parameters == nil {
		return []map[string]interface{}{}
	}

	m := map[string]interface{}{}

	if parameters.PrimaryKeyColumnName != nil {
		m["primary_key_column_name"] = aws.StringValue(parameters.PrimaryKeyColumnName)
	}

	if parameters.EnforceProvidedLabels != nil {
		m["enforce_provided_labels"] = aws.BoolValue(parameters.EnforceProvidedLabels)
	}

	if parameters.AccuracyCostTradeoff != nil {
		m["accuracy_cost_trade_off"] = aws.Float64Value(parameters.AccuracyCostTradeoff)
	}

	if parameters.PrimaryKeyColumnName != nil {
		m["precision_recall_trade_off"] = aws.Float64Value(parameters.PrecisionRecallTradeoff)
	}

	return []map[string]interface{}{m}
}

func flattenMLTransformSchemaColumns(schemaCols []*glue.SchemaColumn) []interface{} {
	l := []interface{}{}

	for _, schemaCol := range schemaCols {
		m := map[string]interface{}{
			names.AttrName: aws.StringValue(schemaCol.Name),
			"data_type":    aws.StringValue(schemaCol.DataType),
		}

		l = append(l, m)
	}

	return l
}
