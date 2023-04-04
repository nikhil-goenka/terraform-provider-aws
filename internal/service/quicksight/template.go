package quicksight

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/quicksight"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_quicksight_template")
func ResourceTemplate() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceTemplateCreate,
		ReadWithoutTimeout:   resourceTemplateRead,
		UpdateWithoutTimeout: resourceTemplateUpdate,
		DeleteWithoutTimeout: resourceTemplateDelete,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(5 * time.Minute),
			Delete: schema.DefaultTimeout(5 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"aws_account_id": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ForceNew:     true,
				ValidateFunc: verify.ValidAccountID,
			},
			"created_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"definition": definitionSchema(),
			"last_updated_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringLenBetween(1, 2048),
			},
			"permissions": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				MaxItems: 64,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"actions": {
							Type:     schema.TypeSet,
							Required: true,
							MinItems: 1,
							MaxItems: 16,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"principal": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringLenBetween(1, 256),
						},
					},
				},
			},
			"source_entity": sourceEntitySchema(),
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tags":     tftags.TagsSchema(),
			"tags_all": tftags.TagsSchemaComputed(),
			"template_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"version_description": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringLenBetween(1, 512),
			},
			"version_number": {
				Type:     schema.TypeInt,
				Computed: true,
			},
		},
		CustomizeDiff: verify.SetTagsDiff,
	}
}

func definitionSchema() *schema.Schema {
	return &schema.Schema{ // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_TemplateVersionDefinition.html
		Type:     schema.TypeList,
		MaxItems: 1,
		Optional: true,
		ExactlyOneOf: []string{
			"definition",
			"source_entity",
		},
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"data_set_configuration": dataSetConfigurationSchema(), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_DataSetConfiguration.html
				"analysis_defaults":      analysisDefaultSchema(),      // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_AnalysisDefaults.html
				"calculated_fields": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CalculatedField.html
					Type:     schema.TypeList,
					MinItems: 1,
					MaxItems: 100,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"data_set_identifier": stringSchema(true, validation.StringLenBetween(1, 2048)),
							"expression":          stringSchema(true, validation.StringLenBetween(1, 4096)),
							"name":                stringSchema(true, validation.StringLenBetween(1, 128)),
						},
					},
				},
				"column_configurations": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ColumnConfiguration.html
					Type:     schema.TypeList,
					MinItems: 1,
					MaxItems: 200,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"column":               columnSchema(),              // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ColumnIdentifier.html
							"format_configuration": formatConfigurationSchema(), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_FormatConfiguration.html
							"role":                 stringSchema(false, validation.StringInSlice(quicksight.ColumnRole_Values(), false)),
						},
					},
				},
				"filter_groups": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_FilterGroup.html
					Type:     schema.TypeList,
					MinItems: 1,
					MaxItems: 2000,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"cross_dataset":       stringSchema(true, validation.StringInSlice(quicksight.CrossDatasetTypes_Values(), false)),
							"filter_group_id":     idSchema(),
							"filters":             filtersSchema(),                  // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_Filter.html
							"scope_configuration": filterScopeConfigurationSchema(), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_FilterScopeConfiguration.html
							"status":              stringSchema(false, validation.StringInSlice(quicksight.Status_Values(), false)),
						},
					},
				},
				"parameters_declarations": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ParameterDeclaration.html
					Type:     schema.TypeList,
					MinItems: 1,
					MaxItems: 200,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"date_time_parameter_declaration": dateTimeParameterDeclarationSchema(), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_DateTimeParameterDeclaration.html
							"decimal_parameter_declaration":   decimalParameterDeclarationSchema(),  // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_DecimalParameterDeclaration.html
							"integer_parameter_declaration":   integerParameterDeclarationSchema(),  // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_IntegerParameterDeclaration.html
							"string_parameter_declaration":    stringParameterDeclarationSchema(),   // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_StringParameterDeclaration.html
						},
					},
				},
				"sheets": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_SheetDefinition.html
					Type:     schema.TypeList,
					MinItems: 1,
					MaxItems: 20,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"sheet_id":              idSchema(),
							"content_type":          stringSchema(false, validation.StringInSlice(quicksight.SheetContentType_Values(), false)),
							"description":           stringSchema(false, validation.StringLenBetween(1, 1024)),
							"filter_controls":       filterControlsSchema(), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_FilterControl.html
							"layouts":               layoutSchema(),         // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_Layout.html
							"name":                  stringSchema(false, validation.StringLenBetween(1, 2048)),
							"parameter_controls":    parameterControlsSchema(),   // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ParameterControl.html
							"sheet_control_layouts": sheetControlLayoutsSchema(), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_SheetControlLayout.html
							"text_boxes": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_SheetTextBox.html
								Type:     schema.TypeList,
								MinItems: 1,
								MaxItems: 100,
								Optional: true,
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"sheet_text_box_id": idSchema(),
										"content":           stringSchema(false, validation.StringLenBetween(1, 150000)),
									},
								},
							},
							"title":   stringSchema(false, validation.StringLenBetween(1, 1024)),
							"visuals": visualsSchema(), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_Visual.html
						},
					},
				},
			},
		},
	}
}

func stringSchema(required bool, validateFunc schema.SchemaValidateFunc) *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Required:     required,
		Optional:     !required,
		ValidateFunc: validateFunc,
	}
}

func intSchema(required bool, validateFunc schema.SchemaValidateFunc) *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeInt,
		Required:     required,
		Optional:     !required,
		ValidateFunc: validateFunc,
	}
}

func floatSchema(required bool, validateFunc schema.SchemaValidateFunc) *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeFloat,
		Required:     required,
		Optional:     !required,
		ValidateFunc: validateFunc,
	}
}

func aggregationFunctionSchema(required bool) *schema.Schema {
	return &schema.Schema{ // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_AggregationFunction.html
		Type:     schema.TypeList,
		Required: required,
		Optional: !required,
		MinItems: 1,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"categorical_aggregation_function": stringSchema(false, validation.StringInSlice(quicksight.CategoricalAggregationFunction_Values(), false)),
				"date_aggregation_function":        stringSchema(false, validation.StringInSlice(quicksight.DateAggregationFunction_Values(), false)),
				"numerical_aggregation_function":   numericalAggregationFunctionSchema(false), // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_NumericalAggregationFunction.html
			},
		},
	}
}

func numericalAggregationFunctionSchema(required bool) *schema.Schema {
	return &schema.Schema{ // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_NumericalAggregationFunction.html
		Type:     schema.TypeList,
		Required: required,
		Optional: !required,
		MinItems: 1,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"percentile_aggregation": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_PercentileAggregation.html
					Type:     schema.TypeList,
					Optional: true,
					MinItems: 1,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"percentile_value": {
								Type:         schema.TypeFloat,
								Optional:     true,
								ValidateFunc: validation.IntBetween(0, 100),
							},
						},
					},
				},
				"simple_numerical_aggregation": stringSchema(false, validation.StringInSlice(quicksight.SimpleNumericalAggregationFunction_Values(), false)),
			},
		},
	}
}

func idSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ValidateFunc: validation.All(
			validation.StringLenBetween(1, 512),
			validation.StringMatch(regexp.MustCompile(`[\w\-]+`), "must contain only alphanumeric, hyphen, and underscore characters"),
		),
	}
}

func columnSchema() *schema.Schema {
	return &schema.Schema{ // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ColumnIdentifier.html
		Type:     schema.TypeList,
		MinItems: 1,
		MaxItems: 1,
		Required: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"column_name":         stringSchema(true, validation.StringLenBetween(1, 128)),
				"data_set_identifier": stringSchema(true, validation.StringLenBetween(1, 2048)),
			},
		},
	}
}

func dataSetConfigurationSchema() *schema.Schema {
	return &schema.Schema{ // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_DataSetConfiguration.html
		Type:     schema.TypeList,
		MaxItems: 30,
		Required: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"column_group_schema_list": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ColumnGroupSchema.html
					Type:     schema.TypeList,
					MinItems: 1,
					MaxItems: 500,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"column_group_column_schema_list": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ColumnGroupColumnSchema.html
								Type:     schema.TypeList,
								MinItems: 1,
								MaxItems: 500,
								Optional: true,
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"name": {
											Type:     schema.TypeString,
											Optional: true,
										},
									},
								},
							},
							"name": {
								Type:     schema.TypeString,
								Optional: true,
							},
						},
					},
				},
				"data_set_schema": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_DataSetSchema.html
					Type:     schema.TypeList,
					MinItems: 1,
					MaxItems: 1,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"column_schema_list": { // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ColumnSchema.html
								Type:     schema.TypeList,
								MinItems: 1,
								MaxItems: 500,
								Optional: true,
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"data_type": {
											Type:     schema.TypeString,
											Optional: true,
										},
										"geographic_role": {
											Type:     schema.TypeString,
											Optional: true,
										},
										"name": {
											Type:     schema.TypeString,
											Optional: true,
										},
									},
								},
							},
						},
					},
				},
				"placeholder": {
					Type:     schema.TypeString,
					Optional: true,
				},
			},
		},
	}
}

func rollingDateConfigurationSchema() *schema.Schema {
	return &schema.Schema{ // https://docs.aws.amazon.com/quicksight/latest/APIReference/API_RollingDateConfiguration.html
		Type:     schema.TypeList,
		MinItems: 1,
		MaxItems: 1,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"data_set_identifier": stringSchema(false, validation.StringLenBetween(1, 2048)),
				"expression":          stringSchema(true, validation.StringLenBetween(1, 4096)),
			},
		},
	}
}

func sourceEntitySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		MaxItems: 1,
		Optional: true,
		ExactlyOneOf: []string{
			"definition",
			"source_entity",
		},
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"source_analysis": {
					Type:         schema.TypeList,
					MaxItems:     1,
					Optional:     true,
					ExactlyOneOf: []string{"source_entity.0.source_analysis", "source_entity.0.source_template"},
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"arn": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: verify.ValidARN,
							},
							"data_set_references": {
								Type:     schema.TypeList,
								Required: true,
								MinItems: 1,
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"data_set_arn": {
											Type:         schema.TypeString,
											Required:     true,
											ValidateFunc: verify.ValidARN,
										},
										"data_set_placeholder": {
											Type:     schema.TypeString,
											Required: true,
										},
									},
								},
							},
						},
					},
				},
				"source_template": {
					Type:         schema.TypeList,
					MaxItems:     1,
					Optional:     true,
					ExactlyOneOf: []string{"source_entity.0.source_analysis", "source_entity.0.source_template"},
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"arn": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: verify.ValidARN,
							},
						},
					},
				},
			},
		},
	}
}

const (
	ResNameTemplate = "Template"
)

func resourceTemplateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).QuickSightConn()
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig

	awsAccountId := meta.(*conns.AWSClient).AccountID
	if v, ok := d.GetOk("aws_account_id"); ok {
		awsAccountId = v.(string)
	}
	templateId := d.Get("template_id").(string)

	d.SetId(createTemplateId(awsAccountId, templateId))

	input := &quicksight.CreateTemplateInput{
		AwsAccountId: aws.String(awsAccountId),
		TemplateId:   aws.String(templateId),
		Name:         aws.String(d.Get("name").(string)),
	}

	if v, ok := d.GetOk("version_description"); ok {
		input.VersionDescription = aws.String(v.(string))
	}

	if v, ok := d.GetOk("source_entity"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		input.SourceEntity = expandSourceEntity(v.([]interface{}))
	}

	if v, ok := d.GetOk("definition"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		input.Definition = expandDefinition(d.Get("definition").([]interface{}))
	}

	if v, ok := d.GetOk("permissions"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		input.Permissions = expandResourcePermissions(v.([]interface{}))
	}

	tags := defaultTagsConfig.MergeTags(tftags.New(ctx, d.Get("tags").(map[string]interface{})))
	if len(tags) > 0 {
		input.Tags = Tags(tags.IgnoreAWS())
	}

	_, err := conn.CreateTemplateWithContext(ctx, input)
	if err != nil {
		return create.DiagError(names.QuickSight, create.ErrActionCreating, ResNameTemplate, d.Get("name").(string), err)
	}

	if _, err := waitTemplateCreated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
		return create.DiagError(names.QuickSight, create.ErrActionWaitingForCreation, ResNameTemplate, d.Id(), err)
	}

	return resourceTemplateRead(ctx, d, meta)
}

func resourceTemplateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).QuickSightConn()

	awsAccountId, templateId, err := ParseTemplateId(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	out, err := FindTemplateByID(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] QuickSight Template (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return create.DiagError(names.QuickSight, create.ErrActionReading, ResNameTemplate, d.Id(), err)
	}

	d.Set("arn", out.Arn)
	d.Set("aws_account_id", awsAccountId)
	d.Set("created_time", out.CreatedTime.Format(time.RFC3339))
	d.Set("last_updated_time", out.LastUpdatedTime.Format(time.RFC3339))
	d.Set("name", out.Name)
	d.Set("status", out.Version.Status)
	d.Set("template_id", out.TemplateId)
	d.Set("version_description", out.Version.Description)
	d.Set("version_number", out.Version.VersionNumber)

	tags, err := ListTags(ctx, conn, aws.StringValue(out.Arn))
	if err != nil {
		return create.DiagError(names.QuickSight, create.ErrActionReading, ResNameTemplate, d.Id(), err)
	}

	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	ignoreTagsConfig := meta.(*conns.AWSClient).IgnoreTagsConfig
	tags = tags.IgnoreAWS().IgnoreConfig(ignoreTagsConfig)

	if err := d.Set("tags", tags.RemoveDefaultConfig(defaultTagsConfig).Map()); err != nil {
		return create.DiagError(names.QuickSight, create.ErrActionSetting, ResNameTemplate, d.Id(), err)
	}

	if err := d.Set("tags_all", tags.Map()); err != nil {
		return create.DiagError(names.QuickSight, create.ErrActionSetting, ResNameTemplate, d.Id(), err)
	}

	permsResp, err := conn.DescribeTemplatePermissionsWithContext(ctx, &quicksight.DescribeTemplatePermissionsInput{
		AwsAccountId: aws.String(awsAccountId),
		TemplateId:   aws.String(templateId),
	})

	if err != nil {
		return diag.Errorf("error describing QuickSight Template (%s) Permissions: %s", d.Id(), err)
	}

	if err := d.Set("permissions", flattenPermissions(permsResp.Permissions)); err != nil {
		return diag.Errorf("error setting permissions: %s", err)
	}

	return nil
}

func resourceTemplateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).QuickSightConn()

	awsAccountId, templateId, err := ParseTemplateId(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	if d.HasChangesExcept("permission", "tags", "tags_all") {
		in := &quicksight.UpdateTemplateInput{
			AwsAccountId:       aws.String(awsAccountId),
			TemplateId:         aws.String(templateId),
			Name:               aws.String(d.Get("name").(string)),
			VersionDescription: aws.String(d.Get("version_description").(string)),
		}

		if d.HasChange("source_entity") {
			in.SourceEntity = expandSourceEntity(d.Get("source_entity").([]interface{}))
		}

		if d.HasChange("definition") {
			in.Definition = expandDefinition(d.Get("definition").([]interface{}))
		}

		log.Printf("[DEBUG] Updating QuickSight Template (%s): %#v", d.Id(), in)
		_, err := conn.UpdateTemplateWithContext(ctx, in)
		if err != nil {
			return create.DiagError(names.QuickSight, create.ErrActionUpdating, ResNameTemplate, d.Id(), err)
		}

		if _, err := waitTemplateUpdated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutUpdate)); err != nil {
			return create.DiagError(names.QuickSight, create.ErrActionWaitingForUpdate, ResNameTemplate, d.Id(), err)
		}
	}

	if d.HasChange("permissions") {
		oraw, nraw := d.GetChange("permissions")
		o := oraw.([]interface{})
		n := nraw.([]interface{})

		toGrant, toRevoke := DiffPermissions(o, n)

		params := &quicksight.UpdateTemplatePermissionsInput{
			AwsAccountId: aws.String(awsAccountId),
			TemplateId:   aws.String(templateId),
		}

		if len(toGrant) > 0 {
			params.GrantPermissions = toGrant
		}

		if len(toRevoke) > 0 {
			params.RevokePermissions = toRevoke
		}

		_, err = conn.UpdateTemplatePermissionsWithContext(ctx, params)

		if err != nil {
			return diag.Errorf("error updating QuickSight Template (%s) permissions: %s", templateId, err)
		}
	}

	if d.HasChange("tags_all") {
		o, n := d.GetChange("tags_all")

		if err := UpdateTags(ctx, conn, d.Get("arn").(string), o, n); err != nil {
			return diag.Errorf("error updating QuickSight Template (%s) tags: %s", d.Id(), err)
		}
	}

	return resourceTemplateRead(ctx, d, meta)
}

func resourceTemplateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).QuickSightConn()

	awsAccountId, templateId, err := ParseTemplateId(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[INFO] Deleting QuickSight Template %s", d.Id())
	_, err = conn.DeleteTemplateWithContext(ctx, &quicksight.DeleteTemplateInput{
		AwsAccountId: aws.String(awsAccountId),
		TemplateId:   aws.String(templateId),
	})

	if tfawserr.ErrCodeEquals(err, quicksight.ErrCodeResourceNotFoundException) {
		return nil
	}

	if err != nil {
		return create.DiagError(names.QuickSight, create.ErrActionDeleting, ResNameTemplate, d.Id(), err)
	}

	return nil
}

func FindTemplateByID(ctx context.Context, conn *quicksight.QuickSight, id string) (*quicksight.Template, error) {
	awsAccountId, templateId, err := ParseTemplateId(id)
	if err != nil {
		return nil, err
	}

	descOpts := &quicksight.DescribeTemplateInput{
		AwsAccountId: aws.String(awsAccountId),
		TemplateId:   aws.String(templateId),
	}

	out, err := conn.DescribeTemplateWithContext(ctx, descOpts)

	if tfawserr.ErrCodeEquals(err, quicksight.ErrCodeResourceNotFoundException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: descOpts,
		}
	}

	if err != nil {
		return nil, err
	}

	if out == nil || out.Template == nil {
		return nil, tfresource.NewEmptyResultError(descOpts)
	}

	return out.Template, nil
}

func expandSourceEntity(tfList []interface{}) *quicksight.TemplateSourceEntity {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}

	sourceEntity := &quicksight.TemplateSourceEntity{}

	if v, ok := tfMap["source_analysis"].([]interface{}); ok && len(v) > 0 {
		sourceEntity.SourceAnalysis = expandSourceAnalysis(v[0].(map[string]interface{}))
	} else if v, ok := tfMap["source_template"].([]interface{}); ok && len(v) > 0 {
		sourceEntity.SourceTemplate = expandSourceTemplate(v[0].(map[string]interface{}))
	}

	return sourceEntity
}

func expandSourceAnalysis(tfMap map[string]interface{}) *quicksight.TemplateSourceAnalysis {
	if tfMap == nil {
		return nil
	}

	sourceAnalysis := &quicksight.TemplateSourceAnalysis{}
	if v, ok := tfMap["arn"].(string); ok && v != "" {
		sourceAnalysis.Arn = aws.String(v)
	}
	if v, ok := tfMap["data_set_references"].([]interface{}); ok && len(v) > 0 {
		sourceAnalysis.DataSetReferences = expandDataSetReferences(v)
	}

	return sourceAnalysis
}

func expandDataSetReferences(tfList []interface{}) []*quicksight.DataSetReference {
	if len(tfList) == 0 {
		return nil
	}

	var dataSetReferences []*quicksight.DataSetReference
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		dataSetReference := expandDataSetReference(tfMap)
		if dataSetReference == nil {
			continue
		}

		dataSetReferences = append(dataSetReferences, dataSetReference)
	}

	return dataSetReferences
}

func expandDataSetReference(tfMap map[string]interface{}) *quicksight.DataSetReference {
	if tfMap == nil {
		return nil
	}

	dataSetReference := &quicksight.DataSetReference{}
	if v, ok := tfMap["data_set_arn"].(string); ok {
		dataSetReference.DataSetArn = aws.String(v)
	}
	if v, ok := tfMap["data_set_placeholder"].(string); ok {
		dataSetReference.DataSetPlaceholder = aws.String(v)
	}

	return dataSetReference
}

func expandSourceTemplate(tfMap map[string]interface{}) *quicksight.TemplateSourceTemplate {
	if tfMap == nil {
		return nil
	}

	sourceTemplate := &quicksight.TemplateSourceTemplate{}
	if v, ok := tfMap["arn"].(string); ok && v != "" {
		sourceTemplate.Arn = aws.String(v)
	}

	return sourceTemplate
}

func expandDefinition(tfList []interface{}) *quicksight.TemplateVersionDefinition {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}

	definition := &quicksight.TemplateVersionDefinition{}

	if v, ok := tfMap["analysis_defaults"].([]interface{}); ok && len(v) > 0 {
		definition.AnalysisDefaults = expandAnalysisDefaults(v)
	}
	if v, ok := tfMap["calculated_fields"].([]interface{}); ok && len(v) > 0 {
		definition.CalculatedFields = expandCalculatedFields(v)
	}
	if v, ok := tfMap["column_configurations"].([]interface{}); ok && len(v) > 0 {
		definition.ColumnConfigurations = expandColumnConfigurations(v)
	}
	if v, ok := tfMap["data_set_configuration"].([]interface{}); ok && len(v) > 0 {
		definition.DataSetConfigurations = expandDataSetConfigurations(v)
	}
	if v, ok := tfMap["filter_groups"].([]interface{}); ok && len(v) > 0 {
		definition.FilterGroups = expandFilterGroups(v)
	}
	if v, ok := tfMap["parameters_declarations"].([]interface{}); ok && len(v) > 0 {
		definition.ParameterDeclarations = expandParameterDeclarations(v)
	}
	if v, ok := tfMap["sheets"].([]interface{}); ok && len(v) > 0 {
		definition.Sheets = expandSheetDefinitions(v)
	}

	return definition
}

func expandCalculatedFields(tfList []interface{}) []*quicksight.CalculatedField {
	if len(tfList) == 0 {
		return nil
	}

	var fields []*quicksight.CalculatedField
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		field := expandCalculatedField(tfMap)
		if field == nil {
			continue
		}

		fields = append(fields, field)
	}

	return fields
}

func expandCalculatedField(tfMap map[string]interface{}) *quicksight.CalculatedField {
	if tfMap == nil {
		return nil
	}

	field := &quicksight.CalculatedField{}

	if v, ok := tfMap["data_set_identifier"].(string); ok && v != "" {
		field.DataSetIdentifier = aws.String(v)
	}
	if v, ok := tfMap["expression"].(string); ok && v != "" {
		field.Expression = aws.String(v)
	}
	if v, ok := tfMap["name"].(string); ok && v != "" {
		field.Name = aws.String(v)
	}

	return field
}

func expandColumnConfigurations(tfList []interface{}) []*quicksight.ColumnConfiguration {
	if len(tfList) == 0 {
		return nil
	}

	var configs []*quicksight.ColumnConfiguration
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		column := expandColumnConfiguration(tfMap)
		if column == nil {
			continue
		}

		configs = append(configs, column)
	}

	return configs
}

func expandColumnConfiguration(tfMap map[string]interface{}) *quicksight.ColumnConfiguration {
	if tfMap == nil {
		return nil
	}

	column := &quicksight.ColumnConfiguration{}

	if v, ok := tfMap["column"].([]interface{}); ok && len(v) > 0 {
		column.Column = expandColumnIdentifier(v)
	}

	if v, ok := tfMap["format_configuration"].([]interface{}); ok && len(v) > 0 {
		column.FormatConfiguration = expandFormatConfiguration(v)
	}

	if v, ok := tfMap["role"].(string); ok && v != "" {
		column.Role = aws.String(v)
	}

	return column
}

func expandColumnIdentifier(tfList []interface{}) *quicksight.ColumnIdentifier {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}

	return expandColumnIdentifierInternal(tfMap)
}

func expandColumnIdentifierInternal(tfMap map[string]interface{}) *quicksight.ColumnIdentifier {
	column := &quicksight.ColumnIdentifier{}

	if v, ok := tfMap["data_set_identifier"].(string); ok && v != "" {
		column.DataSetIdentifier = aws.String(v)
	}
	if v, ok := tfMap["column_name"].(string); ok && v != "" {
		column.ColumnName = aws.String(v)
	}

	return column
}

func expandColumnIdentifiers(tfList []interface{}) []*quicksight.ColumnIdentifier {
	if len(tfList) == 0 {
		return nil
	}

	var columns []*quicksight.ColumnIdentifier
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		col := expandColumnIdentifierInternal(tfMap)
		if col == nil {
			continue
		}

		columns = append(columns, col)
	}

	return columns
}

func expandDataSetConfigurations(tfList []interface{}) []*quicksight.DataSetConfiguration {
	if len(tfList) == 0 {
		return nil
	}

	var configs []*quicksight.DataSetConfiguration
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		config := expandDataSetConfiguration(tfMap)
		if config == nil {
			continue
		}

		configs = append(configs, config)
	}

	return configs
}

func expandDataSetConfiguration(tfMap map[string]interface{}) *quicksight.DataSetConfiguration {
	if tfMap == nil {
		return nil
	}

	config := &quicksight.DataSetConfiguration{}

	if v, ok := tfMap["column_group_schema_list"].([]interface{}); ok && len(v) > 0 {
		config.ColumnGroupSchemaList = expandColumnGroupSchemas(v)
	}
	if v, ok := tfMap["data_set_schema"].([]interface{}); ok && len(v) > 0 {
		config.DataSetSchema = expandDataSetSchema(v)
	}
	if v, ok := tfMap["placeholder"].(string); ok && v != "" {
		config.Placeholder = aws.String(v)
	}

	return config
}

func expandColumnGroupSchemas(tfList []interface{}) []*quicksight.ColumnGroupSchema {
	if len(tfList) == 0 {
		return nil
	}

	var groups []*quicksight.ColumnGroupSchema
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		group := expandColumnGroupSchema(tfMap)
		if group == nil {
			continue
		}

		groups = append(groups, group)
	}

	return groups
}

func expandColumnGroupSchema(tfMap map[string]interface{}) *quicksight.ColumnGroupSchema {
	if tfMap == nil {
		return nil
	}

	group := &quicksight.ColumnGroupSchema{}

	if v, ok := tfMap["column_group_schema_list"].([]interface{}); ok && len(v) > 0 {
		group.ColumnGroupColumnSchemaList = expandColumnGroupColumnSchemas(v)
	}
	if v, ok := tfMap["name"].(string); ok && v != "" {
		group.Name = aws.String(v)
	}

	return group
}

func expandColumnGroupColumnSchemas(tfList []interface{}) []*quicksight.ColumnGroupColumnSchema {
	if len(tfList) == 0 {
		return nil
	}

	var columns []*quicksight.ColumnGroupColumnSchema
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		column := expandColumnGroupColumnSchema(tfMap)
		if column == nil {
			continue
		}

		columns = append(columns, column)
	}

	return columns
}

func expandColumnGroupColumnSchema(tfMap map[string]interface{}) *quicksight.ColumnGroupColumnSchema {
	if tfMap == nil {
		return nil
	}

	column := &quicksight.ColumnGroupColumnSchema{}

	if v, ok := tfMap["name"].(string); ok && v != "" {
		column.Name = aws.String(v)
	}

	return column
}

func expandDataSetSchema(tfList []interface{}) *quicksight.DataSetSchema {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}
	schema := &quicksight.DataSetSchema{}

	if v, ok := tfMap["column_schema_list"].([]interface{}); ok && len(v) > 0 {
		schema.ColumnSchemaList = expandColumnSchemas(v)
	}

	return schema
}

func expandColumnSchemas(tfList []interface{}) []*quicksight.ColumnSchema {
	if len(tfList) == 0 {
		return nil
	}

	var columns []*quicksight.ColumnSchema
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		column := expandColumnSchema(tfMap)
		if column == nil {
			continue
		}

		columns = append(columns, column)
	}

	return columns
}

func expandColumnSchema(tfMap map[string]interface{}) *quicksight.ColumnSchema {
	if tfMap == nil {
		return nil
	}

	column := &quicksight.ColumnSchema{}

	if v, ok := tfMap["data_type"].(string); ok && v != "" {
		column.DataType = aws.String(v)
	}
	if v, ok := tfMap["geographic_role"].(string); ok && v != "" {
		column.GeographicRole = aws.String(v)
	}
	if v, ok := tfMap["name"].(string); ok && v != "" {
		column.Name = aws.String(v)
	}

	return column
}

func expandFilterGroups(tfList []interface{}) []*quicksight.FilterGroup {
	if len(tfList) == 0 {
		return nil
	}

	var groups []*quicksight.FilterGroup
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		group := expandFilterGroup(tfMap)
		if group == nil {
			continue
		}

		groups = append(groups, group)
	}

	return groups
}

func expandFilterGroup(tfMap map[string]interface{}) *quicksight.FilterGroup {
	if tfMap == nil {
		return nil
	}

	group := &quicksight.FilterGroup{}

	if v, ok := tfMap["cross_dataset"].(string); ok && v != "" {
		group.CrossDataset = aws.String(v)
	}
	if v, ok := tfMap["filter_group_id"].(string); ok && v != "" {
		group.FilterGroupId = aws.String(v)
	}
	if v, ok := tfMap["status"].(string); ok && v != "" {
		group.Status = aws.String(v)
	}
	if v, ok := tfMap["filters"].([]interface{}); ok && len(v) > 0 {
		group.Filters = expandFilters(v)
	}
	if v, ok := tfMap["scope_configuration"].([]interface{}); ok && len(v) > 0 {
		group.ScopeConfiguration = expandFilterScopeConfiguration(v)
	}

	return group
}

func expandAggregationFunction(tfList []interface{}) *quicksight.AggregationFunction {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}

	function := &quicksight.AggregationFunction{}

	if v, ok := tfMap["categorical_aggregation_function"].(string); ok && v != "" {
		function.CategoricalAggregationFunction = aws.String(v)
	}
	if v, ok := tfMap["date_aggregation_function"].(string); ok && v != "" {
		function.DateAggregationFunction = aws.String(v)
	}
	if v, ok := tfMap["numerical_aggregation_function"].([]interface{}); ok && len(v) > 0 {
		function.NumericalAggregationFunction = expandNumericalAggregationFunction(v)
	}

	return function
}

func expandNumericalAggregationFunction(tfList []interface{}) *quicksight.NumericalAggregationFunction {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}

	function := &quicksight.NumericalAggregationFunction{}

	if v, ok := tfMap["simple_numerical_aggregation"].(string); ok && v != "" {
		function.SimpleNumericalAggregation = aws.String(v)
	}
	if v, ok := tfMap["percentile_aggregation"].([]interface{}); ok && len(v) > 0 {
		function.PercentileAggregation = expandPercentileAggregation(v)
	}

	return function
}

func expandPercentileAggregation(tfList []interface{}) *quicksight.PercentileAggregation {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}

	agg := &quicksight.PercentileAggregation{}

	if v, ok := tfMap["simple_numerical_aggregation"].(float64); ok {
		agg.PercentileValue = aws.Float64(v)
	}

	return agg
}

func expandRollingDateConfiguration(tfList []interface{}) *quicksight.RollingDateConfiguration {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap, ok := tfList[0].(map[string]interface{})
	if !ok {
		return nil
	}

	config := &quicksight.RollingDateConfiguration{}

	if v, ok := tfMap["data_set_identifier"].(string); ok {
		config.DataSetIdentifier = aws.String(v)
	}
	if v, ok := tfMap["expression"].(string); ok {
		config.Expression = aws.String(v)
	}

	return config
}

func expandParameterDeclarations(tfList []interface{}) []*quicksight.ParameterDeclaration {
	if len(tfList) == 0 {
		return nil
	}

	var params []*quicksight.ParameterDeclaration
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		param := expandParameterDeclaration(tfMap)
		if param == nil {
			continue
		}

		params = append(params, param)
	}

	return params
}

func expandParameterDeclaration(tfMap map[string]interface{}) *quicksight.ParameterDeclaration {
	if tfMap == nil {
		return nil
	}

	param := &quicksight.ParameterDeclaration{}

	if v, ok := tfMap["date_time_parameter_declaration"].([]interface{}); ok && len(v) > 0 {
		param.DateTimeParameterDeclaration = expandDateTimeParameterDeclaration(v)
	}
	if v, ok := tfMap["decimal_parameter_declaration"].([]interface{}); ok && len(v) > 0 {
		param.DecimalParameterDeclaration = expandDecimalParameterDeclaration(v)
	}
	if v, ok := tfMap["integer_parameter_declaration"].([]interface{}); ok && len(v) > 0 {
		param.IntegerParameterDeclaration = expandIntegerParameterDeclaration(v)
	}
	if v, ok := tfMap["string_parameter_declaration"].([]interface{}); ok && len(v) > 0 {
		param.StringParameterDeclaration = expandStringParameterDeclaration(v)
	}

	return param
}

func expandSheetDefinitions(tfList []interface{}) []*quicksight.SheetDefinition {
	if len(tfList) == 0 {
		return nil
	}

	var sheets []*quicksight.SheetDefinition
	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})
		if !ok {
			continue
		}

		sheet := expandSheetDefinition(tfMap)
		if sheet == nil {
			continue
		}

		sheets = append(sheets, sheet)
	}

	return sheets
}

func ParseTemplateId(id string) (string, string, error) {
	parts := strings.SplitN(id, ",", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("unexpected format of ID (%s), expected AWS_ACCOUNT_ID,TEMPLATE_ID", id)
	}
	return parts[0], parts[1], nil
}

func createTemplateId(awsAccountID, templateId string) string {
	return fmt.Sprintf("%s,%s", awsAccountID, templateId)
}
