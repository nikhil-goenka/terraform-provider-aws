// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package glue

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_glue_catalog_database", name="Database")
// @Tags(identifierAttribute="arn")
func ResourceCatalogDatabase() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceCatalogDatabaseCreate,
		ReadWithoutTimeout:   resourceCatalogDatabaseRead,
		UpdateWithoutTimeout: resourceCatalogDatabaseUpdate,
		DeleteWithoutTimeout: resourceCatalogDatabaseDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: verify.SetTagsDiff,

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrCatalogID: {
				Type:     schema.TypeString,
				ForceNew: true,
				Optional: true,
				Computed: true,
			},
			names.AttrName: {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 255),
					validation.StringDoesNotMatch(regexache.MustCompile(`[A-Z]`), "uppercase characters cannot be used"),
				),
			},
			"create_table_default_permission": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrPermissions: {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.StringInSlice(glue.Permission_Values(), false),
							},
						},
						names.AttrPrincipal: {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"data_lake_principal_identifier": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validation.StringLenBetween(1, 255),
									},
								},
							},
						},
					},
				},
			},
			names.AttrDescription: {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringLenBetween(0, 2048),
			},
			"federated_database": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"connection_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						names.AttrIdentifier: {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"location_uri": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			names.AttrParameters: {
				Type:     schema.TypeMap,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
			"target_database": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrCatalogID: {
							Type:     schema.TypeString,
							Required: true,
						},
						names.AttrDatabaseName: {
							Type:     schema.TypeString,
							Required: true,
						},
						names.AttrRegion: {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
		},
	}
}

func resourceCatalogDatabaseCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)
	catalogID := createCatalogID(d, meta.(*conns.AWSClient).AccountID)
	name := d.Get(names.AttrName).(string)

	dbInput := &glue.DatabaseInput{
		Name: aws.String(name),
	}

	if v, ok := d.GetOk(names.AttrDescription); ok {
		dbInput.Description = aws.String(v.(string))
	}

	if v, ok := d.GetOk("location_uri"); ok {
		dbInput.LocationUri = aws.String(v.(string))
	}

	if v, ok := d.GetOk(names.AttrParameters); ok {
		dbInput.Parameters = flex.ExpandStringMap(v.(map[string]interface{}))
	}

	if v, ok := d.GetOk("federated_database"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		dbInput.FederatedDatabase = expandDatabaseFederatedDatabase(v.([]interface{})[0].(map[string]interface{}))
	}

	if v, ok := d.GetOk("target_database"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		dbInput.TargetDatabase = expandDatabaseTargetDatabase(v.([]interface{})[0].(map[string]interface{}))
	}

	if v, ok := d.GetOk("create_table_default_permission"); ok && len(v.([]interface{})) > 0 {
		dbInput.CreateTableDefaultPermissions = expandDatabasePrincipalPermissions(v.([]interface{}))
	}

	input := &glue.CreateDatabaseInput{
		CatalogId:     aws.String(catalogID),
		DatabaseInput: dbInput,
		Tags:          getTagsIn(ctx),
	}

	_, err := conn.CreateDatabaseWithContext(ctx, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Glue Catalog Database (%s): %s", name, err)
	}

	d.SetId(fmt.Sprintf("%s:%s", catalogID, name))

	return append(diags, resourceCatalogDatabaseRead(ctx, d, meta)...)
}

func resourceCatalogDatabaseUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)

	if d.HasChangesExcept(names.AttrTags, names.AttrTagsAll) {
		catalogID, name, err := ReadCatalogID(d.Id())
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating Glue Catalog Database (%s): %s", d.Id(), err)
		}

		dbUpdateInput := &glue.UpdateDatabaseInput{
			CatalogId: aws.String(catalogID),
			Name:      aws.String(name),
		}

		dbInput := &glue.DatabaseInput{
			Name: aws.String(name),
		}

		if v, ok := d.GetOk(names.AttrDescription); ok {
			dbInput.Description = aws.String(v.(string))
		}

		if v, ok := d.GetOk("location_uri"); ok {
			dbInput.LocationUri = aws.String(v.(string))
		}

		if v, ok := d.GetOk(names.AttrParameters); ok {
			dbInput.Parameters = flex.ExpandStringMap(v.(map[string]interface{}))
		}

		if v, ok := d.GetOk("federated_database"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
			dbInput.FederatedDatabase = expandDatabaseFederatedDatabase(v.([]interface{})[0].(map[string]interface{}))
		}

		if v, ok := d.GetOk("create_table_default_permission"); ok && len(v.([]interface{})) > 0 {
			dbInput.CreateTableDefaultPermissions = expandDatabasePrincipalPermissions(v.([]interface{}))
		}

		dbUpdateInput.DatabaseInput = dbInput

		if _, err := conn.UpdateDatabaseWithContext(ctx, dbUpdateInput); err != nil {
			return sdkdiag.AppendErrorf(diags, "updating Glue Catalog Database (%s): %s", d.Id(), err)
		}
	}

	return append(diags, resourceCatalogDatabaseRead(ctx, d, meta)...)
}

func resourceCatalogDatabaseRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)

	catalogID, name, err := ReadCatalogID(d.Id())
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Glue Catalog Database (%s): %s", d.Id(), err)
	}

	out, err := FindDatabaseByName(ctx, conn, catalogID, name)
	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Glue Catalog Database (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Glue Catalog Database (%s): %s", d.Id(), err)
	}

	database := out.Database
	databaseArn := arn.ARN{
		Partition: meta.(*conns.AWSClient).Partition,
		Service:   "glue",
		Region:    meta.(*conns.AWSClient).Region,
		AccountID: meta.(*conns.AWSClient).AccountID,
		Resource:  fmt.Sprintf("database/%s", aws.StringValue(database.Name)),
	}.String()
	d.Set(names.AttrARN, databaseArn)
	d.Set(names.AttrName, database.Name)
	d.Set(names.AttrCatalogID, database.CatalogId)
	d.Set(names.AttrDescription, database.Description)
	d.Set("location_uri", database.LocationUri)
	d.Set(names.AttrParameters, aws.StringValueMap(database.Parameters))

	if database.FederatedDatabase != nil {
		if err := d.Set("federated_database", []interface{}{flattenDatabaseFederatedDatabase(database.FederatedDatabase)}); err != nil {
			return sdkdiag.AppendErrorf(diags, "setting federated_database: %s", err)
		}
	} else {
		d.Set("federated_database", nil)
	}

	if database.TargetDatabase != nil {
		if err := d.Set("target_database", []interface{}{flattenDatabaseTargetDatabase(database.TargetDatabase)}); err != nil {
			return sdkdiag.AppendErrorf(diags, "setting target_database: %s", err)
		}
	} else {
		d.Set("target_database", nil)
	}

	if err := d.Set("create_table_default_permission", flattenDatabasePrincipalPermissions(database.CreateTableDefaultPermissions)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting create_table_default_permission: %s", err)
	}

	return diags
}

func resourceCatalogDatabaseDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).GlueConn(ctx)

	log.Printf("[DEBUG] Glue Catalog Database: %s", d.Id())
	_, err := conn.DeleteDatabaseWithContext(ctx, &glue.DeleteDatabaseInput{
		Name:      aws.String(d.Get(names.AttrName).(string)),
		CatalogId: aws.String(d.Get(names.AttrCatalogID).(string)),
	})
	if tfawserr.ErrCodeEquals(err, glue.ErrCodeEntityNotFoundException) {
		return diags
	}
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Glue Catalog Database (%s): %s", d.Id(), err)
	}

	return diags
}

func ReadCatalogID(id string) (catalogID string, name string, err error) {
	idParts := strings.Split(id, ":")
	if len(idParts) != 2 {
		return "", "", fmt.Errorf("Unexpected format of ID (%q), expected CATALOG-ID:DATABASE-NAME", id)
	}
	return idParts[0], idParts[1], nil
}

func createCatalogID(d *schema.ResourceData, accountid string) (catalogID string) {
	if rawCatalogID, ok := d.GetOkExists(names.AttrCatalogID); ok {
		catalogID = rawCatalogID.(string)
	} else {
		catalogID = accountid
	}
	return
}

func expandDatabaseFederatedDatabase(tfMap map[string]interface{}) *glue.FederatedDatabase {
	if tfMap == nil {
		return nil
	}

	apiObject := &glue.FederatedDatabase{}

	if v, ok := tfMap["connection_name"].(string); ok && v != "" {
		apiObject.ConnectionName = aws.String(v)
	}

	if v, ok := tfMap[names.AttrIdentifier].(string); ok && v != "" {
		apiObject.Identifier = aws.String(v)
	}

	return apiObject
}

func expandDatabaseTargetDatabase(tfMap map[string]interface{}) *glue.DatabaseIdentifier {
	if tfMap == nil {
		return nil
	}

	apiObject := &glue.DatabaseIdentifier{}

	if v, ok := tfMap[names.AttrCatalogID].(string); ok && v != "" {
		apiObject.CatalogId = aws.String(v)
	}

	if v, ok := tfMap[names.AttrDatabaseName].(string); ok && v != "" {
		apiObject.DatabaseName = aws.String(v)
	}

	if v, ok := tfMap[names.AttrRegion].(string); ok && v != "" {
		apiObject.Region = aws.String(v)
	}

	return apiObject
}

func flattenDatabaseFederatedDatabase(apiObject *glue.FederatedDatabase) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.ConnectionName; v != nil {
		tfMap["connection_name"] = aws.StringValue(v)
	}

	if v := apiObject.Identifier; v != nil {
		tfMap[names.AttrIdentifier] = aws.StringValue(v)
	}

	return tfMap
}

func flattenDatabaseTargetDatabase(apiObject *glue.DatabaseIdentifier) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.CatalogId; v != nil {
		tfMap[names.AttrCatalogID] = aws.StringValue(v)
	}

	if v := apiObject.DatabaseName; v != nil {
		tfMap[names.AttrDatabaseName] = aws.StringValue(v)
	}

	if v := apiObject.Region; v != nil {
		tfMap[names.AttrRegion] = aws.StringValue(v)
	}

	return tfMap
}

func expandDatabasePrincipalPermissions(tfList []interface{}) []*glue.PrincipalPermissions {
	if len(tfList) == 0 {
		return nil
	}

	var apiObjects []*glue.PrincipalPermissions

	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})

		if !ok {
			continue
		}

		apiObject := expandDatabasePrincipalPermission(tfMap)

		if apiObject == nil {
			continue
		}

		apiObjects = append(apiObjects, apiObject)
	}

	return apiObjects
}

func expandDatabasePrincipalPermission(tfMap map[string]interface{}) *glue.PrincipalPermissions {
	if tfMap == nil {
		return nil
	}

	apiObject := &glue.PrincipalPermissions{}

	if v, ok := tfMap[names.AttrPermissions].(*schema.Set); ok && v.Len() > 0 {
		apiObject.Permissions = flex.ExpandStringSet(v)
	}

	if v, ok := tfMap[names.AttrPrincipal].([]interface{}); ok && len(v) > 0 {
		apiObject.Principal = expandDatabasePrincipal(v[0].(map[string]interface{}))
	}

	return apiObject
}

func expandDatabasePrincipal(tfMap map[string]interface{}) *glue.DataLakePrincipal {
	if tfMap == nil {
		return nil
	}

	apiObject := &glue.DataLakePrincipal{}

	if v, ok := tfMap["data_lake_principal_identifier"].(string); ok && v != "" {
		apiObject.DataLakePrincipalIdentifier = aws.String(v)
	}

	return apiObject
}

func flattenDatabasePrincipalPermissions(apiObjects []*glue.PrincipalPermissions) []interface{} {
	if len(apiObjects) == 0 {
		return nil
	}

	var tfList []interface{}

	for _, apiObject := range apiObjects {
		if apiObject == nil {
			continue
		}

		tfList = append(tfList, flattenDatabasePrincipalPermission(apiObject))
	}

	return tfList
}

func flattenDatabasePrincipalPermission(apiObject *glue.PrincipalPermissions) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.Permissions; v != nil {
		tfMap[names.AttrPermissions] = flex.FlattenStringSet(v)
	}

	if v := apiObject.Principal; v != nil {
		tfMap[names.AttrPrincipal] = []interface{}{flattenDatabasePrincipal(v)}
	}

	return tfMap
}

func flattenDatabasePrincipal(apiObject *glue.DataLakePrincipal) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.DataLakePrincipalIdentifier; v != nil {
		tfMap["data_lake_principal_identifier"] = aws.StringValue(v)
	}

	return tfMap
}
