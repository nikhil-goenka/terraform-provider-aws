package aws

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/hashcode"
)

func resourceAwsDynamoDbTable() *schema.Resource {
	//lintignore:R011
	return &schema.Resource{
		Create: resourceAwsDynamoDbTableRestore,
		Read:   resourceAwsDynamoDbTableRead,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
			Update: schema.DefaultTimeout(60 * time.Minute),
		},

		CustomizeDiff: customdiff.Sequence(
			func(_ context.Context, diff *schema.ResourceDiff, v interface{}) error {
				return validateDynamoDbTableAttributes(diff)
			},
			func(_ context.Context, diff *schema.ResourceDiff, v interface{}) error {
				if diff.Id() != "" && diff.HasChange("server_side_encryption") {
					o, n := diff.GetChange("server_side_encryption")
					if isDynamoDbTableOptionDisabled(o) && isDynamoDbTableOptionDisabled(n) {
						return diff.Clear("server_side_encryption")
					}
				}
				return nil
			},
		),

		SchemaVersion: 1,
		MigrateState:  resourceAwsDynamoDbTableMigrateState,

		Schema: map[string]*schema.Schema{
			"source_table_arn": {
				Type:     schema.TypeString,
				Required: true,
			},
			"source_table_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"target_table_name": {
                Type:     schema.TypeString,
                Required: true,
                ForceNew: true,
            },
			"use_latest_restore_time": {
				Type:     schema.TypeBool,
				Required: true,
				ForceNew: true,
			},
			"restore_date_time": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"billing_mode_override": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  dynamodb.BillingModeProvisioned,
				ValidateFunc: validation.StringInSlice([]string{
                    dynamodb.BillingModePayPerRequest,
                    dynamodb.BillingModeProvisioned,
                }, false),
			},
			"write_capacity_override": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"read_capacity_override": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"attribute": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"type": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								dynamodb.ScalarAttributeTypeB,
								dynamodb.ScalarAttributeTypeN,
								dynamodb.ScalarAttributeTypeS,
							}, false),
						},
					},
				},
				Set: func(v interface{}) int {
					var buf bytes.Buffer
					m := v.(map[string]interface{})
					buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
					return hashcode.String(buf.String())
				},
			},
			"local_secondary_index_override": {
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"range_key": {
							Type:     schema.TypeString,
							Required: true,
						},
						"projection_type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"non_key_attributes": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
					},
				},
				Set: func(v interface{}) int {
					var buf bytes.Buffer
					m := v.(map[string]interface{})
					buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
					return hashcode.String(buf.String())
				},
			},
			"global_secondary_index_override": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"write_capacity": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"read_capacity": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"hash_key": {
							Type:     schema.TypeString,
							Required: true,
						},
						"range_key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"projection_type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"non_key_attributes": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"server_side_encryption_override": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Required: true,
						},
						"kms_key_arn": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validateArn,
						},
					},
				},
			},
		},
	}
}

func resourceAwsDynamoDbTableRestore(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).dynamodbconn

	req := &dynamodb.RestoreTableToPointInTimeInput{
		SourceTableArn:   aws.String(d.Get("source_table_arn").(string)),
		SourceTableName:  aws.String(d.Get("source_table_name").(string)),
		TargetTableName:  aws.String(d.Get("target_table_name").(string)),
		UseLatestRestorableTime: aws.Bool(d.Get("use_latest_restore_time").(bool)),
	}

	if ok := d.Get("use_latest_restore_time").(bool); !ok {
	    t, _ := time.Parse(time.RFC3339, d.Get("restore_date_time"))
		req.RestoreDateTime = aws.Time(d.Get(t))
	}

	if v, ok := d.GetOk("write_capacity_override"); !ok {
	    req.ProvisionedThroughput{
            WriteCapacityUnits: aws.Int64(int64(v.(int))),
        }
    }

    if v, ok := d.GetOk("read_capacity_override"); !ok {
        req.ProvisionedThroughput{
            ReadCapacityUnits: aws.Int64(int64(v.(int))),
        }
    }

    req.ProvisionedThroughputOverride= ProvisionedThroughput

	if v, ok := d.GetOk("billing_mode_override"); ok {
	    req.BillingModeOverride = aws.String(d.Get("billing_mode_override").(string))
    }

	if v, ok := d.GetOk("local_secondary_index_override"); ok {
		lsiSet := v.(*schema.Set)
		req.LocalSecondaryIndexOverride = expandDynamoDbLocalSecondaryIndexes(lsiSet.List(), keySchemaMap)
	}

	if v, ok := d.GetOk("global_secondary_index_override"); ok {
		globalSecondaryIndexes := []*dynamodb.GlobalSecondaryIndex{}
		gsiSet := v.(*schema.Set)

		for _, gsiObject := range gsiSet.List() {
			gsi := gsiObject.(map[string]interface{})
			if err := validateDynamoDbProvisionedThroughput(gsi, billingMode); err != nil {
				return fmt.Errorf("Failed to create GSI: %v", err)
			}

			gsiObject := expandDynamoDbGlobalSecondaryIndex(gsi, BillingModeOverride)
			globalSecondaryIndexes = append(globalSecondaryIndexes, gsiObject)
		}
		req.GlobalSecondaryIndexOverride = globalSecondaryIndexes
	}

	if v, ok := d.GetOk("server_side_encryption_override"); ok {
		req.SSESpecificationOverride = expandDynamoDbEncryptAtRestOptions(v.([]interface{}))
	}

	var output *dynamodb.RestoreTableToPointInTimeOutput
	err := resource.Retry(2*time.Minute, func() *resource.RetryError {
		var err error
		output, err = conn.RestoreTableToPointInTime(req)
		if err != nil {
			if isAWSErr(err, "ThrottlingException", "") {
				return resource.RetryableError(err)
			}
			if isAWSErr(err, dynamodb.ErrCodeLimitExceededException, "can be created, updated, or deleted simultaneously") {
				return resource.RetryableError(err)
			}
			if isAWSErr(err, dynamodb.ErrCodeLimitExceededException, "indexed tables that can be created simultaneously") {
				return resource.RetryableError(err)
			}
			// AWS GovCloud (US) and others may reply with the following until their API is updated:
			// ValidationException: One or more parameter values were invalid: Unsupported input parameter BillingMode
			if isAWSErr(err, "ValidationException", "Unsupported input parameter BillingMode") {
				req.BillingMode = nil
				return resource.RetryableError(err)
			}
			// AWS GovCloud (US) and others may reply with the following until their API is updated:
			// ValidationException: Unsupported input parameter Tags
			if isAWSErr(err, "ValidationException", "Unsupported input parameter Tags") {
				req.Tags = nil
				requiresTagging = true
				return resource.RetryableError(err)
			}

			return resource.NonRetryableError(err)
		}
		return nil
	})

	if isResourceTimeoutError(err) {
		output, err = conn.RestoreTableToPointInTime(req)
	}

	if err != nil {
		return fmt.Errorf("error restoring DynamoDB Table: %s", err)
	}

	if output == nil || output.TableDescription == nil {
		return fmt.Errorf("error restoring DynamoDB Table: empty response")
	}

	d.SetId(aws.StringValue(output.TableDescription.TableName))
	d.Set("arn", output.TableDescription.TableArn)

	if err := waitForDynamoDbTableToBeActive(d.Id(), d.Timeout(schema.TimeoutCreate), conn); err != nil {
		return err
	}

	//return resourceAwsDynamoDbTableRead(d, meta)
}

func resourceAwsDynamoDbTableRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).dynamodbconn
	ignoreTagsConfig := meta.(*AWSClient).IgnoreTagsConfig

	result, err := conn.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(d.Id()),
	})

	if err != nil {
		if isAWSErr(err, dynamodb.ErrCodeResourceNotFoundException, "") {
			log.Printf("[WARN] Dynamodb Table (%s) not found, error code (404)", d.Id())
			d.SetId("")
			return nil
		}
		return err
	}

	err = flattenAwsDynamoDbTableResource(d, result.Table)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("error describing DynamoDB Table (%s) Time to Live: %s", d.Id(), err)
	}

	pitrOut, err := conn.DescribeContinuousBackups(&dynamodb.DescribeContinuousBackupsInput{
		TableName: aws.String(d.Id()),
	})
	if err != nil && !isAWSErr(err, "UnknownOperationException", "") {
		return err
	}

	return nil
}

func waitForDynamoDbTableToBeActive(tableName string, timeout time.Duration, conn *dynamodb.DynamoDB) error {
	stateConf := &resource.StateChangeConf{
		Pending: []string{dynamodb.TableStatusCreating, dynamodb.TableStatusUpdating},
		Target:  []string{dynamodb.TableStatusActive},
		Timeout: timeout,
		Refresh: func() (interface{}, string, error) {
			result, err := conn.DescribeTable(&dynamodb.DescribeTableInput{
				TableName: aws.String(tableName),
			})
			if err != nil {
				return 42, "", err
			}

			return result, *result.Table.TableStatus, nil
		},
	}
	_, err := stateConf.WaitForState()

	return err
}

func isDynamoDbTableOptionDisabled(v interface{}) bool {
	options := v.([]interface{})
	if len(options) == 0 {
		return true
	}
	e := options[0].(map[string]interface{})["enabled"]
	return !e.(bool)
}
