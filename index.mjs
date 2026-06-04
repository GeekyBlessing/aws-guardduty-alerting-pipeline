import { IAMClient, ListAccessKeysCommand, UpdateAccessKeyCommand, ListAttachedUserPoliciesCommand, DetachUserPolicyCommand, ListGroupsForUserCommand, RemoveUserFromGroupCommand, CreateLoginProfileCommand, DeleteLoginProfileCommand } from "@aws-sdk/client-iam";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import { DynamoDBClient, PutItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { EC2Client, DescribeSecurityGroupsCommand, CreateSecurityGroupCommand, RevokeSecurityGroupEgressCommand, RevokeSecurityGroupIngressCommand, ModifyInstanceAttributeCommand, CreateTagsCommand, DescribeInstancesCommand, StopInstancesCommand } from "@aws-sdk/client-ec2";
import { S3Client, PutPublicAccessBlockCommand, GetBucketPolicyCommand, PutBucketPolicyCommand, PutBucketLoggingCommand } from "@aws-sdk/client-s3";
import { CloudWatchClient, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";

const iam = new IAMClient({});
const sns = new SNSClient({});
const dynamo = new DynamoDBClient({});
const cloudtrail = new CloudTrailClient({});
const ec2 = new EC2Client({});
const s3 = new S3Client({});
const cloudwatch = new CloudWatchClient({});

const TOPIC_ARN = process.env.TOPIC_ARN;
const TABLE_NAME = process.env.DYNAMODB_TABLE;

// ─── THREAT INTELLIGENCE ─────────────────────────────────────────────────────
function getMitreTechnique(findingType) {
  const mitreMap = {
    "UnauthorizedAccess:IAMUser": { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller": { id: "T1078.004", name: "Cloud Accounts", tactic: "Defense Evasion" },
    "UnauthorizedAccess:IAMUser/TorIPCaller": { id: "T1090", name: "Proxy", tactic: "Command and Control" },
    "Recon:IAMUser/MaliciousIPCaller": { id: "T1580", name: "Cloud Infrastructure Discovery", tactic: "Discovery" },
    "CryptoCurrency:EC2/BitcoinTool": { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
    "Trojan:EC2/BlackholeTraffic": { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
    "Backdoor:EC2/C&CActivity": { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
    "Policy:S3/BucketPublicAccessGranted": { id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" },
    "Exfiltration:S3/ObjectRead": { id: "T1537", name: "Transfer Data to Cloud Account", tactic: "Exfiltration" },
  };
  for (const [key, value] of Object.entries(mitreMap)) {
    if (findingType.includes(key.split(":")[1])) return value;
  }
  return { id: "T0000", name: "Unknown Technique", tactic: "Unknown" };
}

function calculateRiskScore(severity, findingType, accountId) {
  let score = severity * 10;
  if (findingType.includes("Backdoor")) score += 20;
  if (findingType.includes("Exfiltration")) score += 25;
  if (findingType.includes("CryptoCurrency")) score += 15;
  if (findingType.includes("Recon")) score += 10;
  return Math.min(score, 100);
}

// ─── CLOUDTRAIL CORRELATION ───────────────────────────────────────────────────
async function getRecentActivity(username) {
  try {
    const response = await cloudtrail.send(new LookupEventsCommand({
      LookupAttributes: [{ AttributeKey: "Username", AttributeValue: username }],
      MaxResults: 10
    }));

    if (!response.Events.length) return "No recent CloudTrail events found";

    return response.Events.map(e => {
      const resources = e.Resources?.map(r => r.ResourceName).join(", ") || "N/A";
      return `${e.EventTime} | ${e.EventName} | IP: ${e.SourceIPAddress} | Resources: ${resources}`;
    }).join("\n");
  } catch (err) {
    return `CloudTrail lookup failed: ${err.message}`;
  }
}

// ─── FULL IAM LOCKDOWN ───────────────────────────────────────────────────────
async function remediateIAM(detail) {
  const username = detail.resource?.accessKeyDetails?.userName;
  if (!username) return "No IAM user found in finding";

  const actions = [];

  try {
    // 1. Disable all access keys
    const keys = await iam.send(new ListAccessKeysCommand({ UserName: username }));
    for (const key of keys.AccessKeyMetadata) {
      await iam.send(new UpdateAccessKeyCommand({
        UserName: username,
        AccessKeyId: key.AccessKeyId,
        Status: "Inactive"
      }));
      actions.push(`🔑 Disabled access key: ${key.AccessKeyId}`);
    }

    // 2. Detach all managed policies
    const policies = await iam.send(new ListAttachedUserPoliciesCommand({ UserName: username }));
    for (const policy of policies.AttachedPolicies) {
      await iam.send(new DetachUserPolicyCommand({
        UserName: username,
        PolicyArn: policy.PolicyArn
      }));
      actions.push(`📋 Detached policy: ${policy.PolicyName}`);
    }

    // 3. Remove from all groups (severity 9+)
    if (detail.severity >= 9) {
      const groups = await iam.send(new ListGroupsForUserCommand({ UserName: username }));
      for (const group of groups.Groups) {
        await iam.send(new RemoveUserFromGroupCommand({
          UserName: username,
          GroupName: group.GroupName
        }));
        actions.push(`👥 Removed from group: ${group.GroupName}`);
      }

      // 4. Delete console login (full lockout)
      try {
        await iam.send(new DeleteLoginProfileCommand({ UserName: username }));
        actions.push(`🚫 Console access revoked for: ${username}`);
      } catch (err) {
        // User may not have console access
      }
    }

    return actions.join("\n");
  } catch (err) {
    return `IAM remediation error: ${err.message}`;
  }
}

// ─── EC2 FULL ISOLATION ───────────────────────────────────────────────────────
async function remediateEC2(detail) {
  const instanceId = detail.resource?.instanceDetails?.instanceId;
  if (!instanceId) return "No EC2 instance found in finding";

  const actions = [];

  try {
    // 1. Get instance details
    const instanceInfo = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: [instanceId]
    }));
    const instance = instanceInfo.Reservations[0]?.Instances[0];
    const vpcId = instance?.VpcId;

    // 2. Create or find isolation security group
    let isolationSgId;
    try {
      const createSg = await ec2.send(new CreateSecurityGroupCommand({
        GroupName: `guardduty-isolation-${Date.now()}`,
        Description: "GuardDuty Auto-Isolation - NO INBOUND/OUTBOUND TRAFFIC",
        VpcId: vpcId
      }));
      isolationSgId = createSg.GroupId;

      // Remove all outbound rules
      await ec2.send(new RevokeSecurityGroupEgressCommand({
        GroupId: isolationSgId,
        IpPermissions: [{ IpProtocol: "-1", IpRanges: [{ CidrIp: "0.0.0.0/0" }] }]
      }));

      actions.push(`🛡️ Created isolation security group: ${isolationSgId}`);
    } catch (err) {
      const existing = await ec2.send(new DescribeSecurityGroupsCommand({
        Filters: [{ Name: "group-name", Values: ["guardduty-isolation"] }]
      }));
      isolationSgId = existing.SecurityGroups[0]?.GroupId;
      actions.push(`🛡️ Using existing isolation group: ${isolationSgId}`);
    }

    // 3. Move instance to isolation group
    await ec2.send(new ModifyInstanceAttributeCommand({
      InstanceId: instanceId,
      Groups: [isolationSgId]
    }));
    actions.push(`🔒 Instance ${instanceId} moved to isolation group`);

    // 4. Tag instance with forensic metadata
    await ec2.send(new CreateTagsCommand({
      Resources: [instanceId],
      Tags: [
        { Key: "GuardDuty-Status", Value: "ISOLATED" },
        { Key: "IsolationTime", Value: new Date().toISOString() },
        { Key: "FindingType", Value: detail.type },
        { Key: "Severity", Value: String(detail.severity) },
        { Key: "IsolationGroup", Value: isolationSgId },
        { Key: "AutoRemediated", Value: "true" }
      ]
    }));
    actions.push(`🏷️ Forensic tags applied to instance`);

    // 5. Stop instance for severity 9+
    if (detail.severity >= 9) {
      await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] }));
      actions.push(`⛔ Instance ${instanceId} STOPPED for forensic analysis`);
    }

    return actions.join("\n");
  } catch (err) {
    return `EC2 isolation failed: ${err.message}`;
  }
}

// ─── S3 FULL REMEDIATION ─────────────────────────────────────────────────────
async function remediateS3(detail) {
  const bucketName = detail.resource?.s3BucketDetails?.[0]?.name;
  if (!bucketName) return "No S3 bucket found in finding";

  const actions = [];

  try {
    // 1. Block all public access
    await s3.send(new PutPublicAccessBlockCommand({
      Bucket: bucketName,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true
      }
    }));
    actions.push(`🔒 Public access BLOCKED for bucket: ${bucketName}`);

    // 2. Apply deny policy for public access
    const denyPolicy = {
      Version: "2012-10-17",
      Statement: [{
        Sid: "GuardDutyAutoRemediation",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          `arn:aws:s3:::${bucketName}`,
          `arn:aws:s3:::${bucketName}/*`
        ],
        Condition: {
          Bool: { "aws:SecureTransport": "false" }
        }
      }]
    };

    await s3.send(new PutBucketPolicyCommand({
      Bucket: bucketName,
      Policy: JSON.stringify(denyPolicy)
    }));
    actions.push(`📋 Deny policy applied to bucket: ${bucketName}`);

    return actions.join("\n");
  } catch (err) {
    return `S3 remediation failed: ${err.message}`;
  }
}

// ─── CLOUDWATCH METRICS ───────────────────────────────────────────────────────
async function publishMetrics(findingType, severity, riskScore) {
  try {
    await cloudwatch.send(new PutMetricDataCommand({
      Namespace: "GuardDuty/AutoRemediation",
      MetricData: [
        {
          MetricName: "FindingCount",
          Value: 1,
          Unit: "Count",
          Dimensions: [{ Name: "FindingType", Value: findingType.split(":")[0] }]
        },
        {
          MetricName: "Severity",
          Value: severity,
          Unit: "None"
        },
        {
          MetricName: "RiskScore",
          Value: riskScore,
          Unit: "None"
        }
      ]
    }));
  } catch (err) {
    console.error(`CloudWatch metrics failed: ${err.message}`);
  }
}

// ─── LOG TO DYNAMODB ─────────────────────────────────────────────────────────
async function logIncident(finding, remediation, cloudtrailEvents, mitre, riskScore) {
  await dynamo.send(new PutItemCommand({
    TableName: TABLE_NAME,
    Item: {
      incidentId: { S: finding.id },
      timestamp: { S: new Date().toISOString() },
      findingType: { S: finding.type },
      severity: { N: String(finding.severity) },
      riskScore: { N: String(riskScore) },
      accountId: { S: finding.accountId },
      region: { S: finding.region },
      remediation: { S: remediation },
      cloudtrailEvents: { S: cloudtrailEvents },
      mitreTechnique: { S: mitre.id },
      mitreTactic: { S: mitre.tactic },
      mitreName: { S: mitre.name },
      status: { S: "AUTO_REMEDIATED" },
      ttl: { N: String(Math.floor(Date.now() / 1000) + 7776000) } // 90 day TTL
    }
  }));
}

// ─── MAIN HANDLER ────────────────────────────────────────────────────────────
export const handler = async (event) => {
  const detail = event.detail;
  const findingType = detail.type;
  const severity = detail.severity;
  const mitre = getMitreTechnique(findingType);
  const riskScore = calculateRiskScore(severity, findingType, detail.accountId);

  console.log(`🚨 Finding: ${findingType} | Severity: ${severity} | Risk: ${riskScore} | MITRE: ${mitre.id}`);

  let remediation = "Notification only - below auto-remediation threshold";
  let cloudtrailEvents = "N/A";

  if (severity >= 7) {
    try {
      if (findingType.includes("IAMUser") || findingType.includes("UnauthorizedAccess")) {
        const username = detail.resource?.accessKeyDetails?.userName;
        if (username) cloudtrailEvents = await getRecentActivity(username);
        remediation = await remediateIAM(detail);

      } else if (findingType.includes("EC2") || findingType.includes("CryptoCurrency") || findingType.includes("Trojan") || findingType.includes("Backdoor")) {
        remediation = await remediateEC2(detail);

      } else if (findingType.includes("S3") || findingType.includes("Policy")) {
        remediation = await remediateS3(detail);

      } else {
        remediation = `⚠️ Unhandled finding type: ${findingType} - escalating for manual review`;
      }
    } catch (err) {
      remediation = `Remediation error: ${err.message}`;
      console.error(remediation);
    }
  }

  // Publish CloudWatch metrics
  await publishMetrics(findingType, severity, riskScore);

  // Log to DynamoDB
  try {
    await logIncident(detail, remediation, cloudtrailEvents, mitre, riskScore);
  } catch (err) {
    console.error(`DynamoDB logging failed: ${err.message}`);
  }

  const severity_emoji = severity >= 9 ? "🔴" : severity >= 7 ? "🟠" : "🟡";

  const message = `
${severity_emoji} GUARDDUTY AUTO-REMEDIATION REPORT ${severity_emoji}
${"═".repeat(50)}

THREAT INTELLIGENCE
───────────────────
MITRE ATT&CK: ${mitre.id} - ${mitre.name}
Tactic:       ${mitre.tactic}
Risk Score:   ${riskScore}/100

FINDING DETAILS
───────────────
Type:         ${findingType}
Severity:     ${severity}/10
Account:      ${detail.accountId}
Region:       ${detail.region}
Time:         ${new Date().toISOString()}
Incident ID:  ${detail.id}

AUTOMATED RESPONSE
──────────────────
${remediation}

CLOUDTRAIL FORENSICS (Last 10 Events)
──────────────────────────────────────
${cloudtrailEvents}

${"═".repeat(50)}
This is an automated response from your GuardDuty
Auto-Remediation Pipeline. Manual review recommended.
  `;

  await sns.send(new PublishCommand({
    TopicArn: TOPIC_ARN,
    Subject: `${severity_emoji} [RISK:${riskScore}] [SEV-${severity}] ${mitre.id} - ${findingType}`,
    Message: message
  }));

  console.log(`✅ Incident ${detail.id} processed | Risk: ${riskScore} | MITRE: ${mitre.id}`);
  return { statusCode: 200, body: JSON.stringify({ incidentId: detail.id, riskScore, mitre }) };
};