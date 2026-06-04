import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

const sns = new SNSClient({ region: "eu-north-1" });

const TOPIC_ARN = "arn:aws:sns:eu-north-1:358487322954:security-alerts";

export const handler = async (event) => {
    const detail = event.detail || {};

    const severity = detail.severity || 0;
    const findingType = detail.type || "Unknown";

    const message = `
GuardDuty Alert

Finding Type: ${findingType}
Severity: ${severity}

Details:
${JSON.stringify(detail, null, 2)}
`;

    if (severity >= 4) {
        await sns.send(
            new PublishCommand({
                TopicArn: TOPIC_ARN,
                Subject: `GuardDuty Alert - Severity ${severity}`,
                Message: message
            })
        );
    }

    return {
        statusCode: 200,
        body: "Alert processed"
    };
};
