import json
from uuid import uuid5
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network

import validators
from pydantic import BaseModel
from boto3.dynamodb.conditions import Key
from lumigo_tracer import lumigo_tracer

import internals
import models
import services.aws
import services.sendgrid
import services.webhook


ALERT_DETAIL = {
    models.FeedSource.CHARLES_HALEY: {
        models.FeedName.SSH_CLIENT: {
            'description': "IP addresses that has been seen initiating an SSH connection to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be SSH server cataloging or conducting authentication attack attempts",
            'summary': "SSH Port Scanning, dictionary attacks, and Bruteforcing Authentication",
            'abuse': "contact@frogfishtech.com",
        },
    },
    models.FeedSource.DARKLIST: {
        models.FeedName.SSH_CLIENT: {
            'description': "Darklist.de is an IP blacklist that uses multiple sensors to identify network attacks (e.g. SSH brute force) and spam incidents. All reports are evaluated and in case of too many incidents the responsible IP holder is informed to solve the problem. After reporting an incident as solved the IP is removed from the blacklist",
            'summary': "SSH dictionary attacks, and Bruteforcing Authentication",
            'abuse': "https://www.darklist.de/removal.php",
        }
    },
    models.FeedSource.TALOS_INTELLIGENCE: {
        models.FeedName.IP_REPUTATION: {
            'description': "Talos' IP and Domain Data Center is the world's most comprehensive real-time threat detection network. The data is made up of daily security intelligence across millions of deployed web, email, firewall and IPS appliances. Talos detects and correlates threats in real time using the largest threat detection network in the world spanning web requests, emails, malware samples, open-source data sets, endpoint intelligence, and network intrusions.",
            'summary': "Spam or Malware origin",
            'abuse': "https://www.talosintelligence.com/reputation_center/sender_ip",
        }
    },
    models.FeedSource.DATAPLANE: {
        models.FeedName.SSH_CLIENT: {
            'description': "IP addresses that has been seen initiating an SSH connection to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be SSH server cataloging or conducting authentication attack attempts",
            'summary': "SSH Port Scanning and Bruteforcing Authentication",
            'abuse': "info@dataplane.org",
        },
        models.FeedName.SSH_PASSWORD_AUTH: {
            'description': "IP addresses that has been seen attempting to remotely login to a host using SSH password authentication. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks",
            'summary': "SSH dictionary attacks",
            'abuse': "info@dataplane.org",
        },
        models.FeedName.RECURSIVE_DNS: {
            'description': "IP addresses that have been identified as sending recursive DNS queries to a remote host. This report lists addresses that may be cataloging open DNS resolvers or evaluating cache entries",
            'summary': "Recursive DNS query cataloging",
            'abuse': "info@dataplane.org",
        },
        models.FeedName.VNC_REMOTE_FRAME_BUFFER: {
            'description': "IP addresses that have been seen initiating a VNC remote frame buffer (RFB) session to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be VNC server cataloging or conducting various forms of remote access abuse",
            'summary': "Suspicious VNC remote frame buffer (RFB) sessions",
            'abuse': "info@dataplane.org",
        }
    },
    models.FeedSource.PROOFPOINT: {
        models.FeedName.IP_REPUTATION: {
            'description': "Emerging Threat (ET) Intelligence provides actionable threat intel feeds to identify IPs and domains involved in suspicious and malicious activity. All threat intelligence feeds are based on behavior observed directly by Proofpoint ET Labs",
            'summary': "Spam or Malware origin",
            'abuse': "https://feedback.emergingthreats.net/feedback",
        },
        models.FeedName.COMPROMISED_IPS: {
            'description': "Emerging Threat (ET) intelligence helps you identify hosts that are performing malicious activities, using a network of honeypots all hosts listed were caught launch attacks from the identified IP addresses",
            'summary': "Exploit kit threat indicators, origins are compromised and performing attacks on others",
            'abuse': "https://feedback.emergingthreats.net/feedback",
        }
    }
}


class EventAttributes(BaseModel):
    ApproximateReceiveCount: int
    SentTimestamp: datetime
    SenderId: str
    ApproximateFirstReceiveTimestamp: datetime


class EventRecord(BaseModel):
    messageId: str
    receiptHandle: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str
    md5OfBody: str
    attributes: EventAttributes
    item: models.FeedStateItem

    def __init__(self, **kwargs):
        kwargs["item"] = json.loads(kwargs["body"])
        super().__init__(**kwargs)


def match_domain(domains: set, data: dict[str, models.ScannerRecord]) -> list[str]:
    return list(
        {
            account_name
            for account_name, scanner_record in data.items()
            for summary in scanner_record.history
            for host in summary.targets
            if host.transport.hostname in domains
        }
    )


def match_email(email: str, accounts: dict[str, models.ScannerRecord]) -> list[str]:
    return []


def make_data(item: models.FeedStateItem, **extra_data) -> dict:
    data = ALERT_DETAIL.get(item.source, {}).get(item.feed_name, {})
    data['asn'] = item.asn
    data['asn_text'] = item.asn_text
    data['first_seen'] = item.first_seen.isoformat()
    data['last_seen'] = item.last_seen.isoformat()
    data['ip_address'] = str(item.ip_address)
    if item.source == models.FeedSource.DARKLIST:
        data['reference_url'] = f'https://www.darklist.de/view.php?ip={item.ip_address}'
    if item.source == models.FeedSource.TALOS_INTELLIGENCE:
        data['reference_url'] = f'https://www.talosintelligence.com/reputation_center/lookup?search={item.ip_address}'

    return {**data, **extra_data}


def main(records: list[dict]):
    for _record in records:
        internals.logger.debug(_record)
        record = EventRecord(**_record)
        internals.logger.info(f"Triggered by {record}")
        matches: dict[models.WebhookEvent, list[models.ObservedIdentifier]] = {
            models.WebhookEvent.EARLY_WARNING_EMAIL: [],
            models.WebhookEvent.EARLY_WARNING_DOMAIN: [],
            models.WebhookEvent.EARLY_WARNING_IP: [],
        }
        if validators.ipv4(str(record.item.ip_address)) or validators.ipv6(str(record.item.ip_address)):
            for _item in services.aws.query_dynamodb(
                table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                IndexName='address-index',
                KeyConditionExpression=Key('address').eq(str(record.item.ip_address))
            ):
                item = models.ObservedIdentifier(**services.aws.get_dynamodb(item_key={'id': _item['id']}, table_name=services.aws.Tables.OBSERVED_IDENTIFIERS))
                if item.address:
                    matches[models.WebhookEvent.EARLY_WARNING_IP].append(item)

        elif validators.ipv4_cidr(str(record.item.ip_address)) is True:
            for ip_address in IPv4Network(str(record.item.ip_address), strict=False):
                if not ip_address.is_global:
                    continue
                for _item in services.aws.query_dynamodb(
                    table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                    IndexName='address-index',
                    KeyConditionExpression=Key('address').eq(str(ip_address))
                ):
                    item = models.ObservedIdentifier(**services.aws.get_dynamodb(item_key={'id': _item['id']}, table_name=services.aws.Tables.OBSERVED_IDENTIFIERS))
                    if item.address:
                        matches[models.WebhookEvent.EARLY_WARNING_IP].append(item)

        elif validators.ipv6_cidr(str(record.item.ip_address)) is True:
            for ip_address in IPv6Network(str(record.item.ip_address), strict=False):
                if not ip_address.is_global:
                    continue
                for _item in services.aws.query_dynamodb(
                    table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                    IndexName='address-index',
                    KeyConditionExpression=Key('address').eq(str(ip_address))
                ):
                    item = models.ObservedIdentifier(**services.aws.get_dynamodb(item_key={'id': _item['id']}, table_name=services.aws.Tables.OBSERVED_IDENTIFIERS))
                    if item.address:
                        matches[models.WebhookEvent.EARLY_WARNING_IP].append(item)

        elif validators.email(record.item.email_address) is True:
            matches[models.WebhookEvent.EARLY_WARNING_EMAIL].append(item)

        elif validators.domain(record.item.domain_name) is True:
            matches[models.WebhookEvent.EARLY_WARNING_DOMAIN].append(item)

        else:
            internals.logger.critical(f'No handler for value {record.item}')
            continue

        if all(len(items) == 0 for _, items in matches.items()):
            internals.logger.info('No matches')
            continue

        for webhook_event, items in matches.items():
            for matched in items:
                internals.logger.info(f"matched account_name {matched.account_name} {webhook_event}")
                account = models.MemberAccount(name=matched.account_name)
                if not account.load():
                    internals.logger.error(f"Invalid account {matched.account_name}")
                    continue
                data = {**make_data(record.item), **matched.dict()}
                data['emailed_to'] = account.primary_email
                services.webhook.send(
                    event_name=webhook_event,
                    account=account,
                    data=data,
                )
                if account.notifications.early_warning:
                    internals.logger.info("Emailing alert")
                    sendgrid = services.sendgrid.send_email(
                        subject="Early Warning Service (EWS) Alert",
                        recipient=account.primary_email,
                        template="early_warning_service",
                        data=data,
                    )
                    if sendgrid._content:  # pylint: disable=protected-access
                        res = json.loads(
                            sendgrid._content.decode()  # pylint: disable=protected-access
                        )
                        if isinstance(res, dict) and res.get("errors"):
                            internals.logger.error(res.get("errors"))

                feed_identifier = record.item.email_address or record.item.domain_name or record.item.ip_address
                services.aws.put_dynamodb(
                    table_name=services.aws.Tables.EARLY_WARNING_SERVICE,
                    item=models.ThreatIntel(
                        id=uuid5(
                            namespace=internals.NAMESPACE,
                            name=f"{account.name}{feed_identifier}{record.item.source}{record.item.feed_name}",
                        ),
                        account_name=account.name,
                        source=record.item.source,
                        feed_identifier=feed_identifier,
                        feed_date=record.item.first_seen,
                        feed_data=matched.dict(),
                        matching_data=data,
                    ).dict(),
                )


def handler(event, context):
    # hack to dynamically retrieve the token fresh with each Lambda invoke
    @lumigo_tracer(
        token=services.aws.get_ssm(f'/{internals.APP_ENV}/{internals.APP_NAME}/Lumigo/token', WithDecryption=True),
        should_report=internals.APP_ENV == "Prod",
        skip_collecting_http_body=True
    )
    def main_wrapper(records: list[dict]):
        main(records)
    main_wrapper(event["Records"])
