import json
from datetime import datetime

import validators
from pydantic import BaseModel

import internals
import models
import services.aws
import services.sendgrid
import services.webhook


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
    return list(set([
        account_name for account_name, scanner_record in data.items() for summary in scanner_record.history for host in summary.targets if host.transport.hostname in domains
    ]))


# def match_email(email: str, accounts: dict[str, models.ScannerRecord]) -> list[str]:
#     pass


def make_data(account: models.MemberAccount, item: models.FeedStateItem) -> dict:
    if item.data_model == "DataPlane":
        feed_item: models.DataPlane = getattr(models, item.data_model)(**item.data)
        if feed_item.category == "sshclient":
            return {
                'description': "IP addresses that has been seen initiating an SSH connection to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be SSH server cataloging or conducting authentication attack attempts",
                'summary': "SSH Port Scanning and Bruteforcing Authentication",
                'abuse_email': "info@dataplane.org",
                'asn': feed_item.asn,
                'asn_text': feed_item.asn_text,
                'ip_address': str(feed_item.ip_address),
                'last_seen': feed_item.last_seen.isoformat(),
                'account_name': account.name,
            }
        if feed_item.category == "sshpwauth":
            return {
                'description': "IP addresses that has been seen attempting to remotely login to a host using SSH password authentication. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks",
                'summary': "SSH dictionary attacks",
                'abuse_email': "info@dataplane.org",
                'asn': feed_item.asn,
                'asn_text': feed_item.asn_text,
                'ip_address': str(feed_item.ip_address),
                'last_seen': feed_item.last_seen.isoformat(),
                'account_name': account.name,
            }
        if feed_item.category == "dnsrd":
            return {
                'description': "IP addresses that have been identified as sending recursive DNS queries to a remote host. This report lists addresses that may be cataloging open DNS resolvers or evaluating cache entries",
                'summary': "Recursive DNS query cataloging",
                'abuse_email': "info@dataplane.org",
                'asn': feed_item.asn,
                'asn_text': feed_item.asn_text,
                'ip_address': str(feed_item.ip_address),
                'last_seen': feed_item.last_seen.isoformat(),
                'account_name': account.name,
            }
        if feed_item.category == "vncrfb":
            return {
                'description': "IP addresses that have been seen initiating a VNC remote frame buffer (RFB) session to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be VNC server cataloging or conducting various forms of remote access abuse",
                'summary': "Suspicious VNC remote frame buffer (RFB) sessions",
                'abuse_email': "info@dataplane.org",
                'asn': feed_item.asn,
                'asn_text': feed_item.asn_text,
                'ip_address': str(feed_item.ip_address),
                'last_seen': feed_item.last_seen.isoformat(),
                'account_name': account.name,
            }


def handler(event, context):
    accounts: dict[str, models.MemberAccount] = {}
    ip_index: dict[str, set] = {}
    account_data: dict[str, models.ScannerRecord] = {}
    for host_path in services.aws.list_s3(f"{internals.APP_ENV}/hosts/"):
        _, _, hostname, _, ip_address, *_ = host_path.split('/')
        ip_index.setdefault(ip_address, set())
        ip_index[ip_address].add(hostname)

    for object_path in services.aws.list_s3(f"{internals.APP_ENV}/accounts/"):
        if not object_path.endswith("scanner-record.json"):
            continue
        _, _, account_name, *_ = object_path.split('/')
        accounts[account_name] = models.MemberAccount(name=account_name)
        account_data.setdefault(account_name, models.ScannerRecord(account=accounts[account_name]).load())

    for _record in event["Records"]:
        matches: list[models.MemberAccount] = []
        record = EventRecord(**_record)
        internals.logger.debug(f"Triggered by {record}")
        internals.logger.debug(f"raw {_record}")
        internals.logger.info(f"Queue data {record.item}")
        if not hasattr(models, record.item.data_model):
            internals.logger.error(f"Missing data model: {record.item.data_model}")
            continue

        extra_data = {}
        if validators.ipv4(record.item.key) is True and record.item.key in ip_index:
            webhook_event = models.WebhookEvent.EARLY_WARNING_IP
            matches = match_domain(ip_index[record.item.key], account_data)
            extra_data["domains"] = list(ip_index[record.item.key])
        elif validators.ipv6(record.item.key) is True and record.item.key in ip_index:
            webhook_event = models.WebhookEvent.EARLY_WARNING_IP
            matches = match_domain(ip_index[record.item.key], account_data)
            extra_data["domains"] = list(ip_index[record.item.key])
        # elif validators.email(record.item.key) is True:
        #     webhook_event = models.WebhookEvent.EARLY_WARNING_EMAIL
        #     matches = match_email(record.item.key, accounts)
        elif validators.email(f"nobody@{record.item.key}") is True:
            webhook_event = models.WebhookEvent.EARLY_WARNING_DOMAIN
            matches = match_domain(set([record.item.key]), account_data)
        else:
            internals.logger.critical(f'No handler for value {record.item.key}')
            continue

        if len(matches) == 0:
            internals.logger.info('No matches')
            continue

        for account_name in matches:
            internals.logger.info(f"matched account {account_name}")
            account = accounts[account_name].load()
            data = {**make_data(account, record.item), **extra_data}
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
